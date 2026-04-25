from __future__ import annotations

import argparse
import getpass
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .crypto import CryptoError, SealedMessage, derive_room_key, open_sealed, seal
from .protocol import Frame, ProtocolError, parse_json_line, read_line_limited
from .webui import EventBus, WebUIGateway, serve_web_ui


@dataclass(frozen=True)
class ChatConfig:
    host: str
    port: int
    username: str
    password: str
    room: str
    room_passphrase: str


class ChatConnection:
    def __init__(self, config: ChatConfig, ssl_context: ssl.SSLContext):
        self._cfg = config
        self._ctx = ssl_context
        self._sock: ssl.SSLSocket | None = None
        self._reader = None
        self._writer = None
        self._send_lock = threading.Lock()
        self._room_key = derive_room_key(config.room_passphrase, config.room)

    def connect(self) -> None:
        raw = socket.create_connection((self._cfg.host, self._cfg.port), timeout=15)
        sock = self._ctx.wrap_socket(raw, server_hostname=self._cfg.host)
        self._sock = sock
        self._reader = sock.makefile("rb")
        self._writer = sock.makefile("wb")

        hello = parse_json_line(read_line_limited(self._reader))
        if hello.kind != "hello":
            raise ProtocolError("server did not send hello")

        self._send_raw(
            Frame(
                "auth",
                {
                    "username": self._cfg.username,
                    "password": self._cfg.password,
                    "room": self._cfg.room,
                },
            )
        )
        resp = parse_json_line(read_line_limited(self._reader))
        if resp.kind == "error":
            msg = str(resp.payload.get("message", "authentication failed"))
            raise RuntimeError(msg)
        if resp.kind != "auth_ok":
            raise ProtocolError("authentication failed")

    def _send_raw(self, frame: Frame) -> None:
        payload = frame.to_json_line()
        with self._send_lock:
            self._writer.write(payload)
            self._writer.flush()

    def send_chat(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        if len(text) > 2000:
            raise ValueError("message too long")
        ts = int(time.time() * 1000)
        aad = f"{self._cfg.room}|{self._cfg.username}|{ts}".encode("utf-8")
        sealed = seal(self._room_key, text.encode("utf-8"), aad)
        self._send_raw(
            Frame(
                "chat",
                {
                    "ts": ts,
                    "nonce": sealed.nonce_b64,
                    "ciphertext": sealed.ciphertext_b64,
                    "mac": sealed.mac_b64,
                },
            )
        )

    def recv_loop(self, on_system, on_chat) -> None:
        while True:
            frame = parse_json_line(read_line_limited(self._reader))
            if frame.kind == "system":
                on_system(str(frame.payload.get("message", "")))
                continue
            if frame.kind == "chat":
                sender = str(frame.payload.get("sender", ""))
                room = str(frame.payload.get("room", ""))
                ts = frame.payload.get("ts")
                if room != self._cfg.room or not sender or not isinstance(ts, int):
                    continue
                sealed = SealedMessage(
                    nonce_b64=str(frame.payload.get("nonce", "")),
                    ciphertext_b64=str(frame.payload.get("ciphertext", "")),
                    mac_b64=str(frame.payload.get("mac", "")),
                )
                aad = f"{room}|{sender}|{ts}".encode("utf-8")
                try:
                    pt = open_sealed(self._room_key, sealed, aad).decode("utf-8")
                except (CryptoError, UnicodeDecodeError):
                    on_chat(sender, "[消息认证失败或密钥不匹配]")
                    continue
                on_chat(sender, pt)
                continue
            if frame.kind == "pong":
                continue

    def close(self) -> None:
        try:
            self._send_raw(Frame("quit", {}))
        except Exception:
            pass
        for obj in (self._writer, self._reader, self._sock):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass


def build_client_ssl_context(cafile: Path | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cafile is not None:
        ctx.load_verify_locations(cafile=str(cafile))
    return ctx


def run_cli(conn: ChatConnection, username: str) -> None:
    stop = threading.Event()

    def on_system(msg: str) -> None:
        print(f"[*] {msg}")

    def on_chat(sender: str, msg: str) -> None:
        print(f"[{sender}] {msg}")

    def receiver() -> None:
        try:
            conn.recv_loop(on_system=on_system, on_chat=on_chat)
        except EOFError:
            print("[*] 连接已关闭")
        except Exception as exc:
            print(f"[!] 接收异常: {exc}")
        finally:
            stop.set()

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    print(f"已连接。你是 {username}，输入 /quit 退出。")
    while not stop.is_set():
        try:
            line = input("")
        except EOFError:
            break
        if not line:
            continue
        if line.strip() == "/quit":
            break
        try:
            conn.send_chat(line)
        except Exception as exc:
            print(f"[!] 发送失败: {exc}")


def run_web(conn: ChatConnection, username: str, host: str, port: int) -> None:
    bus = EventBus()
    bus.add("system", f"登录用户: {username}")

    def on_system(msg: str) -> None:
        bus.add("system", msg)

    def on_chat(sender: str, msg: str) -> None:
        bus.add(sender, msg)

    receiver = threading.Thread(target=lambda: conn.recv_loop(on_system, on_chat), daemon=True)
    receiver.start()

    gateway = WebUIGateway(send_message=conn.send_chat, bus=bus)
    serve_web_ui(host=host, port=port, gateway=gateway)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure stdlib chat client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--username", required=True)
    parser.add_argument("--room", required=True)
    parser.add_argument("--password")
    parser.add_argument("--room-passphrase")
    parser.add_argument("--cafile", type=Path)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--ui", choices=["cli", "web"], default="cli")
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    password = args.password or getpass.getpass("Server password: ")
    room_passphrase = args.room_passphrase or getpass.getpass("Room passphrase (E2E): ")

    cfg = ChatConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        password=password,
        room=args.room,
        room_passphrase=room_passphrase,
    )
    ctx = build_client_ssl_context(cafile=args.cafile, insecure=args.insecure)
    conn = ChatConnection(cfg, ctx)

    try:
        conn.connect()
        if args.ui == "web":
            run_web(conn, username=args.username, host=args.web_host, port=args.web_port)
        else:
            run_cli(conn, username=args.username)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
