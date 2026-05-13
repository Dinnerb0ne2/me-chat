from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from .crypto import derive_user_password_hash, verify_user_password
from .protocol import Frame, ProtocolError, parse_json_line, read_line_limited


LOG = logging.getLogger("me_chat.server")


@dataclass(eq=False)
class Session:
    username: str
    room: str
    writer: object
    send_lock: threading.Lock = field(default_factory=threading.Lock)


class ChatServer:
    def __init__(self, users_path: Path):
        self._users_path = users_path
        self._users_lock = threading.Lock()
        self._rooms: Dict[str, set[Session]] = {}
        self._rooms_lock = threading.Lock()
        self._users = self._load_users()

    def _load_users(self) -> dict:
        if not self._users_path.exists():
            return {"users": {}}
        with self._users_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("users", {}), dict):
            raise ValueError("invalid users database format")
        return data

    def _save_users(self) -> None:
        tmp_path = self._users_path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(self._users, f, ensure_ascii=False, indent=2)
            f.write("\n")
        tmp_path.replace(self._users_path)

    def create_user(self, username: str, password: str) -> None:
        if not username or len(username) > 64:
            raise ValueError("username must be 1..64 characters")
        salt, digest = derive_user_password_hash(password)
        with self._users_lock:
            users = self._users.setdefault("users", {})
            users[username] = {"salt": salt, "password_hash": digest}
            self._save_users()

    def _verify_user(self, username: str, password: str) -> bool:
        with self._users_lock:
            entry = self._users.get("users", {}).get(username)
        if not isinstance(entry, dict):
            return False
        salt = entry.get("salt")
        digest = entry.get("password_hash")
        if not isinstance(salt, str) or not isinstance(digest, str):
            return False
        return verify_user_password(password, salt, digest)

    def _send(self, session: Session, frame: Frame) -> None:
        payload = frame.to_json_line()
        with session.send_lock:
            session.writer.write(payload)
            session.writer.flush()

    def _broadcast(self, room: str, frame: Frame, exclude: Session | None = None) -> None:
        with self._rooms_lock:
            sessions = list(self._rooms.get(room, set()))
        for session in sessions:
            if exclude is not None and session is exclude:
                continue
            try:
                self._send(session, frame)
            except Exception:
                self._remove_session(session)

    def _add_session(self, session: Session) -> None:
        with self._rooms_lock:
            self._rooms.setdefault(session.room, set()).add(session)

    def _remove_session(self, session: Session) -> None:
        with self._rooms_lock:
            members = self._rooms.get(session.room)
            if not members:
                return
            members.discard(session)
            if not members:
                self._rooms.pop(session.room, None)

    def handle_client(self, conn: ssl.SSLSocket, addr: tuple[str, int]) -> None:
        reader = conn.makefile("rb")
        writer = conn.makefile("wb")
        session: Session | None = None
        try:
            hello = Frame("hello", {"version": 1, "features": ["room", "e2e"]})
            writer.write(hello.to_json_line())
            writer.flush()

            auth_frame = parse_json_line(read_line_limited(reader))
            if auth_frame.kind != "auth":
                raise ProtocolError("expected auth frame")

            username = str(auth_frame.payload.get("username", ""))
            password = str(auth_frame.payload.get("password", ""))
            room = str(auth_frame.payload.get("room", ""))
            if not username or len(username) > 64 or not room or len(room) > 64:
                raise ProtocolError("invalid username or room")
            if not self._verify_user(username, password):
                writer.write(Frame("error", {"message": "authentication failed"}).to_json_line())
                writer.flush()
                return

            session = Session(username=username, room=room, writer=writer)
            self._add_session(session)
            self._send(session, Frame("auth_ok", {"username": username, "room": room}))
            LOG.info("client authenticated: user=%s room=%s addr=%s:%s", username, room, addr[0], addr[1])

            self._broadcast(
                room,
                Frame("system", {"message": f"{username} joined room"}),
                exclude=session,
            )

            while True:
                frame = parse_json_line(read_line_limited(reader))
                if frame.kind == "chat":
                    ciphertext = frame.payload.get("ciphertext")
                    nonce = frame.payload.get("nonce")
                    mac = frame.payload.get("mac")
                    ts = frame.payload.get("ts")
                    if not all(isinstance(v, str) for v in (ciphertext, nonce, mac)):
                        raise ProtocolError("invalid encrypted payload")
                    if type(ts) is not int:
                        raise ProtocolError("invalid timestamp")
                    if len(ciphertext) > 65536 or len(nonce) > 256 or len(mac) > 256:
                        raise ProtocolError("payload too large")
                    self._broadcast(
                        room,
                        Frame(
                            "chat",
                            {
                                "sender": username,
                                "room": room,
                                "ts": ts,
                                "ciphertext": ciphertext,
                                "nonce": nonce,
                                "mac": mac,
                            },
                        ),
                        exclude=session,
                    )
                elif frame.kind == "ping":
                    self._send(session, Frame("pong", {}))
                elif frame.kind == "quit":
                    break
                else:
                    raise ProtocolError("unknown frame type")
        except (EOFError, ssl.SSLError):
            pass
        except ProtocolError as exc:
            LOG.warning("protocol error from %s:%s: %s", addr[0], addr[1], exc)
        except Exception:
            LOG.exception("unexpected error serving client %s:%s", addr[0], addr[1])
        finally:
            if session is not None:
                self._remove_session(session)
                self._broadcast(session.room, Frame("system", {"message": f"{session.username} left room"}))
            try:
                writer.close()
            except Exception:
                pass
            try:
                reader.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def build_server_ssl_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context


def run_server(host: str, port: int, certfile: Path, keyfile: Path, users_path: Path) -> None:
    server = ChatServer(users_path=users_path)
    context = build_server_ssl_context(certfile=certfile, keyfile=keyfile)
    with socket.create_server((host, port), backlog=256, reuse_port=False) as sock:
        LOG.info("server listening on %s:%d", host, port)
        while True:
            client, addr = sock.accept()
            try:
                tls_client = context.wrap_socket(client, server_side=True)
            except ssl.SSLError:
                client.close()
                continue
            thread = threading.Thread(
                target=server.handle_client,
                args=(tls_client, addr),
                daemon=True,
            )
            thread.start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure stdlib chat server")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run TLS chat server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=7443)
    serve.add_argument("--certfile", type=Path, required=True)
    serve.add_argument("--keyfile", type=Path, required=True)
    serve.add_argument("--users", type=Path, default=Path("users.json"))

    add_user = sub.add_parser("create-user", help="Create or update a user")
    add_user.add_argument("--users", type=Path, default=Path("users.json"))
    add_user.add_argument("--username", required=True)
    add_user.add_argument("--password", required=True)

    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if args.command == "create-user":
        server = ChatServer(users_path=args.users)
        server.create_user(username=args.username, password=args.password)
        LOG.info("user created/updated: %s", args.username)
        return

    if args.command == "serve":
        run_server(
            host=args.host,
            port=args.port,
            certfile=args.certfile,
            keyfile=args.keyfile,
            users_path=args.users,
        )
        return

    raise ValueError("unknown command")


if __name__ == "__main__":
    main()
