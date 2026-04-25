from __future__ import annotations

import json
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


HTML_PAGE = """<!doctype html>
<html lang=\"zh-CN\">
<head>
  <meta charset=\"utf-8\"/>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
  <title>me-chat secure web ui</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: #0f172a; color: #e2e8f0; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 20px; }
    h1 { margin: 0 0 12px; font-size: 20px; }
    #log { height: 70vh; overflow: auto; background: #111827; border: 1px solid #374151; border-radius: 12px; padding: 12px; }
    .msg { margin: 8px 0; line-height: 1.45; }
    .meta { color: #94a3b8; font-size: 12px; margin-bottom: 4px; }
    form { display: flex; gap: 8px; margin-top: 12px; }
    input { flex: 1; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #1e293b; color: #f8fafc; }
    button { border: 0; border-radius: 10px; padding: 12px 16px; background: #2563eb; color: #fff; cursor: pointer; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>me-chat secure room</h1>
    <div id=\"log\"></div>
    <form id=\"sendForm\">
      <input id=\"message\" autocomplete=\"off\" placeholder=\"输入消息并回车\" maxlength=\"2000\" />
      <button type=\"submit\">发送</button>
    </form>
  </div>
  <script>
    let lastId = 0;
    const log = document.getElementById('log');
    const form = document.getElementById('sendForm');
    const input = document.getElementById('message');

    function addItem(item) {
      const el = document.createElement('div');
      el.className = 'msg';
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = item.meta;
      const body = document.createElement('div');
      body.textContent = item.text;
      el.appendChild(meta);
      el.appendChild(body);
      log.appendChild(el);
      log.scrollTop = log.scrollHeight;
    }

    async function poll() {
      try {
        const res = await fetch('/events?after=' + encodeURIComponent(String(lastId)));
        const data = await res.json();
        for (const ev of data.events) {
          lastId = Math.max(lastId, ev.id);
          addItem({ meta: ev.meta, text: ev.text });
        }
      } catch (_) {}
      setTimeout(poll, 800);
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) return;
      input.value = '';
      await fetch('/send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text })
      });
    });

    poll();
  </script>
</body>
</html>
"""


@dataclass
class EventBus:
    events: list[dict] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    next_id: int = 1

    def add(self, meta: str, text: str) -> None:
        with self.lock:
            self.events.append({"id": self.next_id, "meta": meta, "text": text})
            self.next_id += 1
            if len(self.events) > 1000:
                self.events = self.events[-1000:]

    def since(self, after: int) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e["id"] > after]


class WebUIGateway:
    def __init__(self, send_message, bus: EventBus):
        self._send_message = send_message
        self.bus = bus

    def send(self, text: str) -> None:
        self._send_message(text)


class _Handler(BaseHTTPRequestHandler):
    gateway: WebUIGateway

    def _json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/events":
            q = parse_qs(parsed.query)
            after_raw = q.get("after", ["0"])[0]
            try:
                after = max(0, int(after_raw))
            except ValueError:
                after = 0
            self._json({"events": self.gateway.bus.since(after)})
            return
        self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/send":
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size < 0 or size > 128 * 1024:
            self._json({"error": "payload too large"}, status=HTTPStatus.BAD_REQUEST)
            return
        raw = self.rfile.read(size)
        try:
            payload = json.loads(raw.decode("utf-8"))
            text = str(payload.get("text", "")).strip()
        except Exception:
            self._json({"error": "invalid payload"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not text:
            self._json({"error": "message cannot be empty"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            self.gateway.send(text)
        except Exception as exc:
            self._json({"error": f"send failed: {exc}"}, status=HTTPStatus.BAD_GATEWAY)
            return
        self._json({"ok": True})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def serve_web_ui(host: str, port: int, gateway: WebUIGateway) -> None:
    handler_cls = type("ChatHandler", (_Handler,), {})
    handler_cls.gateway = gateway
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    url = f"http://{host}:{port}/"
    webbrowser.open(url, new=1, autoraise=True)
    gateway.bus.add("system", f"WebUI started at {url}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        time.sleep(0.05)
