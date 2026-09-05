"""Record / replay HTTP server that stands in for the ThreatCluster API.

* replay mode: serves recorded responses from tests/fixtures/api.json; an
  unknown request is a 404 with a clear body and is added to ``misses``.
* record mode: on a cache miss, forwards the request (with whatever auth
  header the MCP server sent) to the real API, stores status + budget
  headers + body, and serves it. Never logs headers or bodies.

Keys are canonical: ``GET /threats?keyword=Cleo Harmony&limit=25&time_filter=7d``
(path relative to the API base, query pairs decoded and sorted) so the python
and node servers must issue byte-for-byte-equivalent requests to hit.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlsplit

import httpx

API_PREFIX = "/api/public/v1"
KEEP_HEADERS = ("content-type", "x-request-cost", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                "x-credits-balance", "retry-after")


def canonical_key(path: str, query: str) -> str:
    rel = path[len(API_PREFIX):] if path.startswith(API_PREFIX) else path
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    return f"GET {rel}" + ("?" + "&".join(f"{k}={v}" for k, v in pairs) if pairs else "")


class RecordReplayServer:
    def __init__(self, fixture_path: Path, mode: str = "replay", upstream: Optional[str] = None) -> None:
        assert mode in ("replay", "record")
        self.fixture_path = fixture_path
        self.mode = mode
        self.upstream = (upstream or "").rstrip("/")
        self.cache: dict[str, dict] = {}
        self.misses: list[str] = []
        self.hits: list[str] = []
        self.recorded: list[str] = []
        self.lock = threading.Lock()
        if fixture_path.exists():
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            self.cache = data.get("responses", {})
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> "RecordReplayServer":
        srv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):  # silence; never log requests
                return

            def do_GET(self):
                srv._handle(self)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    @property
    def api_base(self) -> str:
        assert self._httpd
        return f"http://127.0.0.1:{self._httpd.server_address[1]}{API_PREFIX}"

    # -- request handling ---------------------------------------------------
    def _handle(self, h: BaseHTTPRequestHandler) -> None:
        parts = urlsplit(h.path)
        key = canonical_key(parts.path, parts.query)
        with self.lock:
            entry = self.cache.get(key)
        if entry is None and self.mode == "record" and self.upstream:
            entry = self._forward(h, parts.path, parts.query)
            with self.lock:
                self.cache[key] = entry
                self.recorded.append(key)
        if entry is None:
            with self.lock:
                self.misses.append(key)
            body = json.dumps({"error": "replay miss", "key": key}).encode()
            h.send_response(404)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)
            return
        with self.lock:
            self.hits.append(key)
        body = json.dumps(entry["body"]).encode() if entry.get("json", True) else str(entry["body"]).encode()
        h.send_response(int(entry["status"]))
        for k, v in entry.get("headers", {}).items():
            if k.lower() != "content-length":
                h.send_header(k, v)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def _forward(self, h: BaseHTTPRequestHandler, path: str, query: str) -> dict:
        rel = path[len(API_PREFIX):] if path.startswith(API_PREFIX) else path
        headers = {}
        for name in ("Authorization", "X-API-Key", "Accept", "User-Agent"):
            v = h.headers.get(name)
            if v:
                headers[name] = v
        url = self.upstream + rel + ("?" + query if query else "")
        with httpx.Client(timeout=90.0) as c:
            r = c.get(url, headers=headers)
        try:
            body, is_json = r.json(), True
        except ValueError:
            body, is_json = r.text, False
        kept = {k: v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS}
        return {"status": r.status_code, "headers": kept, "json": is_json, "body": body}

    # -- persistence ----------------------------------------------------------
    def save(self, recorded_at: str) -> None:
        self.fixture_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"recorded_at": recorded_at, "note": "Recorded ThreatCluster API responses (free tier). Regenerate with "
                "THREATCLUSTER_LIVE=1 pytest python/tests/test_live.py. No credentials are stored here.",
                "responses": dict(sorted(self.cache.items()))}
        self.fixture_path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


class ScriptedServer:
    """Answers every request with one scripted response (for 401/429/403 tests).
    Counts requests so a test can assert that no call was made."""

    def __init__(self, status: int, body, headers: Optional[dict] = None) -> None:
        self.status, self.body, self.headers = status, body, headers or {}
        self.requests: list[str] = []
        self.seen_headers: list[dict] = []
        self._httpd: Optional[ThreadingHTTPServer] = None

    def start(self) -> "ScriptedServer":
        srv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                return

            def do_GET(self):
                srv.requests.append(self.path)
                srv.seen_headers.append({k: v for k, v in self.headers.items()})
                payload = json.dumps(srv.body).encode()
                self.send_response(srv.status)
                self.send_header("Content-Type", "application/json")
                for k, v in srv.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    @property
    def api_base(self) -> str:
        assert self._httpd
        return f"http://127.0.0.1:{self._httpd.server_address[1]}{API_PREFIX}"
