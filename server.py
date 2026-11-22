"""Flow Monitor local server: dashboard plus modular read-only telemetry APIs."""
from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from flow_monitor.storage import Repository
from flow_monitor.telemetry import LocalTelemetryCollector

ROOT = Path(__file__).parent
repository = Repository(ROOT / "flow_monitor.db")
collector = LocalTelemetryCollector(repository)

SCOPE = {
    "name": "Local host telemetry",
    "mode": "local-host",
    "active_discovery_enabled": True,
    "network_ranges": ["Current private /24 LAN, detected at runtime"],
    "note": "Active discovery is enabled only for the detected private /24 LAN and is rate-limited to once per minute. Packet payloads are not collected.",
}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def _json(self, content: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(content).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def end_headers(self) -> None:
        """Keep the local dashboard private and prevent content-type guessing."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def _static_file(self, relative_path: str) -> None:
        """Serve only dashboard assets; never expose source, databases, or logs."""
        path = ROOT / relative_path
        if not path.is_file():
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    @staticmethod
    def _limit(values: dict[str, list[str]]) -> int:
        try:
            return min(max(int(values.get("limit", ["100"])[0]), 1), 500)
        except ValueError:
            return 100

    def do_GET(self) -> None:
        request = urlparse(self.path)
        values = parse_qs(request.query)
        if request.path == "/api/snapshot":
            snapshot = collector.snapshot()
            self._json(snapshot)
            return
        if request.path == "/api/connections":
            try:
                status = values.get("status", ["all"])[0]
                self._json({"items": repository.connections(status, self._limit(values)), "scope": "observed since this server started"})
            except ValueError as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
            return
        if request.path == "/api/devices":
            self._json({"items": repository.devices(self._limit(values)), "scope": "remote peers observed by this local host"})
            return
        if request.path == "/api/insights":
            self._json(repository.insights())
            return
        if request.path.startswith("/api/devices/"):
            host = unquote(request.path.removeprefix("/api/devices/"))
            detail = repository.device(host)
            if detail is None:
                self._json({"error": "device not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._json(detail)
            return
        if request.path == "/api/sources":
            self._json({"items": [{"id": "local-host", "type": "local-host-telemetry", "status": "healthy", "collection": "Host telemetry and local LAN discovery", "scope": collector.authorized_range or "Current private LAN (detecting)", "captures_payload": False, "active_discovery": True, "refresh_interval": "3 seconds", "discovery_interval": "60 seconds", "retention": "Connection history while the local database is retained"}]})
            return
        if request.path == "/api/scope":
            self._json(SCOPE)
            return
        static_assets = {
            "/": "index.html",
            "/index.html": "index.html",
            "/styles.css": "styles.css",
            "/overrides.css": "overrides.css",
            "/app.js": "app.js",
        }
        if request.path in static_assets:
            self._static_file(static_assets[request.path])
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)


if __name__ == "__main__":
    print("Flow Monitor: http://127.0.0.1:4173")
    ThreadingHTTPServer(("127.0.0.1", 4173), Handler).serve_forever()
