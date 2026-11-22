import ast
import unittest
from pathlib import Path


class ServerBoundaryTests(unittest.TestCase):
    def test_server_defines_an_explicit_static_asset_allowlist(self) -> None:
        source = Path("server.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn('"/": "index.html"', source)
        self.assertIn('"/app.js": "app.js"', source)
        self.assertIn('self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)', source)

    def test_server_uses_protective_response_headers(self) -> None:
        source = Path("server.py").read_text(encoding="utf-8")
        self.assertIn("Content-Security-Policy", source)
        self.assertIn("X-Content-Type-Options", source)
        self.assertIn("X-Frame-Options", source)


if __name__ == "__main__":
    unittest.main()
