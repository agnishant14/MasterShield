#!/usr/bin/env python3
"""MasterShield AI demo server. No third-party dependencies required."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentinel import DefenseEngine


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
ENGINE = DefenseEngine()


def _parse_json_object(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object")
    return payload


def _json_response(payload: object, status: int = HTTPStatus.OK) -> tuple[int, list[tuple[str, str]], bytes]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ]
    return int(status), headers, body


def _static_response(relative: str) -> tuple[int, list[tuple[str, str]], bytes]:
    requested = (WEB_ROOT / relative.lstrip("/")).resolve()
    web_root = WEB_ROOT.resolve()
    if web_root not in requested.parents and requested != web_root:
        return _json_response({"error": "Not found"}, HTTPStatus.NOT_FOUND)
    if requested.is_dir():
        requested = requested / "index.html"
    if not requested.exists() or not requested.is_file():
        if Path(relative).suffix:
            return _json_response({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        requested = WEB_ROOT / "index.html"
    body = requested.read_bytes()
    content_type = mimetypes.guess_type(str(requested))[0] or "application/octet-stream"
    content_header = f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type
    headers = [
        ("Content-Type", content_header),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-cache"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
    ]
    return int(HTTPStatus.OK), headers, body


def _read_wsgi_body(environ: dict) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if length > 1_000_000:
        raise ValueError("Request body too large")
    stream = environ.get("wsgi.input") or BytesIO()
    return _parse_json_object(stream.read(length) if length else b"{}")


def _dispatch_wsgi(environ: dict) -> tuple[int, list[tuple[str, str]], bytes]:
    """Dispatch a Vercel WSGI request using the same engine as the local server."""
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO") or "/"
    query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    try:
        if method == "GET":
            if path == "/api/health":
                return _json_response({"status": "ok", "model_version": f"hybrid-logit-c{ENGINE.cycle}"})
            if path == "/api/overview":
                return _json_response(ENGINE.overview())
            if path == "/api/attacks":
                return _json_response({"attacks": ENGINE.attacks()})
            if path == "/api/transactions":
                try:
                    limit = int(query.get("limit", ["100"])[0])
                except ValueError as exc:
                    raise ValueError("limit must be an integer") from exc
                return _json_response({"transactions": ENGINE.transactions(limit)})
            if path.startswith("/api/"):
                return _json_response({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
            return _static_response(path)

        if method == "POST":
            payload = _read_wsgi_body(environ)
            if path == "/api/simulate":
                result = ENGINE.simulate(
                    payload.get("attack_ids") or [],
                    payload.get("count", 80),
                    payload.get("intensity", 1.0),
                )
                return _json_response(result, HTTPStatus.CREATED)
            if path == "/api/retrain":
                return _json_response(ENGINE.retrain())
            if path == "/api/score":
                return _json_response(ENGINE.score_transaction(payload))
            return _json_response({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)

        if method == "HEAD":
            status, headers, body = _dispatch_wsgi({**environ, "REQUEST_METHOD": "GET"})
            return status, headers, b""
        return _json_response({"error": "Method not allowed"}, HTTPStatus.METHOD_NOT_ALLOWED)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _json_response({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
    except Exception as exc:  # pragma: no cover - top-level guard for serverless resilience
        return _json_response({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)


def app(environ: dict, start_response) -> list[bytes]:
    """WSGI entrypoint used by Vercel's Python runtime."""
    status, headers, body = _dispatch_wsgi(environ)
    start_response(f"{status} {HTTPStatus(status).phrase}", headers)
    return [body]


class AppHandler(BaseHTTPRequestHandler):
    server_version = "MasterShield/1.0"

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length must be an integer") from exc
        if length > 1_000_000:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return _parse_json_object(raw)

    def _static(self, relative: str) -> None:
        requested = (WEB_ROOT / relative.lstrip("/")).resolve()
        if WEB_ROOT.resolve() not in requested.parents and requested != WEB_ROOT.resolve():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if requested.is_dir():
            requested = requested / "index.html"
        if not requested.exists() or not requested.is_file():
            if Path(relative).suffix:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            requested = WEB_ROOT / "index.html"
        body = requested.read_bytes()
        content_type = mimetypes.guess_type(str(requested))[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/health":
                self._json({"status": "ok", "model_version": f"hybrid-logit-c{ENGINE.cycle}"})
            elif parsed.path == "/api/overview":
                self._json(ENGINE.overview())
            elif parsed.path == "/api/attacks":
                self._json({"attacks": ENGINE.attacks()})
            elif parsed.path == "/api/transactions":
                try:
                    limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
                except ValueError as exc:
                    raise ValueError("limit must be an integer") from exc
                self._json({"transactions": ENGINE.transactions(limit)})
            elif parsed.path.startswith("/api/"):
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._static(parsed.path if parsed.path != "/" else "/index.html")
        except (ValueError, TypeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover - top-level guard for prototype resilience
            self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = self._body()
            if parsed.path == "/api/simulate":
                result = ENGINE.simulate(
                    payload.get("attack_ids") or [],
                    payload.get("count", 80),
                    payload.get("intensity", 1.0),
                )
                self._json(result, HTTPStatus.CREATED)
            elif parsed.path == "/api/retrain":
                self._json(ENGINE.retrain())
            elif parsed.path == "/api/score":
                self._json(ENGINE.score_transaction(payload))
            else:
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover
            self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, fmt: str, *args: object) -> None:
        if os.environ.get("MASTERSHIELD_QUIET") != "1":
            super().log_message(fmt, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MasterShield AI challenge prototype")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    print(f"MasterShield AI running at http://{args.host}:{args.port}")
    print(f"Model: hybrid-logit-c{ENGINE.cycle} | F1 {ENGINE.metrics['f1']:.3f} | AUC {ENGINE.metrics['auc']:.3f}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
