#!/usr/bin/env python3
"""MasterShield AI demo server. No third-party dependencies required."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import math
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentinel import DefenseEngine


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
ENGINE = DefenseEngine()
API_VERSION = "2026-08-19.1"
API_CAPABILITIES = (
    "overview",
    "attacks",
    "transactions",
    "simulate",
    "retrain",
    "score",
    "fidelity",
    "mutate",
    "feedback",
    "simulations",
    "report",
)


def _normalize_path(path: str | None) -> str:
    return (path or "/").rstrip("/") or "/"


def _health_payload(request_id: str | None = None) -> dict:
    payload = {
        "status": "ok",
        "api_version": API_VERSION,
        "capabilities": list(API_CAPABILITIES),
        "model_version": f"hybrid-logit-c{ENGINE.cycle}",
    }
    if request_id:
        payload["request_id"] = request_id
    return payload


def _validate_simulate_payload(payload: dict) -> None:
    attack_ids = payload.get("attack_ids", [])
    if not isinstance(attack_ids, list) or not all(isinstance(item, str) for item in attack_ids):
        raise ValueError("attack_ids must be a list of strings")
    count = payload.get("count", 80)
    intensity = payload.get("intensity", 1.0)
    if isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(float(count)):
        raise ValueError("count must be a finite number")
    if isinstance(intensity, bool) or not isinstance(intensity, (int, float)) or not math.isfinite(float(intensity)):
        raise ValueError("intensity must be a finite number")
    if float(count) < 5 or float(count) > 500:
        raise ValueError("count must be between 5 and 500")
    if float(intensity) < 0.35 or float(intensity) > 1.4:
        raise ValueError("intensity must be between 0.35 and 1.4")


def _validate_mutate_payload(payload: dict) -> None:
    if payload.get("transaction_id") is not None and not isinstance(payload.get("transaction_id"), str):
        raise ValueError("transaction_id must be a string")
    if payload.get("attack_id") is not None and not isinstance(payload.get("attack_id"), str):
        raise ValueError("attack_id must be a string")
    count = payload.get("count", 24)
    if isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(float(count)) or not 1 <= float(count) <= 100:
        raise ValueError("count must be between 1 and 100")


def _parse_json_object(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object")
    return payload


def _json_response(payload: object, status: int = HTTPStatus.OK, request_id: str | None = None) -> tuple[int, list[tuple[str, str]], bytes]:
    if request_id and isinstance(payload, dict) and "request_id" not in payload:
        payload = {**payload, "request_id": request_id}
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'"),
        ("Referrer-Policy", "no-referrer"),
    ]
    if request_id:
        headers.append(("X-Request-ID", request_id))
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
    path = _normalize_path(environ.get("PATH_INFO"))
    query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    request_id = environ.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())
    try:
        if method == "GET":
            if path == "/api/health":
                return _json_response(_health_payload(request_id), request_id=request_id)
            if path == "/api/overview":
                return _json_response(ENGINE.overview(), request_id=request_id)
            if path == "/api/attacks":
                return _json_response({"attacks": ENGINE.attacks()}, request_id=request_id)
            if path == "/api/transactions":
                try:
                    limit = int(query.get("limit", ["100"])[0])
                except ValueError as exc:
                    raise ValueError("limit must be an integer") from exc
                return _json_response({"transactions": ENGINE.transactions(limit)}, request_id=request_id)
            if path == "/api/fidelity":
                return _json_response(ENGINE.fidelity(), request_id=request_id)
            if path == "/api/report":
                return _json_response(ENGINE.report(), request_id=request_id)
            if path == "/api/simulations":
                return _json_response({"simulations": ENGINE.simulations()}, request_id=request_id)
            if path == "/api/feedback":
                return _json_response({"feedback": ENGINE.store.list("feedback")}, request_id=request_id)
            if path.startswith("/api/"):
                return _json_response({"error": "API endpoint not found", "request_id": request_id}, HTTPStatus.NOT_FOUND, request_id)
            return _static_response(path)

        if method == "POST":
            payload = _read_wsgi_body(environ)
            if path == "/api/simulate":
                _validate_simulate_payload(payload)
                result = ENGINE.simulate(payload.get("attack_ids") or [], payload.get("count", 80), payload.get("intensity", 1.0))
                result["request_id"] = request_id
                return _json_response(result, HTTPStatus.CREATED, request_id)
            if path == "/api/mutate":
                _validate_mutate_payload(payload)
                result = ENGINE.mutate_transaction(payload.get("transaction_id"), payload.get("attack_id"), payload.get("count", 24))
                result["request_id"] = request_id
                return _json_response(result, request_id=request_id)
            if path == "/api/retrain":
                if payload and payload.keys() - {"confirm"}:
                    raise ValueError("retrain accepts only the optional confirm field")
                return _json_response(ENGINE.retrain(), request_id=request_id)
            if path == "/api/score":
                return _json_response(ENGINE.score_transaction(payload), request_id=request_id)
            if path == "/api/feedback":
                if not isinstance(payload.get("transaction_id"), str) or not isinstance(payload.get("outcome"), str):
                    raise ValueError("transaction_id and outcome are required strings")
                return _json_response(ENGINE.submit_feedback(payload["transaction_id"], payload["outcome"], payload.get("note", "")), HTTPStatus.CREATED, request_id)
            return _json_response({"error": "API endpoint not found", "request_id": request_id}, HTTPStatus.NOT_FOUND, request_id)

        if method == "HEAD":
            status, headers, body = _dispatch_wsgi({**environ, "REQUEST_METHOD": "GET"})
            return status, headers, b""
        return _json_response({"error": "Method not allowed"}, HTTPStatus.METHOD_NOT_ALLOWED, request_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _json_response({"error": str(exc), "request_id": request_id}, HTTPStatus.BAD_REQUEST, request_id)
    except Exception as exc:  # pragma: no cover - top-level guard for serverless resilience
        if os.environ.get("MASTERSHIELD_DEBUG") == "1":
            error = str(exc)
        else:
            error = "Internal server error"
        return _json_response({"error": error, "request_id": request_id}, HTTPStatus.INTERNAL_SERVER_ERROR, request_id)


def app(environ: dict, start_response) -> list[bytes]:
    """WSGI entrypoint used by Vercel's Python runtime."""
    status, headers, body = _dispatch_wsgi(environ)
    start_response(f"{status} {HTTPStatus(status).phrase}", headers)
    return [body]


class AppHandler(BaseHTTPRequestHandler):
    server_version = "MasterShield/1.0"

    def _json(self, payload: object, status: int = 200) -> None:
        if isinstance(payload, dict) and "request_id" not in payload:
            payload = {**payload, "request_id": getattr(self, "request_id", str(uuid.uuid4()))}
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Request-ID", getattr(self, "request_id", str(uuid.uuid4())))
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
        path = _normalize_path(parsed.path)
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        try:
            if path == "/api/health":
                self._json(_health_payload(self.request_id))
            elif path == "/api/overview":
                self._json(ENGINE.overview())
            elif path == "/api/attacks":
                self._json({"attacks": ENGINE.attacks()})
            elif path == "/api/transactions":
                try:
                    limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
                except ValueError as exc:
                    raise ValueError("limit must be an integer") from exc
                self._json({"transactions": ENGINE.transactions(limit)})
            elif path == "/api/fidelity":
                self._json(ENGINE.fidelity())
            elif path == "/api/report":
                self._json(ENGINE.report())
            elif path == "/api/simulations":
                self._json({"simulations": ENGINE.simulations()})
            elif path == "/api/feedback":
                self._json({"feedback": ENGINE.store.list("feedback")})
            elif path.startswith("/api/"):
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._static(path if path != "/" else "/index.html")
        except (ValueError, TypeError) as exc:
            self._json({"error": str(exc), "request_id": self.request_id}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover - top-level guard for prototype resilience
            self._json({"error": str(exc) if os.environ.get("MASTERSHIELD_DEBUG") == "1" else "Internal server error", "request_id": self.request_id}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = _normalize_path(parsed.path)
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        try:
            payload = self._body()
            if path == "/api/simulate":
                _validate_simulate_payload(payload)
                result = ENGINE.simulate(
                    payload.get("attack_ids") or [],
                    payload.get("count", 80),
                    payload.get("intensity", 1.0),
                )
                self._json(result, HTTPStatus.CREATED)
            elif path == "/api/retrain":
                self._json(ENGINE.retrain())
            elif path == "/api/mutate":
                _validate_mutate_payload(payload)
                self._json(ENGINE.mutate_transaction(payload.get("transaction_id"), payload.get("attack_id"), payload.get("count", 24)))
            elif path == "/api/score":
                self._json(ENGINE.score_transaction(payload))
            elif path == "/api/feedback":
                if not isinstance(payload.get("transaction_id"), str) or not isinstance(payload.get("outcome"), str):
                    raise ValueError("transaction_id and outcome are required strings")
                self._json(ENGINE.submit_feedback(payload["transaction_id"], payload["outcome"], payload.get("note", "")), HTTPStatus.CREATED)
            else:
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc), "request_id": self.request_id}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover
            self._json({"error": str(exc) if os.environ.get("MASTERSHIELD_DEBUG") == "1" else "Internal server error", "request_id": self.request_id}, HTTPStatus.INTERNAL_SERVER_ERROR)

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
