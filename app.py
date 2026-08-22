#!/usr/bin/env python3
"""MasterShield AI demo server. No third-party dependencies required."""

from __future__ import annotations

import argparse
import csv
import json
import mimetypes
import os
import sys
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentinel import DefenseEngine
from sentinel.contracts import (
    MAX_BODY_BYTES,
    validate_feedback_payload,
    validate_limit,
    validate_mutate_payload,
    validate_retrain_payload,
    validate_rollback_payload,
    validate_score_payload,
    validate_simulate_payload,
)


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
    "models",
    "rollback",
    "audit",
)


def _normalize_path(path: str | None) -> str:
    return (path or "/").rstrip("/") or "/"


def _health_payload(request_id: str | None = None) -> dict:
    payload = {
        "status": "ok",
        "api_version": API_VERSION,
        "capabilities": list(API_CAPABILITIES),
        "model_version": ENGINE.active_model_version or f"hybrid-logit-c{ENGINE.cycle}",
    }
    if request_id:
        payload["request_id"] = request_id
    return payload


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


def _csv_response(rows: list[dict], request_id: str | None = None) -> tuple[int, list[tuple[str, str]], bytes]:
    fields = sorted({key for row in rows for key in row}) if rows else ["message"]
    stream = StringIO()
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, ensure_ascii=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})
    body = stream.getvalue().encode("utf-8")
    headers = [("Content-Type", "text/csv; charset=utf-8"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")]
    if request_id:
        headers.append(("X-Request-ID", request_id))
    return int(HTTPStatus.OK), headers, body


def _static_response(relative: str) -> tuple[int, list[tuple[str, str]], bytes]:
    # Browsers commonly request /favicon.ico even when the document declares an SVG icon.
    # Serve the existing branded SVG through that compatibility path as well.
    static_relative = "/favicon.svg" if _normalize_path(relative) == "/favicon.ico" else relative
    requested = (WEB_ROOT / static_relative.lstrip("/")).resolve()
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
    if length < 0 or length > MAX_BODY_BYTES:
        raise ValueError("Request body too large")
    stream = environ.get("wsgi.input") or BytesIO()
    return _parse_json_object(stream.read(length) if length else b"{}")


def _structured_log(event: str, **fields: object) -> None:
    """Emit bounded JSON request logs without payment or identity payloads."""
    if os.environ.get("MASTERSHIELD_QUIET") == "1":
        return
    safe = {"timestamp": time.time(), "event": event}
    safe.update({key: value for key, value in fields.items() if key not in {"body", "payload", "transaction", "customer_id", "device_id"}})
    print(json.dumps(safe, separators=(",", ":"), ensure_ascii=True), file=sys.stderr)


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
                limit = validate_limit(query.get("limit", ["100"])[0])
                return _json_response({"transactions": ENGINE.transactions(limit)}, request_id=request_id)
            if path == "/api/fidelity":
                return _json_response(ENGINE.fidelity(), request_id=request_id)
            if path == "/api/report":
                if query.get("format", ["json"])[0].lower() == "csv":
                    return _csv_response([{"section": "metrics", **ENGINE.metrics}, {"section": "policy_tradeoff", **ENGINE.policy.tradeoff(ENGINE.immutable_holdout_rows, ENGINE.detector)}], request_id)
                return _json_response(ENGINE.report(), request_id=request_id)
            if path == "/api/simulations":
                if query.get("format", ["json"])[0].lower() == "csv":
                    return _csv_response(ENGINE.simulations(), request_id)
                return _json_response({"simulations": ENGINE.simulations()}, request_id=request_id)
            if path == "/api/feedback":
                return _json_response({"feedback": ENGINE.feedback_queue(validate_limit(query.get("limit", ["100"])[0]))}, request_id=request_id)
            if path == "/api/models":
                return _json_response({"models": ENGINE.models(), "active_model_version": ENGINE.active_model_version}, request_id=request_id)
            if path == "/api/audit":
                return _json_response({"audit": ENGINE.audit(validate_limit(query.get("limit", ["100"])[0]))}, request_id=request_id)
            if path.startswith("/api/"):
                return _json_response({"error": "API endpoint not found", "request_id": request_id}, HTTPStatus.NOT_FOUND, request_id)
            return _static_response(path)

        if method == "POST":
            payload = _read_wsgi_body(environ)
            if path == "/api/simulate":
                validate_simulate_payload(payload)
                result = ENGINE.simulate(payload.get("attack_ids") or [], payload.get("count", 80), payload.get("intensity", 1.0))
                result["request_id"] = request_id
                return _json_response(result, HTTPStatus.CREATED, request_id)
            if path == "/api/mutate":
                validate_mutate_payload(payload)
                result = ENGINE.mutate_transaction(payload.get("transaction_id"), payload.get("attack_id"), payload.get("count", 24))
                result["request_id"] = request_id
                return _json_response(result, request_id=request_id)
            if path == "/api/retrain":
                validate_retrain_payload(payload)
                return _json_response(ENGINE.retrain(confirm=payload.get("confirm", False)), request_id=request_id)
            if path == "/api/score":
                validate_score_payload(payload)
                return _json_response(ENGINE.score_transaction(payload), request_id=request_id)
            if path == "/api/feedback":
                validate_feedback_payload(payload)
                return _json_response(ENGINE.submit_feedback(payload["transaction_id"], payload["outcome"], payload.get("note", ""), payload.get("override_decision")), HTTPStatus.CREATED, request_id)
            if path == "/api/models/rollback":
                validate_rollback_payload(payload)
                return _json_response(ENGINE.rollback_model(payload["model_version"]), request_id=request_id)
            return _json_response({"error": "API endpoint not found", "request_id": request_id}, HTTPStatus.NOT_FOUND, request_id)

        if method == "HEAD":
            status, headers, body = _dispatch_wsgi({**environ, "REQUEST_METHOD": "GET"})
            return status, headers, b""
        return _json_response({"error": "Method not allowed"}, HTTPStatus.METHOD_NOT_ALLOWED, request_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _json_response({"error": str(exc), "request_id": request_id}, HTTPStatus.BAD_REQUEST, request_id)
    except Exception:  # pragma: no cover - top-level guard for serverless resilience
        return _json_response({"error": "Internal server error", "request_id": request_id}, HTTPStatus.INTERNAL_SERVER_ERROR, request_id)


def app(environ: dict, start_response) -> list[bytes]:
    """WSGI entrypoint used by Vercel's Python runtime."""
    started = time.perf_counter()
    status, headers, body = _dispatch_wsgi(environ)
    _structured_log(
        "http_request",
        method=environ.get("REQUEST_METHOD", "GET").upper(),
        path=_normalize_path(environ.get("PATH_INFO")),
        request_id=headers[-1][1] if headers and headers[-1][0] == "X-Request-ID" else None,
        status=status,
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
    )
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
        started = getattr(self, "request_started", None)
        _structured_log("http_request", method=self.command, path=_normalize_path(urlparse(self.path).path), request_id=getattr(self, "request_id", None), status=int(status), duration_ms=round((time.perf_counter() - started) * 1000, 3) if started else None)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length must be an integer") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return _parse_json_object(raw)

    def _raw(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        started = getattr(self, "request_started", None)
        _structured_log("http_request", method=self.command, path=_normalize_path(urlparse(self.path).path), request_id=getattr(self, "request_id", None), status=int(status), duration_ms=round((time.perf_counter() - started) * 1000, 3) if started else None)

    def _static(self, relative: str) -> None:
        static_relative = "/favicon.svg" if _normalize_path(relative) == "/favicon.ico" else relative
        requested = (WEB_ROOT / static_relative.lstrip("/")).resolve()
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
        started = getattr(self, "request_started", None)
        _structured_log("http_request", method=self.command, path=_normalize_path(urlparse(self.path).path), request_id=getattr(self, "request_id", None), status=200, duration_ms=round((time.perf_counter() - started) * 1000, 3) if started else None)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = _normalize_path(parsed.path)
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        self.request_started = time.perf_counter()
        try:
            if path == "/api/health":
                self._json(_health_payload(self.request_id))
            elif path == "/api/overview":
                self._json(ENGINE.overview())
            elif path == "/api/attacks":
                self._json({"attacks": ENGINE.attacks()})
            elif path == "/api/transactions":
                limit = validate_limit(parse_qs(parsed.query).get("limit", ["100"])[0])
                self._json({"transactions": ENGINE.transactions(limit)})
            elif path == "/api/fidelity":
                self._json(ENGINE.fidelity())
            elif path == "/api/report":
                if parse_qs(parsed.query).get("format", ["json"])[0].lower() == "csv":
                    status, headers, body = _csv_response([{"section": "metrics", **ENGINE.metrics}, {"section": "policy_tradeoff", **ENGINE.policy.tradeoff(ENGINE.immutable_holdout_rows, ENGINE.detector)}], self.request_id)
                    self._raw(status, headers, body)
                    return
                self._json(ENGINE.report())
            elif path == "/api/simulations":
                if parse_qs(parsed.query).get("format", ["json"])[0].lower() == "csv":
                    status, headers, body = _csv_response(ENGINE.simulations(), self.request_id)
                    self._raw(status, headers, body)
                    return
                self._json({"simulations": ENGINE.simulations()})
            elif path == "/api/feedback":
                self._json({"feedback": ENGINE.feedback_queue(validate_limit(parse_qs(parsed.query).get("limit", ["100"])[0]))})
            elif path == "/api/models":
                self._json({"models": ENGINE.models(), "active_model_version": ENGINE.active_model_version})
            elif path == "/api/audit":
                self._json({"audit": ENGINE.audit(validate_limit(parse_qs(parsed.query).get("limit", ["100"])[0]))})
            elif path.startswith("/api/"):
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._static(path if path != "/" else "/index.html")
        except (ValueError, TypeError) as exc:
            self._json({"error": str(exc), "request_id": self.request_id}, HTTPStatus.BAD_REQUEST)
        except Exception:  # pragma: no cover - top-level guard for prototype resilience
            self._json({"error": "Internal server error", "request_id": self.request_id}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_HEAD(self) -> None:  # noqa: N802
        """Serve GET headers without a body for health checks and deployment probes."""
        parsed = urlparse(self.path)
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        self.request_started = time.perf_counter()
        try:
            status, headers, _body = _dispatch_wsgi({
                "REQUEST_METHOD": "GET",
                "PATH_INFO": parsed.path,
                "QUERY_STRING": parsed.query,
                "HTTP_X_REQUEST_ID": self.request_id,
                "CONTENT_LENGTH": "0",
                "wsgi.input": BytesIO(),
            })
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            _structured_log("http_request", method="HEAD", path=_normalize_path(parsed.path), request_id=self.request_id, status=status, duration_ms=round((time.perf_counter() - self.request_started) * 1000, 3))
        except Exception:  # pragma: no cover - probe resilience
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = _normalize_path(parsed.path)
        self.request_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        self.request_started = time.perf_counter()
        try:
            payload = self._body()
            if path == "/api/simulate":
                validate_simulate_payload(payload)
                result = ENGINE.simulate(
                    payload.get("attack_ids") or [],
                    payload.get("count", 80),
                    payload.get("intensity", 1.0),
                )
                self._json(result, HTTPStatus.CREATED)
            elif path == "/api/retrain":
                validate_retrain_payload(payload)
                self._json(ENGINE.retrain(confirm=payload.get("confirm", False)))
            elif path == "/api/mutate":
                validate_mutate_payload(payload)
                self._json(ENGINE.mutate_transaction(payload.get("transaction_id"), payload.get("attack_id"), payload.get("count", 24)))
            elif path == "/api/score":
                validate_score_payload(payload)
                self._json(ENGINE.score_transaction(payload))
            elif path == "/api/feedback":
                validate_feedback_payload(payload)
                self._json(ENGINE.submit_feedback(payload["transaction_id"], payload["outcome"], payload.get("note", ""), payload.get("override_decision")), HTTPStatus.CREATED)
            elif path == "/api/models/rollback":
                validate_rollback_payload(payload)
                self._json(ENGINE.rollback_model(payload["model_version"]))
            else:
                self._json({"error": "API endpoint not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc), "request_id": self.request_id}, HTTPStatus.BAD_REQUEST)
        except Exception:  # pragma: no cover
            self._json({"error": "Internal server error", "request_id": self.request_id}, HTTPStatus.INTERNAL_SERVER_ERROR)

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
    print(f"Model: {ENGINE.active_model_version or 'unversioned'} | F1 {ENGINE.metrics['f1']:.3f} | AUC {ENGINE.metrics['auc']:.3f} | p95 {ENGINE._p95_latency():.2f} ms")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
