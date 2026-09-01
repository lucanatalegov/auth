# ============================================================
#  app/middleware.py
#  Middleware Flask: logging automatico request/response.
#
#  before_request legge l'header X-Request-Id e lo salva in
#  flask.g.request_id. RequestIdFilter lo inietta automaticamente
#  in OGNI riga di log emessa durante la richiesta. Se il client
#  non invia l'header, viene generato un UUID4.
# ============================================================

import logging
import re
import time

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from app.utils.request_context import get_or_create_request_id

log = logging.getLogger("authapi.middleware")
_PWD_RE = re.compile(r'("password"\s*:\s*)"([^"]*)"', re.IGNORECASE)


def _redact(content_type: str, raw: str) -> str:
    if not raw:
        return ""
    if "application/json" in content_type:
        return _PWD_RE.sub(r'\1"********"', raw)
    return raw[:2000]


def register_middleware(app: Flask) -> None:
    """Registra before/after_request e errorhandler(Exception)."""

    @app.before_request
    def log_request() -> None:
        g.request_id = get_or_create_request_id()
        g.t_start     = time.perf_counter()

        raw = request.get_data(as_text=True)
        log.info("HTTP request ricevuta",
                 extra={"http_method":  request.method,
                        "req_url":      request.url,
                        "remote_addr":  request.remote_addr,
                        "content_type": request.content_type,
                        "req_body":     _redact(request.content_type or "", raw)})

    @app.after_request
    def log_response(response: Response) -> Response:
        elapsed_ms = round((time.perf_counter() - getattr(g, "t_start", 0)) * 1000, 2)
        try:
            body = (response.get_data(as_text=True)[:2000]
                    if "application/json" in (response.content_type or "")
                    else f"<{response.content_type}>")
        except Exception:
            body = "<body non leggibile>"

        response.headers["X-Request-Id"] = getattr(g, "request_id", "")

        log.info("HTTP response inviata",
                 extra={"http_method": request.method, "req_url": request.url,
                        "status_code": response.status_code,
                        "elapsed_ms":  elapsed_ms, "resp_body": body})
        return response

    @app.errorhandler(Exception)
    def handle_exception(exc: Exception):
        if isinstance(exc, HTTPException):
            return exc

        log.exception("Eccezione non gestita",
                      extra={"http_method": request.method,
                             "req_url":     request.url,
                             "error_txt":   str(exc)})
        return jsonify({"code": "500", "description": "Errore interno del server"}), 500
