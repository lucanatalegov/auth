# ============================================================
#  app/middleware.py
#  Middleware Flask: logging automatico request/response.
#
#  before_request legge l'header X-Request-Id e lo salva in
#  flask.g.request_id. RequestIdFilter lo inietta automaticamente
#  in OGNI riga di log emessa durante la richiesta. Se il client
#  non invia l'header, viene generato un UUID4.
# ============================================================

import json
import logging
import re
import time

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from app.utils.request_context import (get_application, get_or_create_request_id, get_session_id,
                                       header_request_id)

log = logging.getLogger("authapi.middleware")
_PWD_RE = re.compile(r'("password"\s*:\s*)"([^"]*)"', re.IGNORECASE)
_MASK = "********"

# Campi mascherati nei body JSON loggati (richiesta e risposta), a qualunque
# livello di annidamento. secret/qr_code_base64: risposta di /otp/setup
# method='app' — il QR codifica lo stesso secret TOTP, chi li legge nel log
# puo' generare i codici 2FA dell'utente.
_SENSITIVE_KEYS = frozenset({"password", "secret", "qr_code_base64"})

# "code" e' il codice OTP solo nelle RICHIESTE /otp/* (verify, disable,
# setup/confirm); nelle risposte e' l'esito ("000", "020", ...) e resta in chiaro.
_OTP_PATH_RE = re.compile(r"/otp/")


def _mask_json(obj, keys: frozenset):
    if isinstance(obj, dict):
        return {k: (_MASK if k.lower() in keys and v is not None else _mask_json(v, keys))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_json(v, keys) for v in obj]
    return obj


def _redact(content_type: str, raw: str, keys: frozenset = _SENSITIVE_KEYS) -> str:
    """Body pronto per il log: campi sensibili mascherati, max 2000 caratteri
    (troncato DOPO il mascheramento, mai prima)."""
    if not raw:
        return ""
    if "application/json" in content_type:
        try:
            return json.dumps(_mask_json(json.loads(raw), keys),
                              ensure_ascii=False)[:2000]
        except ValueError:
            # JSON non valido (sara' comunque un 422): niente di parsabile,
            # resta solo la regex sulla password.
            return _PWD_RE.sub(rf'\1"{_MASK}"', raw)[:2000]
    return raw[:2000]


def register_middleware(app: Flask) -> None:
    """Registra before/after_request e errorhandler(Exception)."""

    @app.before_request
    def log_request() -> None:
        g.request_id  = get_or_create_request_id()
        g.application = get_application()
        g.session_id  = get_session_id()
        g.t_start     = time.perf_counter()

        raw = request.get_data(as_text=True)
        keys = (_SENSITIVE_KEYS | {"code"} if _OTP_PATH_RE.search(request.path)
                else _SENSITIVE_KEYS)
        log.info("HTTP request ricevuta",
                 extra={"http_method":  request.method,
                        "req_url":      request.url,
                        "remote_addr":  request.remote_addr,
                        "content_type": request.content_type,
                        # header X-Request-Id cosi' come arrivato (troncato):
                        # se il client manda anche client_request_id, quello
                        # vince come request_id e l'header resta solo qui.
                        "x_request_id": header_request_id(),
                        "req_body":     _redact(request.content_type or "", raw, keys)})

    @app.after_request
    def log_response(response: Response) -> Response:
        elapsed_ms = round((time.perf_counter() - getattr(g, "t_start", 0)) * 1000, 2)
        try:
            body = (_redact(response.content_type, response.get_data(as_text=True))
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
