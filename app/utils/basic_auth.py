# ============================================================
#  app/utils/basic_auth.py
#  Decorator HTTP Basic Auth per gli endpoint /otp/* — identifica
#  l'applicativo chiamante (public.service_accounts), non l'utente reale.
#
#  Nessuna dipendenza aggiuntiva (niente flask_httpauth): Basic Auth letto
#  direttamente da flask.request.authorization, verificato tramite
#  app.services.otp_service.authenticate_service_account().
# ============================================================

import functools
import logging

from flask import g, jsonify, request

from app.services.otp_service import authenticate_service_account

log = logging.getLogger("authapi.middleware.basicauth")

_WWW_AUTHENTICATE = 'Basic realm="Auth API 2FA"'


def require_service_account(cfg: dict):
    """
    Decorator da applicare alle route /otp/*, sotto @app.post/@app.put
    (stesso punto in cui il documento di riferimento applicava
    @auth.login_required). In caso di credenziali assenti/non valide
    risponde 401 senza chiamare la view.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.authorization
            if auth is None or not auth.username or not auth.password:
                log.warning("Richiesta a endpoint 2FA senza credenziali Basic Auth")
                resp = jsonify({"code": "401", "description": "Autenticazione applicativa richiesta (HTTP Basic)."})
                resp.status_code = 401
                resp.headers["WWW-Authenticate"] = _WWW_AUTHENTICATE
                return resp

            if not authenticate_service_account(cfg, auth.username, auth.password):
                resp = jsonify({"code": "401", "description": "Applicativo non autorizzato."})
                resp.status_code = 401
                resp.headers["WWW-Authenticate"] = _WWW_AUTHENTICATE
                return resp

            g.service_account = auth.username
            return fn(*args, **kwargs)
        return wrapper
    return decorator
