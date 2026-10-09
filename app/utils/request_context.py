# ============================================================
#  app/utils/request_context.py
#
#  Filtro di logging che inietta automaticamente il request_id
#  (client_request_id del client, o header HTTP X-Request-Id) in ogni LogRecord,
#  senza dover passare request_id=... manualmente in ogni extra={}.
#
#  Funzionamento:
#    1. Il middleware (before_request) calcola l'id (vedi get_or_create_request_id)
#       e lo salva in flask.g.request_id.
#    2. RequestIdFilter viene applicato a tutti gli handler di
#       logging. Ad ogni record, legge flask.g.request_id (se siamo
#       in un contesto di richiesta Flask attivo) e lo assegna come
#       attributo record.request_id.
#    3. JsonFormatter include "request_id" nel JSON di output.
#
#  Priorita': client_request_id inviato dal client (body JSON o query
#  string) → header X-Request-Id → UUID4 generato, così ogni richiesta ha
#  sempre un identificativo.
# ============================================================

import logging
import uuid

from flask import g, has_request_context, request

REQUEST_ID_HEADER = "X-Request-Id"
# Header facoltativo (ApplicationHeader, app/models/common_model.py) con il
# nome dell'applicazione chiamante: campo "application" di ogni riga di log
# (se assente, l'utente della Basic Auth — vedi get_application()).
APPLICATION_HEADER = "X-Application"
APPLICATION_MAX_LENGTH = 100


CLIENT_REQUEST_ID_FIELD = "client_request_id"
# Lunghezza massima di client_request_id: oltre, Pydantic risponde 422 (vedi
# max_length nei modelli) e qui il valore viene ignorato, cosi' anche le
# righe di log della richiesta rifiutata non lo riportano.
CLIENT_REQUEST_ID_MAX_LENGTH = 100
# client_session_id: id di sessione del client, campo "session_id" dei log
# (nessun fallback: null se il client non lo invia). Stesso limite.
CLIENT_SESSION_ID_FIELD = "client_session_id"
CLIENT_SESSION_ID_MAX_LENGTH = 100


def _client_field(name: str, max_length: int) -> str | None:
    """Campo inviato dal client (client_request_id, client_session_id): body
    JSON (POST) o query string (GET /otp/status). None se assente, vuoto,
    non stringa o oltre max_length (Pydantic poi rifiuta con 422); un body non
    JSON o malformato viene ignorato (la validazione vera la fa Pydantic dopo)."""
    body = request.get_json(silent=True)
    value = body.get(name) if isinstance(body, dict) else None
    if value is None:
        value = request.args.get(name)
    if isinstance(value, str) and value.strip() and len(value) <= max_length:
        return value.strip()
    return None


def get_session_id() -> str | None:
    """client_session_id inviato dal client, None se assente (nessun fallback)."""
    return _client_field(CLIENT_SESSION_ID_FIELD, CLIENT_SESSION_ID_MAX_LENGTH)


def header_request_id() -> str | None:
    """Header X-Request-Id della richiesta, troncato a
    CLIENT_REQUEST_ID_MAX_LENGTH (e' un header, non un campo validato:
    si tronca invece di rifiutare). None se assente o vuoto."""
    value = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return value[:CLIENT_REQUEST_ID_MAX_LENGTH] or None


def get_application() -> str | None:
    """
    Applicazione chiamante, per il campo "application" dei log:
      1. header X-Application;
      2. utente della Basic Auth (Authorization: Basic ...).
    Troncato a APPLICATION_MAX_LENGTH, None se nessuno dei due e' presente.
    Letto PRIMA della validazione e della verifica della Basic Auth: anche le
    righe di una richiesta poi rifiutata (422/401) riportano quanto arrivato.
    """
    value = (request.headers.get(APPLICATION_HEADER) or "").strip()
    if not value and request.authorization is not None:
        value = (request.authorization.username or "").strip()
    return value[:APPLICATION_MAX_LENGTH] or None


def get_or_create_request_id() -> str:
    """
    Id di correlazione della richiesta corrente, in ordine di priorita':
      1. client_request_id inviato dal client (body JSON o query string);
      2. header X-Request-Id;
      3. UUID4 generato.
    Deve essere chiamata dentro un contesto di richiesta Flask attivo.
    """
    return (_client_field(CLIENT_REQUEST_ID_FIELD, CLIENT_REQUEST_ID_MAX_LENGTH)
            or header_request_id()
            or str(uuid.uuid4()))


class RequestIdFilter(logging.Filter):
    """
    Filtro di logging che aggiunge l'attributo 'request_id' a ogni
    LogRecord, leggendolo da flask.g se siamo in un contesto di
    richiesta HTTP attivo. None fuori da una richiesta (es. log di
    startup dell'applicazione).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.request_id  = getattr(g, "request_id", None)
            record.application = getattr(g, "application", None)
            record.session_id  = getattr(g, "session_id", None)
        else:
            record.request_id  = None
            record.application = None
            record.session_id  = None
        return True
