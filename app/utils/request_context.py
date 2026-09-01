# ============================================================
#  app/utils/request_context.py
#
#  Filtro di logging che inietta automaticamente il request_id
#  (proveniente dall'header HTTP X-Request-Id) in ogni LogRecord,
#  senza dover passare requestid=... manualmente in ogni extra={}.
#
#  Funzionamento:
#    1. Il middleware (before_request) legge l'header X-Request-Id
#       e lo salva in flask.g.request_id.
#    2. RequestIdFilter viene applicato a tutti gli handler di
#       logging. Ad ogni record, legge flask.g.request_id (se siamo
#       in un contesto di richiesta Flask attivo) e lo assegna come
#       attributo record.requestid.
#    3. JsonFormatter include "requestid" nel JSON di output.
#
#  Se l'header X-Request-Id non è presente, viene generato un UUID4
#  automaticamente, così ogni richiesta ha sempre un identificativo.
# ============================================================

import logging
import uuid

from flask import g, has_request_context, request

REQUEST_ID_HEADER = "X-Request-Id"


def get_or_create_request_id() -> str:
    """
    Legge l'header X-Request-Id dalla richiesta corrente.
    Se assente, genera un UUID4 nuovo.
    Deve essere chiamata dentro un contesto di richiesta Flask attivo.
    """
    return request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())


class RequestIdFilter(logging.Filter):
    """
    Filtro di logging che aggiunge l'attributo 'requestid' a ogni
    LogRecord, leggendolo da flask.g se siamo in un contesto di
    richiesta HTTP attivo. None fuori da una richiesta (es. log di
    startup dell'applicazione).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.requestid = getattr(g, "request_id", None)
        else:
            record.requestid = None
        return True
