# ============================================================
#  app/controllers/credential_verify_portale_controller.py
#  Controller MVC per /credential/verify-portale.
#
#  Log storico su history.auth_credential_log (stesse query gia'
#  configurate per /credential/verify — operations_sql.insert.
#  auth_credential_log, .update.auth_credential_log_extop,
#  .update.auth_credential_log_end — nessuna query nuova in config.yaml,
#  distinte solo dalla colonna `service` = "verify-portale").
#  Flusso piu' snello di /credential/verify: niente check TCP esplicito
#  duplicato (un solo check, interno a call_credential_verify_portale_soap()),
#  niente cache/fallback (questo endpoint non ne ha).
#    1. insert.auth_credential_log — appena la richiesta arriva
#    2. update.auth_credential_log_extop — dopo la risposta SOAP (raw XML)
#    3. update.auth_credential_log_end — sempre, qualunque code (non solo
#       su successo: auth_validation e' sempre "soap" per questo endpoint)
#  Tutte fail-open: un errore di DB non deve mai rompere la risposta al
#  client, stesso pattern di credential_verify_controller.py.
# ============================================================

import json
import logging
import time

from flask import g

from app.services.soap_service import call_credential_verify_portale_soap
from app.utils.db_pool import get_pg_connection, release_pg_connection
from app.utils.security import mask_password

log = logging.getLogger("authapi.controller.credential_verify_portale")


def _log_request_history(cfg: dict, login: str, client_request_id: str, score: int,
                          request: str, client: str | None) -> int | None:
    """
    INSERT immediato in history.auth_credential_log, appena la richiesta
    arriva (prima della chiamata SOAP), indipendentemente dall'esito.

    Riusa operations_sql.insert.auth_credential_log (stessa query di
    /credential/verify) — auth_type e' qui sempre "soap" (hardcoded, non
    config-driven: questo endpoint ha un unico backend), service="verify-portale".

    `client` e' l'applicativo chiamante autenticato via HTTP Basic Auth
    (flask.g.service_account, valorizzato da require_service_account() —
    vedi app/utils/basic_auth.py), NON l'utente reale (quello e' il campo
    `login`). Stesso pattern gia' in uso per la colonna `client` di
    history.otp_requests (otp_controller.py).

    Fail-open: un errore qui (es. trigger di audit) viene loggato e non
    deve interrompere l'elaborazione della richiesta.

    Returns:
        L'id della riga inserita (RETURNING id), o None se l'insert non e'
        stato eseguito/e' fallito — in quel caso gli update successivi
        vengono saltati.
    """
    sql_cfg = cfg.get("operations_sql", {})
    log_sql = sql_cfg.get("insert", {}).get("auth_credential_log", "")

    if not log_sql:
        log.warning("operations_sql.insert.auth_credential_log non configurato, salto log richiesta",
                    extra={"login": login})
        return None

    params = {
        "login":             login,
        "client_request_id": client_request_id,
        "score":             score,
        "auth_type":         "soap",
        "service":           "verify-portale",
        "request":           request,
        "client":            client,
    }

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(log_sql, params)
            inserted_id = None
            if cur.description is not None:
                row = cur.fetchone()
                inserted_id = row[0] if row else None
        conn.commit()
        log.info("Richiesta login registrata (auth_credential_log)",
                 extra={"login": login, "client_request_id": client_request_id,
                        "score": score, "inserted_id": inserted_id})
        return inserted_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'insert in auth_credential_log",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _update_log_extop(cfg: dict, auth_credential_log_id: int | None, login: str,
                       remote_response: str | None) -> None:
    """
    UPDATE di history.auth_credential_log (operations_sql.update.auth_credential_log_extop,
    stessa query di /credential/verify) dopo la risposta del SOAP esterno,
    valorizzando remote_response con l'XML grezzo restituito dal server
    (result["raw_response"] in call_credential_verify_portale_soap()).

    remote_response puo' essere None se non e' arrivata una vera risposta
    HTTP (TCP down, template illeggibile, eccezione di rete/timeout).

    Fail-open, stesso pattern di _log_request_history().
    """
    if auth_credential_log_id is None:
        log.warning("auth_credential_log_id assente (insert precedente fallito/non eseguito), "
                    "salto update extop", extra={"login": login})
        return

    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("auth_credential_log_extop", "")

    if not update_sql:
        log.warning("operations_sql.update.auth_credential_log_extop non configurato, salto update",
                    extra={"login": login})
        return

    params = {
        "auth_credential_log_id": auth_credential_log_id,
        "remote_response":        remote_response,
    }

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, params)
        conn.commit()
        log.info("auth_credential_log aggiornato (extop)",
                 extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                        "remote_response": remote_response})
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'update di auth_credential_log_extop",
                  extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                         "error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)


def _update_log_end(cfg: dict, auth_credential_log_id: int | None, login: str,
                     success: int, failure_reason: str | None, response: str,
                     code: str) -> None:
    """
    UPDATE di history.auth_credential_log (operations_sql.update.auth_credential_log_end,
    stessa query di /credential/verify), eseguito sempre — qualunque code,
    non solo su successo — a chiusura della richiesta.

    auth_validation e' sempre "soap" (unico meccanismo di questo endpoint,
    nessun fallback su cache).

    Fail-open, stesso pattern di _log_request_history().
    """
    if auth_credential_log_id is None:
        log.warning("auth_credential_log_id assente (insert precedente fallito/non eseguito), "
                    "salto update end", extra={"login": login})
        return

    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("auth_credential_log_end", "")

    if not update_sql:
        log.warning("operations_sql.update.auth_credential_log_end non configurato, salto update",
                    extra={"login": login})
        return

    params = {
        "auth_credential_log_id": auth_credential_log_id,
        "auth_validation":        "soap",
        "success":                success,
        "failure_reason":         failure_reason,
        "response":               response,
        "code":                   code,
    }

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, params)
        conn.commit()
        log.info("auth_credential_log aggiornato (end)",
                 extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                        "success": success, "failure_reason": failure_reason, "code": code})
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'update di auth_credential_log_end",
                  extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                         "error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)


def _failure_reason_for_code(code: str) -> str | None:
    """
    Messaggio di audit (colonna failure_reason) per ogni code possibile di
    call_credential_verify_portale_soap(). None su successo (code="000").
    """
    if code == "000":
        return None
    if code == "500":
        return "Login/matricola non valida (rifiutata esplicitamente dal servizio SOAP esterno)"
    if code == "501":
        return "Credenziali non valide - password errata (rifiutata esplicitamente dal servizio SOAP esterno)"
    if code == "503":
        return "Esito del servizio SOAP esterno non riconosciuto (fault HTTP 500 non corrispondente a nessun pattern noto)"
    if code == "200":
        return "Errore HTTP non gestito dal servizio SOAP esterno"
    if code == "300":
        return "Servizio SOAP non raggiungibile o eccezione durante la chiamata"
    return f"Esito non riconosciuto (code={code})"


def handle_credential_verify_portale(cfg: dict, login: str, password: str,
                                  client_request_id: str | None = None) -> tuple[dict, int]:
    """
    Logga richiesta (password mascherata), chiama SOAP, restituisce risposta.

    client_request_id e' opzionale — se assente si usa il nostro X-Request-Id
    (flask.g.request_id) sia per i log applicativi sia per il log storico su
    history.auth_credential_log (vedi _log_request_history/_update_log_extop/
    _update_log_end sopra — stesse query di /credential/verify, distinte
    dalla colonna service="verify-portale").

    Returns:
        ({"code": ..., "auth_validation": "soap", "description": ..., "elapsed_time": ...}, 200)
    """
    t0 = time.perf_counter()

    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"

    # Snapshot JSON della richiesta ricevuta dal client (colonna `request`),
    # password sempre mascherata.
    client_request = json.dumps({
        "login":             login,
        "password":          mask_password(password),
        "client_request_id": client_request_id,
    })

    log.info("Richiesta login ricevuta",
             extra={"login": login, "pwd_masked": mask_password(password),
                    "client_request_id": client_request_id})

    score = 1
    auth_credential_log_id = _log_request_history(cfg, login, client_request_id, score, client_request,
                                                    getattr(g, "service_account", None))

    result = call_credential_verify_portale_soap(cfg, login, password)

    log.info("Risposta login inviata al client",
             extra={"login": login, "result_code": result.get("code"),
                    "wsdlresponse": result.get("wsdlresponse")})

    # Output grezzo del server SOAP (XML completo), None se non e' arrivata
    # una vera risposta HTTP (TCP down, eccezione di rete/timeout).
    _update_log_extop(cfg, auth_credential_log_id, login, result.get("raw_response"))

    elapsed_time = round((time.perf_counter() - t0) * 1000, 2)

    # Il default "300" (non piu' "700") rispecchia lo schema code attuale di
    # call_credential_verify_portale_soap() in soap_service.py — ramo di fatto
    # irraggiungibile, dato che quella funzione valorizza sempre "code", ma
    # tenuto coerente con lo schema reale.
    code = result.get("code", "300")

    response_body = {
        "code":            code,
        # auth_validation="soap" sempre: questo endpoint ha un unico
        # meccanismo di autenticazione (nessun fallback su cache come
        # /credential/verify), quindi qualunque code — successo, rifiuto
        # esplicito, TCP down, eccezione — e' comunque il SOAP ad aver
        # gestito la richiesta.
        "auth_validation": "soap",
        "description":     result.get("wsdlresponse", "errore imprevisto"),
        "elapsed_time":    elapsed_time,
    }

    _update_log_end(cfg, auth_credential_log_id, login,
                     success=1 if code == "000" else 0,
                     failure_reason=_failure_reason_for_code(code),
                     response=json.dumps(response_body), code=code)

    return response_body, result.get("status_code", 200)
