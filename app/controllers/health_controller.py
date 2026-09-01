# ============================================================
#  app/controllers/health_controller.py
#
#  Health check approfondito PostgreSQL + raggiungibilità SOAP esterno.
#
#  REGOLA CRITICA: usa get_pg_pool() (getter) NON importa
#  _pg_pool direttamente.
#
#  Check SOAP a due livelli:
#    - default: solo verifica che il servizio sia in ascolto (connessione
#      TCP al host:porta dell'endpoint) — nessuna richiesta HTTP/SOAP inviata.
#    - debug=True (query param ?debug=true su /health): esegue una vera
#      richiesta di login SOAP con login configurabile
#      (health.soap_check_login) e password fittizia hardcoded — richiesta
#      REALE al servizio di terzi, non un check mockato.
#
#  HTTP status: 200 UP | 207 DEGRADED | 503 DOWN
# ============================================================

import logging
import time

from app.services.soap_service import call_credential_verify_portale_soap, check_soap_listening
from app.utils.db_pool import (
    get_pg_connection,
    get_pg_init_error,
    get_pg_pool,
    release_pg_connection,
)

log = logging.getLogger("authapi.controller.health")

# Password fittizia usata solo per il check SOAP approfondito (debug=True):
# il servizio la rifiuterà sempre, l'obiettivo è solo verificare che
# risponda (non un tentativo di autenticazione reale).
_SOAP_CHECK_DUMMY_PASSWORD = "Health!Check1"


def _check_postgres(cfg: dict) -> dict:
    """Esegue il check completo su PostgreSQL. Usa get_pg_pool() per leggere il pool aggiornato."""
    pg_cfg     = cfg.get("postgres", {})
    health_cfg = cfg.get("health", {})

    result = {
        "status": "DOWN", "elapsed_ping_ms": None, "elapsed_stats_ms": None,
        "pool_min": int(pg_cfg.get("pool_min", 2)),
        "pool_max": int(pg_cfg.get("pool_max", 10)),
        "pool_available": None, "performance_row": None,
        "connections": None, "db_stats": None, "error": None,
    }

    pool = get_pg_pool()
    if pool is None:
        result["error"] = get_pg_init_error() or "Pool non inizializzato"
        log.error("Health PG: DOWN", extra={"error_txt": result["error"]})
        return result

    conn = None
    try:
        conn = get_pg_connection()
        result["pool_available"] = len(get_pg_pool()._pool)   # noqa: SLF001

        t = time.perf_counter()
        perf_q = health_cfg.get("performance_query", "SELECT 1 AS ping")
        with conn.cursor() as cur:
            cur.execute(perf_q)
            cols = [d[0] for d in cur.description]
            row  = cur.fetchone()
        result["elapsed_ping_ms"] = round((time.perf_counter() - t) * 1000, 2)
        result["performance_row"] = (
            dict(zip(cols, [str(v) for v in row])) if row else {}
        )

        t = time.perf_counter()
        conn_q = health_cfg.get("connections_query", "")
        if conn_q:
            with conn.cursor() as cur:
                cur.execute(conn_q)
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
            result["connections"] = [dict(zip(cols, r)) for r in rows]

        db_q = health_cfg.get("db_stats_query", "")
        if db_q:
            with conn.cursor() as cur:
                cur.execute(db_q)
                cols = [d[0] for d in cur.description]
                row  = cur.fetchone()
            if row:
                result["db_stats"] = dict(zip(cols, [str(v) for v in row]))

        result["elapsed_stats_ms"] = round((time.perf_counter() - t) * 1000, 2)
        result["status"] = "UP"
        # Chiude esplicitamente la transazione (sola lettura: non c'e' nulla
        # da salvare, ma senza questo la connessione tornava al pool ancora
        # "dentro" una transazione mai chiusa — rilevante qui piu' che altrove,
        # dato che questo e' il check dietro GET /health senza ?debug=true,
        # documentato come sicuro da pollare ad alta frequenza).
        conn.commit()
        log.info("Health PG: UP",
                 extra={"elapsed_ping_ms": result["elapsed_ping_ms"],
                        "pool_available":  result["pool_available"]})

    except Exception as exc:
        if conn is not None:
            conn.rollback()
        result["error"] = str(exc)
        log.error("Health PG: DOWN (eccezione)", extra={"error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)

    return result


def _check_soap_login(cfg: dict) -> dict:
    """
    Verifica approfondita (debug=True): invia una vera richiesta di
    autenticazione SOAP con login configurabile (health.soap_check_login)
    e password fittizia. Non valuta l'esito dell'autenticazione (ci si aspetta
    un rifiuto), solo che il servizio abbia risposto.

    code == "700" nella risposta di call_credential_verify_portale_soap indica
    un'eccezione locale (connessione fallita, timeout, template mancante, ...)
    → servizio non raggiungibile. Qualunque altro code (000/500/600) significa
    che una risposta reale è arrivata dal server → servizio raggiungibile.
    """
    health_cfg = cfg.get("health", {})
    login      = health_cfg.get("soap_check_login", "")

    result = {
        "status": "DOWN", "elapsed_ms": None,
        "code": None, "wsdlresponse": None, "error": None,
    }

    if not login:
        result["error"] = "health.soap_check_login non configurato"
        log.error("Health SOAP: DOWN", extra={"error_txt": result["error"]})
        return result

    t = time.perf_counter()
    try:
        soap_res = call_credential_verify_portale_soap(cfg, login, _SOAP_CHECK_DUMMY_PASSWORD)
        result["elapsed_ms"]   = round((time.perf_counter() - t) * 1000, 2)
        result["code"]         = soap_res.get("code")
        result["wsdlresponse"] = soap_res.get("wsdlresponse")
        result["status"]       = "DOWN" if soap_res.get("code") == "700" else "UP"
        log.info(f"Health SOAP: {result['status']}",
                 extra={"elapsed_ms": result["elapsed_ms"], "code": result["code"]})
    except Exception as exc:
        result["elapsed_ms"] = round((time.perf_counter() - t) * 1000, 2)
        result["error"]      = str(exc)
        log.error("Health SOAP: DOWN (eccezione)", extra={"error_txt": str(exc)}, exc_info=True)

    return result


def handle_health(cfg: dict, debug: bool = False) -> tuple[dict, int]:
    """
    Orchestratore: esegue check PG + SOAP, calcola stato globale.
    200=UP | 207=DEGRADED | 503=DOWN

    debug=False (default): il check SOAP verifica solo che il servizio sia
    in ascolto (TCP, nessuna richiesta inviata).
    debug=True: il check SOAP esegue una vera richiesta di login con
    login configurabile e password fittizia (chiamata reale al servizio
    di terzi).
    """
    t0          = time.perf_counter()
    version_str = "{release}.{patch}.{build}".format(**cfg["version"])

    log.info("Health check avviato", extra={"version_info": version_str, "debug": debug})

    pg_res   = _check_postgres(cfg)
    soap_res = _check_soap_login(cfg) if debug else check_soap_listening(cfg)

    pg_up   = pg_res["status"]   == "UP"
    soap_up = soap_res["status"] == "UP"

    if pg_up and soap_up:
        status, code = "UP", 200
    elif not pg_up and not soap_up:
        status, code = "DOWN", 503
    else:
        status, code = "DEGRADED", 207

    elapsed_time = round((time.perf_counter() - t0) * 1000, 2)
    log.info("Health check completato",
             extra={"global_status": status, "http_code": code, "elapsed_time": elapsed_time})

    return {
        "status":       status,
        "version":      version_str,
        "elapsed_time": elapsed_time,
        "postgres":     pg_res,
        "soap":         soap_res,
    }, code
