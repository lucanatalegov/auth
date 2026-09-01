# ============================================================
#  app/controllers/credential_verify_controller.py
#  Controller MVC per /credential/verify.
#
#  Copia di credential_verify_portale_controller.py, punto di partenza per
#  un servizio distinto — vedi nota in credential_verify_model.py.
#
#  Dopo che il SOAP esterno valida con successo (code=="000"), sincronizza
#  una cache PostgreSQL (config.yaml, sezione operations_sql):
#    1. select.checkcache — la cache esiste se la query restituisce una riga
#       (qualunque colonna selezioni), non esiste se non ne restituisce
#    2. riga presente    -> update.updatecache (password_hash,
#       last_successful_login, client_request_id)
#       riga assente -> insert.insertcache (login, password_hash,
#       client_request_id)
#
#  Fallback su cache (TCP down o SOAP raggiungibile ma code != "000"):
#  _try_cache_fallback() rilegge la stessa select.checkcache (sola lettura,
#  nessuna scrittura su auth_credential_cache in questo ramo) e confronta
#  l'hash della password con quello memorizzato + la scadenza calcolata
#  (expires_at). Se coincide ed e' ancora valida, autentica comunque
#  l'utente; altrimenti nega l'accesso. Esito sempre scritto su
#  update.auth_credential_log_end.
# ============================================================

import datetime
import json
import logging
import time

from flask import g

from app.services.soap_service import call_credential_verify_soap, check_soap_listening
from app.utils.db_pool import get_pg_connection, release_pg_connection
from app.utils.security import hash_password, mask_password

log = logging.getLogger("authapi.controller.credential_verify")

# ------------------------------------------------------------------
# Mappatura dei code del fallback su cache (_try_cache_fallback):
# code finale = <origin_code><numero_motivo>, concatenati come stringhe.
# origin_code:
#   "100" = TCP down (nessuna chiamata SOAP tentata, sintetizzato dal
#           controller — non e' uno dei code restituiti da
#           call_credential_verify_soap())
#   "200" = SOAP chiamato, errore HTTP non gestito (result_code reale)
#   "300" = SOAP chiamato, eccezione/timeout durante la chiamata (result_code reale)
# numero_motivo (perche' il fallback su cache e' stato negato):
#   1 = nessuna riga di cache trovata per la login
#   2 = hash password non corrispondente alla cache
#   3 = cache priva di scadenza calcolata (expires_at nullo)
#   4 = cache scaduta (now >= expires_at)
# ------------------------------------------------------------------
_FALLBACK_REASON_NUMBER = {
    "no_cache":      "1",
    "hash_mismatch": "2",
    "no_expiry":     "3",
    "expired":       "4",
}

_FALLBACK_DB_REASONS = {
    "no_cache":      "nessuna riga di cache trovata (o errore di lettura) per la login",
    "hash_mismatch": "hash password non corrispondente alla cache",
    "no_expiry":     "cache priva di scadenza calcolata (expires_at nullo)",
    "expired":       "cache scaduta (expires_at superato)",
}

# description per il client, differenziata per origin_code e motivo — vedi
# tabella concordata: "100" = servizio non disponibile (TCP down), "300" =
# servizio in errore (eccezione SOAP), "200" = errore del servizio (HTTP non
# gestito dal SOAP), "503" = fault HTTP 500 con testo non riconosciuto da
# nessuno dei pattern configurati (auth_success/auth_error_string1/2 —
# vedi soap_service.py). NOTA: "500"/"501" (rifiuto esplicito delle
# credenziali) NON compaiono qui — non passano mai da _try_cache_fallback(),
# vedi il check esplicito in handle_credential_verify() sotto.
_FALLBACK_DESCRIPTIONS = {
    "100": {
        "no_cache":      "Servizio non disponibile e nessuna sessione precedente trovata per l'utente.",
        "hash_mismatch": "Servizio non disponibile, credenziali non verificabili.",
        "no_expiry":     "Servizio non disponibile, sessione precedente non verificabile.",
        "expired":       "Servizio non disponibile e sessione precedente scaduta.",
    },
    "300": {
        "no_cache":      "Servizio in errore e nessuna sessione precedente trovata per l'utente.",
        "hash_mismatch": "Servizio in errore, credenziali non verificabili.",
        "no_expiry":     "Servizio in errore, sessione precedente non verificabile.",
        "expired":       "Servizio in errore e sessione precedente scaduta.",
    },
    "200": {
        "no_cache":      "Errore del servizio e nessuna sessione precedente trovata per l'utente.",
        "hash_mismatch": "Errore del servizio, credenziali non verificabili.",
        "no_expiry":     "Errore del servizio, sessione precedente non verificabile.",
        "expired":       "Errore del servizio e sessione precedente scaduta.",
    },
    "503": {
        "no_cache":      "Esito del servizio non riconosciuto e nessuna sessione precedente trovata per l'utente.",
        "hash_mismatch": "Esito del servizio non riconosciuto, credenziali non verificabili.",
        "no_expiry":     "Esito del servizio non riconosciuto, sessione precedente non verificabile.",
        "expired":       "Esito del servizio non riconosciuto e sessione precedente scaduta.",
    },
}


def _sync_login_cache(cfg: dict, login: str, password_hash: str, client_request_id: str, prov: str,
                       auth_type: str) -> None:
    """
    SELECT checkcache -> UPDATE updatecache (riga presente) o INSERT
    insertcache (riga assente).

    Parametri disponibili in tutte e tre le query (uno statement puo'
    referenziarne solo un sottoinsieme, quelli non usati vengono ignorati
    da psycopg2): %(login)s, %(password_hash)s, %(client_request_id)s,
    %(last_successful_login)s, %(prov)s, %(auth_type)s.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("checkcache",  "")
    update_sql = sql_cfg.get("update", {}).get("updatecache", "")
    insert_sql = sql_cfg.get("insert", {}).get("insertcache", "")

    if not select_sql:
        log.warning("operations_sql.select.checkcache non configurato, salto sync cache login",
                    extra={"login": login})
        return

    params = {
        "login":                  login,
        "password_hash":          password_hash,
        "client_request_id":      client_request_id,
        "last_successful_login":  datetime.datetime.now(datetime.timezone.utc),
        "prov":                   prov,
        "auth_type":              auth_type,
    }

    conn = None
    try:
        conn = get_pg_connection()

        with conn.cursor() as cur:
            cur.execute(select_sql, params)
            # checkcache ora restituisce una riga (o nessuna) invece di un
            # booleano: l'esistenza della cache e' data dalla presenza della
            # riga, non dal suo contenuto.
            cache_exists = cur.fetchone() is not None

        target_sql, op_name = (update_sql, "UPDATE") if cache_exists else (insert_sql, "INSERT")
        if not target_sql:
            log.warning(f"operations_sql non configurato per {op_name}, salto sync cache login",
                        extra={"login": login, "cache_exists": cache_exists})
            return

        inserted_id = None
        with conn.cursor() as cur:
            cur.execute(target_sql, params)
            if op_name == "INSERT" and cur.description is not None:
                # RETURNING id nella query insertcache, se presente.
                row = cur.fetchone()
                inserted_id = row[0] if row else None
        conn.commit()

        log_extra = {"login": login, "client_request_id": client_request_id}
        if op_name == "INSERT":
            log_extra["inserted_id"] = inserted_id
        log.info(f"Cache login sincronizzata ({op_name})", extra=log_extra)

    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la sincronizzazione della cache login",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)


def _log_request_history(cfg: dict, login: str, client_request_id: str, score: int,
                          auth_type: str, service: str, request: str, client: str | None) -> int | None:
    """
    INSERT immediato in history.auth_credential_log, appena la richiesta
    arriva (prima della chiamata SOAP), indipendentemente dall'esito.

    `service` identifica quale servizio/endpoint ha generato la riga (colonna
    `service`, aggiunta dall'utente in config.yaml) — sempre
    "verify" per questo controller, utile per distinguere le
    righe se in futuro altri endpoint scriveranno sulla stessa tabella
    history.auth_credential_log.

    `client` e' l'applicativo chiamante autenticato via HTTP Basic Auth
    (flask.g.service_account, valorizzato da require_service_account() —
    vedi app/utils/basic_auth.py), NON l'utente reale (quello e' il campo
    `login`). Stesso pattern gia' in uso per la colonna `client` di
    history.otp_requests (otp_controller.py).

    `request` e' lo snapshot JSON della richiesta ricevuta dal client
    (colonna `request`, aggiunta dall'utente) — password SEMPRE mascherata
    (mask_password()), mai in chiaro nel DB.

    Fail-open, stesso pattern di _sync_login_cache: un errore qui (es. il
    trigger di audit sulla tabella history) viene loggato e non deve
    interrompere l'elaborazione della richiesta.

    Returns:
        L'id della riga inserita (RETURNING id), o None se l'insert non e'
        stato eseguito/e' fallito — in quel caso _update_log_tcp() lo salta.
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
        "auth_type":         auth_type,
        "service":           service,
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
                        "score": score, "service": service, "inserted_id": inserted_id})
        return inserted_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'insert in auth_credential_log",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _update_log_tcp(cfg: dict, auth_credential_log_id: int | None, login: str, tcp_status: str,
                     failure_reason: str | None, response: str | None = None) -> None:
    """
    UPDATE di history.auth_credential_log (operations_sql.update.auth_credential_log_tcp)
    subito dopo la verifica di raggiungibilita' TCP del servizio SOAP,
    valorizzando connection_tcp con l'esito sulla riga creata da
    _log_request_history().

    tcp_status e' la stringa "UP"/"DOWN" restituita da check_soap_listening()
    (usata solo per log leggibili); la colonna connection_tcp e' boolean,
    quindi viene convertita in True/False prima del bind del parametro.

    failure_reason e' None se il TCP check e' andato a buon fine, altrimenti
    il motivo valorizzato da handle_credential_verify() (query aggiornata
    dall'utente per scrivere anche questa colonna su questo update, non solo
    su auth_credential_log_end).

    response e' la risposta JSON restituita al client, valorizzata SOLO nel
    ramo di uscita anticipata per TCP down (colonna `response`, aggiunta
    dall'utente su history.auth_credential_log) — None quando il TCP e' UP,
    dato che a questo punto del flusso la risposta finale al client non e'
    ancora nota.

    Fail-open, stesso pattern delle altre funzioni di sync in questo modulo.
    """
    if auth_credential_log_id is None:
        log.warning("auth_credential_log_id assente (insert precedente fallito/non eseguito), "
                    "salto update connection_tcp", extra={"login": login})
        return

    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("auth_credential_log_tcp", "")

    if not update_sql:
        log.warning("operations_sql.update.auth_credential_log_tcp non configurato, salto update",
                    extra={"login": login})
        return

    params = {
        "auth_credential_log_id": auth_credential_log_id,
        "tcpcheck":               tcp_status == "UP",
        "failure_reason":         failure_reason,
        "response":               response,
    }

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, params)
        conn.commit()
        log.info("auth_credential_log aggiornato (connection_tcp)",
                 extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                        "tcp_status": tcp_status, "failure_reason": failure_reason,
                        "response": response})
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'update di auth_credential_log_tcp",
                  extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                         "error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)


def _update_log_extop(cfg: dict, auth_credential_log_id: int | None, login: str,
                       remote_response: str | None) -> None:
    """
    UPDATE di history.auth_credential_log (operations_sql.update.auth_credential_log_extop)
    dopo la risposta del SOAP esterno, valorizzando la riga con remote_response
    (XML grezzo restituito dal server SOAP — result["raw_response"] in
    call_credential_verify_soap()).

    remote_response puo' essere None se non e' arrivata una vera risposta
    HTTP dal servizio (TCP down, eccezione di rete/timeout): niente fallback
    a wsdlresponse, in quel caso la colonna viene aggiornata a NULL.

    Parametri passati alla query: %(auth_credential_log_id)s, %(remote_response)s.

    Fail-open, stesso pattern delle altre funzioni di sync in questo modulo.
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
                     auth_validation: str | None, success: int, failure_reason: str | None,
                     response: str | None = None, code: str | None = None) -> None:
    """
    UPDATE di history.auth_credential_log (operations_sql.update.auth_credential_log_end),
    eseguito quando la richiesta raggiunge un esito finale: SOAP riuscito
    (code == "000"), oppure fallback su cache locale deciso da
    _try_cache_fallback() (TCP down o SOAP code != "000"). Valorizza
    auth_validation/success/failure_reason/response/code sulla riga creata da
    _log_request_history().

    auth_validation puo' essere None (nessuna validazione riuscita — caso di
    fallback negato). response e' il JSON della risposta effettivamente
    inviata al client (colonna `response`, aggiunta dall'utente). code e' il
    valore finale del campo "code" di quella stessa risposta (colonna `code`,
    aggiunta dall'utente) — puo' essere uno dei code SOAP reali ("000"/"500"/
    "200"/"300") o uno dei code composti dal fallback su cache (es. "1002").

    Parametri passati alla query: %(auth_credential_log_id)s, %(auth_validation)s,
    %(success)s, %(failure_reason)s, %(response)s, %(code)s.

    Fail-open, stesso pattern delle altre funzioni di sync in questo modulo.
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
        "auth_validation":        auth_validation,
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
                        "auth_validation": auth_validation, "success": success,
                        "failure_reason": failure_reason, "response": response, "code": code})
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'update di auth_credential_log_end",
                  extra={"login": login, "auth_credential_log_id": auth_credential_log_id,
                         "error_txt": str(exc)}, exc_info=True)
    finally:
        release_pg_connection(conn)


def _check_cache_credential(cfg: dict, login: str, prov: str) -> dict | None:
    """
    SELECT operations_sql.select.checkcache per recuperare l'hash password e
    la scadenza calcolata (expires_at) memorizzati in
    public.auth_credential_cache per questa login — sola lettura, usata come
    fallback di autenticazione quando il SOAP esterno non e' raggiungibile
    (TCP down) o ha rifiutato le credenziali (code != "000").

    Ritorna un dict con le colonne selezionate dalla query (tipicamente
    password_hash, expires_at) oppure None se non c'e' nessuna riga per la
    login, la query non e' configurata, o si verifica un errore — fail-open,
    stesso pattern delle altre funzioni di questo modulo: un problema qui
    nega semplicemente il fallback, non solleva un'eccezione al chiamante.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("checkcache", "")

    if not select_sql:
        log.warning("operations_sql.select.checkcache non configurato, salto fallback cache",
                    extra={"login": login})
        return None

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"login": login, "prov": prov})
            row  = cur.fetchone()
            cols = [d[0] for d in cur.description] if row is not None else None
        # Chiude esplicitamente la transazione della SELECT (sola lettura,
        # nulla da salvare) — prima non veniva mai chiusa su nessun path,
        # nemmeno quello di successo: la connessione tornava al pool ancora
        # dentro una transazione aperta. Spostato fuori dal blocco "with" del
        # cursore (ed entrambi i return uniti in uno solo) cosi' il commit
        # avviene un'unica volta, indipendentemente da riga trovata o meno.
        conn.commit()
        return dict(zip(cols, row)) if row is not None else None
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la select di fallback su cache",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _try_cache_fallback(cfg: dict, login: str, password_hash: str, prov: str,
                         auth_credential_log_id: int | None, auth_type: str,
                         t0: float, origin_code: str) -> tuple[dict, int]:
    """
    Fallback di autenticazione su cache locale (public.auth_credential_cache),
    usato quando il SOAP esterno non e' raggiungibile (TCP down, origin_code
    "100") o e' stato chiamato ma non e' riuscito a validare (origin_code
    "200"=errore HTTP non gestito, "300"=eccezione/timeout — i code reali
    restituiti da call_credential_verify_soap()): confronta l'hash della
    password appena calcolata con quello memorizzato in cache e verifica che
    la cache non sia scaduta (now < expires_at — la cache e' ancora nella
    sua finestra di validita').

    - Valido (hash coincide, now < expires_at): autentica comunque l'utente
      — auth_validation="cache", success=1, failure_reason=None, risposta al
      client con code="000".
    - Non valido (nessuna riga, hash diverso, cache priva di scadenza, o
      scaduta): nega l'accesso — auth_validation="cache" (il meccanismo
      cache e' comunque quello che ha tentato la validazione, anche se
      negata), success=0, failure_reason descrittivo del motivo. Il code
      finale e' <origin_code><numero_motivo> (concatenazione stringa, es.
      "1002", "3004", "2001" — vedi _FALLBACK_REASON_NUMBER), con una
      description distinta per ogni combinazione (vedi _FALLBACK_DESCRIPTIONS).

    In entrambi i casi l'esito viene scritto su
    operations_sql.update.auth_credential_log_end (che valorizza anche la
    colonna `response` con il JSON della risposta inviata al client).

    Returns:
        (response_body, 200) — da restituire cosi' com'e' come esito di
        handle_credential_verify().
    """
    cache_row = _check_cache_credential(cfg, login, prov)

    valid = False
    deny_key = "no_cache"
    if cache_row is not None:
        cached_hash = cache_row.get("password_hash")
        expires_at  = cache_row.get("expires_at")
        if cached_hash != password_hash:
            deny_key = "hash_mismatch"
        elif expires_at is None:
            deny_key = "no_expiry"
        else:
            # expires_at arriva senza timezone (la query in config.yaml fa
            # un cast ::TIMESTAMP, non ::TIMESTAMPTZ su un'espressione che
            # parte da una colonna timestamptz): confronto con un now()
            # locale altrettanto naive, coerente col fuso del server
            # PostgreSQL che ha calcolato il valore.
            now = datetime.datetime.now()
            if now < expires_at:
                valid = True
            else:
                deny_key = "expired"

    elapsed_time = round((time.perf_counter() - t0) * 1000, 2)

    # Solo per log/failure_reason leggibili — dinamico su auth_type.upper(),
    # non piu' "SOAP" fisso, in vista di futuri backend ldap/db.
    origin_label = (f"{auth_type.upper()} TCP down" if origin_code == "100"
                     else f"{auth_type.upper()} code={origin_code}")

    if valid:
        response_body = {
            "code":         "000",
            "auth_type":    auth_type,
            "description":  "Accesso autorizzato (validato da cache locale).",
            "elapsed_time": elapsed_time,
        }
        log.info(f"Fallback su cache riuscito ({origin_label})",
                 extra={"login": login, "auth_credential_log_id": auth_credential_log_id})
        _update_log_end(cfg, auth_credential_log_id, login, auth_validation="cache",
                         success=1, failure_reason=None, response=json.dumps(response_body),
                         code=response_body["code"])
    else:
        final_code = f"{origin_code}{_FALLBACK_REASON_NUMBER[deny_key]}"
        response_body = {
            "code":         final_code,
            "auth_type":    auth_type,
            "description":  _FALLBACK_DESCRIPTIONS[origin_code][deny_key],
            "elapsed_time": elapsed_time,
        }
        failure_reason = f"Fallback su cache negato ({origin_label}): {_FALLBACK_DB_REASONS[deny_key]}"
        log.info(failure_reason,
                 extra={"login": login, "auth_credential_log_id": auth_credential_log_id})
        # auth_validation="cache" anche sul diniego: il meccanismo "cache" e'
        # comunque quello che ha tentato la validazione (fallita), non None
        # come prima — coerente con auth_validation=auth_type sul code=500.
        _update_log_end(cfg, auth_credential_log_id, login, auth_validation="cache",
                         success=0, failure_reason=failure_reason, response=json.dumps(response_body),
                         code=response_body["code"])

    return response_body, 200


def handle_credential_verify(cfg: dict, login: str, password: str, prov: str,
                                client_request_id: str | None = None) -> tuple[dict, int]:
    """
    Logga richiesta (password mascherata), calcola l'hash della password,
    chiama SOAP, sincronizza la cache login su successo, restituisce risposta.

    auth_type e' letto da config.yaml (credential_verify.auth_type, default
    "soap") — non piu' hardcoded. Resta comunque un valore statico di config,
    non determinato dinamicamente in base al backend che ha effettivamente
    gestito la richiesta (vedi i flag soap/ldap/db, ancora solo dichiarativi):
    quando verranno implementati backend alternativi andra' rivisto.

    Fallback su cache locale (_try_cache_fallback()): scatta SOLO quando il
    SOAP non riesce a dare una risposta definitiva — TCP down (nessuna
    chiamata SOAP in quel caso, inutile: fallirebbe comunque sullo stesso
    check al suo interno; origin_code sintetico "100"), oppure raggiungibile
    ma con code diverso sia da "000" (successo) sia da "500" (il SOAP HA
    validato ed ha rifiutato esplicitamente le credenziali — password
    errata, nessun fallback: la cache non deve scavalcare un rifiuto
    esplicito). Negli altri code reali (oggi "200" errore HTTP non gestito,
    "300" eccezione/timeout — vedi soap_service.py) confronta l'hash della
    password con quello in cache e la relativa scadenza, e decide se
    autenticare comunque l'utente — il code finale in caso di diniego e'
    <origin_code><1-4>, concatenazione stringa (vedi _FALLBACK_REASON_NUMBER).

    Returns:
        ({"code": ..., "auth_type": "soap", "description": ..., "elapsed_time": ...}, 200)
    """
    t0 = time.perf_counter()
    # Motivo di un eventuale fallimento della richiesta, valorizzato via via
    # che si scoprono errori nelle fasi seguenti (oggi solo il TCP check).
    # Resta None finche' non emerge un motivo concreto.
    failure_reason = None

    # Snapshot JSON della richiesta ricevuta dal client (colonna `request`,
    # aggiunta dall'utente) — password SEMPRE mascherata, mai in chiaro nel
    # DB. Costruito PRIMA della sostituzione di client_request_id con
    # l'X-Request-Id qui sotto, per riflettere esattamente cio' che il
    # client ha inviato nel body (incluso client_request_id assente/None).
    client_request = json.dumps({
        "login":             login,
        "password":          mask_password(password),
        "prov":              prov,
        "client_request_id": client_request_id,
    })

    # Se il client non fornisce client_request_id, usa il nostro X-Request-Id
    # (flask.g.request_id, valorizzato dal middleware in before_request) invece
    # di un placeholder statico: cosi' la riga di history/cache resta comunque
    # correlabile ai log della richiesta tramite X-Request-Id.
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"

    # auth_type: letto da config.yaml (credential_verify.auth_type), non piu'
    # hardcoded — unico backend realmente implementato oggi resta "soap" (vedi
    # i flag soap/ldap/db, ancora solo dichiarativi).
    auth_type = cfg.get("credential_verify", {}).get("auth_type", "soap")

    log.info("Richiesta login ricevuta",
             extra={"login": login, "pwd_masked": mask_password(password),
                    "client_request_id": client_request_id})

    # Appena la richiesta arriva, prima della chiamata SOAP e
    # indipendentemente dall'esito: registrazione in history.auth_credential_log.
    score = 1
    service = "verify"
    auth_credential_log_id = _log_request_history(cfg, login, client_request_id, score,
                                                    auth_type, service, client_request,
                                                    getattr(g, "service_account", None))

    # Hash calcolato subito, prima del check TCP: serve sia per la sync
    # cache sul ramo di successo SOAP, sia per l'eventuale fallback su cache
    # (_try_cache_fallback) sui rami TCP down/code != "000" — non piu'
    # calcolato solo dopo il check TCP come in precedenza. Non inviato al
    # servizio esterno (che continua a ricevere la password in chiaro, come
    # richiede il suo protocollo) — vedi hash_password() per il caveat su
    # uso/sicurezza (SHA-256 senza salt).
    password_hash = hash_password(password)
    log.debug("Hash password calcolato", extra={"login": login, "pwd_hash": password_hash})

    # Verifica di raggiungibilita' TCP del servizio SOAP (stessa
    # check_soap_listening() usata poi da call_credential_verify_soap()
    # come primo passo) — subito dopo, update della riga appena creata con
    # l'esito del check.
    tcp_check = check_soap_listening(cfg)
    if tcp_check["status"] != "UP":
        # Dinamica su auth_type, non piu' "SOAP" fisso: quando ldap/db
        # verranno implementati e useranno lo stesso check_tcp_listening()/
        # _update_log_tcp(), il motivo riportera' il backend realmente
        # coinvolto invece di riportare sempre "SOAP".
        failure_reason = f"Connessione TCP al servizio {auth_type.upper()} down"
        _update_log_tcp(cfg, auth_credential_log_id, login, tcp_check["status"], failure_reason)

        # Nessuna chiamata SOAP (fallirebbe comunque sullo stesso check al
        # suo interno): fallback diretto su cache locale.
        log.info("TCP down: nessuna chiamata SOAP, tento fallback su cache locale",
                 extra={"login": login})
        return _try_cache_fallback(cfg, login, password_hash, prov, auth_credential_log_id,
                                    auth_type, t0, origin_code="100")

    _update_log_tcp(cfg, auth_credential_log_id, login, tcp_check["status"], failure_reason)

    result = call_credential_verify_soap(cfg, login, password)

    log.info("Risposta SOAP ricevuta",
             extra={"login": login, "result_code": result.get("code"),
                    "wsdlresponse": result.get("wsdlresponse")})

    # Output grezzo del server SOAP (XML completo) salvato in remote_response,
    # poi update extop sulla riga di history.auth_credential_log creata a
    # inizio richiesta. None se non e' arrivata una vera risposta HTTP (TCP
    # down, eccezione di rete/timeout) — nessun fallback a wsdlresponse.
    remote_response = result.get("raw_response")
    _update_log_extop(cfg, auth_credential_log_id, login, remote_response)

    result_code = result.get("code")

    if result_code == "000":
        _sync_login_cache(cfg, login, password_hash, client_request_id, prov, auth_type)

        elapsed_time = round((time.perf_counter() - t0) * 1000, 2)
        response_body = {
            "code":         result_code,
            "auth_type":    auth_type,
            "description":  result.get("wsdlresponse", "errore imprevisto"),
            "elapsed_time": elapsed_time,
        }
        # auth_validation=auth_type: il SOAP e' il meccanismo che ha
        # effettivamente validato con successo la richiesta.
        _update_log_end(cfg, auth_credential_log_id, login, auth_type,
                         success=1, failure_reason=None, response=json.dumps(response_body),
                         code=response_body["code"])
        return response_body, result.get("status_code", 200)

    if result_code in ("500", "501"):
        # Il SOAP e' riuscito a validare la richiesta ed ha rifiutato
        # ESPLICITAMENTE le credenziali — non ha senso un fallback su cache
        # in questo caso: il servizio ha gia' dato una risposta definitiva,
        # la cache non deve scavalcarla. Due varianti (vedi soap_service.py):
        # 500 = login/matricola non valida, 501 = credenziali non valide
        # (password errata) — stesso trattamento "nessun fallback" per
        # entrambe, cambia solo il messaggio di audit.
        elapsed_time = round((time.perf_counter() - t0) * 1000, 2)
        response_body = {
            "code":         result_code,
            "auth_type":    auth_type,
            "description":  result.get("wsdlresponse", "errore imprevisto"),
            "elapsed_time": elapsed_time,
        }
        failure_reason = (
            "Login/matricola non valida (rifiutata esplicitamente dal servizio SOAP esterno)"
            if result_code == "500" else
            "Credenziali non valide - password errata (rifiutata esplicitamente dal servizio SOAP esterno)"
        )
        log.info(f"SOAP ha validato e rifiutato le credenziali (code={result_code}), nessun fallback su cache",
                 extra={"login": login})
        # auth_validation=auth_type: il SOAP HA validato la richiesta (esito
        # negativo, ma comunque un esito definitivo dato dal meccanismo
        # "soap") — stesso principio del ramo di successo sopra.
        _update_log_end(cfg, auth_credential_log_id, login, auth_type,
                         success=0, failure_reason=failure_reason, response=json.dumps(response_body),
                         code=response_body["code"])
        return response_body, result.get("status_code", 200)

    # Qualunque altro code diverso da "000"/"500"/"501" (oggi "200" errore
    # HTTP non gestito, "300" eccezione/errore imprevisto, o "503" fault
    # HTTP 500 con testo non riconosciuto da nessun pattern configurato —
    # vedi soap_service.py): il SOAP NON e' riuscito a validare la
    # richiesta (non ha dato una risposta definitiva su password
    # giusta/sbagliata) — fallback su cache locale, stesso trattamento del
    # ramo TCP down. result_code diventa l'origin_code usato da
    # _try_cache_fallback() per comporre il code finale (es. "2001", "3004",
    # "5031").
    log.info(f"SOAP non e' riuscito a validare (code={result_code}), tento fallback su cache locale",
             extra={"login": login, "result_code": result_code})
    return _try_cache_fallback(cfg, login, password_hash, prov, auth_credential_log_id,
                                auth_type, t0, origin_code=result_code)
