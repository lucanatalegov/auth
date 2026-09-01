# ============================================================
#  app/controllers/otp_controller.py
#  Controller MVC per gli endpoint 2FA (POST /otp/setup,
#  PUT /otp/setup/confirm, POST /otp/sendmailotp, POST /otp/verify,
#  GET /otp/status, POST /otp/disable).
#
#  Tutte le query SQL vivono in config.yaml (operations_sql, chiavi
#  prefissate otp_*), eseguite via psycopg2 con parametri nominati
#  %(nome)s — stesso pattern di credential_verify_controller.py, nessuna
#  query costruita dinamicamente lato Python.
#
#  A differenza delle scritture di credential_verify_controller.py (fail-
#  open: un errore DB viene loggato ma non interrompe la richiesta, perche'
#  la storicizzazione e' un side-effect accessorio rispetto all'esito SOAP),
#  qui le scritture su public.otp_methods/history.otp_requests SONO il dato
#  primario dell'operazione: un errore DB durante setup/confirm/sendmailotp/
#  disable si traduce in una risposta 500 al chiamante, non viene inghiottito.
#
#  Operazioni composte da piu' statement (es. attiva + marca verificata la
#  richiesta di registrazione collegata) vengono eseguite su un'unica
#  connessione con un solo commit, per evitare stati intermedi inconsistenti
#  se il processo si interrompe a meta'.
#
#  REGOLA "un solo metodo attivo per login": non e' piu' l'attivazione
#  (/otp/setup, /otp/setup/confirm) a disattivare in silenzio un metodo gia'
#  attivo — handle_otp_setup() rifiuta esplicitamente (code 225) se ne trova
#  gia' uno. L'unico modo per liberare lo slot e' un esplicito POST
#  /otp/disable. L'indice univoco DB (otp_methods_one_active_per_login) resta
#  comunque come backstop fail-closed contro eventuali race condition fra il
#  controllo e la scrittura: se scattasse, l'INSERT/UPDATE fallisce e la
#  richiesta torna 500 invece di attivare in silenzio un secondo metodo.
# ============================================================

import logging
import time
from datetime import datetime, timedelta

from flask import g

from app.services import otp_service
from app.utils.db_pool import get_pg_connection, release_pg_connection

log = logging.getLogger("authapi.controller.otp")


def _elapsed(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


# ------------------------------------------------------------------
# Helper DB — public.otp_methods
# ------------------------------------------------------------------

def _insert_pending_method(cfg, login, method, secret, mail_to):
    sql_cfg    = cfg.get("operations_sql", {})
    insert_sql = sql_cfg.get("insert", {}).get("otp_method", "")
    if not insert_sql:
        log.error("operations_sql.insert.otp_method non configurato")
        return None

    params = {"login": login, "method": method, "secret": secret, "mail_to": mail_to}
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(insert_sql, params)
            row = cur.fetchone()
            config_id = row[0] if row else None
        conn.commit()
        log.info("Metodo 2FA registrato (pending)",
                 extra={"login": login, "method": method, "config_id": config_id})
        return config_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la registrazione del metodo 2FA",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _insert_and_activate_method(cfg, login, method, secret, mail_to):
    """
    Inserisce il nuovo metodo gia' attivo (usato per method='mail' quando
    otp2fa.require_mail_confirmation=false: l'indirizzo arriva gia' validato
    dall'applicazione chiamante, non serve dimostrarne di nuovo il possesso).

    Il chiamante (handle_otp_setup) ha gia' verificato che non esista un
    metodo attivo per questa login — non disattiva piu' nulla qui. Se
    esistesse comunque (race condition fra il check e questo INSERT),
    l'indice univoco otp_methods_one_active_per_login fa fallire lo
    statement e la richiesta torna 500 invece di attivarne un secondo.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    insert_sql = sql_cfg.get("insert", {}).get("otp_method_active", "")
    if not insert_sql:
        log.error("operations_sql.insert.otp_method_active non configurato")
        return None

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(insert_sql, {"login": login, "method": method, "secret": secret, "mail_to": mail_to})
            row = cur.fetchone()
            config_id = row[0] if row else None
        conn.commit()
        log.info("Metodo 2FA attivato immediatamente", extra={"login": login, "config_id": config_id})
        return config_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'attivazione immediata del metodo 2FA",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _activate_method(cfg, login, config_id):
    """
    Attiva config_id e marca 'verified' l'eventuale richiesta di
    registrazione pending collegata — un'unica transazione (usata da
    /otp/setup/confirm).

    Il chiamante (handle_otp_confirm, tramite il check gia' fatto dal
    corrispondente /otp/setup) presuppone che non esista un metodo attivo
    per questa login — non disattiva piu' nulla qui. Se esistesse comunque
    (race condition), l'indice univoco otp_methods_one_active_per_login fa
    fallire l'UPDATE e la richiesta torna 500.

    otp_request_verify_register (WHERE status='pending') e' ormai per lo piu'
    un no-op difensivo: handle_otp_confirm() marca gia' 'verified'/'failed' la
    riga di history.otp_requests PRIMA di chiamare questa funzione (vedi
    _get_register_request()) — resta comunque come rete di sicurezza per
    l'eventuale riga trovata solo in un secondo momento.
    """
    sql_cfg      = cfg.get("operations_sql", {})
    activate_sql = sql_cfg.get("update", {}).get("otp_method_activate", "")
    request_sql  = sql_cfg.get("update", {}).get("otp_request_verify_register", "")
    if not activate_sql:
        log.error("operations_sql.update.otp_method_activate non configurato")
        return False

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(activate_sql, {"config_id": config_id})
            if request_sql:
                cur.execute(request_sql, {"config_id": config_id})
        conn.commit()
        log.info("Metodo 2FA attivato", extra={"login": login, "config_id": config_id})
        return True
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'attivazione del metodo 2FA",
                  extra={"login": login, "config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return False
    finally:
        release_pg_connection(conn)


def _disable_method(cfg, login, requested_by_login, force):
    """
    Disattiva il metodo attivo di login (se esiste) — unico punto del
    codice che puo' liberare lo slot 'un solo metodo attivo per login'.
    Usata da /otp/disable. Logga sempre un audit esplicito (chi l'ha
    chiesto, se in force, cosa e' stato disattivato).
    """
    sql_cfg     = cfg.get("operations_sql", {})
    disable_sql = sql_cfg.get("update", {}).get("otp_method_disable_active", "")
    if not disable_sql:
        log.error("operations_sql.update.otp_method_disable_active non configurato")
        return False

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(disable_sql, {"login": login, "requested_by_login": requested_by_login})
            disabled = cur.fetchall()
        conn.commit()
        for old_id, old_method in disabled:
            log.warning("2FA disattivato",
                        extra={"login": login, "requested_by_login": requested_by_login, "force": force,
                               "disabled_config_id": old_id, "disabled_method": old_method})
        return True
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la disattivazione del metodo 2FA",
                  extra={"login": login, "requested_by_login": requested_by_login, "error_txt": str(exc)},
                  exc_info=True)
        return False
    finally:
        release_pg_connection(conn)


def _get_method_by_id(cfg, config_id):
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_method_by_id", "")
    if not select_sql:
        log.error("operations_sql.select.otp_method_by_id non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"config_id": config_id})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura della configurazione 2FA",
                  extra={"config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _get_active_method(cfg, login):
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_active_method", "")
    if not select_sql:
        log.error("operations_sql.select.otp_active_method non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"login": login})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura del metodo 2FA attivo",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _get_login_status(cfg, login):
    """
    Ultima configurazione 2FA per login, qualunque sia il suo status
    (pending/active/disabled) — a differenza di _get_active_method(), che
    filtra solo su status='active'. Usata da GET /otp/status.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_login_status", "")
    if not select_sql:
        log.error("operations_sql.select.otp_login_status non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"login": login})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura dello stato 2FA",
                  extra={"login": login, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _update_method_counter(cfg, config_id, new_counter):
    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("otp_method_counter", "")
    if not update_sql:
        log.error("operations_sql.update.otp_method_counter non configurato")
        return False
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, {"new_counter": new_counter, "config_id": config_id})
        conn.commit()
        return True
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'aggiornamento del contatore HOTP",
                  extra={"config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return False
    finally:
        release_pg_connection(conn)


def _update_totp_step(cfg, config_id, step) -> bool:
    """
    Persiste l'ultimo timestep TOTP verificato con successo per config_id —
    protezione anti-replay. UPDATE atomico e condizionale (query
    otp_method_totp_step, "RETURNING id"): scrive last_totp_step SOLO se la
    condizione (NULL o < step) e' ancora vera nell'istante esatto della
    scrittura — non prima. E' la scrittura stessa a fare da check (compare-
    and-swap lato DB), non piu' un confronto fatto in Python su un valore
    letto in anticipo da una SELECT separata.

    Questo chiude una race condition reale: con la vecchia sequenza
    "leggi last_totp_step -> decidi in Python -> scrivi", due richieste
    concorrenti con lo stesso step potevano leggere entrambe lo stesso
    valore (nessuna delle due aveva ancora scritto) e risultare entrambe
    "valide". Con l'UPDATE condizionale, se due richieste lo eseguono nello
    stesso momento, PostgreSQL serializza a livello di riga: la seconda
    aspetta il lock della prima, e quando riprende rivaluta la WHERE sui
    dati appena committati — la condizione non e' piu' vera, quindi la sua
    UPDATE tocca zero righe e "RETURNING id" non restituisce nulla.

    Returns:
        True  se lo step e' stato accettato (riga aggiornata, nessun replay)
              — anche in caso di errore DB (fail-open: un problema
              infrastrutturale qui non deve bloccare un'autenticazione gia'
              validata da pyotp; lascia solo quello specifico step riusabile
              per la sua finestra residua, tipicamente pochi secondi — impatto
              molto minore di un contatore HOTP non persistito).
        False se la UPDATE non ha toccato nessuna riga: lo step (o uno
              successivo) e' gia' stato consumato — replay reale.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("otp_method_totp_step", "")
    if not update_sql:
        log.error("operations_sql.update.otp_method_totp_step non configurato")
        return True   # fail-open: nessuna query configurata, non blocchiamo il login
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, {"config_id": config_id, "step": step})
            accepted = cur.fetchone() is not None
        conn.commit()
        return accepted
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'aggiornamento atomico di last_totp_step",
                  extra={"config_id": config_id, "step": step, "error_txt": str(exc)}, exc_info=True)
        return True   # fail-open: errore infrastrutturale, non un replay reale
    finally:
        release_pg_connection(conn)


# ------------------------------------------------------------------
# Helper DB — config.mail_templates / history.otp_requests
# ------------------------------------------------------------------

def _get_template(cfg, template_id):
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_mail_template", "")
    if not select_sql:
        log.error("operations_sql.select.otp_mail_template non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"template_id": template_id})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura del template email",
                  extra={"template_id": template_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _masked_otp_code(cfg, otp_code):
    """
    Quanto del codice OTP reale (otp_code) finisce in history.otp_requests.code,
    secondo otp2fa.debug_code (0/1/2 - vedi config.yaml). Il formato si
    autodenuncia sempre come mascherato/pieno guardando solo la stringa:
    "******" (nessuna cifra reale), "****13" (ultime 2 cifre reali), o il
    codice completo.
    """
    debug_code = cfg.get("otp2fa", {}).get("debug_code", 0)
    if debug_code == 2:
        return otp_code
    if debug_code == 1:
        return f"****{otp_code[-2:]}"
    return "******"


def _insert_otp_request(cfg, config_id, login, purpose, counter_used, expires_at, request_id, client_id, otp_code):
    """
    expires_at (datetime) e' calcolata dal chiamante PRIMA di inviare la mail
    (vedi handle_otp_setup/handle_otp_sendmailotp) e passata identica sia a
    otp_service.send_otp_mail() (per {{EXPIRES_AT}} nel body) sia qui — un
    solo calcolo condiviso, cosi' l'orario mostrato all'utente coincide
    sempre con quello effettivamente salvato (prima la scadenza era ricalcolata
    qui da un now() Postgres, potenzialmente diverso da quando la mail era
    gia' partita).
    """
    sql_cfg    = cfg.get("operations_sql", {})
    insert_sql = sql_cfg.get("insert", {}).get("otp_request", "")
    if not insert_sql:
        log.error("operations_sql.insert.otp_request non configurato")
        return None

    params = {
        "config_id":    config_id,
        "login":        login,
        "purpose":      purpose,
        "counter_used": counter_used,
        "request_id":   request_id,
        "client_id":    client_id or "NA",
        "expires_at":   expires_at,
        "code":         _masked_otp_code(cfg, otp_code),
    }
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(insert_sql, params)
            row = cur.fetchone()
            request_row_id = row[0] if row else None
        conn.commit()
        log.info("Richiesta OTP registrata",
                 extra={"login": login, "config_id": config_id, "purpose": purpose,
                        "request_row_id": request_row_id})
        return request_row_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la registrazione della richiesta OTP",
                  extra={"login": login, "config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _insert_otp_verify_log(cfg, config_id, login, request_id, client_id, otp_code, valid):
    """
    Log di un tentativo di verifica TOTP (method='app') su /otp/verify o
    /otp/disable — a differenza di _insert_otp_request() (flusso mail, dove
    la riga esiste gia' dall'invio ed e' solo aggiornata), qui non c'e' un
    "invio" precedente: ogni tentativo genera una riga nuova, gia' con lo
    stato finale (verified/failed), senza passare da 'pending'. code
    mascherato secondo otp2fa.debug_code, stesso helper del flusso mail.
    """
    sql_cfg    = cfg.get("operations_sql", {})
    insert_sql = sql_cfg.get("insert", {}).get("otp_request_verify", "")
    if not insert_sql:
        log.error("operations_sql.insert.otp_request_verify non configurato")
        return None

    params = {
        "config_id":  config_id,
        "login":      login,
        "request_id": request_id,
        "client_id":  client_id or "NA",
        "code":       _masked_otp_code(cfg, otp_code),
        "status":     "verified" if valid else "failed",
    }
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(insert_sql, params)
            row = cur.fetchone()
            request_row_id = row[0] if row else None
        conn.commit()
        log.info("Tentativo di verifica OTP (app) registrato",
                 extra={"login": login, "config_id": config_id, "valid": valid,
                        "request_row_id": request_row_id})
        return request_row_id
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la registrazione del tentativo di verifica OTP",
                  extra={"login": login, "config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _get_register_request(cfg, config_id):
    """
    Ultima riga purpose='register' per config_id — usata da handle_otp_confirm()
    per applicare allo stesso codice di conferma il controllo scadenza/stato
    gia' presente in _check_otp_code() per il flusso mail-login. A differenza
    di _get_request_by_id() non richiede request_id (il confirm non l'ha mai
    chiesto al client): un solo codice di registrazione atteso per config_id.

    None se la riga non esiste (es. insert fallito al momento dell'invio,
    fail-open come le altre scritture di history.otp_requests) — in quel
    caso il chiamante procede comunque solo sul controllo HOTP/TOTP, senza
    gating su scadenza/stato: la riga di history e' un log, non la fonte di
    verita' della validita' del codice (quella resta otp_methods.secret).
    """
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_request_by_config", "")
    if not select_sql:
        log.error("operations_sql.select.otp_request_by_config non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"config_id": config_id})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura della richiesta di registrazione OTP",
                  extra={"config_id": config_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _get_request_by_id(cfg, request_id, config_id, login):
    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_request_by_id", "")
    if not select_sql:
        log.error("operations_sql.select.otp_request_by_id non configurato")
        return None
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"request_id": request_id, "config_id": config_id, "login": login})
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante la lettura della richiesta OTP",
                  extra={"request_id": request_id, "error_txt": str(exc)}, exc_info=True)
        return None
    finally:
        release_pg_connection(conn)


def _update_request_status(cfg, request_row_id, new_status):
    sql_cfg    = cfg.get("operations_sql", {})
    update_sql = sql_cfg.get("update", {}).get("otp_request_status", "")
    if not update_sql:
        log.error("operations_sql.update.otp_request_status non configurato")
        return False
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(update_sql, {"new_status": new_status, "id": request_row_id})
        conn.commit()
        return True
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'aggiornamento dello stato della richiesta OTP",
                  extra={"request_row_id": request_row_id, "error_txt": str(exc)}, exc_info=True)
        return False
    finally:
        release_pg_connection(conn)


# ============================================================
# 1. SETUP — genera QR+secret (app) o attiva/invia il primo codice (mail)
# ============================================================

def handle_otp_setup(cfg: dict, login: str, method: str, template_id: int | None,
                      mail_to: str | None, client_request_id: str | None = None) -> tuple[dict, int]:
    t0 = time.perf_counter()
    # Se il client non fornisce client_request_id, usa il nostro X-Request-Id
    # (vedi credential_verify_controller.py per lo stesso pattern).
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Setup 2FA richiesto", extra={"login": login, "method": method,
                                            "client_request_id": client_request_id})

    # Regola: non si puo' attivare un metodo (subito, o via /otp/setup/confirm
    # in seguito) se ne esiste gia' uno attivo per questa login — qualunque
    # sia il metodo nuovo o quello gia' attivo. Va prima disattivato
    # esplicitamente con POST /otp/disable. Controllo fatto qui, prima di
    # qualunque scrittura (nessun secret/QR generato inutilmente).
    if _get_active_method(cfg, login) is not None:
        return {"message": "Esiste gia' un metodo 2FA attivo per questo utente: "
                            "disattivarlo prima con POST /otp/disable, poi ripetere il setup",
                "code": "225", "elapsed_time": _elapsed(t0)}, 409

    if method == "app":
        secret = otp_service.generate_secret()
        config_id = _insert_pending_method(cfg, login, method, secret, mail_to)
        if config_id is None:
            return {"message": "Errore durante la registrazione del metodo 2FA",
                    "code": "500", "elapsed_time": _elapsed(t0)}, 500

        issuer_name = cfg.get("otp2fa", {}).get("issuer_name", "Auth API")
        qr_base64 = otp_service.generate_qr_base64(cfg, login, secret, issuer_name)
        return {
            "message": "Scansiona il QR code con la tua app di autenticazione, poi conferma con il primo codice",
            "code": "000",
            "config_id": config_id,
            "secret": secret,               # fallback per inserimento manuale
            "qr_code_base64": qr_base64,
            "elapsed_time": _elapsed(t0),
        }, 200

    # method == "mail"
    template = _get_template(cfg, template_id)
    if template is None:
        return {"message": "Template non trovato o non attivo",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    secret = otp_service.generate_secret()
    require_confirmation = cfg.get("otp2fa", {}).get("require_mail_confirmation", False)

    if not require_confirmation:
        # Attivazione immediata: l'indirizzo mail_to arriva gia' validato
        # dall'applicazione chiamante, non serve riprovarne il possesso.
        config_id = _insert_and_activate_method(cfg, login, method, secret, mail_to)
        if config_id is None:
            return {"message": "Errore durante l'attivazione del metodo 2FA",
                    "code": "500", "elapsed_time": _elapsed(t0)}, 500
        return {"message": "Metodo 2FA via mail attivato", "code": "000",
                "config_id": config_id, "elapsed_time": _elapsed(t0)}, 200

    # Flusso classico: invia un primo codice (HOTP, counter=0) e resta
    # 'pending' finche' l'utente non lo conferma su /otp/setup/confirm.
    config_id = _insert_pending_method(cfg, login, method, secret, mail_to)
    if config_id is None:
        return {"message": "Errore durante la registrazione del metodo 2FA",
                "code": "500", "elapsed_time": _elapsed(t0)}, 500

    otp_code = otp_service.hotp_code(secret, 0)
    # Calcolata PRIMA dell'invio: stesso valore mostrato nella mail
    # ({{EXPIRES_AT}}) e salvato su history.otp_requests, nessun ricalcolo
    # successivo che potrebbe disallinearsi (vedi _insert_otp_request()).
    expires_at = datetime.now() + timedelta(seconds=int(template["timeout_seconds"]))
    sent = otp_service.send_otp_mail(template, login, mail_to, otp_code, expires_at)
    if not sent:
        return {"message": "Il server di posta e' down", "code": "300", "elapsed_time": _elapsed(t0)}, 412

    request_row_id = _insert_otp_request(
        cfg, config_id, login, "register", 0, expires_at,
        client_request_id, getattr(g, "service_account", None), otp_code,
    )
    return {
        "message": "Codice di conferma inviato via email",
        "code": "000",
        "config_id": config_id,
        "request_id": request_row_id,
        "elapsed_time": _elapsed(t0),
    }, 200


# ============================================================
# 2. CONFIRM — verifica il primo codice e attiva il metodo
# ============================================================

def handle_otp_confirm(cfg: dict, config_id: int, code: str, client_request_id: str | None = None) -> tuple[dict, int]:
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Conferma setup 2FA richiesta", extra={"config_id": config_id, "client_request_id": client_request_id})

    cfg_row = _get_method_by_id(cfg, config_id)
    if cfg_row is None:
        return {"message": "Configurazione non trovata", "code": "210", "elapsed_time": _elapsed(t0)}, 404

    if cfg_row["status"] != "pending":
        return {"message": "Configurazione gia' confermata o non piu' valida",
                "code": "220", "elapsed_time": _elapsed(t0)}, 409

    # method == "mail": stesso controllo scadenza/stato gia' applicato al
    # flusso mail-login da _check_otp_code() — se la riga non esiste (fail-open
    # all'invio) si procede comunque solo sul controllo HOTP sotto, senza
    # gating (vedi _get_register_request()). method == "app" non ha mai una
    # riga di history.otp_requests (nessun invio), register_request resta None.
    register_request = None
    if cfg_row["method"] == "mail":
        register_request = _get_register_request(cfg, config_id)
        if register_request is not None:
            if register_request["status"] != "pending":
                return {"message": "Codice gia' utilizzato o non piu' valido",
                        "code": "240", "elapsed_time": _elapsed(t0)}, 409
            if int(register_request["not_expired"]) == 0:
                _update_request_status(cfg, register_request["id"], "expired")
                return {"message": "Codice OTP scaduto", "code": "010", "elapsed_time": _elapsed(t0)}, 401
        else:
            log.warning("Nessuna riga history.otp_requests trovata per il confirm: procedo "
                        "solo con la verifica HOTP, senza controllo scadenza",
                        extra={"config_id": config_id})

    if cfg_row["method"] == "app":
        # verify_totp_with_step() invece di verify_totp(): un config_id appena
        # creato ha sempre last_totp_step NULL (nessun controllo di replay
        # possibile qui, e' per costruzione il primo utilizzo) — ma persistere
        # subito lo step chiude il cerchio: senza questo, lo stesso codice
        # appena usato per confermare resterebbe riusabile su /otp/verify per
        # il resto della sua finestra di validita'.
        valid_window = cfg.get("otp2fa", {}).get("totp_valid_window", 1)
        valid, step = otp_service.verify_totp_with_step(cfg_row["secret"], code, valid_window=valid_window)
        if valid:
            _update_totp_step(cfg, config_id, step)
    else:
        # method == "mail": il codice di conferma era generato con counter=0
        valid = otp_service.verify_hotp(cfg_row["secret"], code, 0)

    if register_request is not None:
        _update_request_status(cfg, register_request["id"], "verified" if valid else "failed")

    if not valid:
        log.info("Codice di conferma errato", extra={"config_id": config_id})
        return {"message": "Codice non valido", "code": "020", "elapsed_time": _elapsed(t0)}, 401

    if not _activate_method(cfg, cfg_row["login"], config_id):
        return {"message": "Errore durante l'attivazione del metodo 2FA",
                "code": "500", "elapsed_time": _elapsed(t0)}, 500

    return {"message": "Metodo 2FA attivato", "code": "000", "elapsed_time": _elapsed(t0)}, 200


# ============================================================
# 3. SEND MAIL OTP — richiede un nuovo codice via mail (solo method='mail')
# ============================================================

def handle_otp_sendmailotp(cfg: dict, login: str, template_id: int, client_request_id: str | None = None) -> tuple[dict, int]:
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Richiesta invio OTP via mail",
             extra={"login": login, "template_id": template_id, "client_request_id": client_request_id})

    active = _get_active_method(cfg, login)
    if active is None:
        return {"message": "Nessun metodo 2FA attivo per questo utente",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    if active["method"] != "mail":
        return {"message": "Il metodo attivo e' 'app': non e' necessario richiedere un codice via mail",
                "code": "230", "elapsed_time": _elapsed(t0)}, 400

    # template_id e' specificato dal chiamante ad ogni richiesta (non piu'
    # quello salvato in otp_methods al setup): il messaggio inviato puo'
    # variare da un OTP all'altro.
    template = _get_template(cfg, template_id)
    if template is None:
        return {"message": "Template non trovato o non attivo",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    new_counter = int(active["counter"]) + 1
    otp_code = otp_service.hotp_code(active["secret"], new_counter)

    # Calcolata PRIMA dell'invio, stesso valore per mail e DB — vedi nota in
    # _insert_otp_request() e nel ramo "register" di handle_otp_setup().
    expires_at = datetime.now() + timedelta(seconds=int(template["timeout_seconds"]))
    sent = otp_service.send_otp_mail(template, login, active["mail_to"], otp_code, expires_at)
    if not sent:
        return {"message": "Il server di posta e' down", "code": "300", "elapsed_time": _elapsed(t0)}, 412

    # Persistiamo il nuovo counter solo dopo l'invio andato a buon fine.
    if not _update_method_counter(cfg, active["id"], new_counter):
        return {"message": "Errore durante l'aggiornamento del contatore OTP",
                "code": "500", "elapsed_time": _elapsed(t0)}, 500

    request_row_id = _insert_otp_request(
        cfg, active["id"], login, "login", new_counter, expires_at,
        client_request_id, getattr(g, "service_account", None), otp_code,
    )

    return {
        "message": "Codice OTP inviato via email",
        "code": "000",
        "request_id": request_row_id,
        "elapsed_time": _elapsed(t0),
    }, 200


# ============================================================
# 3bis. REQUEST OTP (retrocompatibilita' legacy, ex SEND OTP / /otp/sendotp)
# — setup+invio in un'unica chiamata, per sistemi che non conoscono ancora
# il flusso separato /otp/setup + /otp/sendmailotp. Risposta con contratto
# legacy fisso (code/response_id/message), diverso da tutti gli altri
# endpoint /otp/*. Usa template_id come tutti gli altri endpoint (non piu'
# template_name) — rinominato da /otp/sendotp in una sessione successiva.
# ============================================================

def handle_otp_requestotp(cfg: dict, login: str, template_id: int, mail_to: str,
                           client_request_id: str | None = None) -> tuple[dict, int]:
    """
    Un solo metodo attivo per login, sempre 'mail' (crea/riusa quello
    esistente). _get_active_method() filtra gia' su status='active': una
    login con status='pending' (setup non confermato) o 'disabled' finisce
    quindi automaticamente nello stesso ramo di "nessun metodo" — nessuna
    gestione ad-hoc necessaria, l'unica conseguenza e' che l'eventuale vecchia
    riga pending/disabled resta orfana nel DB (l'indice unico
    otp_methods_one_active_per_login vincola solo le righe active, quindi
    nessun conflitto in fase di inserimento).

    method='app' gia' attivo: NON e' un errore per questo endpoint (a
    differenza di /otp/sendmailotp, che risponde code:"230") — richiesta
    esplicita dell'utente per compatibilita' col chiamante legacy, che si
    aspetta sempre un esito "codice generato" indipendentemente dal metodo
    realmente configurato. Nessuna mail viene davvero inviata in quel caso
    (non c'e' nulla da inviare per TOTP), nessuna riga history.otp_requests
    creata: response_id resta None.
    """
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Richiesta requestotp (legacy)",
             extra={"login": login, "template_id": template_id, "client_request_id": client_request_id})

    template = _get_template(cfg, template_id)
    if template is None:
        return {"message": "Template non trovato o non attivo",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    active = _get_active_method(cfg, login)
    newly_created = False
    if active is None:
        # Nessun metodo attivo (assente, pending o disabled — vedi docstring):
        # crea un metodo mail gia' attivo, stesso meccanismo del ramo
        # require_mail_confirmation=false di handle_otp_setup(). Costruito qui
        # un dict minimale equivalente al risultato di _get_active_method(),
        # per evitare una SELECT ridondante subito dopo l'INSERT.
        secret = otp_service.generate_secret()
        config_id = _insert_and_activate_method(cfg, login, "mail", secret, mail_to)
        if config_id is None:
            return {"message": "Errore durante l'attivazione del metodo 2FA",
                    "code": "500", "elapsed_time": _elapsed(t0)}, 500
        active = {"id": config_id, "secret": secret, "counter": 0, "mail_to": mail_to, "method": "mail"}
        newly_created = True

    if active["method"] != "mail":
        # method == "app": nessun invio reale possibile, ma il chiamante
        # legacy si aspetta comunque un "codice generato" — vedi docstring.
        return {"message": "codice OTP generato", "code": "000",
                "response_id": None, "elapsed_time": _elapsed(t0)}, 200

    if not newly_created and active["mail_to"] != mail_to:
        # mail_to della richiesta ignorato quando il metodo esiste gia' (si
        # comporta come /otp/sendmailotp, che non lo prende nemmeno in
        # input) — solo un segnale diagnostico, non blocca nulla: l'invio
        # prosegue comunque verso active["mail_to"], quello registrato al
        # setup.
        log.warning("mail_to fornito diverso da quello registrato al setup (ignorato)",
                    extra={"login": login, "mail_to_richiesto": mail_to,
                           "mail_to_registrato": active["mail_to"]})

    new_counter = int(active["counter"]) + 1
    otp_code = otp_service.hotp_code(active["secret"], new_counter)

    expires_at = datetime.now() + timedelta(seconds=int(template["timeout_seconds"]))
    sent = otp_service.send_otp_mail(template, login, active["mail_to"], otp_code, expires_at)
    if not sent:
        return {"message": "Il server di posta e' down", "code": "300", "elapsed_time": _elapsed(t0)}, 412

    if not _update_method_counter(cfg, active["id"], new_counter):
        return {"message": "Errore durante l'aggiornamento del contatore OTP",
                "code": "500", "elapsed_time": _elapsed(t0)}, 500

    request_row_id = _insert_otp_request(
        cfg, active["id"], login, "login", new_counter, expires_at,
        client_request_id, getattr(g, "service_account", None), otp_code,
    )

    return {
        "message": "codice OTP generato",
        "code": "000",
        "response_id": request_row_id,
        "elapsed_time": _elapsed(t0),
    }, 200


# ============================================================
# 4. VERIFY — verifica il codice al login (app o mail)
# ============================================================

def _check_otp_code(cfg, login, active, code, request_id, client_request_id, action="verifica"):
    """
    Verifica code contro il metodo attivo active (app: TOTP stateless;
    mail: HOTP legato a una richiesta history.otp_requests specifica via
    request_id). Condivisa tra /otp/verify e /otp/disable (force=false)
    — stessa identica prova di possesso del metodo, solo lo scopo finale
    cambia (login vs autorizzare una disattivazione).

    Ritorna (True, None) se valido, (False, (result_dict_senza_elapsed, http_status))
    altrimenti — il chiamante aggiunge "elapsed_time" e restituisce.
    `action` e' solo per i messaggi di log diagnostici (es. "verifica"/"disattivazione").
    """
    if active["method"] == "app":
        if request_id is not None:
            # Campo superfluo per questo metodo (il TOTP e' stateless, non serve
            # nessun riferimento a una richiesta) — non blocca, ma e' un segnale
            # che il chiamante potrebbe presumere erroneamente method='mail'.
            log.warning(f"request_id fornito per una {action} 'app' (ignorato): "
                        "il chiamante potrebbe presumere method='mail' per questa login",
                        extra={"login": login, "request_id": request_id})
        valid_window = cfg.get("otp2fa", {}).get("totp_valid_window", 1)
        valid, step = otp_service.verify_totp_with_step(active["secret"], code, valid_window=valid_window)

        # Anti-replay: TOTP e' altrimenti stateless, un codice valido resta
        # riutilizzabile per l'intera finestra di tolleranza senza questo
        # controllo. A differenza di una versione precedente (che confrontava
        # in Python lo step con active["last_totp_step"] letto in anticipo da
        # _get_active_method() — vulnerabile a una race condition fra due
        # richieste concorrenti con lo stesso step, entrambe lette PRIMA che
        # una delle due scrivesse), qui la decisione e' presa dalla scrittura
        # stessa: _update_totp_step() esegue un UPDATE condizionale e
        # atomico (compare-and-swap lato DB, "RETURNING id") — l'accettazione
        # o il rifiuto dipendono dallo stato della riga nell'istante esatto
        # della scrittura, non da un valore letto separatamente in anticipo.
        replay = False
        if valid:
            accepted = _update_totp_step(cfg, active["id"], step)
            if not accepted:
                replay = True
                valid = False
                log.warning("Replay TOTP rilevato: step gia' usato (o consumato da una richiesta concorrente)",
                            extra={"login": login, "config_id": active["id"], "step": step})

        # Log del tentativo (purpose='verify') — a differenza del ramo mail
        # sotto, qui non esiste una riga precedente da aggiornare: ne creiamo
        # una nuova, gia' con lo stato finale (vedi _insert_otp_verify_log()).
        _insert_otp_verify_log(cfg, active["id"], login, client_request_id,
                                getattr(g, "service_account", None), code, valid)

        if replay:
            return False, ({"message": "Codice gia' utilizzato", "code": "240"}, 409)
        if valid:
            return True, None
        return False, ({"message": "Codice OTP errato", "code": "020"}, 401)

    # method == "mail": serve il riferimento alla richiesta specifica
    if request_id is None:
        log.warning(f"{action.capitalize()} 'mail' senza request_id: il chiamante potrebbe presumere "
                    "method='app' per questa login", extra={"login": login})
        return False, ({"message": "Il metodo attivo per questo utente e' 'mail': indicare request_id "
                                    "(restituito da /otp/sendmailotp)", "code": "200"}, 400)

    req_row = _get_request_by_id(cfg, request_id, active["id"], login)
    if req_row is None:
        return False, ({"message": "Richiesta OTP non trovata", "code": "210"}, 404)

    if req_row["status"] != "pending":
        return False, ({"message": "Codice gia' utilizzato o non piu' valido", "code": "240"}, 409)

    if int(req_row["not_expired"]) == 0:
        _update_request_status(cfg, req_row["id"], "expired")
        return False, ({"message": "Codice OTP scaduto", "code": "010"}, 401)

    valid = otp_service.verify_hotp(active["secret"], code, int(req_row["counter_used"]))
    _update_request_status(cfg, req_row["id"], "verified" if valid else "failed")
    if valid:
        return True, None
    return False, ({"message": "Codice OTP errato", "code": "020"}, 401)


def handle_otp_verify(cfg: dict, login: str, code: str, request_id: int | None,
                       client_request_id: str | None = None) -> tuple[dict, int]:
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Verifica codice OTP richiesta", extra={"login": login, "client_request_id": client_request_id})

    active = _get_active_method(cfg, login)
    if active is None:
        return {"message": "Nessun metodo 2FA attivo per questo utente",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    valid, err = _check_otp_code(cfg, login, active, code, request_id, client_request_id, action="verifica")
    if not valid:
        result, http_status = err
        return {**result, "elapsed_time": _elapsed(t0)}, http_status

    return {"message": "Codice OTP valido", "code": "000", "elapsed_time": _elapsed(t0)}, 200


# ============================================================
# 5. STATUS — stato 2FA di una login (qualunque status, non solo attivo)
# ============================================================

def handle_otp_status(cfg: dict, login: str, client_request_id: str | None = None) -> tuple[dict, int]:
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    log.info("Stato 2FA richiesto", extra={"login": login, "client_request_id": client_request_id})

    row = _get_login_status(cfg, login)
    if row is None:
        return {"login": login, "status": "none", "method": None, "elapsed_time": _elapsed(t0)}, 200

    return {"login": login, "status": row["status"], "method": row["method"],
            "elapsed_time": _elapsed(t0)}, 200


# ============================================================
# 6. DISABLE — disattiva il metodo attivo (con OTP, o in force senza)
# ============================================================

def handle_otp_disable(cfg: dict, login: str, requested_by_login: str | None, force: bool,
                        code: str, request_id: int | None,
                        client_request_id: str | None = None) -> tuple[dict, int]:
    """
    requested_by_login e' obbligatorio solo se force=true (validato gia' a
    livello di modello, OtpDisableRequest) — se force=false arriva sempre
    None qui: il richiedente e' per costruzione il target stesso, quindi lo
    normalizziamo su 'login' PRIMA di loggare/persistere, cosi' l'audit
    (public.otp_methods.requested_by_login) e' sempre valorizzato in modo
    significativo, mai NULL.
    """
    t0 = time.perf_counter()
    client_request_id = client_request_id or getattr(g, "request_id", None) or "none"
    audit_requested_by = requested_by_login if force else login
    log.info("Disattivazione 2FA richiesta",
             extra={"login": login, "requested_by_login": audit_requested_by, "force": force,
                    "client_request_id": client_request_id})

    target_active = _get_active_method(cfg, login)
    if target_active is None:
        return {"message": "Nessun metodo 2FA attivo per questo utente",
                "code": "210", "elapsed_time": _elapsed(t0)}, 404

    # L'OTP e' sempre obbligatorio. force=False: si verifica sul target (login) —
    # stessa identita' che viene disattivata. force=True: si verifica invece su chi
    # ha richiesto la disattivazione (requested_by_login) — un operatore prova la
    # propria identita' con il proprio 2FA quando il target ha perso l'accesso al
    # proprio (niente piu' bypass senza OTP).
    if not force:
        verify_login, verify_active = login, target_active
    else:
        verify_login = requested_by_login
        verify_active = _get_active_method(cfg, requested_by_login)
        if verify_active is None:
            return {"message": f"Nessun metodo 2FA attivo per requested_by_login ({requested_by_login})",
                    "code": "210", "elapsed_time": _elapsed(t0)}, 404

    valid, err = _check_otp_code(cfg, verify_login, verify_active, code, request_id, client_request_id, action="disattivazione")
    if not valid:
        result, http_status = err
        return {**result, "elapsed_time": _elapsed(t0)}, http_status

    if not _disable_method(cfg, login, audit_requested_by, force):
        return {"message": "Errore durante la disattivazione del metodo 2FA",
                "code": "500", "elapsed_time": _elapsed(t0)}, 500

    return {"message": "Metodo 2FA disattivato", "code": "000", "elapsed_time": _elapsed(t0)}, 200
