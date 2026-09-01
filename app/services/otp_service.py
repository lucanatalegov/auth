# ============================================================
#  app/services/otp_service.py
#  Service 2FA: TOTP (app authenticator) + HOTP (mail), invio email,
#  autenticazione degli applicativi chiamanti (service account).
#
#  SICUREZZA:
#    - Il secret pyotp non viene mai loggato.
#    - La password del service account non viene mai loggata; la verifica
#      avviene lato PostgreSQL con crypt() (estensione pgcrypto) — l'hash
#      (bcrypt, salted) non lascia mai il DB, e un cambio password si fa
#      con un semplice UPDATE SQL (vedi sql/otp_2fa_schema.sql), senza
#      toccare codice Python.
# ============================================================

import base64
import io
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pyotp
import qrcode

from app.services.soap_service import check_tcp_listening
from app.utils.db_pool import get_pg_connection, release_pg_connection
from app.utils.logger import _resolve_log_dir

log = logging.getLogger("authapi.service.otp")


# ------------------------------------------------------------------
# TOTP / HOTP / QR
# ------------------------------------------------------------------

def generate_secret() -> str:
    return pyotp.random_base32()


def generate_qr_base64(cfg: dict, login: str, secret: str, issuer_name: str) -> str:
    """
    PNG (base64, senza prefisso data:) del QR code per lo scan da app
    authenticator.

    Se otp2fa.save_qr_to_disk=true (default false), salva anche una copia su
    disco in logging.dir/last_otp_qr.png (stessa cartella dei log
    applicativi, stessa risoluzione path di logger.py::_resolve_log_dir() —
    relativo alla root del progetto o assoluto) — sovrascritta ad ogni
    chiamata, comodo per test manuali quando non si puo' visualizzare il
    base64 direttamente dalla risposta JSON (basta aprire il file con un
    qualunque visualizzatore immagini). Fail-open: un errore in scrittura
    viene loggato ma non impedisce la risposta normale (il client ha
    comunque secret/qr_code_base64 dal JSON).

    ATTENZIONE SICUREZZA: il file scritto su disco codifica lo stesso
    secret TOTP restituito nel campo "secret" della risposta — chiunque
    abbia accesso al filesystem in quella cartella (tipicamente la stessa
    dei log applicativi) puo' leggerlo e attivare un secondo authenticator
    con le stesse credenziali dell'utente. Per questo il default e' false —
    va abilitato solo per test locali, mai in un ambiente condiviso/produzione
    (create_app() emette un log.warning esplicito all'avvio se attivo,
    stesso pattern di otp2fa.debug_code=2).
    """
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=login, issuer_name=issuer_name)
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    if cfg.get("otp2fa", {}).get("save_qr_to_disk", False):
        try:
            log_dir = _resolve_log_dir(cfg["logging"]["dir"], cfg.get("_root", "."))
            os.makedirs(log_dir, exist_ok=True)
            qr_path = os.path.join(log_dir, "last_otp_qr.png")
            with open(qr_path, "wb") as f:
                f.write(png_bytes)
            log.info("QR OTP salvato su disco", extra={"login": login, "qr_path": qr_path})
        except Exception as exc:
            log.error("Errore durante il salvataggio del QR su disco",
                      extra={"login": login, "error_txt": str(exc)}, exc_info=True)

    return base64.b64encode(png_bytes).decode()


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=valid_window)


def verify_totp_with_step(secret: str, code: str, valid_window: int = 1):
    """
    Come verify_totp(), ma restituisce anche l'esatto timestep TOTP che ha
    prodotto il match — pyotp.verify() da solo non lo espone, e serve alla
    protezione anti-replay (_check_otp_code()/handle_otp_confirm() in
    otp_controller.py): TOTP e' altrimenti stateless, un codice valido resta
    riutilizzabile per l'intera finestra di tolleranza senza questo controllo.

    Ritorna (True, step) se valido, (False, None) altrimenti. step e' un
    intero comparabile (numero di step da 30s dall'epoch), da persistere in
    public.otp_methods.last_totp_step e confrontare al tentativo successivo.
    """
    totp = pyotp.TOTP(secret)
    for_time = datetime.now()
    for offset in range(-valid_window, valid_window + 1):
        if totp.at(for_time, offset) == code:
            return True, totp.timecode(for_time) + offset
    return False, None


def verify_hotp(secret: str, code: str, counter: int) -> bool:
    return pyotp.HOTP(secret).verify(code, counter)


def hotp_code(secret: str, counter: int) -> str:
    return pyotp.HOTP(secret).at(counter)


# ------------------------------------------------------------------
# Invio mail
# ------------------------------------------------------------------

def send_otp_mail(template: dict, login: str, mail_to: str, otp_code: str, expires_at) -> bool:
    """
    Invia il codice OTP via mail secondo il template indicato.

    Verifica prima la raggiungibilita' TCP del server SMTP (riuso di
    check_tcp_listening, la stessa funzione generica gia' usata dal check
    SOAP) — se il server non e' in ascolto non tenta nemmeno l'invio.

    expires_at (datetime, calcolata dal chiamante PRIMA di questa chiamata)
    e' lo stesso valore poi salvato in history.otp_requests.expires_at — un
    solo calcolo condiviso fra mail e DB, cosi' l'orario mostrato all'utente
    coincide sempre con quello effettivamente valido, anche se l'invio SMTP
    impiega qualche secondo (un now() Postgres calcolato DOPO l'invio, come
    accadeva prima di questa modifica, avrebbe potuto risultare leggermente
    diverso).

    Sostituzione placeholder nel body: semplice str.replace(), non un vero
    template engine — se un placeholder non compare nel template e' un
    no-op silenzioso, nessun errore/warning. Vale anche per {{EXPIRES_AT}}.

    Ritorna True/False; non solleva eccezioni al chiamante.
    """
    reachability = check_tcp_listening(
        template["mailserver"], int(template["portmailserver"]), label="SMTP",
    )
    if reachability["status"] != "UP":
        log.error("Server di posta non raggiungibile",
                  extra={"mailserver": template["mailserver"], "port": template["portmailserver"]})
        return False

    body = template["body"]
    body = body.replace("{{LOGIN}}", login)
    body = body.replace("{{OTP}}", otp_code)
    body = body.replace("{{TIMEOUT_MINUTES}}", str(int(int(template["timeout_seconds"]) / 60)))
    body = body.replace("{{EXPIRES_AT}}", expires_at.strftime("%d/%m/%Y %H:%M"))

    message = MIMEMultipart("alternative")
    message["Subject"] = template["subject"]
    message["From"]    = template["sender_email"]
    message["To"]      = mail_to
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(template["mailserver"], int(template["portmailserver"]), timeout=10) as server:
            server.sendmail(template["sender_email"], mail_to, message.as_string())
        log.info("Codice OTP inviato via email", extra={"login": login, "mail_to": mail_to})
        return True
    except Exception as exc:
        log.error("Errore durante l'invio dell'email OTP",
                  extra={"login": login, "mail_to": mail_to, "error_txt": str(exc)}, exc_info=True)
        return False


# ------------------------------------------------------------------
# Autenticazione applicativa (service account, HTTP Basic Auth)
# ------------------------------------------------------------------

def authenticate_service_account(cfg: dict, username: str, password: str) -> bool:
    """
    Verifica le credenziali dell'applicativo chiamante contro
    public.service_accounts. Non ha nulla a che fare con l'utente reale
    (quello arriva nel campo 'login' del body di ogni richiesta).

    La verifica avviene interamente lato PostgreSQL (operations_sql.select.
    otp_service_account, WHERE passwd_hash = crypt(%(password)s, passwd_hash))
    tramite pgcrypto: la password in chiaro passa solo nella query, mai
    salvata; l'hash salvato e' bcrypt (gen_salt('bf')).
    """
    if not username or not password:
        log.warning("Nessuna credenziale applicativa fornita")
        return False

    sql_cfg    = cfg.get("operations_sql", {})
    select_sql = sql_cfg.get("select", {}).get("otp_service_account", "")
    if not select_sql:
        log.error("operations_sql.select.otp_service_account non configurato")
        return False

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(select_sql, {"client_id": username, "password": password})
            row = cur.fetchone()

        if row is None:
            log.warning("Applicativo non valido o non attivo", extra={"client_id": username})
            # Chiude comunque la transazione della SELECT appena fatta — senza
            # questo, ogni singolo tentativo di Basic Auth fallita (il caso piu'
            # facile da riprodurre, dato che authenticate_service_account() e'
            # chiamata su OGNI richiesta a /otp/*, /credential/verify*) lasciava
            # la connessione tornare al pool ancora dentro una transazione mai
            # chiusa.
            conn.commit()
            return False

        # Aggiorna last_used_at, utile per individuare applicativi inattivi
        # da disattivare — non blocca l'autenticazione se fallisce.
        update_sql = sql_cfg.get("update", {}).get("otp_service_account_last_used", "")
        if update_sql:
            try:
                with conn.cursor() as cur:
                    cur.execute(update_sql, {"client_id": username})
                conn.commit()
            except Exception as exc:
                conn.rollback()
                log.warning("Non sono riuscito ad aggiornare last_used_at",
                            extra={"client_id": username, "error_txt": str(exc)})
        else:
            # Nessuna query di update configurata: chiude comunque la
            # transazione della SELECT precedente (stesso motivo del ramo
            # "row is None" sopra — altrimenti questo path restava scoperto).
            conn.commit()

        return True
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        log.error("Errore durante l'autenticazione dell'applicativo",
                  extra={"client_id": username, "error_txt": str(exc)}, exc_info=True)
        return False
    finally:
        release_pg_connection(conn)
