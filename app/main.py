# ============================================================
#  app/main.py
#  Factory create_app() — crea l'istanza Flask configurata.
#
#  MVC:
#    Model      → app/models/       (Pydantic)
#    View       → Swagger UI        (flask-openapi3)
#    Controller → app/controllers/  (business logic)
#    Service    → app/services/     (SOAP, DB)
# ============================================================

import logging

from flask import jsonify
#from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address
from flask_openapi3 import Info, OpenAPI, Tag
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import load_config
from app.controllers.health_controller import handle_health
from app.controllers.otp_controller import (
    handle_otp_confirm,
    handle_otp_disable,
    handle_otp_requestotp,
    handle_otp_sendmailotp,
    handle_otp_setup,
    handle_otp_status,
    handle_otp_verify,
)
from app.controllers.credential_verify_controller import handle_credential_verify
from app.controllers.credential_verify_portale_controller import handle_credential_verify_portale
from app.middleware import register_middleware
from app.models.common_model import ApplicationHeader
from app.models.health_model import HealthQuery, HealthResponse
from app.models.otp_model import (
    OtpConfirmRequest,
    OtpConfirmResponse,
    OtpDisableResponse,
    OtpRequestOtpResponse,
    OtpSendMailResponse,
    OtpSetupResponse,
    OtpStatusResponse,
    OtpVerifyResponse,
    build_otp_models,
)
from app.models.credential_verify_model import build_credential_verify_models
from app.models.credential_verify_portale_model import build_credential_verify_portale_models
from app.utils.basic_auth import require_service_account
from app.utils.db_pool import init_pools
from app.utils.logger import setup_logging

log = logging.getLogger("authapi.main")


def create_app(config_path: str = None) -> OpenAPI:
    """Factory: crea e restituisce l'app Flask configurata."""

    cfg = load_config(config_path)
    setup_logging(cfg)
    init_pools(cfg)   # init pool PostgreSQL

    if cfg.get("otp2fa", {}).get("debug_code", 0) == 2:
        log.warning(
            "otp2fa.debug_code=2: i codici OTP verranno salvati IN CHIARO in "
            "history.otp_requests.code — non lasciarlo attivo in produzione"
        )

    if cfg.get("otp2fa", {}).get("save_qr_to_disk", False):
        log.warning(
            "otp2fa.save_qr_to_disk=true: i QR OTP (secret TOTP in chiaro) "
            "verranno salvati su disco in logging.dir/last_otp_qr.png — "
            "non lasciarlo attivo in produzione o in un ambiente condiviso"
        )

    release     = cfg["version"]["release"]
    patch       = cfg["version"]["patch"]
    build       = cfg["version"]["build"]
    version_str = f"{release}.{patch}.{build}"

    info = Info(
        title       = "Auth API — Autenticazione & 2FA",
        version     = version_str,
        description = (
            "Autenticazione SOAP (con fallback su cache locale) e 2FA (TOTP app / HOTP mail).<br>"
            f"<b>Release:</b> {release} | <b>Patch:</b> {patch} | <b>Build:</b> {build}"
        ),
    )
    app = OpenAPI(__name__, info=info)
    app.config["CFG"] = cfg

    # Il servizio gira dietro nginx (vedi api.conf, root del progetto) — senza
    # ProxyFix, Werkzeug costruisce qualunque URL assoluto (in particolare il
    # redirect 308 automatico "/openapi" → "/openapi/" generato da
    # flask-openapi3, che registra la Swagger UI con url_prefix="/openapi" +
    # rule="/") usando solo scheme/host/porta della connessione TCP interna
    # container↔nginx — mai quelli reali visti dal client. Risultato senza
    # questo fix: redirect verso "http://<host>/openapi/" senza porta, quindi
    # porta 80 implicita, indipendentemente da schema/porta esterni reali.
    # x_proto/x_host/x_port dicono a Werkzeug di fidarsi rispettivamente di
    # X-Forwarded-Proto/X-Forwarded-Host/X-Forwarded-Port — nginx deve
    # impostarli (vedi api.conf, tutti i blocchi location) altrimenti questo
    # middleware non ha nulla da leggere e non cambia comportamento.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)

    rl_cfg  = cfg.get("rate_limit", {})
    #limiter = Limiter(
    #    key_func       = get_remote_address,
    #    app            = app,
    #    storage_uri    = rl_cfg.get("storage_uri", "memory://"),
    #    default_limits = [],
    #)

    register_middleware(app)

    CredentialVerifyPortaleRequest, CredentialVerifyPortaleResponse = build_credential_verify_portale_models(cfg)
    CredentialVerifyRequest, CredentialVerifyResponse     = build_credential_verify_models(cfg)
    (OtpSetupRequest, OtpSendMailRequest, OtpRequestOtpRequest,
     OtpVerifyRequest, OtpStatusQuery, OtpDisableRequest) = build_otp_models(cfg)

    # Schema condiviso per le risposte 422 (errori di validazione Pydantic:
    # array di oggetti {type, loc, msg, input, ctx, url}).
    _validation_error_schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "type":  {"type": "string"},
                "loc":   {"type": "array", "items": {"type": "string"}},
                "msg":   {"type": "string"},
                "input": {},
                "ctx":   {"type": "object"},
                "url":   {"type": "string"},
            },
        },
    }
    # Schema condiviso per le risposte 429 (rate_limit_exceeded).
    _rate_limit_schema = {
        "type": "object",
        "properties": {
            "code":        {"type": "string", "examples": ["429"]},
            "description": {"type": "string", "examples": ["Troppi tentativi. Riprovare più tardi."]},
        },
    }
    # Schema condiviso per le risposte 401 degli endpoint /otp/* (Basic Auth
    # applicativa mancante/non valida — vedi app/utils/basic_auth.py).
    _otp_unauthorized_schema = {
        "type": "object",
        "properties": {
            "code":        {"type": "string", "examples": ["401"]},
            "description": {"type": "string", "examples": ["Applicativo non autorizzato."]},
        },
    }

    tag_auth   = Tag(name="Autenticazione", description="Verifica password Portale — rate limited")
    tag_health = Tag(name="Health",         description="Monitoraggio PostgreSQL")
    tag_otp    = Tag(name="2FA", description="Autenticazione a due fattori (TOTP app / HOTP mail) — Basic Auth applicativa")

    base   = cfg["api"]["base_path"]
    prefix = f"{base}/{release}"
    credential_verify_portale_limit = rl_cfg.get("credential_verify_portale_limit", "10 per minute")
    credential_verify_limit   = rl_cfg.get("credential_verify_limit",   "10 per minute")

    @app.post(f"{prefix}/credential/verify-portale", tags=[tag_auth],
              summary="Autenticazione SOAP (rate limited, Basic Auth applicativa)",
              responses={
                  200: {"description": "Risposta auth",
                        "content": {"application/json": {"schema": CredentialVerifyPortaleResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato",
                        "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
                  429: {"description": "Rate limit superato",
                        "content": {"application/json": {"schema": _rate_limit_schema}}},
              })
    #@limiter.limit(credential_verify_portale_limit)
    @require_service_account(cfg)
    def credential_verify_portale(body: CredentialVerifyPortaleRequest, header: ApplicationHeader):
        """
        Autentica tramite SOAP. Richiede HTTP Basic Auth applicativa (stesso
        meccanismo di `/otp/*`, `public.service_accounts`) — identifica
        l'applicativo chiamante, non l'utente reale (campo `login` nel body).

        - **login**: formato configurato in config.yaml (credential_verify_portale.login_pattern)
        - **password**: formato configurato in config.yaml (credential_verify_portale.password_pattern) —
          default: almeno una lettera, almeno un carattere speciale, lunghezza minima 8
        - **client_request_id** (opzionale): id di correlazione lato client — se assente
          si usa il nostro `X-Request-Id`. Ogni richiesta viene comunque registrata in
          `history.auth_credential_log` (`service="verify-portale"`), incluso
          l'applicativo chiamante autenticato via Basic Auth (colonna `client`, per
          audit — non l'utente reale, quello è `login`); scrittura fail-open, un
          errore DB non blocca la risposta
        - Risposta: `{"code": "000|500|501|200|300|503", "auth_validation": "soap", "description": "...", "elapsed_time": ...}`
          (`auth_validation` è sempre `"soap"` — unico meccanismo di questo endpoint, indipendente da `code`)
        """
        result, code = handle_credential_verify_portale(cfg, body.login, body.password, body.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/credential/verify", tags=[tag_auth],
              summary="Autenticazione con fallback su cache locale (rate limited, Basic Auth applicativa)",
              responses={
                  200: {"description": "Risposta auth",
                        "content": {"application/json": {"schema": CredentialVerifyResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato",
                        "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
                  429: {"description": "Rate limit superato",
                        "content": {"application/json": {"schema": _rate_limit_schema}}},
              })
    #@limiter.limit(credential_verify_limit)
    @require_service_account(cfg)
    def credential_verify(body: CredentialVerifyRequest, header: ApplicationHeader):
        """
        Autentica tramite SOAP; se il servizio esterno non riesce a dare una risposta
        definitiva, tenta un fallback su cache locale. Richiede HTTP Basic Auth
        applicativa (stesso meccanismo di `/otp/*`, `public.service_accounts`).

        - **login**: formato configurato in config.yaml (credential_verify.login_pattern)
        - **password**: formato configurato in config.yaml (credential_verify.password_pattern) —
          default: almeno una lettera, almeno un carattere speciale, lunghezza minima 8
        - **prov** (opzionale, default `"--"` se assente): provincia dell'ufficio in cui è in
          servizio l'utente, formato configurato in config.yaml (credential_verify.prov_pattern —
          il pattern si applica solo se il campo viene fornito, non al default). Usata per calcolare
          `expires_at` nel fallback su cache locale (query `select.checkcache`, funzione PostgreSQL
          `next_working_day()`): la cache di login resta valida per **N giorni lavorativi**
          (N configurabile lato funzione DB, non in questa applicazione) dopo l'ultima
          autenticazione riuscita presso il servizio esterno.
        - Risposta: `{"code": "...", "auth_type": "soap", "description": "...", "elapsed_time": ...}`
        - **client_request_id** (opzionale): id di correlazione lato client — se assente
          si usa il nostro `X-Request-Id`. Salvato nella cache di login solo su
          validazione riuscita (code=000); registrato invece in
          `history.auth_credential_log` per **ogni** richiesta, insieme all'applicativo
          chiamante autenticato via Basic Auth (colonna `client`, per audit — non
          l'utente reale, quello è `login`)

        <h4>Backend <code>auth_type</code> supportati</h4>
        <table><thead><tr><th>auth_type</th><th>Stato</th></tr></thead><tbody><tr><td><code>soap</code></td><td>Implementato — unico backend realmente attivo oggi</td></tr><tr><td><code>ldap</code> &#42;</td><td>Non ancora sviluppato</td></tr><tr><td><code>db</code> &#42;</td><td>Non ancora sviluppato</td></tr></tbody></table>
        <p>&#42; = backend riservato (placeholder in config.yaml, sezione credential_verify), non ancora implementato.</p>

        <h4>Tabella <code>code</code> / <code>description</code> / <code>origine</code></h4>
        <p>Se il SOAP esterno non riesce a dare una risposta definitiva (TCP down, errore HTTP non gestito, eccezione), viene tentato un fallback su cache locale prima di rispondere al client — da cui i <code>code</code> composti <code>&lt;origine&gt;&lt;1-4&gt;</code> (concatenazione stringa, non somma). <code>auth_type</code> nella colonna origine è il valore effettivo del campo <code>auth_type</code> della risposta (es. <code>soap</code>).</p>
        <table><thead><tr><th>code</th><th>description</th><th>origine</th></tr></thead><tbody><tr><td><code>000</code></td><td>Messaggio reale del SOAP (es. "Accesso autorizzato.") o, se validato da cache, "Accesso autorizzato (validato da cache locale)."</td><td><code>auth_type</code></td></tr><tr><td><code>500</code></td><td>Messaggio di rifiuto reale del SOAP — login/matricola non valida</td><td><code>auth_type</code></td></tr><tr><td><code>501</code></td><td>Messaggio di rifiuto reale del SOAP — credenziali non valide (password errata)</td><td><code>auth_type</code></td></tr><tr><td><code>1001</code></td><td>"Servizio non disponibile e nessuna sessione precedente trovata per l'utente."</td><td><code>auth_type</code> TCP down</td></tr><tr><td><code>1002</code></td><td>"Servizio non disponibile, credenziali non verificabili."</td><td><code>auth_type</code> TCP down</td></tr><tr><td><code>1003</code></td><td>"Servizio non disponibile, sessione precedente non verificabile."</td><td><code>auth_type</code> TCP down</td></tr><tr><td><code>1004</code></td><td>"Servizio non disponibile e sessione precedente scaduta."</td><td><code>auth_type</code> TCP down</td></tr><tr><td><code>3001</code></td><td>"Servizio in errore e nessuna sessione precedente trovata per l'utente."</td><td><code>auth_type</code> code=300</td></tr><tr><td><code>3002</code></td><td>"Servizio in errore, credenziali non verificabili."</td><td><code>auth_type</code> code=300</td></tr><tr><td><code>3003</code></td><td>"Servizio in errore, sessione precedente non verificabile."</td><td><code>auth_type</code> code=300</td></tr><tr><td><code>3004</code></td><td>"Servizio in errore e sessione precedente scaduta."</td><td><code>auth_type</code> code=300</td></tr><tr><td><code>2001</code></td><td>"Errore del servizio e nessuna sessione precedente trovata per l'utente."</td><td><code>auth_type</code> code=200</td></tr><tr><td><code>2002</code></td><td>"Errore del servizio, credenziali non verificabili."</td><td><code>auth_type</code> code=200</td></tr><tr><td><code>2003</code></td><td>"Errore del servizio, sessione precedente non verificabile."</td><td><code>auth_type</code> code=200</td></tr><tr><td><code>2004</code></td><td>"Errore del servizio e sessione precedente scaduta."</td><td><code>auth_type</code> code=200</td></tr><tr><td><code>5031</code></td><td>"Esito del servizio non riconosciuto e nessuna sessione precedente trovata per l'utente."</td><td><code>auth_type</code> code=503</td></tr><tr><td><code>5032</code></td><td>"Esito del servizio non riconosciuto, credenziali non verificabili."</td><td><code>auth_type</code> code=503</td></tr><tr><td><code>5033</code></td><td>"Esito del servizio non riconosciuto, sessione precedente non verificabile."</td><td><code>auth_type</code> code=503</td></tr><tr><td><code>5034</code></td><td>"Esito del servizio non riconosciuto e sessione precedente scaduta."</td><td><code>auth_type</code> code=503</td></tr></tbody></table>
        <p>Il suffisso numerico (1-4) indica il motivo del diniego del fallback su cache: 1=nessuna riga di cache trovata, 2=hash password non corrispondente, 3=scadenza cache non calcolabile, 4=cache scaduta.</p>
        """
        result, code = handle_credential_verify(cfg, body.login, body.password, body.prov, body.client_request_id)
        return jsonify(result), code

    @app.get(f"{prefix}/health", tags=[tag_health],
             summary="Health check approfondito PostgreSQL + SOAP esterno",
             responses={
                 200: {"description": "UP",
                       "content": {"application/json": {"schema": HealthResponse.model_json_schema()}}},
                 207: {"description": "DEGRADED",
                       "content": {"application/json": {"schema": HealthResponse.model_json_schema()}}},
                 503: {"description": "DOWN",
                       "content": {"application/json": {"schema": HealthResponse.model_json_schema()}}},
             })
    def health(query: HealthQuery):
        """
        Verifica PostgreSQL (ping, pg_stat_database, pg_stat_activity) e la
        raggiungibilità del servizio SOAP esterno.

        - **debug=false** (default): verifica solo che il servizio SOAP sia
          in ascolto (connessione TCP, nessuna richiesta inviata)
        - **debug=true**: esegue una vera richiesta di login SOAP con login
          configurabile (health.soap_check_login) e password fittizia —
          richiesta reale al servizio di terzi

        HTTP 200=UP | 207=DEGRADED | 503=DOWN
        """
        result, code = handle_health(cfg, debug=query.debug)
        return jsonify(result), code

    # ------------------------------------------------------------------
    # 2FA (TOTP app / HOTP mail) — Basic Auth applicativa (service account,
    # public.service_accounts), non l'utente reale (campo 'login' nel body).
    # Nessun rate limiting per ora (punto aperto, come da documento di
    # riferimento — vedi CLAUDE.md).
    # ------------------------------------------------------------------

    @app.post(f"{prefix}/otp/setup", tags=[tag_otp],
              summary="Registra un metodo 2FA per un utente (app o mail)",
              responses={
                  200: {"description": "Esito setup",
                        "content": {"application/json": {"schema": OtpSetupResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato",
                        "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                  404: {"description": "Template non trovato",
                        "content": {"application/json": {"schema": OtpSetupResponse.model_json_schema()}}},
                  409: {"description": "Esiste gia' un metodo 2FA attivo per questo utente",
                        "content": {"application/json": {"schema": OtpSetupResponse.model_json_schema()}}},
                  412: {"description": "Server di posta non raggiungibile",
                        "content": {"application/json": {"schema": OtpSetupResponse.model_json_schema()}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
              })
    @require_service_account(cfg)
    def otp_setup(body: OtpSetupRequest, header: ApplicationHeader):
        """
        Registra un metodo 2FA per **login** (matricola dell'utente reale,
        non l'applicativo autenticato via Basic Auth).

        - **method=app**: genera secret + QR code (base64), stato `pending`
          — va confermato con `POST /otp/setup/confirm`.
        - **method=mail**: richiede `template_id` e `mail_to`. Si attiva
          subito (`otp2fa.require_mail_confirmation=false`, default) oppure
          invia un primo codice da confermare (`true`).
        - Rifiutato (`code:225`, `409`) se esiste gia' un metodo attivo per
          questa login: disattivarlo prima con `POST /otp/disable`.
        """
        result, code = handle_otp_setup(cfg, body.login, body.method, body.template_id, body.mail_to,
                                         body.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/otp/setup/confirm", tags=[tag_otp],
             summary="Conferma il setup 2FA (metodo app, o mail se richiesta conferma)",
             responses={
                 200: {"description": "Metodo attivato",
                       "content": {"application/json": {"schema": OtpConfirmResponse.model_json_schema()}}},
                 401: {"description": "Applicativo non autorizzato, o codice di conferma errato/scaduto (solo method='mail')",
                       "content": {"application/json": {"schema": OtpConfirmResponse.model_json_schema()}}},
                 404: {"description": "Configurazione non trovata",
                       "content": {"application/json": {"schema": OtpConfirmResponse.model_json_schema()}}},
                 409: {"description": "Configurazione gia' confermata, o codice gia' utilizzato/non piu' valido (solo method='mail')",
                       "content": {"application/json": {"schema": OtpConfirmResponse.model_json_schema()}}},
                 422: {"description": "Input non valido",
                       "content": {"application/json": {"schema": _validation_error_schema}}},
             })
    @require_service_account(cfg)
    def otp_setup_confirm(body: OtpConfirmRequest, header: ApplicationHeader):
        """
        Verifica il primo codice (`config_id` restituito da `/otp/setup`) e
        attiva il metodo. Per `method='mail'`, applica anche il controllo di
        scadenza/stato del codice inviato (stesso meccanismo di `/otp/verify`
        per il flusso mail-login): un codice scaduto (`code:"010"`) o gia'
        utilizzato (`code:"240"`) viene rifiutato prima ancora di verificarlo.
        """
        result, code = handle_otp_confirm(cfg, body.config_id, body.code, body.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/otp/sendmailotp", tags=[tag_otp],
              summary="Richiede un nuovo codice via mail (solo metodo mail attivo)",
              responses={
                  200: {"description": "Codice inviato",
                        "content": {"application/json": {"schema": OtpSendMailResponse.model_json_schema()}}},
                  400: {"description": "Il metodo attivo e' 'app'",
                        "content": {"application/json": {"schema": OtpSendMailResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato",
                        "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                  404: {"description": "Nessun metodo attivo per la login",
                        "content": {"application/json": {"schema": OtpSendMailResponse.model_json_schema()}}},
                  412: {"description": "Server di posta non raggiungibile",
                        "content": {"application/json": {"schema": OtpSendMailResponse.model_json_schema()}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
              })
    @require_service_account(cfg)
    def otp_sendmailotp(body: OtpSendMailRequest, header: ApplicationHeader):
        """
        Invia un nuovo codice HOTP via mail per `login` (deve avere un metodo
        `mail` attivo). `template_id` e' obbligatorio ad ogni chiamata: il
        messaggio inviato puo' variare da un OTP all'altro, non e' fissato
        una volta per tutte al setup.
        """
        result, code = handle_otp_sendmailotp(cfg, body.login, body.template_id, body.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/otp/requestotp", tags=[tag_otp],
              summary="Setup+invio in un'unica chiamata (retrocompatibilita' legacy)",
              responses={
                  200: {"description": "Codice generato (anche se il metodo attivo e' 'app', vedi descrizione)",
                        "content": {"application/json": {"schema": OtpRequestOtpResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato",
                        "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                  404: {"description": "Template non trovato",
                        "content": {"application/json": {"schema": OtpRequestOtpResponse.model_json_schema()}}},
                  412: {"description": "Server di posta non raggiungibile",
                        "content": {"application/json": {"schema": OtpRequestOtpResponse.model_json_schema()}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
              })
    @require_service_account(cfg)
    def otp_requestotp(body: OtpRequestOtpRequest, header: ApplicationHeader):
        """
        Endpoint di retrocompatibilita' per sistemi legacy che non conoscono
        ancora il flusso separato `/otp/setup` + `/otp/sendmailotp`: una sola
        chiamata che copre entrambi. Rinominato da `/otp/sendotp` in una
        sessione successiva; usa `template_id` (non piu' `template_name`)
        come tutti gli altri endpoint `/otp/*`.

        - **Nessun metodo attivo** per `login` (assente, o presente ma con
          `status` `pending`/`disabled` — trattati come assenti): crea un
          metodo `mail` gia' attivo (stesso comportamento del ramo
          `require_mail_confirmation=false` di `/otp/setup`) e invia subito
          un codice, come farebbe `/otp/sendmailotp`.
        - **Metodo `mail` gia' attivo**: si comporta come `/otp/sendmailotp`
          (nuovo codice, counter incrementato). L'eventuale `mail_to` nella
          richiesta viene ignorato in questo caso — resta quello registrato
          al setup, non aggiornabile da qui.
        - **Metodo `app` gia' attivo**: a differenza di `/otp/sendmailotp`
          (che risponderebbe `code:"230"`), qui la risposta e' comunque
          `code:"000"` con `response_id:null` — nessun invio mail reale
          possibile per TOTP, ma il chiamante legacy si aspetta sempre un
          esito "codice generato".

        Risposta con contratto fisso e diverso dagli altri endpoint `/otp/*`:
        `response_id` invece di `request_id`, niente `config_id`.
        """
        result, code = handle_otp_requestotp(cfg, body.login, body.template_id, body.mail_to,
                                              body.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/otp/verify", tags=[tag_otp],
              summary="Verifica il codice OTP al login (app o mail)",
              responses={
                  200: {"description": "Codice valido",
                        "content": {"application/json": {"schema": OtpVerifyResponse.model_json_schema()}}},
                  400: {"description": "request_id mancante per method='mail'",
                        "content": {"application/json": {"schema": OtpVerifyResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato o codice OTP errato/scaduto",
                        "content": {"application/json": {"schema": OtpVerifyResponse.model_json_schema()}}},
                  404: {"description": "Nessun metodo attivo o richiesta OTP non trovata",
                        "content": {"application/json": {"schema": OtpVerifyResponse.model_json_schema()}}},
                  409: {"description": "Codice gia' utilizzato o non piu' valido",
                        "content": {"application/json": {"schema": OtpVerifyResponse.model_json_schema()}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
              })
    @require_service_account(cfg)
    def otp_verify(body: OtpVerifyRequest, header: ApplicationHeader):
        """
        Verifica il codice OTP per `login`. `request_id` (restituito da
        `/otp/sendmailotp`) e' obbligatorio solo per il metodo `mail`.

        Anti-replay: per `method='app'`, un codice TOTP gia' accettato in
        precedenza (stesso timestep) viene rifiutato (`code:"240"`) anche se
        matematicamente ancora valido per la finestra di tolleranza — non e'
        riutilizzabile piu' di una volta, come il codice mail.
        """
        result, code = handle_otp_verify(cfg, body.login, body.code, body.request_id, body.client_request_id)
        return jsonify(result), code

    @app.get(f"{prefix}/otp/status", tags=[tag_otp],
             summary="Stato 2FA di una login (solo status dell'ultima configurazione, non il metodo)",
             responses={
                 200: {"description": "Stato recuperato (anche 'none' se mai configurato)",
                       "content": {"application/json": {"schema": OtpStatusResponse.model_json_schema()}}},
                 401: {"description": "Applicativo non autorizzato",
                       "content": {"application/json": {"schema": _otp_unauthorized_schema}}},
                 422: {"description": "Input non valido",
                       "content": {"application/json": {"schema": _validation_error_schema}}},
             })
    @require_service_account(cfg)
    def otp_status(query: OtpStatusQuery, header: ApplicationHeader):
        """
        Stato dell'**ultima** configurazione 2FA per `login`, qualunque sia
        il suo `status` (`pending`/`active`/`disabled`) — non solo quella
        attiva. `status="none"` se non e' mai stato registrato nessun
        metodo. Non espone volutamente **quale** metodo (`app`/`mail`) sia
        configurato — informazione di ricognizione non necessaria al
        chiamante.
        """
        result, code = handle_otp_status(cfg, query.login, query.client_request_id)
        return jsonify(result), code

    @app.post(f"{prefix}/otp/disable", tags=[tag_otp],
              summary="Disattiva il metodo 2FA attivo di un utente (OTP sempre richiesto)",
              responses={
                  200: {"description": "Metodo disattivato",
                        "content": {"application/json": {"schema": OtpDisableResponse.model_json_schema()}}},
                  400: {"description": "request_id mancante per method='mail'",
                        "content": {"application/json": {"schema": OtpDisableResponse.model_json_schema()}}},
                  401: {"description": "Applicativo non autorizzato o codice OTP errato/scaduto",
                        "content": {"application/json": {"schema": OtpDisableResponse.model_json_schema()}}},
                  404: {"description": "Nessun metodo attivo (sul target o sul richiedente) o richiesta OTP non trovata",
                        "content": {"application/json": {"schema": OtpDisableResponse.model_json_schema()}}},
                  409: {"description": "Codice gia' utilizzato o non piu' valido",
                        "content": {"application/json": {"schema": OtpDisableResponse.model_json_schema()}}},
                  422: {"description": "Input non valido",
                        "content": {"application/json": {"schema": _validation_error_schema}}},
              })
    @require_service_account(cfg)
    def otp_disable(body: OtpDisableRequest, header: ApplicationHeader):
        """
        Disattiva il metodo 2FA attivo di `login`. L'OTP e' **sempre** richiesto:

        - **force=false** (default): l'OTP (`code` + `request_id` se il
          metodo attivo e' `mail`) viene verificato su `login` — l'utente
          disattiva il proprio 2FA.
        - **force=true**: l'OTP viene verificato su `requested_by_login`
          invece che su `login` — un operatore/helpdesk prova la propria
          identita' con il *proprio* 2FA quando il target ha perso l'accesso
          al proprio. Nessun bypass senza OTP in nessun caso.
        - **requested_by_login**: sempre obbligatorio, indipendentemente da
          `force` — chi ha richiesto la disattivazione (persistito su
          `public.otp_methods.requested_by_login`; puo' coincidere con
          `login` se e' l'utente stesso).
        """
        result, code = handle_otp_disable(cfg, body.login, body.requested_by_login, body.force,
                                           body.code, body.request_id, body.client_request_id)
        return jsonify(result), code

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        log.warning("Rate limit superato", extra={"remote": ""})
        return jsonify({"code": "429", "description": "Troppi tentativi. Riprovare più tardi."}), 429

    log.info("Auth API avviata",
             extra={"version_info":  version_str,
                    "prefix":        prefix,
                    "swagger_ui":    "/openapi",
                    "credential_verify_portale_limit": credential_verify_portale_limit,
                    "soap_endpoint": cfg["soap"]["endpoint_url"],
                    "pg_host":       cfg["postgres"]["host"]})
    return app
