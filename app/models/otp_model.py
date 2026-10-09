# ============================================================
#  app/models/otp_model.py
#  Modelli Pydantic per gli endpoint 2FA (POST /otp/setup,
#  POST /otp/setup/confirm, POST /otp/sendmailotp, POST /otp/requestotp,
#  POST /otp/verify, GET /otp/status, POST /otp/disable).
#
#  I modelli che contengono un campo 'login' (e, per /otp/disable, anche
#  'requested_by_login') sono costruiti a runtime da build_otp_models(cfg),
#  chiamata da create_app() prima della registrazione delle route — il
#  pattern di formato e' letto da config.yaml (otp2fa.login_pattern). A
#  differenza di una sessione precedente, NON e' (piu') lo stesso pattern di
#  credential_verify_portale/credential_verify (divergenza voluta su
#  richiesta esplicita dell'utente): il formato login del solo 2FA e'
#  alfanumerico con almeno una lettera (ovunque, non solo in testa) e almeno
#  una cifra — da cui il lookahead e regex_engine="python-re" sotto (lo
#  stesso motivo per cui credential_verify_portale.password_pattern lo
#  richiede: il motore Rust di default di Pydantic v2 non supporta i
#  lookahead). Gli altri modelli (senza campo login, o response) restano
#  classi statiche.
# ============================================================

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, create_model, model_validator

from app.utils.request_context import CLIENT_REQUEST_ID_MAX_LENGTH, CLIENT_SESSION_ID_MAX_LENGTH

_DEFAULT_LOGIN_PATTERN  = r"^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]+$"
_DEFAULT_LOGIN_EXAMPLES = ["A1B2C3", "12345X", "otp42"]


def _validate_mail_fields(self):
    """model_validator(mode='after') di OtpSetupRequest: template_id/mail_to obbligatori se method='mail'."""
    if self.method == "mail" and (self.template_id is None or self.mail_to is None):
        raise ValueError("template_id e mail_to sono obbligatori quando method='mail'")
    return self


def _validate_disable_requester(self):
    """
    model_validator(mode='after') di OtpDisableRequest: requested_by_login e'
    legato a force, non piu' sempre obbligatorio — force=true (un
    operatore/helpdesk prova la propria identita' per conto del target):
    obbligatorio. force=false (default, self-service): deve restare
    assente/vuoto, l'identita' del richiedente e' per costruzione il target
    stesso ('login'), non serve chiederlo di nuovo al client.
    """
    if self.force and not self.requested_by_login:
        raise ValueError("requested_by_login e' obbligatorio quando force=true")
    if not self.force and self.requested_by_login:
        raise ValueError("requested_by_login deve essere assente/vuoto quando force=false "
                          "(self-service: il richiedente e' implicitamente 'login')")
    return self


def build_otp_models(cfg: dict) -> tuple[type[BaseModel], ...]:
    """
    Costruisce i modelli /otp/* che contengono un campo login-like, leggendo
    il pattern da cfg['otp2fa']['login_pattern']/['login_examples'] (default
    hardcoded sopra se la chiave manca). Ritorna, in quest'ordine:
    OtpSetupRequest, OtpSendMailRequest, OtpRequestOtpRequest,
    OtpVerifyRequest, OtpStatusQuery, OtpDisableRequest.
    """
    otp_cfg = cfg.get("otp2fa", {})
    login_pattern  = otp_cfg.get("login_pattern",  _DEFAULT_LOGIN_PATTERN)
    login_examples = otp_cfg.get("login_examples", _DEFAULT_LOGIN_EXAMPLES)
    # Esempio distinto per requested_by_login (operatore/helpdesk), solo per
    # non mostrare due volte lo stesso valore nello Swagger — stesso pattern,
    # stesso formato di login: anche un operatore lo rispetta.
    requested_by_examples = [login_examples[1]] if len(login_examples) > 1 else login_examples

    OtpSetupRequest = create_model(
        "OtpSetupRequest",
        __doc__="Corpo JSON della POST /otp/setup.",
        __config__=ConfigDict(regex_engine="python-re"),
        __validators__={
            "_check_mail_fields": model_validator(mode="after")(_validate_mail_fields),
        },
        login=(str, Field(
            ...,
            description="Login dell'utente reale per cui si configura il 2FA. "
                        "Formato configurato in config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        method=(Literal["app", "mail"], Field(
            ...,
            description="Metodo 2FA da registrare: 'app' (TOTP, richiede conferma) o 'mail' (HOTP).",
        )),
        template_id=(Optional[int], Field(
            None,
            description="Obbligatorio se method='mail': id del template email (config.mail_templates.id) da usare.",
            examples=[3],
        )),
        mail_to=(Optional[EmailStr], Field(
            None,
            description="Obbligatorio se method='mail': indirizzo a cui inviare i codici OTP.",
            examples=["mario.rossi@esempio.it"],
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log/lo storico applicativo). "
                         "Se assente si usa il nostro X-Request-Id.",
            examples=["client-id-123"],
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    OtpSendMailRequest = create_model(
        "OtpSendMailRequest",
        __doc__="Corpo JSON della POST /otp/sendmailotp — richiede un nuovo codice via mail (login).",
        __config__=ConfigDict(regex_engine="python-re"),
        login=(str, Field(
            ...,
            description="Login dell'utente, con metodo 'mail' gia' attivo. "
                        "Formato configurato in config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        template_id=(int, Field(
            ...,
            description="Id del template email (config.mail_templates.id) da usare per QUESTO invio — "
                        "puo' variare rispetto a quello usato in fase di setup o in invii precedenti.",
            examples=[3],
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log/lo storico applicativo). "
                         "Se assente si usa il nostro X-Request-Id.",
            examples=["client-id-123"],
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    OtpRequestOtpRequest = create_model(
        "OtpRequestOtpRequest",
        __doc__=(
            "Corpo JSON della POST /otp/requestotp (ex /otp/sendotp) — endpoint di "
            "retrocompatibilita' per sistemi legacy: unica chiamata che crea il metodo "
            "mail se assente (o se esiste ma non e' attivo — pending/disabled trattati "
            "come assenti) e invia comunque un codice, oppure invia un nuovo codice se "
            "un metodo mail e' gia' attivo. Usa template_id come tutti gli altri "
            "endpoint /otp/* (non piu' template_name)."
        ),
        __config__=ConfigDict(regex_engine="python-re"),
        login=(str, Field(
            ...,
            description="Login dell'utente reale. Formato configurato in "
                        "config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        template_id=(int, Field(
            ...,
            description="Id del template email (config.mail_templates.id) da usare.",
            examples=[3],
        )),
        mail_to=(EmailStr, Field(
            ...,
            description="Indirizzo a cui inviare il codice. Usato solo se il metodo mail viene creato ora — "
                        "se un metodo mail e' gia' attivo, si usa l'indirizzo gia' registrato al setup.",
            examples=["mario.rossi@esempio.it"],
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log/lo storico applicativo). "
                         "Se assente si usa il nostro X-Request-Id.",
            examples=["client-id-123"],
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    OtpVerifyRequest = create_model(
        "OtpVerifyRequest",
        __doc__="Corpo JSON della POST /otp/verify — verifica il codice al login.",
        __config__=ConfigDict(regex_engine="python-re"),
        login=(str, Field(
            ...,
            description="Login dell'utente. Formato configurato in config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        code=(str, Field(..., description="Codice OTP a 6 cifre.", examples=["111222"])),
        request_id=(Optional[int], Field(
            None,
            description="Obbligatorio solo per method='mail': id restituito da /otp/sendmailotp.",
            examples=[78],
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log applicativi). "
                         "Se assente si usa il nostro X-Request-Id.",
            examples=["client-id-123"],
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    OtpStatusQuery = create_model(
        "OtpStatusQuery",
        __doc__="Query string della GET /otp/status.",
        __config__=ConfigDict(regex_engine="python-re"),
        # Niente 'examples' qui: a differenza dei modelli di request/response
        # JSON, flask-openapi3 converte i field dei modelli 'query' in oggetti
        # OpenAPI Parameter, che vogliono 'examples' come dict (nome -> esempio),
        # non come lista — stesso motivo per cui HealthQuery non lo usa.
        login=(str, Field(
            ...,
            description="Login dell'utente di cui interrogare lo stato 2FA. "
                        "Formato configurato in config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log applicativi). "
                         "Se assente si usa il nostro X-Request-Id.",
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
        )),
    )

    OtpDisableRequest = create_model(
        "OtpDisableRequest",
        __doc__="Corpo JSON della POST /otp/disable — disattiva il metodo 2FA attivo di un utente.",
        __config__=ConfigDict(regex_engine="python-re"),
        __validators__={
            "_check_requested_by": model_validator(mode="after")(_validate_disable_requester),
        },
        login=(str, Field(
            ...,
            description="Login dell'utente di cui disattivare il metodo 2FA attivo. "
                        "Formato configurato in config.yaml (otp2fa.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        requested_by_login=(Optional[str], Field(
            None,
            description="Login di chi ha richiesto la disattivazione (audit — persistita comunque su "
                        "public.otp_methods.requested_by_login anche quando non fornita: in quel caso "
                        "vale implicitamente 'login'). Deve essere ASSENTE/vuota se force=false "
                        "(self-service — il richiedente e' per costruzione il target stesso), "
                        "OBBLIGATORIA se force=true (e' anche l'identita' su cui viene verificato "
                        "l'OTP: un operatore/helpdesk che agisce per conto del target). Stesso formato "
                        "di 'login' (otp2fa.login_pattern) quando fornita.",
            pattern=login_pattern,
            examples=requested_by_examples,
        )),
        force=(bool, Field(
            False,
            description="Se false (default): l'OTP viene verificato sull'utente target ('login') — l'utente "
                        "disattiva il proprio 2FA. requested_by_login deve essere assente in questo caso. "
                        "Se true: l'OTP viene verificato su 'requested_by_login' (obbligatorio) invece che "
                        "su 'login' — un operatore/helpdesk prova la propria identita' con il proprio 2FA "
                        "quando il target ha perso l'accesso al proprio. L'OTP e' SEMPRE obbligatorio, "
                        "in entrambi i casi.",
        )),
        code=(str, Field(
            ...,
            description="Codice OTP — dell'utente target se force=false, di requested_by_login se force=true. "
                        "Sempre obbligatorio.",
            examples=["123456"],
        )),
        request_id=(Optional[int], Field(
            None,
            description="Obbligatorio se il metodo attivo dell'account su cui si verifica l'OTP (login se "
                        "force=false, requested_by_login se force=true) e' 'mail'.",
            examples=[78],
        )),
        client_request_id=(Optional[str], Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description="Id di correlazione del client (facoltativo, solo per i log applicativi). "
                         "Se assente si usa il nostro X-Request-Id.",
            examples=["client-id-123"],
        )),
        client_session_id=(Optional[str], Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    return (OtpSetupRequest, OtpSendMailRequest, OtpRequestOtpRequest,
            OtpVerifyRequest, OtpStatusQuery, OtpDisableRequest)


class OtpSetupResponse(BaseModel):
    """Risposta JSON della POST /otp/setup — i campi valorizzati dipendono da method e da otp2fa.require_mail_confirmation."""

    message: str = Field(..., examples=["Scansiona il QR code con la tua app di autenticazione, poi conferma con il primo codice"])
    code: str = Field(..., description="000=ok, 210=template non trovato, 300=server di posta non raggiungibile.", examples=["000"])
    config_id: Optional[int] = Field(None, description="Id della configurazione 2FA creata.", examples=[12])
    secret: Optional[str] = Field(None, description="Solo method='app': secret base32, fallback per inserimento manuale.", examples=["JBSWY3DPEHPK3PXP"])
    qr_code_base64: Optional[str] = Field(
        None,
        description="Solo method='app': PNG in base64 (senza prefisso data:image/png;base64,).",
    )
    request_id: Optional[int] = Field(
        None,
        description="Solo method='mail' con otp2fa.require_mail_confirmation=true: id da passare a /otp/setup/confirm.",
    )
    elapsed_time: float = Field(..., description="Tempo impiegato dal server, in millisecondi.", examples=[42.17])


class OtpConfirmRequest(BaseModel):
    """Corpo JSON della POST /otp/setup/confirm — conferma il setup (solo metodo app, o mail se richiesta conferma)."""

    config_id: int = Field(..., description="Id restituito da /otp/setup.", examples=[12])
    code: str = Field(..., description="Primo codice letto dall'app authenticator (o dalla mail).", examples=["123456"])
    client_request_id: Optional[str] = Field(
        None,
        max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
        description="Id di correlazione del client (facoltativo, solo per i log applicativi). "
                     "Se assente si usa il nostro X-Request-Id.",
        examples=["client-id-123"],
    )
    client_session_id: Optional[str] = Field(
        None,
        max_length=CLIENT_SESSION_ID_MAX_LENGTH,
        description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
        examples=["client-session-456"],
    )


class OtpConfirmResponse(BaseModel):
    message: str = Field(..., examples=["Metodo 2FA attivato"])
    code: str = Field(
        ...,
        description="000=ok, 210=configurazione non trovata, 220=gia' confermata, 020=codice non valido, "
                    "010=codice scaduto (solo method='mail'), 240=codice gia' utilizzato/non piu' valido "
                    "(solo method='mail').",
        examples=["000"],
    )
    elapsed_time: float = Field(..., examples=[18.4])


class OtpSendMailResponse(BaseModel):
    message: str = Field(..., examples=["Codice OTP inviato via email"])
    code: str = Field(..., description="000=ok, 210=nessun metodo attivo/template non trovato, 230=metodo attivo e' 'app', 300=server di posta non raggiungibile.", examples=["000"])
    request_id: Optional[int] = Field(None, description="Da passare a /otp/verify.", examples=[78])
    elapsed_time: float = Field(..., examples=[210.5])


class OtpRequestOtpResponse(BaseModel):
    """
    Contratto di risposta legacy, fisso e diverso dagli altri endpoint
    /otp/* (`response_id` invece di `request_id`) — per compatibilita' con
    sistemi che si aspettano gia' questo formato.
    """

    code: str = Field(
        ...,
        description="000=ok (anche se il metodo attivo e' 'app', vedi sotto), 210=template non trovato, "
                    "300=server di posta non raggiungibile.",
        examples=["000"],
    )
    response_id: Optional[int] = Field(
        None,
        description="Id della riga history.otp_requests per questo invio. None se il metodo attivo e' "
                    "'app' (nessun invio mail reale possibile, ma la risposta e' comunque code:\"000\" "
                    "per compatibilita' col chiamante legacy) o su un ramo di errore.",
        examples=[78],
    )
    message: str = Field(..., examples=["codice OTP generato"])
    elapsed_time: float = Field(..., examples=[210.5])


class OtpVerifyResponse(BaseModel):
    message: str = Field(..., examples=["Codice OTP valido"])
    code: str = Field(
        ...,
        description="000=valido, 020=errato, 010=scaduto (solo method='mail'), 240=gia' utilizzato/non "
                    "piu' valido (mail: codice gia' verificato; app: replay — stesso timestep TOTP gia' "
                    "accettato in precedenza), 210=nessun metodo attivo/richiesta non trovata, "
                    "200=request_id mancante per method='mail'.",
        examples=["000"],
    )
    elapsed_time: float = Field(..., examples=[33.9])


class OtpStatusResponse(BaseModel):
    """
    Risposta JSON della GET /otp/status — stato dell'ultima configurazione 2FA
    (qualunque status), non solo quella attiva. Espone anche il metodo
    (app/mail) della configurazione trovata — reintrodotto su richiesta
    esplicita dell'utente il 2026-08-11 (in precedenza rimosso deliberatamente
    per ridurre l'informazione di ricognizione disponibile a un chiamante con
    Basic Auth applicativa valida).
    """

    login:  str = Field(..., examples=["EEAB12345"])
    status: str = Field(
        ...,
        description="Stato dell'ultima configurazione 2FA per questa login: pending | active | disabled, "
                    "oppure 'none' se non e' mai stato registrato nessun metodo.",
        examples=["active"],
    )
    method: Optional[str] = Field(
        None,
        description="Metodo dell'ultima configurazione 2FA trovata: app | mail. None se status='none' "
                    "(nessuna configurazione registrata, nessuna riga da cui leggerlo).",
        examples=["app"],
    )
    elapsed_time: float = Field(..., examples=[9.4])


class OtpDisableResponse(BaseModel):
    message: str = Field(..., examples=["Metodo 2FA disattivato"])
    code: str = Field(
        ...,
        description="000=ok, 210=nessun metodo attivo (sul target 'login', o su 'requested_by_login' se "
                    "force=true), 020=codice errato, 010=scaduto (solo method='mail'), 240=codice gia' "
                    "usato/non piu' valido (mail: gia' verificato; app: replay TOTP), "
                    "200=request_id mancante per method='mail'.",
        examples=["000"],
    )
    elapsed_time: float = Field(..., examples=[15.2])
