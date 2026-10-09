# ============================================================
#  app/models/credential_verify_portale_model.py
#  Modelli Pydantic per l'endpoint POST /credential/verify-portale.
#
#  Il pattern di login/password e i relativi examples sono letti
#  da config.yaml (sezione credential_verify_portale) tramite
#  build_credential_verify_portale_models(cfg), chiamata da create_app()
#  prima della registrazione della route — i vincoli non sono più
#  hardcoded nel modello.
# ============================================================

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from app.utils.security import apply_password_case
from app.utils.request_context import CLIENT_REQUEST_ID_MAX_LENGTH, CLIENT_SESSION_ID_MAX_LENGTH

_DEFAULT_LOGIN_PATTERN    = r"^(EE[A-Z]{2}[0-9]{5}|P0[0-9]{4,5}|AG[A-Z]{2}[0-9]{6})$"
_DEFAULT_LOGIN_EXAMPLES   = ["EEAB12345", "P012345", "AGAB123456"]
_DEFAULT_PASSWORD_PATTERN = r"^(?=.*[A-Za-z])(?=.*[^A-Za-z0-9]).{8,}$"
_DEFAULT_PASSWORD_EXAMPLES = ["Passw0rd!"]
_DEFAULT_PASSWORD_CASE    = "none"


def build_credential_verify_portale_models(cfg: dict) -> tuple[type[BaseModel], type[BaseModel]]:
    """Costruisce CredentialVerifyPortaleRequest/Response leggendo i vincoli da cfg['credential_verify_portale']."""
    vp_cfg = cfg.get("credential_verify_portale", {})

    login_pattern      = vp_cfg.get("login_pattern",      _DEFAULT_LOGIN_PATTERN)
    login_examples     = vp_cfg.get("login_examples",     _DEFAULT_LOGIN_EXAMPLES)
    password_pattern   = vp_cfg.get("password_pattern",   _DEFAULT_PASSWORD_PATTERN)
    password_examples  = vp_cfg.get("password_examples",  _DEFAULT_PASSWORD_EXAMPLES)
    password_case      = vp_cfg.get("password_case",      _DEFAULT_PASSWORD_CASE)

    def _normalize_password_case(cls, v):
        return apply_password_case(v, password_case)

    CredentialVerifyPortaleRequest = create_model(
        "CredentialVerifyPortaleRequest",
        __doc__="Corpo JSON della POST /credential/verify-portale.",
        # Motore regex Python (non Rust): il pattern password usa i lookahead
        # (?=...), non supportati dal motore Rust di default di Pydantic v2.
        __config__=ConfigDict(regex_engine="python-re"),
        __validators__={
            # mode="before": upper/lower/nothing sulla password PRIMA che
            # venga validata contro password_pattern (config.yaml, password_case).
            "_password_case_validator": field_validator("password", mode="before")(_normalize_password_case),
        },
        login=(str, Field(
            ...,
            description="Identificativo utente. Formato configurato in config.yaml (credential_verify_portale.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        password=(str, Field(
            ...,
            description=(
                "Password: almeno una lettera, almeno un carattere speciale, "
                "lunghezza minima 8 caratteri. Formato configurato in "
                "config.yaml (credential_verify_portale.password_pattern). Prima "
                "della validazione viene applicato upper/lower/nulla secondo "
                "credential_verify_portale.password_case."
            ),
            pattern=password_pattern,
            examples=password_examples,
        )),
        client_request_id=(str | None, Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description=(
                "Identificativo fornito dal client chiamante, per correlare "
                "questa richiesta ai propri log — scritto nella colonna "
                "request_id di history.auth_credential_log (stessa tabella "
                "e stesse query di /credential/verify, righe distinte dalla "
                "colonna service). A differenza di /credential/verify, "
                "questo endpoint non ha pero' una colonna/cache dedicata "
                "propria (nessun fallback su cache locale). Opzionale: se "
                "assente si usa il nostro X-Request-Id."
            ),
            examples=["client-correlation-id-123"],
        )),
        client_session_id=(str | None, Field(
            None,
            max_length=CLIENT_SESSION_ID_MAX_LENGTH,
            description="Id di sessione del client (facoltativo, solo per i log applicativi: campo session_id).",
            examples=["client-session-456"],
        )),
    )

    class CredentialVerifyPortaleResponse(BaseModel):
        """Risposta JSON della POST /credential/verify-portale. code: 000|500|200|300."""

        code: str = Field(
            ...,
            description=(
                "000=ok, 500=login/matricola non valida, 501=credenziali non valide "
                "(password errata), 200=errore HTTP non gestito dal SOAP, 300=servizio non "
                "raggiungibile o eccezione, 503=fault HTTP 500 con testo non riconosciuto "
                "da nessuno dei pattern configurati (soap.auth_success/auth_error_string1/"
                "auth_error_string2). 500/501/503 derivano tutti da un fault HTTP 500: il "
                "faultstring viene confrontato, in quest'ordine, con auth_success (lista — "
                "un match indica un successo mascherato da fault, quirk del servizio "
                "esterno), poi auth_error_string1, poi auth_error_string2; se nessuno "
                "corrisponde il code e' 503, mai 000 di default."
            ),
            examples=["000", "500", "501", "503"],
        )
        auth_validation: str = Field(
            ...,
            description=(
                "Sempre \"soap\": unico meccanismo di autenticazione di "
                "questo endpoint (nessun fallback su cache come "
                "/credential/verify) — valorizzato indipendentemente da "
                "\"code\" (successo, rifiuto esplicito, TCP down, eccezione)."
            ),
            examples=["soap"],
        )
        description: str = Field(
            ...,
            description="Messaggio di risposta dal servizio SOAP.",
            examples=["Accesso autorizzato."],
        )
        elapsed_time: float = Field(
            ...,
            description="Tempo impiegato dal server per evadere la richiesta, in millisecondi.",
            examples=[42.17],
        )

    return CredentialVerifyPortaleRequest, CredentialVerifyPortaleResponse
