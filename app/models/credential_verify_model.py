# ============================================================
#  app/models/credential_verify_model.py
#  Modelli Pydantic per l'endpoint POST /credential/verify.
#
#  Copia di credential_verify_portale_model.py, punto di partenza per un
#  servizio distinto (vedi config.yaml, sezione credential_verify,
#  che include anche i placeholder vuoti ldap/postgres per un futuro
#  backend di verifica diverso dal SOAP esterno).
#
#  Il pattern di login/password e i relativi examples sono letti
#  da config.yaml (sezione credential_verify) tramite
#  build_credential_verify_models(cfg), chiamata da create_app()
#  prima della registrazione della route — i vincoli non sono
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
# Sigla provincia italiana: 2 lettere maiuscole (es. RM, MI, TO).
_DEFAULT_PROV_PATTERN     = r"^[A-Z]{2}$"
_DEFAULT_PROV_EXAMPLES    = ["RM", "MI", "TO"]


def build_credential_verify_models(cfg: dict) -> tuple[type[BaseModel], type[BaseModel]]:
    """Costruisce CredentialVerifyRequest/Response leggendo i vincoli da cfg['credential_verify']."""
    vp_cfg = cfg.get("credential_verify", {})

    login_pattern      = vp_cfg.get("login_pattern",      _DEFAULT_LOGIN_PATTERN)
    login_examples     = vp_cfg.get("login_examples",     _DEFAULT_LOGIN_EXAMPLES)
    password_pattern   = vp_cfg.get("password_pattern",   _DEFAULT_PASSWORD_PATTERN)
    password_examples  = vp_cfg.get("password_examples",  _DEFAULT_PASSWORD_EXAMPLES)
    password_case      = vp_cfg.get("password_case",      _DEFAULT_PASSWORD_CASE)
    prov_pattern       = vp_cfg.get("prov_pattern",       _DEFAULT_PROV_PATTERN)
    prov_examples      = vp_cfg.get("prov_examples",      _DEFAULT_PROV_EXAMPLES)

    def _normalize_password_case(cls, v):
        return apply_password_case(v, password_case)

    CredentialVerifyRequest = create_model(
        "CredentialVerifyRequest",
        __doc__="Corpo JSON della POST /credential/verify.",
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
            description="Identificativo utente. Formato configurato in config.yaml (credential_verify.login_pattern).",
            pattern=login_pattern,
            examples=login_examples,
        )),
        password=(str, Field(
            ...,
            description=(
                "Password: almeno una lettera, almeno un carattere speciale, "
                "lunghezza minima 8 caratteri. Formato configurato in "
                "config.yaml (credential_verify.password_pattern). Prima "
                "della validazione viene applicato upper/lower/nulla secondo "
                "credential_verify.password_case."
            ),
            pattern=password_pattern,
            examples=password_examples,
        )),
        prov=(str, Field(
            "--",
            description=(
                "Provincia associata all'ufficio in cui e' in servizio "
                "l'utente. Opzionale: se assente, default \"--\" (il "
                "controllo sul formato, credential_verify.prov_pattern in "
                "config.yaml, si applica solo se il campo viene fornito — un "
                "default non viene rivalidato da Pydantic). Usata per "
                "calcolare expires_at (query select.checkcache in "
                "config.yaml, funzione PostgreSQL next_working_day()): la "
                "cache di login resta valida per N giorni lavorativi "
                "(configurabile lato funzione DB, non in questa applicazione) "
                "dopo l'ultima autenticazione riuscita presso il servizio "
                "esterno."
            ),
            pattern=prov_pattern,
            examples=prov_examples,
        )),
        client_request_id=(str | None, Field(
            None,
            max_length=CLIENT_REQUEST_ID_MAX_LENGTH,
            description=(
                "Identificativo fornito dal client chiamante, salvato nella "
                "cache di login in caso di validazione riuscita (code=000). "
                "Se assente, viene usato \"none\"."
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

    class CredentialVerifyResponse(BaseModel):
        """Risposta JSON della POST /credential/verify. Vedi tabella code/description/origine nella descrizione dell'endpoint."""

        code: str = Field(
            ...,
            description=(
                "000=ok (SOAP o cache), 500=login/matricola non valida, 501=credenziali "
                "non valide (password errata) — rifiutate esplicitamente dal SOAP, mai "
                "fallback su cache per 500/501: e' gia' una risposta definitiva. Se il SOAP "
                "non riesce a dare una risposta definitiva (200=errore HTTP non gestito, "
                "300=eccezione/TCP down, 503=fault HTTP 500 non riconosciuto — nessuno dei "
                "pattern auth_success/auth_error_string1/auth_error_string2 corrisponde), si "
                "tenta un fallback su cache locale: in caso di diniego il code e' "
                "<origin><1-4> (concatenazione stringa), es. \"1001\"..\"1004\" (TCP down), "
                "\"3001\"..\"3004\" (eccezione SOAP), \"2001\"..\"2004\" (errore HTTP SOAP non "
                "gestito), \"5031\"..\"5034\" (fault HTTP 500 non riconosciuto) — vedi tabella "
                "completa nella descrizione dell'endpoint."
            ),
            examples=["000", "500", "501", "1001", "3002", "2004", "5031"],
        )
        auth_type: str = Field(
            ...,
            description=(
                "Backend di autenticazione effettivamente usato per validare "
                "la richiesta: soap | ldap | db (vedi config.yaml, sezione "
                "credential_verify)."
            ),
            examples=["soap"],
        )
        description: str | None = Field(
            None,
            description="Messaggio di risposta dal servizio SOAP. Presente solo se auth_type=soap.",
            examples=["Accesso autorizzato."],
        )
        elapsed_time: float = Field(
            ...,
            description="Tempo impiegato dal server per evadere la richiesta, in millisecondi.",
            examples=[42.17],
        )

    return CredentialVerifyRequest, CredentialVerifyResponse
