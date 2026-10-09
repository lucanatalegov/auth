# ============================================================
#  app/services/soap_service.py
#
#  Chiamata SOAP per l'autenticazione.
#
#  SICUREZZA LOG:
#    - Il contenuto XML NON viene mai loggato
#    - Password sempre mascherata
#    - Chiavi riservate LogRecord mai in extra={}
#
#  SSL: _LegacySSLAdapter con SECLEVEL=0 per DH < 1024 bit.
#  Output: {"status_code": 200, "code": "000|500|200|300", "wsdlresponse": "..."}
#  (000=ok, 500=credenziali rifiutate, 200=errore HTTP non gestito, 300=TCP down/eccezione)
# ============================================================

import logging
import socket
import ssl
import time
from urllib.parse import urlsplit

import requests
import urllib3
import xmltodict
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from app.utils.security import mask_password

log = logging.getLogger("authapi.service.soap")

_LEGACY_CIPHERS = "ALL:@SECLEVEL=0"


def check_tcp_listening(host: str | None, port: int | None, timeout_seconds: int = 30,
                         label: str = "TCP") -> dict:
    """
    Verifica generica di raggiungibilita' TCP: apre una connessione al
    host:porta indicati e la chiude subito. Nessun dato applicativo viene
    scambiato — nessun tentativo di login, nessuna richiesta HTTP/SOAP.

    Funzione unica condivisa da tutti i backend di autenticazione
    (auth_type): oggi solo "soap" la usa (tramite check_soap_listening()
    sotto), ma e' pensata per essere richiamata direttamente con host/porta
    propri quando i backend "ldap"/"db" (oggi solo placeholder in
    config.yaml, vedi credential_verify) verranno implementati — ognuno
    avra' un proprio endpoint da verificare, non necessariamente quello SOAP.

    `label` e' usato solo per rendere leggibili i log (es. "SOAP", "LDAP").
    """
    result = {
        "status": "DOWN", "elapsed_ms": None,
        "host": host, "port": port, "error": None,
    }

    if not host:
        result["error"] = f"{label}: host non configurato o non valido"
        log.error(f"Check {label} listening: DOWN", extra={"error_txt": result["error"]})
        return result

    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            pass
        result["elapsed_ms"] = round((time.perf_counter() - t) * 1000, 2)
        result["status"] = "UP"
        log.info(f"Check {label} listening: UP",
                 extra={"elapsed_ms": result["elapsed_ms"], "host": host, "port": port})
    except Exception as exc:
        result["elapsed_ms"] = round((time.perf_counter() - t) * 1000, 2)
        result["error"] = str(exc)
        log.error(f"Check {label} listening: DOWN",
                  extra={"elapsed_ms": result["elapsed_ms"],
                         "error_txt": str(exc), "host": host, "port": port})

    return result


def check_soap_listening(cfg: dict) -> dict:
    """
    Verifica SOLO che il servizio SOAP esterno sia in ascolto: ricava
    host/porta da soap.endpoint_url e delega a check_tcp_listening().
    Nessuna richiesta HTTP/SOAP viene inviata — nessun tentativo di login,
    nessun dato scambiato col servizio di terzi.

    Wrapper mantenuto per compatibilita' con tutti i chiamanti esistenti
    (call_credential_verify_portale_soap, call_credential_verify_soap,
    health_controller, credential_verify_controller) — stessa firma e
    stesso dict di ritorno di prima della generalizzazione.
    """
    soap_cfg = cfg.get("soap", {})
    endpoint = soap_cfg.get("endpoint_url", "")
    parsed   = urlsplit(endpoint)
    host     = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host:
        result = {
            "status": "DOWN", "elapsed_ms": None, "host": host, "port": port,
            "error": "soap.endpoint_url non configurato o non valido",
        }
        log.error("Check SOAP listening: DOWN", extra={"error_txt": result["error"]})
        return result

    timeout = int(soap_cfg.get("timeout_seconds", 30))
    return check_tcp_listening(host, port, timeout_seconds=timeout, label="SOAP")


class _LegacySSLAdapter(HTTPAdapter):
    """
    HTTPAdapter con SSLContext SECLEVEL=0.
    Necessario per endpoint SOAP con parametri DH < 1024 bit.
    Montato solo sulla sessione locale, nessun side-effect globale.
    """

    def __init__(self, **kwargs):
        self._ssl_ctx = create_urllib3_context(ciphers=_LEGACY_CIPHERS)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ssl_ctx
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **kwargs):
        kwargs["ssl_context"] = self._ssl_ctx
        return super().proxy_manager_for(proxy, **kwargs)


def call_credential_verify_portale_soap(cfg: dict, login: str, password: str) -> dict:
    """
    Esegue la chiamata SOAP di autenticazione.

    Flusso:
      0. Verifica che il servizio sia in ascolto (check TCP) — se non lo è,
         la richiesta NON viene inviata
      1. Legge il template XML (NON loggato)
      2. Sostituisce _MYLOGIN_ e _MYPASSWORD_
      3. Invia via POST con _LegacySSLAdapter
      4. Parsa la risposta XML con xmltodict
      5. Interpreta HTTP status + faultstring

    Returns:
        {"status_code": 200, "code": "...", "wsdlresponse": "...", "raw_response": "..."}
        raw_response e' nel formato "HTTP <status_code>\n<xml grezzo>" restituito
        dal server, valorizzato solo se e' arrivata una vera risposta HTTP (None
        nei casi di TCP down, template illeggibile o eccezione di rete/timeout).
    """
    soap_cfg = cfg["soap"]
    out = {"status_code": 200, "code": "", "wsdlresponse": "", "raw_response": None}

    reachability = check_soap_listening(cfg)
    if reachability["status"] != "UP":
        log.error("Servizio SOAP non in ascolto, richiesta non inviata",
                  extra={"host": reachability.get("host"), "port": reachability.get("port"),
                         "error_txt": reachability.get("error")})
        out["code"] = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"
        return out

    try:
        with open(soap_cfg["template_file"], "r", encoding="utf-8") as fh:
            xml = fh.read()
    except OSError as exc:
        log.error("Impossibile leggere template XML SOAP",
                  extra={"template_path": soap_cfg["template_file"], "error_txt": str(exc)})
        out["code"] = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"
        return out

    xml = xml.replace(soap_cfg["token_login"],    login)
    xml = xml.replace(soap_cfg["token_password"], password)

    log.info("Invio richiesta SOAP",
             extra={"endpoint": soap_cfg["endpoint_url"],
                    "login":    login,
                    "pwd_masked": mask_password(password)})

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    adapter = _LegacySSLAdapter()
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    t_ws = time.perf_counter()
    try:
        r = session.post(
            url     = soap_cfg["endpoint_url"],
            data    = xml,
            headers = dict(soap_cfg["headers"]),
            verify  = False,
            timeout = int(soap_cfg.get("timeout_seconds", 30)),
        )
        ws_elapsed_ms = round((time.perf_counter() - t_ws) * 1000, 2)

        response_dict = xmltodict.parse(r.text)
        out["status_code"]  = r.status_code
        out["code"]         = str(r.status_code)
        # HTTP status in prima riga, seguito dall'XML grezzo della risposta.
        out["raw_response"] = f"HTTP {r.status_code}\n{r.text}"

        log.info("Risposta SOAP ricevuta",
                 extra={"elapsed_ms": ws_elapsed_ms,
                        "endpoint": soap_cfg["endpoint_url"],
                        "http_status": r.status_code,
                        "body_length": len(r.text)})

        if r.status_code == 500:
            fault_text = (
                response_dict
                .get("SOAP-ENV:Envelope", {})
                .get("SOAP-ENV:Body", {})
                .get("SOAP-ENV:Fault", {})
                .get("faultstring", {})
                .get("#text", "")
            )
            out["wsdlresponse"] = fault_text
            auth_error1  = soap_cfg.get("auth_error_string1", "Errore durante l'autenticazione: matricola")
            auth_error2  = soap_cfg.get("auth_error_string2", "Errore durante l'autenticazione: credenziali non valide")
            auth_success = soap_cfg.get("auth_success", [])
            # Ordine dei controlli: success PRIMA di error1/error2 — un fault
            # HTTP 500 il cui testo corrisponde a uno dei pattern noti di
            # "successo mascherato da fault" (quirk del servizio esterno)
            # vince su un'eventuale corrispondenza parziale con i pattern di
            # errore. Se nessuno dei tre gruppi corrisponde, code "503"
            # (esito non riconosciuto) — MAI un successo di default: prima
            # del controllo esplicito su auth_success, un fault non
            # riconosciuto veniva trattato come "Accesso autorizzato" (code
            # "000"), pericoloso perche' un messaggio reale ma non previsto
            # (typo, nuova versione del servizio, testo leggermente diverso)
            # avrebbe autenticato l'utente per sbaglio.
            if any(s in fault_text for s in auth_success):
                out["wsdlresponse"] = "Accesso autorizzato."
                out["code"]         = "000"
            elif auth_error1 in fault_text:
                out["code"] = "500"
            elif auth_error2 in fault_text:
                out["code"] = "501"
            else:
                # wsdlresponse resta il fault_text originale se presente
                # (utile per capire cosa non ha fatto match), altrimenti un
                # messaggio generico.
                out["wsdlresponse"] = fault_text or "errore non gestito"
                out["code"]         = "503"

        elif r.status_code == 200:
            out["wsdlresponse"] = "Accesso autorizzato."
            out["code"]         = "000"
        else:
            out["wsdlresponse"] = "errore non gestito"
            out["code"]         = "200"

    except Exception as exc:
        log.error("Eccezione durante chiamata SOAP",
                  extra={"elapsed_ms": round((time.perf_counter() - t_ws) * 1000, 2),
                         "endpoint": soap_cfg["endpoint_url"], "error_txt": str(exc)},
                  exc_info=True)
        out["code"]         = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"

    out["status_code"] = 200

    log.info("Esito SOAP",
             extra={"login": login, "result_code": out["code"],
                    "wsdlresponse": out["wsdlresponse"]})
    return out


def call_credential_verify_soap(cfg: dict, login: str, password: str) -> dict:
    """
    Copia di call_credential_verify_portale_soap, punto di partenza per il
    servizio /credential/verify — vedi nota in credential_verify_model.py.
    Esegue la chiamata SOAP di autenticazione.

    Flusso:
      0. Verifica che il servizio sia in ascolto (check TCP) — se non lo è,
         la richiesta NON viene inviata
      1. Legge il template XML (NON loggato)
      2. Sostituisce _MYLOGIN_ e _MYPASSWORD_
      3. Invia via POST con _LegacySSLAdapter
      4. Parsa la risposta XML con xmltodict
      5. Interpreta HTTP status + faultstring

    Returns:
        {"status_code": 200, "code": "...", "wsdlresponse": "...", "raw_response": "..."}
        raw_response e' nel formato "HTTP <status_code>\n<xml grezzo>" restituito
        dal server, valorizzato solo se e' arrivata una vera risposta HTTP (None
        nei casi di TCP down, template illeggibile o eccezione di rete/timeout —
        nessun output reale da riportare in quei casi).
    """
    soap_cfg = cfg["soap"]
    out = {"status_code": 200, "code": "", "wsdlresponse": "", "raw_response": None}

    reachability = check_soap_listening(cfg)
    if reachability["status"] != "UP":
        log.error("Servizio SOAP non in ascolto, richiesta non inviata",
                  extra={"host": reachability.get("host"), "port": reachability.get("port"),
                         "error_txt": reachability.get("error")})
        out["code"] = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"
        return out

    try:
        with open(soap_cfg["template_file"], "r", encoding="utf-8") as fh:
            xml = fh.read()
    except OSError as exc:
        log.error("Impossibile leggere template XML SOAP",
                  extra={"template_path": soap_cfg["template_file"], "error_txt": str(exc)})
        out["code"] = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"
        return out

    xml = xml.replace(soap_cfg["token_login"],    login)
    xml = xml.replace(soap_cfg["token_password"], password)

    log.info("Invio richiesta SOAP",
             extra={"endpoint": soap_cfg["endpoint_url"],
                    "login":    login,
                    "pwd_masked": mask_password(password)})

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    adapter = _LegacySSLAdapter()
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    t_ws = time.perf_counter()
    try:
        r = session.post(
            url     = soap_cfg["endpoint_url"],
            data    = xml,
            headers = dict(soap_cfg["headers"]),
            verify  = False,
            timeout = int(soap_cfg.get("timeout_seconds", 30)),
        )
        ws_elapsed_ms = round((time.perf_counter() - t_ws) * 1000, 2)

        response_dict = xmltodict.parse(r.text)
        out["status_code"]   = r.status_code
        out["code"]          = str(r.status_code)
        # HTTP status in prima riga, seguito dall'XML grezzo della risposta.
        out["raw_response"]  = f"HTTP {r.status_code}\n{r.text}"

        log.info("Risposta SOAP ricevuta",
                 extra={"elapsed_ms": ws_elapsed_ms,
                        "endpoint": soap_cfg["endpoint_url"],
                        "http_status": r.status_code,
                        "body_length": len(r.text)})

        if r.status_code == 500:
            fault_text = (
                response_dict
                .get("SOAP-ENV:Envelope", {})
                .get("SOAP-ENV:Body", {})
                .get("SOAP-ENV:Fault", {})
                .get("faultstring", {})
                .get("#text", "")
            )
            out["wsdlresponse"] = fault_text
            auth_error1  = soap_cfg.get("auth_error_string1", "Errore durante l'autenticazione: matricola")
            auth_error2  = soap_cfg.get("auth_error_string2", "Errore durante l'autenticazione: credenziali non valide")
            auth_success = soap_cfg.get("auth_success", [])
            # Ordine dei controlli: success PRIMA di error1/error2 — un fault
            # HTTP 500 il cui testo corrisponde a uno dei pattern noti di
            # "successo mascherato da fault" (quirk del servizio esterno)
            # vince su un'eventuale corrispondenza parziale con i pattern di
            # errore. Se nessuno dei tre gruppi corrisponde, code "503"
            # (esito non riconosciuto) — MAI un successo di default: un
            # fault non riconosciuto trattato come "Accesso autorizzato"
            # sarebbe pericoloso (un messaggio reale ma non previsto —
            # typo, nuova versione del servizio, testo leggermente diverso —
            # autenticherebbe l'utente per sbaglio).
            if any(s in fault_text for s in auth_success):
                out["wsdlresponse"] = "Accesso autorizzato."
                out["code"]         = "000"
            elif auth_error1 in fault_text:
                out["code"] = "500"
            elif auth_error2 in fault_text:
                out["code"] = "501"
            else:
                # wsdlresponse resta il fault_text originale se presente
                # (utile per capire cosa non ha fatto match), altrimenti un
                # messaggio generico.
                out["wsdlresponse"] = fault_text or "errore non gestito"
                out["code"]         = "503"

        elif r.status_code == 200:
            out["wsdlresponse"] = "Accesso autorizzato."
            out["code"]         = "000"
        else:
            out["wsdlresponse"] = "errore non gestito"
            out["code"]         = "200"

    except Exception as exc:
        log.error("Eccezione durante chiamata SOAP",
                  extra={"elapsed_ms": round((time.perf_counter() - t_ws) * 1000, 2),
                         "endpoint": soap_cfg["endpoint_url"], "error_txt": str(exc)},
                  exc_info=True)
        out["code"]         = "300"
        out["wsdlresponse"] = "il portale e' andato in anomalia , riprovare"

    out["status_code"] = 200

    log.info("Esito SOAP",
             extra={"login": login, "result_code": out["code"],
                    "wsdlresponse": out["wsdlresponse"]})
    return out
