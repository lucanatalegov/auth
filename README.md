# Auth API — v1.2.2

Web service REST di autenticazione con Flask e OpenAPI.

## Versione
| Campo | Valore | Configurabile |
|-------|--------|---------------|
| Release | v1 | `./release` o `config.yaml` |
| Patch   | 2  | `./patch` o `config.yaml`  |
| Build   | 2  | `./version` — auto-incrementato |

## Installazione
```bash
pip install -r requirements.txt
```
**Requisiti:** Python 3.11+, PostgreSQL ≥ 13

## Avvio
```bash
python run.py
# Produzione:
gunicorn --workers 4 --bind 0.0.0.0:3002 "main:app"
```
Swagger UI → **http://localhost:3002/openapi**

Titolo/descrizione mostrati nella UI (`app/main.py::create_app()`, oggetto `Info(...)`,
aggiornati in una sessione successiva del 2026-08-11 per rendere esplicito che il servizio
non copre solo `/credential/verify*` via SOAP ma anche i 7 endpoint `/otp/*` — vedi sezione
"2FA" sotto):
> **Auth API — Autenticazione & 2FA**
> Autenticazione SOAP (con fallback su cache locale) e 2FA (TOTP app / HOTP mail).

---

## Alberatura
```
auth-openapi3_v1_p2_v1/
├── main.py / run.py / requirements.txt
├── release / patch / version
├── README.md / SUMMARY.md
├── logs/api-auth.log          # JSON strutturato, RotatingFileHandler
├── templates/checkuser.template.xml
├── sql/otp_2fa_schema.sql     # DDL 2FA — da eseguire una tantum (non applicato dal codice)
└── app/
    ├── main.py                 # Factory create_app()
    ├── middleware.py            # Log automatico + X-Request-Id
    ├── config/
    │   ├── __init__.py
    │   └── config.yaml          # Tutti i parametri
    ├── models/
    │   ├── credential_verify_portale_model.py
    │   ├── credential_verify_model.py  # login/password/prov/client_request_id
    │   ├── health_model.py
    │   └── otp_model.py         # OtpSetup/Confirm/SendMail/Verify Request/Response
    ├── controllers/
    │   ├── credential_verify_portale_controller.py # + _log_request_history()/_update_log_extop()
    │   │                                     #   /_update_log_end() (insert+extop+end su
    │   │                                     #   history.auth_credential_log, service="verify-portale",
    │   │                                     #   _end sempre — auth_validation costante "soap")
    │   ├── credential_verify_controller.py # + _sync_login_cache() (checkcache/updatecache/insertcache)
    │   │                                     # + _log_request_history()/_update_log_tcp()/_update_log_extop()
    │   │                                     #   /_update_log_end() (insert + 3 update su
    │   │                                     #   history.auth_credential_log, service="verify" —
    │   │                                     #   _end sempre, non solo su code=="000")
    │   │                                     # + _check_cache_credential()/_try_cache_fallback() (fallback su
    │   │                                     #   cache locale quando il SOAP non valida, sola lettura)
    │   ├── health_controller.py # get_pg_pool()
    │   └── otp_controller.py    # handle_otp_setup/confirm/sendmailotp/verify/status/disable
    │                             # — query in config.yaml (operations_sql, chiavi otp_*),
    │                             # transazioni singole (un commit) per le operazioni composte
    ├── services/
    │   ├── soap_service.py      # SOAP + SSL SECLEVEL=0 + check_tcp_listening()/check_soap_listening()
    │   │                         # call_credential_verify_portale_soap() + call_credential_verify_soap()
    │   │                         # entrambe restituiscono anche raw_response (XML grezzo)
    │   │                         # code: 000|500|501|200|300|503 (200/300 ex 600/700;
    │   │                         # 500/501/503 derivano da un fault HTTP 500, distinti via
    │   │                         # soap.auth_success/auth_error_string1/auth_error_string2)
    │   └── otp_service.py       # pyotp (TOTP/HOTP) + QR base64 + invio mail (smtplib, riusa
    │                             # check_tcp_listening) + authenticate_service_account() (pgcrypto)
    └── utils/
        ├── logger.py            # JsonFormatter + requestid
        ├── request_context.py   # X-Request-Id filter
        ├── db_pool.py            # Pool PostgreSQL con getter
        ├── security.py          # mask_password() + hash_password() + apply_password_case()
        └── basic_auth.py        # require_service_account() — decorator HTTP Basic per /otp/*
```

---

## Logging — configurazione (build 1)

```yaml
logging:
  level: "DEBUG"
  dir: "logs"                    # path relativo o assoluto (es. "/var/log/sportello")
  filename: "api-auth.log"       # nome del file di log
  max_bytes: 5242880
  backup_count: 10
  console_enabled: true          # false = disabilita lo stdout
```

### X-Request-Id

Ogni richiesta HTTP può includere l'header `X-Request-Id`. Se presente, il
suo valore viene incluso in **ogni** riga di log emessa durante l'elaborazione
di quella richiesta, sotto la chiave `"requestid"`. Se l'header non è
presente, il server ne genera uno automaticamente (UUID4).

L'header viene anche restituito nella risposta HTTP, per permettere al
client di correlare i propri log con quelli del server.

```
POST /mit4me/auth/api/v1/credential/verify-portale
X-Request-Id: 24dc894f-9d46-400d-a431-da5c6afde458
```

```json
{"asctime": "...", "level": "INFO", "requestid": "24dc894f-9d46-400d-a431-da5c6afde458",
 "message": "HTTP request ricevuta", "context": {...}}
```

### Path del file di log

`logging.dir` accetta sia path relativi alla root del progetto (es. `"logs"`)
sia path assoluti (es. `"/var/log/sportello"`). La cartella viene creata
automaticamente se non esiste.

### Disabilitare lo stdout

Impostare `logging.console_enabled: false` per scrivere i log solo su file,
senza output su console. Utile in produzione con supervisori di processo
(systemd, supervisord) che già catturano e gestiscono lo stdout altrove.

---

## Endpoint

### POST `/mit4me/auth/api/v1/credential/verify-portale` — Rate Limited, Basic Auth applicativa
Richiede HTTP Basic Auth applicativa (stesso meccanismo di `/otp/*`, `public.service_accounts`
— identifica l'applicativo chiamante, non l'utente reale, che è il campo `login` nel body).
Senza credenziali valide: `401` prima ancora di validare login/password o chiamare il SOAP.
```json
{"login": "EEAB12345", "password": "Passw0rd!"}
→ {"code": "000", "auth_validation": "soap", "description": "Accesso autorizzato.", "elapsed_time": 812.4}
```

**Formato login e password configurabili** in `config.yaml`, sezione `credential_verify_portale`
(nessun default hardcoded nel modello — letti da `build_credential_verify_portale_models(cfg)`):
```yaml
credential_verify_portale:
  login_pattern: '^(EE[A-Z]{2}[0-9]{5}|P0[0-9]{4,5}|AG[A-Z]{2}[0-9]{6})$'
  login_examples: ["EEAB12345", "P012345", "AGAB123456"]
  password_pattern: '^(?=.*[A-Za-z])(?=.*[^A-Za-z0-9]).{8,}$'
  password_examples: ["Passw0rd!"]
  password_case: "none"   # "upper" | "lower" | "none" — applicato PRIMA della validazione
```
Default: login nei formati `EE[A-Z]{2}[0-9]{5}` | `P0[0-9]{4,5}` | `AG[A-Z]{2}[0-9]{6}`;
password con almeno una lettera, almeno un carattere speciale, lunghezza minima 8.
Il pattern password usa lookahead `(?=...)`, per questo il modello imposta
`ConfigDict(regex_engine="python-re")` (il motore Rust di default di Pydantic v2
non li supporta). `password_case` trasforma la password (`str.upper()`/`str.lower()`/nulla)
tramite un `field_validator(mode="before")`, quindi **prima** che il pattern venga
verificato — il valore trasformato è anche quello effettivamente inviato al SOAP esterno.

**Request:**
```json
{"login": "EEAB12345", "password": "Passw0rd!", "client_request_id": "client-id-123"}
```
`client_request_id` è opzionale, solo per correlazione nei log applicativi (se assente
si usa il nostro `X-Request-Id`) — scritto nella colonna `request_id` di
`history.auth_credential_log` (vedi sotto): a differenza di `/credential/verify`, questo
endpoint non ha però una colonna/cache dedicata propria (nessun fallback su cache locale).

**Response:**
```json
{"code": "000", "auth_validation": "soap", "description": "Accesso autorizzato.", "elapsed_time": 812.4}
```
- `code`: `000`=ok, `500`=login/matricola non valida, `501`=credenziali non valide (password
  errata), `200`=errore HTTP non gestito dal SOAP, `300`=servizio non raggiungibile (TCP down,
  template illeggibile) o eccezione durante la chiamata, `503`=fault HTTP 500 il cui testo non
  corrisponde a nessuno dei pattern configurati (`soap.auth_success`/`auth_error_string1`/
  `auth_error_string2`) — schema condiviso con `call_credential_verify_soap()` in
  `soap_service.py` (fino a due build fa erano `600`/`700`). `500`/`501`/`503` derivano tutti
  da una risposta HTTP 500 con `SOAP-ENV:Fault`: il testo del `faultstring` viene confrontato,
  in quest'ordine, con `soap.auth_success` (lista — un match → `000`, non un errore: quirk
  del servizio esterno), poi `auth_error_string1` (→ `500`), poi `auth_error_string2`
  (→ `501`); se nessuno corrisponde → `503`, **mai** un successo di default (fail-safe: un
  fault non riconosciuto non deve autenticare l'utente per sbaglio)
- `auth_validation`: **sempre** `"soap"` — questo endpoint ha un unico meccanismo di
  autenticazione (nessun fallback su cache, a differenza di `/credential/verify`),
  quindi è valorizzato indipendentemente da `code`
- `description`: messaggio di risposta dal SOAP (rinominato da `wsdlresponse`)

**Pre-check di raggiungibilità:** prima di inviare la richiesta SOAP reale,
`call_credential_verify_portale_soap()` verifica con `check_soap_listening()` (connessione
TCP al host:porta di `soap.endpoint_url`, nessun dato inviato) che il servizio sia in
ascolto. Se non lo è, la richiesta con le credenziali **non viene inviata**: si torna
subito `{"code": "300", "description": "il portale e' andato in anomalia , riprovare"}`.

**`elapsed_time`**: tempo in millisecondi impiegato dal server per evadere la richiesta
(l'intera chiamata SOAP inclusa). Presente solo sulle risposte 200 — non sulle 422
(la validazione fallisce prima di entrare nel controller, dove vive il timer).

**Log storico su `history.auth_credential_log`** (stesse query di `config.yaml` già
configurate per `/credential/verify` — nessuna query nuova, distinte solo dalla colonna
`service="verify-portale"`): a differenza di `/credential/verify`, flusso più
snello — solo 3 scritture, niente check TCP esplicito duplicato (un solo check, interno
a `call_credential_verify_portale_soap()`) e niente logica di cache:
1. `insert.auth_credential_log` — appena la richiesta arriva
2. `update.auth_credential_log_extop` — dopo la risposta SOAP, valorizza `remote_response`
   con l'XML grezzo (`NULL` se non è arrivata una vera risposta HTTP)
3. `update.auth_credential_log_end` — **sempre**, qualunque `code` (non solo su successo,
   dato che `auth_validation` è costante `"soap"`): valorizza `success` (`1` se
   `code=="000"`), `failure_reason` (messaggio specifico per `500`/`501`/`200`/`300`/`503`,
   `NULL` su successo), `response` (JSON della risposta al client), `code`

### POST `/mit4me/auth/api/v1/credential/verify` — Rate Limited, Basic Auth applicativa
Richiede HTTP Basic Auth applicativa, stesso meccanismo di `/credential/verify-portale`/`/otp/*`
(`public.service_accounts`). Nato come copia di `/credential/verify-portale`, oggi profondamente diverso: valida via SOAP,
sincronizza una cache PostgreSQL, e — novità principale — **tenta un fallback di
autenticazione via cache locale** quando il SOAP non riesce a dare una risposta definitiva.
Config in `config.yaml`, sezione `credential_verify` (stessa struttura di
`credential_verify_portale`, più campi aggiuntivi):
```yaml
credential_verify:
  login_pattern: '...'
  login_examples: [...]
  password_pattern: '...'
  password_examples: [...]
  password_case: "lower"
  prov_pattern: '^[A-Z]{2}$'          # sigla provincia, es. RM/MI/TO
  prov_examples: ["RM", "MI", "TO"]
  soap: true    # backend attivo — unico realmente implementato
  ldap: false   # riservato, non ancora sviluppato
  db: false     # riservato, non ancora sviluppato (non "postgres", per non
                # confondersi con la chiave top-level postgres: della app)
```
⚠️ I flag `soap`/`ldap`/`db` **non sono ancora letti da nessun codice**: sono solo
indicatori documentali. Il controller chiama sempre e solo il servizio SOAP
esterno (`call_credential_verify_soap`), indipendentemente dai loro valori.

**Request:**
```json
{"login": "P014452", "password": "Mit!0626", "prov": "RM", "client_request_id": "client-id-123"}
```
- `login`, `password`: come `credential_verify_portale`
- `prov` (**opzionale**, default `"--"` se assente — il pattern si applica solo se il campo
  viene fornito, un default non viene rivalidato da Pydantic): sigla provincia dell'ufficio
  dell'utente, usata per calcolare `expires_at` in `select.checkcache` (funzione PostgreSQL
  `next_working_day()`) — la cache resta valida per **N giorni lavorativi** (N configurabile
  lato funzione DB, non in questa applicazione) dopo l'ultima autenticazione riuscita
- `client_request_id` (opzionale): se assente, il server usa il proprio `X-Request-Id`
  (header ricevuto dal client o UUID4 generato) invece di un placeholder statico —
  così la riga di history/cache resta correlabile ai log della richiesta anche senza
  questo campo

**Response:**
```json
{"code": "000", "auth_type": "soap", "description": "Accesso autorizzato.", "elapsed_time": 940.1}
```
- `auth_type`: backend che ha effettivamente gestito la richiesta — letto da `config.yaml`
  (`credential_verify.auth_type`, default Python `"soap"` se la chiave manca; oggi manca,
  quindi il valore resta sempre `"soap"`). Non più hardcoded nel codice, ma i flag
  `soap`/`ldap`/`db` di config sopra non pilotano ancora nulla — resta l'unico backend reale
- `description`: messaggio di risposta (rinominato da `wsdlresponse`), presente solo se
  `auth_type == "soap"`
- `elapsed_time`: tempo totale, **inclusa** l'eventuale sincronizzazione/fallback cache

**Schema `code` completo**, `000`/`500`/`501` sempre uguali a se stessi; se il SOAP non
riesce a dare una risposta definitiva (TCP down, errore HTTP non gestito, eccezione, o fault
HTTP 500 non riconosciuto) scatta il fallback su cache — il `code` finale in caso di diniego
è `<origine><1-4>` (**concatenazione di stringhe**, non somma):

| code | origine | descrizione |
|---|---|---|
| `000` | SOAP reale o cache valida | successo |
| `500` | SOAP | rifiuto esplicito — login/matricola non valida — **mai** fallback su cache: è già una risposta definitiva |
| `501` | SOAP | rifiuto esplicito — credenziali non valide (password errata) — **mai** fallback su cache, stesso trattamento di `500` |
| `1001`–`1004` | TCP down (nessuna chiamata SOAP tentata) | fallback su cache negato — vedi motivi sotto |
| `3001`–`3004` | SOAP chiamato, eccezione/timeout (code SOAP reale `300`) | fallback su cache negato |
| `2001`–`2004` | SOAP chiamato, errore HTTP non gestito (code SOAP reale `200`) | fallback su cache negato |
| `5031`–`5034` | SOAP chiamato, fault HTTP 500 non riconosciuto (code SOAP reale `503` — nessuno dei pattern `soap.auth_success`/`auth_error_string1`/`auth_error_string2` corrisponde) | fallback su cache negato |

Suffisso 1-4 (motivo del diniego): `1`=nessuna riga di cache trovata per la login,
`2`=hash password non corrispondente, `3`=cache priva di scadenza calcolabile,
`4`=cache scaduta (`now() >= expires_at`). Tabella `code`/`description`/`origine`
completa (19 righe) anche nello Swagger UI dell'endpoint.

**`auth_validation` non è un campo della risposta HTTP** (a differenza di
`/credential/verify-portale`) — vive solo nel log storico su DB (vedi sotto), ma vale la pena
sapere che **non è mai `NULL`**: è `auth_type` quando il SOAP ha determinato l'esito
(successo o rifiuto esplicito, `code` `000`/`500`/`501`), oppure `"cache"` quando è stato il
fallback a decidere — riuscito o negato che sia.

**Sincronizzazione cache DB (solo se `code == "000"` da SOAP reale — sola lettura+scrittura,
mai sul successo via fallback):**
prima della chiamata SOAP viene calcolato `password_hash` (SHA-256 esadecimale, **senza salt** —
adatto a correlazione/audit nei log, non a conservare credenziali). Dopo un esito SOAP positivo,
`_sync_login_cache()` esegue, su `public.auth_credential_cache` (tabella reale di produzione):

1. `operations_sql.select.checkcache` — la cache esiste se la query restituisce una riga (qualunque colonna), non esiste se non ne restituisce
2. riga presente → `operations_sql.update.updatecache`
   riga assente → `operations_sql.insert.insertcache`

Le tre query sono scritte in `config.yaml` (SQL a scelta dell'operatore, non hardcoded nel codice);
il codice fornisce sempre questi parametri, uno statement può referenziarne solo un sottoinsieme:
`%(login)s`, `%(password_hash)s`, `%(client_request_id)s`, `%(last_successful_login)s`, `%(prov)s`,
`%(auth_type)s`. Quest'ultimo è disponibile ma oggi non referenziato da nessuna delle tre query
(era su `insertcache` in una versione precedente di `config.yaml`, poi rimosso).

Schema reale di `public.auth_credential_cache`:
```
id                       integer      PK, auto-incrementale
login                    varchar      NOT NULL
password_hash            varchar      nullable
created_at               timestamptz  NOT NULL, default now()
last_successful_login    timestamptz  NOT NULL, default now()
client_request_id        varchar      NOT NULL (rinominata da remote_request_id)
trace                    smallint     nullable (valorizzato da un trigger di audit)
```
⚠️ Il nome colonna SQL nelle query (`updatecache`/`insertcache`) resta `client_request_id`
letterale — il placeholder Python `%(client_request_id)s` in questo caso coincide col nome
colonna, ma non è un requisito: contano solo le posizioni nella query, non la coincidenza dei nomi.
Nessuna colonna `prov` — deliberatamente, `prov` è usato solo dentro l'espressione SQL di
`checkcache` (una funzione `next_working_day(data, prov)`), non salvato come colonna.

⚠️ La tabella ha un **trigger di audit** che replica ogni INSERT/UPDATE in
`history.auth_credential_cache` (stessa login, struttura da log generico: `schema_name`,
`table_name`, `action`, `old_data`/`new_data` jsonb). Se quel trigger fallisce (es. vincoli
non soddisfatti sulla tabella `history`), l'intera transazione va in rollback — il codice
applicativo gestisce questo con `try/except` + `conn.rollback()`, loggando l'errore senza
lasciare scritture parziali.

⚠️ Ogni chiamata con `login`/`password`/`prov` che superano la validazione arriva fino alla
vera chiamata SOAP (se il TCP è su) **e**, se ha successo, scrive davvero su
`public.auth_credential_cache` in produzione.

**Fallback su cache locale** (`_try_cache_fallback()` in `credential_verify_controller.py`):
scatta **solo** quando il SOAP non riesce a dare una risposta definitiva — TCP down (nessuna
chiamata SOAP tentata: fallirebbe comunque sullo stesso check al suo interno) oppure
raggiungibile ma con `code` diverso sia da `000` sia da `500`. **Sola lettura**: rilegge
`select.checkcache` (stessa query della sync sopra) e confronta l'hash appena calcolato con
`password_hash` in cache, verificando `now() < expires_at`. `expires_at` arriva dalla query
come timestamp senza fuso in ora di Roma (fuso della sessione PostgreSQL): il codice lo
localizza in `Europe/Rome` e lo confronta con l'ora corrente in UTC, così il risultato non
dipende dal fuso del container (vedi "Fuso orario" in fondo). Se valido, autentica comunque
l'utente (`code="000"`); altrimenti nega con uno dei code `1001`–`2004` visti sopra.
**Non scrive mai** su `public.auth_credential_cache` (né `updatecache` né `insertcache`),
riuscito o negato che sia — solo il log storico (sotto) viene aggiornato.

**Log richieste su `history.auth_credential_log` (ogni richiesta, indipendentemente
dall'esito):** oltre alla cache sopra (solo su successo SOAP reale), ogni richiesta scrive
anche — sempre — su `history.auth_credential_log` (tabella distinta da
`history.auth_credential_cache`, stesso schema `history`). Fino a quattro operazioni
fail-open, tutte in `config.yaml` sotto `operations_sql`:

1. `insert.auth_credential_log` — appena la richiesta arriva, prima della chiamata SOAP.
   Parametri: `login`, `client_request_id`, `score`, `auth_type`, `service`
   (`"verify"`, per distinguere le righe da `/credential/verify-portale`, che scrive
   sulla stessa tabella), `request` (snapshot JSON della richiesta, password **sempre
   mascherata**), `client` (l'applicativo chiamante autenticato via Basic Auth,
   `flask.g.service_account` — NON l'utente reale, quello è `login` — stesso pattern
   già in uso per `history.otp_requests.client`). `RETURNING id` → l'id inserito viene
   tenuto per le update seguenti.
2. `update.auth_credential_log_tcp` — subito dopo un check TCP di raggiungibilità del
   servizio SOAP (`check_soap_listening()`, indipendente da quello interno alla chiamata
   SOAP vera e propria — per ogni richiesta il TCP check viene quindi eseguito due volte).
   Valorizza `connection_tcp` (colonna boolean) e `failure_reason` (intermedio, se TCP down —
   viene comunque sovrascritto dall'update `_end` successiva).
3. `update.auth_credential_log_extop` — dopo la risposta SOAP (solo se il SOAP è stato
   effettivamente chiamato — saltata sul ramo TCP down), valorizza `remote_response` con
   l'output grezzo del server nel formato `"HTTP <status_code>\n<xml grezzo>"`. `NULL` se il
   servizio non restituisce nessuna risposta HTTP reale — nessun fallback al messaggio
   sintetizzato.
4. `update.auth_credential_log_end` — **sempre**, a chiusura della richiesta (successo SOAP,
   rifiuto esplicito, o fallback su cache riuscito/negato). Valorizza `auth_validation`
   (`auth_type` o `"cache"`, mai `NULL`), `success` (`1`/`0`), `failure_reason` (`NULL` solo
   su successo), `response` (JSON della risposta effettiva al client) e `code` (il valore
   finale, incluse le forme composte `1001`–`2004`).

Schema reale di `history.auth_credential_log` (colonne aggiunte in questa sessione:
`service`, `request`, `code`; colonna `client` aggiunta in una sessione successiva,
stesso 2026-08-11):
```
id                 bigint       PK, auto-incrementale
login              varchar      NOT NULL
login_at           timestamptz  NOT NULL (nessuna colonna created_at)
auth_validation    varchar      valorizzata solo da update.auth_credential_log_end
failure_reason     text         valorizzata da _tcp (intermedio) e _end (finale)
success            smallint     valorizzata solo da update.auth_credential_log_end
request_id         varchar      = client_request_id (id di correlazione del client, o X-Request-Id)
connection_tcp     boolean      valorizzata da update.auth_credential_log_tcp
remote_response    varchar      valorizzata da update.auth_credential_log_extop
updated_at         timestamptz
elapsed_time       numeric
score              integer      1=insert, 2=tcp, 3=extop, 9=end (solo indicativo)
auth_type          varchar      valorizzata dall'insert
response           varchar      JSON della risposta al client, valorizzata da _end
service            varchar      "verify" | "verify-portale"
request            varchar      snapshot JSON della richiesta (password mascherata)
code               varchar      valore finale del campo "code" della risposta
client             varchar      applicativo chiamante via Basic Auth (g.service_account),
                                valorizzata dall'insert — NON l'utente reale (quello è `login`)
```

⚠️ **Attenzione ai nomi dei parametri**: il codice deve rispecchiare esattamente i
placeholder `%(...)s` scritti nella query in `config.yaml`, typo inclusi — un
disallineamento produce `KeyError` a runtime lato `psycopg2` (loggato, fail-open, la
richiesta HTTP non si rompe ma quella singola scrittura viene persa silenziosamente).

### GET `/mit4me/auth/api/v1/health`
HTTP 200=UP | 207=DEGRADED | 503=DOWN — verifica PostgreSQL + raggiungibilità SOAP esterno.

Query param `debug` (default `false`):
- **`debug=false`**: il check SOAP usa solo `check_soap_listening()` — connessione TCP,
  nessuna richiesta HTTP/SOAP inviata
- **`debug=true`**: esegue una vera richiesta di login SOAP con login configurabile
  (`health.soap_check_login` in `config.yaml`) e password fittizia hardcoded nel
  controller — **chiamata reale** al servizio di terzi

```
GET /mit4me/auth/api/v1/health           → check SOAP: solo TCP (sicuro, nessuna chiamata reale)
GET /mit4me/auth/api/v1/health?debug=true → check SOAP: login reale con soap_check_login
```

Il campo di durata totale nella risposta si chiama `elapsed_time` (rinominato da `elapsed_ms`,
per coerenza con `credential_verify_portale`/`credential_verify`). I timer interni per singolo
check (`elapsed_ping_ms`/`elapsed_stats_ms` dentro `postgres`, `elapsed_ms` dentro `soap`)
restano invariati — sono dettagli interni, non il totale.

---

## 2FA — TOTP app / HOTP mail

Servizio 2FA integrato **nello stesso processo** di Auth API (non un servizio
separato): sette endpoint sotto lo stesso prefisso versionato (quattro di gestione
setup/verifica + `GET /otp/status` + `POST /otp/disable` + `POST /otp/requestotp`
[ex `/otp/sendotp`], quest'ultimo di retrocompatibilità legacy — vedi sezione dedicata
sotto), protetti
da **HTTP Basic Auth applicativa** (identifica l'applicativo chiamante — tabella
`public.service_accounts` — non l'utente reale, che è il campo `login` nel body
di ogni richiesta). Nessun rate limiting per ora (punto aperto).

**DDL** (`sql/otp_2fa_schema.sql`, da eseguire una tantum, non applicato dal
codice): estensione `pgcrypto` (hash/verifica password service account via
`crypt()`, così un cambio password è un semplice `UPDATE` SQL — nessun codice
applicativo coinvolto), `public.service_accounts`, `public.otp_methods`,
`config.mail_templates` (schema `config`, già usato per `config.provinces`/
`config.next_working_day()`), `history.otp_requests`.

`config.yaml`, sezione `otp2fa`:
```yaml
otp2fa:
  login_pattern: '^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]+$'   # alfanumerico, almeno 1 lettera + 1 cifra
  login_examples: ["A1B2C3", "12345X", "otp42"]
  issuer_name: "Auth API"            # mostrato nell'app authenticator
  require_mail_confirmation: false   # false: il metodo mail si attiva subito al setup
  totp_valid_window: 1               # tolleranza (step da 30s) nella verifica TOTP
  debug_code: 0                      # 0=nessuna cifra reale in history.otp_requests.code,
                                      # 1=ultime 2 cifre reali ("****13"), 2=codice completo
                                      # in chiaro (SOLO debug mirato, MAI in produzione)
```

`login_pattern`/`login_examples` (aggiunti in una sessione successiva, 2026-08-11) valgono per
**ogni** campo login-like di `/otp/*` — `login` su tutti gli endpoint, **e anche**
`requested_by_login` su `/otp/disable`. Costruiti a runtime da `build_otp_models(cfg)`
(`app/models/otp_model.py`, stesso pattern config-driven già in uso per
`credential_verify(_portale)`), chiamata in `create_app()` prima della registrazione delle route.

⚠️ **Il pattern è cambiato di nuovo, sempre nella stessa sessione**: inizialmente reso identico
a `credential_verify(_portale).login_pattern` (formato matricola `EE.../P0.../AG.../OP...`),
poi sostituito su richiesta esplicita dell'utente con un formato più permissivo e **deliberatamente
diverso** da quello delle credential: qualunque stringa alfanumerica con almeno una lettera
(ovunque nella stringa, maiuscola o minuscola) e almeno una cifra — non più un prefisso fisso.
Richiede `ConfigDict(regex_engine="python-re")` in `build_otp_models()` (lookahead nel pattern,
non supportati dal motore Rust di default di Pydantic v2 — stesso motivo per cui
`credential_verify_portale.password_pattern` lo richiede già). `credential_verify_portale`/
`credential_verify` **non** sono stati toccati: mantengono il formato matricola invariato — la
sincronia fra i due mondi (login "vera" vs login 2FA) è stata rotta di proposito.

Ogni richiesta `/otp/*` accetta anche `client_request_id` (opzionale, stesso pattern di
`/credential/verify`/`/credential/verify-portale`): id di correlazione lato client per i log
applicativi — se assente si usa il nostro `X-Request-Id`. Da non confondere con `request_id`
(intero, il riferimento alla riga `history.otp_requests` di un codice mail specifico, vedi
`/otp/sendmailotp` sotto) — nomi simili, concetti diversi.

### POST `/mit4me/auth/api/v1/otp/setup` — registra un metodo 2FA

**Request (app):** `{"login": "EEAB12345", "method": "app"}`
**Response (app):**
```json
{"message": "Scansiona il QR code...", "code": "000", "config_id": 12,
 "secret": "JBSWY3DPEHPK3PXP", "qr_code_base64": "iVBORw0KGgo...", "elapsed_time": 42.1}
```
`qr_code_base64` è un PNG in base64 senza prefisso `data:image/png;base64,`.

**Request (mail):** `{"login": "EEAB12345", "method": "mail", "template_id": 3, "mail_to": "mario.rossi@esempio.it"}`
(`template_id`/`mail_to` obbligatori con `method='mail'`, validato da Pydantic — 422 se mancanti;
`template_id` referenzia `config.mail_templates.id` — non più il `name` testuale. `template_id` qui è
solo il template usato per l'eventuale primo codice di conferma: non viene salvato da nessuna parte
come "template di default" del metodo — `public.otp_methods` non ha più una colonna template)

**Response (mail, `require_mail_confirmation=false`, default):**
`{"message": "Metodo 2FA via mail attivato", "code": "000", "config_id": 13, "elapsed_time": 55.0}`

**Response (mail, `require_mail_confirmation=true`):**
`{"message": "Codice di conferma inviato via email", "code": "000", "config_id": 13, "request_id": 78, "elapsed_time": 62.0}`
(`request_id` è l'id della riga `history.otp_requests` creata per questo invio — vedi sezione
"Log delle richieste OTP" sotto per il ciclo di vita completo di questa riga)

### POST `/mit4me/auth/api/v1/otp/setup/confirm` — conferma il setup (metodo app, o mail se richiesta conferma)

**Request:** `{"config_id": 12, "code": "123456"}`
**Response:** `{"message": "Metodo 2FA attivato", "code": "000", "elapsed_time": 18.4}`

Per `method='mail'`, applica anche il controllo di scadenza/stato del codice inviato — stesso
meccanismo di `/otp/verify` per il flusso mail-login (vedi sezione "Log delle richieste OTP"):
un codice scaduto (`code:"010"`, 401) o già utilizzato/verificato in un tentativo precedente
(`code:"240"`, 409) viene rifiutato prima ancora di controllarlo. `method='app'` non è
interessato (nessuna riga di log per quel percorso).

### POST `/mit4me/auth/api/v1/otp/sendmailotp` — richiede un nuovo codice via mail

**Request:** `{"login": "EEAB12345", "template_id": 3}`
(`template_id` **obbligatorio ad ogni chiamata**: il messaggio inviato può variare da un OTP
all'altro, non è fissato una volta per tutte al setup)

**Response:** `{"message": "Codice OTP inviato via email", "code": "000", "request_id": 78, "elapsed_time": 210.5}`

### POST `/mit4me/auth/api/v1/otp/requestotp` — setup+invio in un'unica chiamata (retrocompatibilità legacy)

⚠️ **Rinominato da `/otp/sendotp`** (sessione 2026-08-11, insieme al cambio `template_name`→
`template_id` sotto) — breaking change per client esistenti, stesso trattamento già applicato
in passato a `/verifycredential*`→`/credential/verify*`.

Endpoint per sistemi legacy che non conoscono ancora il flusso separato `/otp/setup` +
`/otp/sendmailotp`: una sola chiamata copre entrambi. **Contratto di risposta ancora diverso da
tutti gli altri endpoint `/otp/*`** — `response_id` invece di `request_id`, niente `config_id`
(l'unica differenza residua dopo il rename: il riferimento al template è tornato ad essere
`template_id` come ovunque altrove).

**Request:** `{"login": "EEAB12345", "template_id": 3, "mail_to": "mario.rossi@esempio.it"}`
(`template_id`, non più `template_name` — allineato al resto di `/otp/*`, referenzia
`config.mail_templates.id`)

**Response:** `{"code": "000", "response_id": 78, "message": "codice OTP generato", "elapsed_time": 210.5}`

Comportamento secondo lo stato del metodo 2FA per `login`:
- **Nessun metodo attivo** (assente, o presente con `status` `pending`/`disabled` — trattati
  come assenti: l'eventuale vecchia riga resta semplicemente orfana nel DB, nessun conflitto
  con l'indice unico che vincola solo le righe `active`): crea un metodo `mail` **già attivo**
  (stesso comportamento del ramo `require_mail_confirmation=false` di `/otp/setup`, indipendentemente
  dal valore reale di quella config) e invia subito un codice, come farebbe `/otp/sendmailotp`.
- **Metodo `mail` già attivo**: si comporta come `/otp/sendmailotp` (nuovo codice, counter
  incrementato). `mail_to` nella richiesta viene **ignorato** in questo caso — resta quello
  registrato al setup, non aggiornabile da qui.
- **Metodo `app` già attivo**: a differenza di `/otp/sendmailotp` (che risponderebbe
  `code:"230"`), qui la risposta è **comunque** `{"code": "000", "response_id": null, "message": "codice OTP generato"}`
  — nessun invio mail reale possibile per TOTP, ma il chiamante legacy si aspetta sempre un
  esito "codice generato" indipendentemente dal metodo realmente configurato.

`code`: `000`=ok, `210`=template non trovato, `300`=server di posta non raggiungibile.

### POST `/mit4me/auth/api/v1/otp/verify` — verifica il codice al login

**Request (app):** `{"login": "EEAB12345", "code": "111222"}`
**Request (mail):** `{"login": "EEAB12345", "code": "999888", "request_id": 78}`
(`request_id`, restituito da `/otp/sendmailotp`, obbligatorio solo per method='mail' — intero,
riferimento alla riga `history.otp_requests`, non confondere con `client_request_id` opzionale)

**Response:** `{"message": "Codice OTP valido", "code": "000", "elapsed_time": 33.9}`

**Protezione anti-replay (solo `method='app'`)**: TOTP è per natura stateless — `pyotp` verifica solo
che il codice corrisponda alla finestra temporale corrente (± `otp2fa.totp_valid_window` step da 30s),
senza alcuna protezione contro il riuso dello stesso codice più volte all'interno di quella finestra.
`public.otp_methods.last_totp_step` traccia l'ultimo timestep TOTP verificato con successo per ogni
metodo: un codice il cui timestep è **uguale o precedente** a quello già registrato viene rifiutato con
`code:"240"` (stesso codice usato per il flusso mail — "già utilizzato o non più valido"), anche se
matematicamente ancora valido per `pyotp`. Si applica sia a `/otp/verify` sia a `/otp/disable`
(condividono `_check_otp_code()`), **e** al primo codice usato su `/otp/setup/confirm` — quel codice
non è riutilizzabile subito dopo su `/otp/verify`. Il flusso mail (HOTP) non ne ha bisogno: è già
one-shot per costruzione (ogni codice è legato a una riga `history.otp_requests` specifica, marcata
`verified`/`failed` dopo il primo utilizzo).

### GET `/mit4me/auth/api/v1/otp/status` — stato 2FA di una login

**Request:** query string `?login=EEAB12345` (nessun body)
**Response:** `{"login": "EEAB12345", "status": "active", "method": "app", "elapsed_time": 9.4}`

Restituisce lo stato dell'**ultima** configurazione 2FA per `login`, qualunque sia il suo
`status` (`pending`/`active`/`disabled`) — non solo quella attualmente attiva, cosi' un
applicativo puo' distinguere "mai configurato" da "configurato ma non ancora confermato" da
"disattivato". Se non e' mai stato registrato nessun metodo: `{"status": "none", "method": null}`
(sempre `HTTP 200`, non e' un errore).

**Espone il metodo** (`app`/`mail`) della configurazione trovata — `null` solo su
`status:"none"` (nessuna riga da cui leggerlo). Reintrodotto su richiesta esplicita
dell'utente il 2026-08-11: era stato rimosso deliberatamente in una sessione precedente per
ridurre l'informazione di ricognizione disponibile a un chiamante con Basic Auth applicativa
valida (vedi sezione "2026-08-11" del changelog storico); a fronte di quel trade-off,
l'utente ha scelto di ripristinarlo. Nessuna scrittura, sola lettura — protetto comunque da
Basic Auth applicativa come tutti gli altri endpoint `/otp/*`.

### POST `/mit4me/auth/api/v1/otp/disable` — disattiva il metodo attivo (OTP sempre richiesto)

**Request (self-service, OTP dell'utente stesso):** `{"login": "EEAB12345", "code": "123456"}`
**Request (self-service, metodo mail):** `{"login": "EEAB12345", "code": "999888", "request_id": 78}`
**Request (operatore, force — OTP dell'operatore, non del target):** `{"login": "EEAB12345", "requested_by_login": "P012345", "force": true, "code": "654321"}`

**Response:** `{"message": "Metodo 2FA disattivato", "code": "000", "elapsed_time": 15.2}`

- `requested_by_login`: **legato a `force`**, non più sempre obbligatorio (cambiato in una
  sessione successiva, 2026-08-11, su richiesta esplicita dell'utente):
  - `force=false` (default): deve essere **assente/vuoto** — `422` se fornito. Il richiedente
    è per costruzione il target stesso (`login`), non ha senso chiederlo di nuovo al client.
  - `force=true`: **obbligatorio** — `422` se assente. È l'operatore/helpdesk che agisce per
    conto del target.

  In entrambi i casi viene comunque persistito nella colonna
  `public.otp_methods.requested_by_login` (valorizzata solo su disattivazione, insieme a
  `disabled_at`): se `force=false` il controller lo normalizza internamente su `login` prima
  di scrivere/loggare, così la colonna non è mai `NULL`.
- `code`: **sempre obbligatorio** (validato da Pydantic, `422` se mancante) — nessun bypass
  senza OTP, in nessun caso. `force` cambia solo **su chi** viene verificato:
  - `force=false` (default): l'OTP viene verificato su `login` (il target) — stessa identica
    prova di possesso di `/otp/verify` (stesso schema `code`/`request_id`, stesse regole
    per metodo `app` vs `mail`). L'utente disattiva il proprio 2FA con il proprio codice.
  - `force=true`: l'OTP viene verificato su `requested_by_login` **invece che** su `login` —
    un operatore/helpdesk prova la propria identita' con il *proprio* 2FA quando il target ha
    perso l'accesso al proprio (es. device smarrito, nessun codice disponibile per `login`).
    Se `requested_by_login` non ha un metodo attivo: `code:"210"`, `404` (messaggio distinto
    da "nessun metodo attivo per il target", per non confondere le due situazioni).
- Se non esiste nessun metodo attivo per `login` (il target): `code:"210"`, `404` (niente da
  disattivare) — controllato per primo, prima ancora di verificare l'OTP.

### Regola "un solo metodo attivo per login"

**Non e' piu' possibile attivare un metodo 2FA (subito, o via `/otp/setup/confirm`) se ne
esiste gia' uno attivo per la stessa login** — qualunque sia il metodo nuovo o quello gia'
attivo (`app`+`app`, `app`+`mail`, ecc.). `POST /otp/setup` rifiuta immediatamente con
`code:"225"`, `HTTP 409`, prima di generare qualunque secret/QR:
```json
{"message": "Esiste gia' un metodo 2FA attivo per questo utente: disattivarlo prima con POST /otp/disable, poi ripetere il setup",
 "code": "225"}
```
Per sostituire un metodo (es. utente che ha perso il device con l'app authenticator) il
flusso e' quindi: `POST /otp/disable` (con OTP, o `force:true`) → `POST /otp/setup` →
eventuale `POST /otp/setup/confirm`. **Non e' piu' un'unica chiamata implicita** come in una
versione precedente di questo endpoint (dove confermare un nuovo setup disattivava in
silenzio quello vecchio) — quel comportamento e' stato rimosso: l'attivazione ora presuppone
sempre che lo slot sia libero, e l'indice univoco DB (`otp_methods_one_active_per_login`)
resta come backstop fail-closed contro eventuali race condition fra il controllo applicativo
e la scrittura (in quel caso l'attivazione fallisce con `500` invece di attivarne un secondo
in silenzio).

### Log delle richieste OTP — `history.otp_requests`

Ogni codice OTP (mail o app) lascia una traccia in `history.otp_requests`, con un ciclo di vita
diverso a seconda di `purpose`. Colonna `code`: mascherata secondo `otp2fa.debug_code` (vedi
sopra), mai il codice reale in chiaro per default. Colonna `client`: applicativo chiamante
(`g.service_account`, dalla Basic Auth). Colonna `request_id`: `client_request_id` risolto
(client o il nostro `X-Request-Id`) — non l'id della riga stessa.

| `purpose` | Origine riga | Status alla creazione | Evento che lo aggiorna | Nuovo status | Note |
|---|---|---|---|---|---|
| **`register`**<br>(mail, `/otp/setup` con `require_mail_confirmation:true`) | insert in `handle_otp_setup` | `pending` | — | — | Se `POST /otp/setup/confirm` non viene mai chiamata, resta `pending` per sempre — nessun job la scade in background |
| | | | `/otp/setup/confirm` — riga già `≠ pending` | *(invariato)* | Rifiutata `code:"240"` (409), status non ritoccato |
| | | | `/otp/setup/confirm` — scaduta (`now() ≥ expires_at`) | `expired` | Controllato **prima** del codice → `code:"010"` (401) |
| | | | `/otp/setup/confirm` — codice verificato | `verified` o `failed` | Aggiornata sempre, giusto o sbagliato — un solo tentativo "conta" (one-shot) |
| **`login`**<br>(mail, `/otp/sendmailotp`) | insert in `handle_otp_sendmailotp` | `pending` | — | — | Se nessuno chiama `/otp/verify`/`/otp/disable` su quel codice, resta `pending` per sempre |
| | | | `/otp/verify` o `/otp/disable` — riga già `≠ pending` | *(invariato)* | Rifiutata `code:"240"` (409) |
| | | | `/otp/verify` o `/otp/disable` — scaduta | `expired` | Controllato prima del codice → `code:"010"` (401) |
| | | | `/otp/verify` o `/otp/disable` — codice verificato | `verified` o `failed` | One-shot: un tentativo (giusto o sbagliato) chiude la riga |
| **`verify`**<br>(app, `/otp/verify` o `/otp/disable`) | insert in `_check_otp_code()` | **già** `verified` o `failed` | — | — | Mai `pending`: TOTP non ha un "invio" precedente (il codice lo genera l'authenticator, non lo mandiamo noi) — ogni tentativo crea una riga nuova, già chiusa, mai aggiornata dopo |

`expires_at` (righe mail) = istante dell'invio + `config.mail_templates.timeout_seconds`,
calcolato una sola volta in Python, in UTC con fuso esplicito, prima dell'invio. Lo stesso
valore compare nella mail (placeholder `{{EXPIRES_AT}}`, mostrato in ora italiana,
`gg/mm/aaaa hh:mm`). Fino al 2026-10-06 era un `datetime.now()` senza fuso: nel container
(UTC) ogni codice mail nasceva già scaduto (`code:"010"`), vedi "Fuso orario" in fondo.

In sintesi: per `register`/`login` (mail) lo status segue `pending → verified/failed/expired`,
con **al massimo un** aggiornamento — dopo, la riga è bruciata (ogni riverifica trova
`≠ pending` → `240`). Per `verify` (app) non c'è ciclo: ogni chiamata crea direttamente una
riga definitiva.

### Tabella `code` (setup/confirm/sendmailotp/verify/status/disable)

| code | significato |
|---|---|
| `000` | ok |
| `020` | codice errato/non valido |
| `010` | codice scaduto |
| `240` | codice già utilizzato o non più valido (mail: codice già verificato; app: replay — stesso timestep TOTP già accettato in precedenza) |
| `210` | risorsa non trovata (config/template/richiesta OTP/metodo attivo) |
| `220` | configurazione già confermata o non più valida |
| `225` | esiste già un metodo attivo per questa login: disattivarlo prima con `POST /otp/disable` |
| `230` | metodo attivo è 'app', richiesta mail non necessaria |
| `200` | `request_id` mancante per method='mail' |
| `300` | server di posta non raggiungibile |
| `401` (HTTP, non nel body) | applicativo non autorizzato (Basic Auth) |
| `500` | errore interno durante una scrittura DB |

### Content-Type nello Swagger

Tutti i codici di risposta di tutti gli endpoint dichiarano esplicitamente
`content: {"application/json": {...}}` in `app/main.py` — inclusi `422`/`429` per i due
endpoint di autenticazione (schemi generici per errori di validazione Pydantic e per il
rate limit) e `207`/`503` per `/health` (stesso schema di `200`, valori diversi). Stesso
principio applicato ai sette endpoint `/otp/*` (incluso `401` per la Basic Auth).

---

## Ruoli PostgreSQL per l'health check

```sql
GRANT pg_monitor TO auth;                          -- PostgreSQL ≥ 10
-- oppure
GRANT pg_read_all_stats TO auth;
-- oppure (PostgreSQL ≤ 9.x)
GRANT SELECT ON pg_stat_database TO auth;
GRANT SELECT ON pg_stat_activity  TO auth;
```
Utente PostgreSQL applicativo attuale: `auth` (config.yaml, `postgres.user`) sul database `db_auth`.

---

## Flusso /credential/verify-portale

```
Client POST /credential/verify-portale  [X-Request-Id: <uuid>]
  → flask-limiter: controlla contatore IP (429 se superato)
  → Middleware: g.request_id = header o nuovo UUID4
                 log "HTTP request ricevuta" {requestid: ...}
  → Pydantic valida CredentialVerifyPortaleRequest (422 se non valido)
  → CredentialVerifyPortaleController
      insert.auth_credential_log (history, service="verify-portale")
      → SoapService
          check_soap_listening() → se DOWN: code=300, nessuna richiesta inviata
          altrimenti: XML non loggato, SSL SECLEVEL=0, POST SOAP, parse xmltodict
      update.auth_credential_log_extop (remote_response)
      update.auth_credential_log_end (sempre — auth_validation="soap", success, code)
  → Middleware: log "HTTP response inviata" {requestid: ...}
                 risposta con header X-Request-Id
  → HTTP 200 {"code": "000", "auth_validation": "soap", "description": "Accesso autorizzato."}
```

## Gestione errori HTTP

`app/middleware.py` registra un `@app.errorhandler(Exception)` globale. Le eccezioni
HTTP di Werkzeug (`HTTPException` — 404, 405, ecc.) vengono lasciate propagare con
il loro status code originale; solo le eccezioni applicative impreviste vengono
loggate e trasformate in `500 {"code": "500", "description": "Errore interno del server"}`
(stesso rename `wsdlresponse`→`description` applicato anche qui e alla risposta 429 di
rate-limit, per coerenza con gli endpoint di autenticazione).

---

## Deploy — Docker / Docker Swarm (5 nodi)

⚠️ **In produzione il file usato è `docker-compose-prod.yaml`, non
`docker-compose.yml`** — quest'ultimo (descritto sotto) è un template
locale/dev. `docker-compose-prod.yaml` è uno stack multi-servizio (nginx
`authmanager` su `5005:80`, `oldotpapi`, `robot4meV1api1`, `auth-api` sulla
porta reale **3000**) su rete Swarm esterna `produzione`. Le variabili
`GUNICORN_WORKERS`/`HEALTHCHECK_*` descritte sotto vanno impostate lì per
avere effetto reale, non su `docker-compose.yml`.

### Locale (singola macchina, sviluppo/test)

```bash
docker compose up --build      # build + avvio in foreground
docker compose up -d --build   # in background
docker compose down
```
Build e run in un solo passaggio: `docker-compose.yml` builda l'immagine dalla
sezione `build:` ad ogni `up --build`. Variabili personalizzabili via `.env`
nella stessa cartella: `IMAGE_NAME`, `VERSION_TAG`, `UID`, `GID`, `PORT`, `LOG_DIR`.

### Cluster Swarm a 5 nodi (`mit4me01`..`mit4me05`)

`docker stack deploy` **non builda mai immagini** — a differenza di
`docker compose`, ignora del tutto la sezione `build:` (solo un warning) e si
aspetta che l'immagine sia già presente sul nodo su cui Swarm schedula il
container. Senza un registry condiviso dal cluster, la build va fatta una
volta sola e distribuita esplicitamente:

```bash
# 1) Su mit4me01 — build + distribuzione automatica sugli altri 4 nodi
#    (docker save | scp | docker load, richiede SSH senza password verso
#    mit4me02..mit4me05):
./build.sh

# 2) docker stack deploy NON legge .env da solo — va sourcato a mano:
set -a; source .env; set +a

# 3) Deploy dello stack:
docker stack deploy -c docker-compose.yml auth-api
```

Varianti utili di `build.sh`:
```bash
./build.sh --local-only              # solo build locale, nessuna distribuzione
REMOTE_NODES="mit4me02 mit4me03" ./build.sh   # distribuisce solo a un sottoinsieme
SSH_USER=opadmin ./build.sh          # utente SSH diverso da quello corrente
```
Se anche un solo nodo non riceve l'immagine (SSH irraggiungibile, `scp`/`docker load`
falliti), lo script termina con `exit 1` ed elenca i nodi falliti — non procedere
con `docker stack deploy` finché il riepilogo non mostra tutti e 5 i nodi allineati:
un task rischedulato su un nodo rimasto indietro eseguirebbe silenziosamente codice
non allineato al resto dello stack.

Note operative:
- I log (`LOG_DIR:-./log-host`, bind-mount su `/var/log/mit4me/auth`) sono un path
  **locale al nodo** che riceve il task — su 5 nodi restano quindi per-nodo, non
  centralizzati, a meno di un vincolo di piazzamento (`deploy.placement.constraints`,
  presente ma commentato in `docker-compose.yml`) o di uno storage condiviso.
- `GET /health` (senza `?debug`) resta l'endpoint corretto per l'health check di
  Swarm/orchestratore — solo TCP verso il SOAP esterno, sicuro da pollare ad alta
  frequenza (già definito come `HEALTHCHECK` nel Dockerfile).

### Nginx davanti al servizio (`api.conf`)

Se esponi Auth API dietro un reverse proxy nginx (`api.conf`), imposta questi
header in ogni blocco `location` che fa `proxy_pass` verso `auth-api` —
altrimenti redirect automatici di Flask (es. `/openapi` → `/openapi/`)
perdono schema/porta reali e finiscono su `http://host/...` senza porta
(quindi porta 80 implicita):
```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $http_host;
proxy_set_header X-Forwarded-Port $server_port;
```
Lato applicativo serve anche `ProxyFix` (già configurato in
`app/main.py::create_app()`) perché Flask/Werkzeug si fidi di questi header.

### Tuning worker gunicorn / pool PostgreSQL

Il `Dockerfile` avvia gunicorn con `--workers 4` fisso. Per un carico
concorrente più alto (il servizio è I/O-bound: query PostgreSQL, chiamate
SOAP esterne), senza rebuildare l'immagine, sovrascrivi il comando nel
`docker-compose-prod.yaml`:
```yaml
command: ["sh", "-c", "exec gunicorn --workers ${GUNICORN_WORKERS:-8} --bind 0.0.0.0:${PORT:-3000} main:app"]
```

Il pool PostgreSQL (`postgres.pool_min`/`pool_max` in `app/config/config.yaml`,
default `1`/`3` — un worker gunicorn `sync` gestisce una richiesta alla volta,
quindi non serve più di 1 connessione realmente in uso per worker) è invece
**dentro l'immagine** (`COPY app/` nel Dockerfile, non un volume montato) —
una modifica lì richiede `./build.sh` + ridistribuzione, non basta un
restart del container con l'immagine già presente sul nodo. Per verificare
quale config sia realmente attiva senza dover interrogare PostgreSQL
direttamente, `GET /health` espone `pool_min`/`pool_max` nel campo
`postgres` della risposta.

### Fuso orario — container UTC, PostgreSQL Europe/Rome

Il container gira in **UTC**, la sessione PostgreSQL è in **`Europe/Rome`**, l'host
(`python run.py` in locale) è in ora italiana. Un `datetime.now()` senza fuso in Python
vale quindi ora locale in sviluppo e UTC in produzione: i bug di fuso orario si vedono
solo nel container.

Regola applicata nel codice (correzione del 2026-10-06):
- i valori scritti nel DB o confrontati con valori del DB usano `datetime.now(timezone.utc)`;
- i timestamp senza fuso letti dal DB (es. `expires_at` di `checkcache`) vengono
  localizzati esplicitamente in `Europe/Rome`;
- gli orari mostrati all'utente (es. `{{EXPIRES_AT}}` nella mail) e i log vengono
  convertiti in `Europe/Rome`.

Bug corretti con questa regola: OTP via mail sempre scaduto (`code:"010"` su
`/otp/verify`, `/otp/disable`, `/otp/setup/confirm` per il metodo `mail`) e cache di
`/credential/verify` valida circa 2 ore oltre il previsto. Il metodo `app` (TOTP) non era
coinvolto.
