# Auth API — contesto per Claude Code

Web service REST (Flask + flask-openapi3) per autenticazione via SOAP esterno. Pattern MVC:

- **Model** → `app/models/` (Pydantic)
- **View** → Swagger UI (flask-openapi3), su `/openapi`
- **Controller** → `app/controllers/`
- **Service** → `app/services/` (SOAP, DB)

Tre endpoint applicativi attivi: `POST /credential/verify-portale` e `POST /credential/verify`
(autenticazione, quest'ultimo copia del primo — vedi sezione dedicata sotto) e `GET /health`
(monitoraggio PostgreSQL + raggiungibilità SOAP esterno). **Dal 2026-08-10, `credential_verify_portale`
e `credential_verify` richiedono HTTP Basic Auth applicativa** (`require_service_account()`,
stesso meccanismo e stessa tabella `public.service_accounts` già in uso per `/otp/*` — non
un secondo store di credenziali separato). `GET /health` resta senza autenticazione. Il CRUD generico
(`insertdate/updatedate/deletedate/selectdate`, `data_controller.py`, `data_service.py`,
`data_model.py`, `operations.json`) e l'intera integrazione Redis (pool, health check,
config) sono stati **rimossi interamente** dal progetto — non esistono più nel codice.

## Naming attuale (post-rename, build v1.2.1)

Il progetto si chiamava "Sportello API" con endpoint `/login`, cartella `sportello-openapi3_v1_p1_v20/`, prefisso logger `sportello.*` e file di log `api-sportello.log`. È stato rinominato in modo esaustivo in **"Auth API"**:

| Elemento | Nuovo valore |
|---|---|
| Titolo/descrizione Swagger | `Auth API — Autenticazione & 2FA` (ex semplicemente `Auth API`; title e description estesi in una sessione successiva, 2026-08-11, per rendere esplicito che il servizio copre anche i 7 endpoint `/otp/*`, non solo `/credential/verify*` via SOAP — vedi `app/main.py::create_app()`, oggetto `Info(...)`) |
| Endpoint autenticazione | `POST /credential/verify-portale` (ex `/login`, poi `/verifypasswordsimot`, poi `/verifypasswordportale`, poi `/verifycredentialportale`, rinominato nuovamente in una sessione successiva 2026-08-11) |
| `base_path` | `/auth/api` (ex `/sportello/api`) |
| File/classi/funzioni auth | `credential_verify_portale_controller.py`, `credential_verify_portale_model.py`, `CredentialVerifyPortaleRequest/Response`, `handle_credential_verify_portale`, `call_credential_verify_portale_soap` (ex `verifypasswordportale_*`, poi `verifycredentialportale_*`) |
| Prefisso logger applicativi | `authapi.*` (ex `sportello.*`) |
| Chiave rate-limit | `rate_limit.credential_verify_portale_limit` (ex `login_limit`, poi `verifypasswordsimot_limit`, poi `verifypasswordportale_limit`, poi `verifycredentialportale_limit`) |
| Nome file di log | `api-auth.log` (ex `api-sportello.log`) |
| Cartella progetto | `auth-openapi3_v1_p2_v1/` |

**Non rinominato deliberatamente** (fuori scope, riferimenti legittimi non legati al brand "Sportello"):
- Il campo/parametro `login` nel body delle richieste (identificativo utente, colonna reale nel DB, usato da tutte le operazioni CRUD)
- Utente/ruolo PostgreSQL `sportello` (utente reale nel DB `mit4medb01`; rinominarlo richiede una modifica lato server, non solo nel codice)
- Cartella di log operativa `/var/log/mit4me/sportello` (path assoluto in produzione, non nel repo)
- Cartella sorella `sportello-openapi3_v1_p1_v19/` (release precedente, in `/app/mit4me/apisportello/api/`)
- Righe storiche del changelog in `SUMMARY.md` (descrivono correttamente lo stato delle build passate, non vanno riscritte)

Se in futuro viene chiesto di continuare la pulizia, questi sono i punti rimasti.

## Validazione login/password — config-driven

Pattern login/password e relativi `examples` **non sono hardcoded** in `app/models/credential_verify_portale_model.py`: sono letti da `config.yaml`, sezione `credential_verify_portale` (`login_pattern`, `login_examples`, `password_pattern`, `password_examples`). Il modello è costruito a runtime da `build_credential_verify_portale_models(cfg)`, chiamata in `create_app()` prima della registrazione della route.

Il pattern password di default usa lookahead (`(?=.*[A-Za-z])(?=.*[^A-Za-z0-9])`) per imporre "almeno una lettera + almeno un carattere speciale + lunghezza minima 8". Per questo il modello imposta `ConfigDict(regex_engine="python-re")`: il motore regex Rust di default di Pydantic v2 **non supporta i lookahead** e fa fallire la creazione del modello con `SchemaError`.

## /credential/verify — divergente da /credential/verify-portale, non più una copia identica

Ex `/verifyloginpassword` (`verifyloginpassword_*`/`VerifyLoginPassword*`), rinominato in
modo esaustivo in `verifycredential` — stesso trattamento subito da `verifypasswordportale`
→ `verifycredentialportale` (vedi tabella "Naming attuale" sopra), stessa sessione. Rinominato
di nuovo in una sessione successiva (2026-08-11, stesso trattamento esaustivo — URL, file,
funzioni, classi, chiavi `config.yaml`, colonna `service` — applicato in coppia con
`verifycredentialportale` → `/credential/verify-portale`, vedi tabella "Naming attuale" sopra)
in `/credential/verify`.

`POST /credential/verify` è nato come copia di `/credential/verify-portale`, ma ha da allora
acquisito comportamento proprio: campo `prov` opzionale (default `"--"` se assente),
calcolo hash password, sincronizzazione di una cache PostgreSQL su validazione riuscita, e
un fallback di autenticazione via cache locale quando il SOAP non riesce a validare
(`_try_cache_fallback()` in `credential_verify_controller.py` — **non ancora documentato
in dettaglio in questo file**, sviluppato nella stessa sessione del rename; vedi la memoria
di sessione per i dettagli: code composti `<origine><1-4>`, `auth_validation` sempre
valorizzato, colonne `request`/`code`/`service` in `history.auth_credential_log`). Resta
condiviso solo lo
scheletro (model factory pattern, `call_credential_verify_soap` — copia di
`call_credential_verify_portale_soap` con lo stesso pre-check `check_soap_listening()`). File
coinvolti: `app/models/credential_verify_model.py`, `app/controllers/credential_verify_controller.py`,
`call_credential_verify_soap()` in `app/services/soap_service.py`.

`config.yaml`, sezione `credential_verify`:
```yaml
login_pattern/login_examples/password_pattern/password_examples   # come credential_verify_portale
password_case: "lower"       # "upper" | "lower" | "none" — applicato prima della validazione
prov_pattern: '^[A-Z]{2}$'   # sigla provincia, obbligatoria nel body
prov_examples: ["RM", "MI", "TO"]
soap: true    # unico backend realmente implementato oggi
ldap: false   # riservato, non sviluppato
db: false     # riservato, non sviluppato (chiamato "db" e non "postgres"
              # per non confondersi con la chiave top-level postgres:)
```
**I flag `soap`/`ldap`/`db` non sono letti da nessun codice**: sono solo placeholder
documentali per un futuro dispatch multi-backend. Il servizio oggi chiama sempre e solo il
SOAP esterno reale, indipendentemente dai loro valori. `auth_type` nella risposta **non è
più hardcoded**: è letto da `config.yaml` (`credential_verify.auth_type`, default
Python `"soap"` se la chiave manca) — oggi la chiave non è presente in `config.yaml`,
quindi il valore effettivo resta sempre `"soap"` tramite il default, ma il punto
d'ingresso per renderlo configurabile c'è. Lo stesso valore viene ora scritto anche nel
DB: colonna `auth_type` in `insert.auth_credential_log` e `auth_validation` in
`update.auth_credential_log_end` (vedi sezione "Log richieste" sotto).

**`client_request_id`** (rinominato da `remote_request_id` in una sessione successiva —
stesso campo, nuovo nome per tutti gli endpoint del progetto: si confondeva col senso
opposto di "remote" già in uso per `remote_response`, la risposta del SOAP *esterno*, non
del client chiamante), **se assente dal body**: non più un placeholder statico `"none"` —
il controller usa il nostro `X-Request-Id` (`flask.g.request_id`, valorizzato dal
middleware in `before_request`, header ricevuto o UUID4 generato). Così la riga di
history/cache resta comunque correlabile ai log della richiesta anche quando il client
non passa `client_request_id`.

### Sincronizzazione cache login (solo su `code == "000"`)

`_sync_login_cache()` in `credential_verify_controller.py`, dopo un esito SOAP positivo:
1. `operations_sql.select.checkcache` (config.yaml) — esistenza = riga restituita o meno
   (non più un booleano: la query è stata riscritta dall'utente per restituire dati, es.
   `password_hash` e una scadenza calcolata via `next_working_day(data, prov)`)
2. riga presente → `operations_sql.update.updatecache`; riga assente → `operations_sql.insert.insertcache`

Le tre query sono **scritte dall'utente in config.yaml**, non generate da questo codice — il
controller si limita a passare un dizionario di parametri fisso (`login`, `password_hash`,
`client_request_id`, `last_successful_login`, `prov`, `auth_type`) e a decidere quale
statement eseguire. `auth_type` è disponibile ma oggi non referenziato da nessuna delle
tre query attuali (era presente su `insertcache` in una versione precedente di
`config.yaml`, poi rimosso dall'utente) — resta comunque nel dizionario, pronto per
quando/se servirà di nuovo.
Se una query referenzia una colonna/tabella inesistente, l'errore arriva da psycopg2 a runtime
(vedi sezione sotto sulla tabella reale) — **non validare a priori lo schema del DB dal codice
applicativo**, è responsabilità di chi scrive le query in config.

`password_hash` è SHA-256 esadecimale **senza salt** (`app/utils/security.py::hash_password`) —
adatto a correlazione/audit nei log, non a conservare credenziali in modo sicuro.

### Tabella reale `public.auth_credential_cache`

Verificata via query dirette (sola lettura) contro la produzione, colonne:
```
id, login, password_hash, created_at, last_successful_login, client_request_id, trace
```
(`client_request_id` rinominata da `remote_request_id` in una sessione successiva, sia lato
DB — `ALTER TABLE ... RENAME COLUMN`, eseguito dall'utente — sia lato codice/query in
`config.yaml`; il nome colonna nella query e il placeholder Python `%(client_request_id)s`
coincidono qui per scelta, non per requisito tecnico.)

**Nessuna colonna `prov`** — deliberatamente escluso su richiesta dell'utente: `prov` va usato
solo dentro espressioni SQL (es. in `checkcache`), mai aggiunto come colonna da scrivere in
`updatecache`/`insertcache`, a meno di indicazione esplicita futura.

⚠️ **Trigger di audit**: la tabella ha un trigger (`history.trace_func()`) che replica ogni
INSERT/UPDATE in `history.auth_credential_cache` (stessa login, struttura generica da log:
`schema_name`, `table_name`, `action`, `old_data`/`new_data` jsonb). Se il trigger fallisce
(già successo una volta per un vincolo NOT NULL sull'`id` della tabella history, poi risolto
lato DB dall'utente), l'intera transazione va in rollback — gestito correttamente dal codice
applicativo (`try/except` + `conn.rollback()` in `_sync_login_cache()`), nessuna scrittura
parziale. Se emergono di nuovo errori simili, il problema è quasi certamente nel trigger
lato database, non nel codice Python.

Esistono **due tabelle omonime**: `public.auth_credential_cache` (quella usata dall'app) e
`history.auth_credential_cache` (quella di audit, popolata dal trigger) — occhio a non
confonderle quando si ispeziona lo schema.

### Log richieste — `history.auth_credential_log` (insert + 3 update, per ogni richiesta)

Indipendente dalla cache sopra (che scrive solo su `code=="000"`): **ogni** richiesta a
`/credential/verify` scrive anche — sempre, indipendentemente dall'esito — su
`history.auth_credential_log` (tabella distinta da `history.auth_credential_cache`, stesso
schema `history` ma popolazione diversa: qui insert/update espliciti dal controller, non
un trigger). Quattro operazioni SQL in `config.yaml`, sezione `operations_sql`, tutte
fail-open (try/except + rollback, un errore viene loggato ma non interrompe la richiesta,
stesso pattern di `_sync_login_cache()`):

1. `insert.auth_credential_log` — eseguito appena la richiesta arriva, prima della
   chiamata SOAP. Parametri: `login`, `client_request_id`, `score` (variabile Python
   hardcoded a `1` nel controller, passata come parametro `%(score)s`), `auth_type`
   (letto da config, vedi sopra). `RETURNING id` → l'id inserito viene tenuto in
   `auth_credential_log_id` per le tre update seguenti.
2. `update.auth_credential_log_tcp` — eseguito subito dopo un `check_soap_listening()`
   esplicito nel controller (un secondo check TCP, indipendente da quello interno a
   `call_credential_verify_soap()` — per ogni richiesta il TCP check viene quindi
   eseguito due volte). Valorizza `connection_tcp`, colonna **boolean** (non testo): il
   controller converte `"UP"/"DOWN"` in `True`/`False` prima del bind del parametro
   `%(tcpcheck)s`.
3. `update.auth_credential_log_extop` — eseguito dopo la risposta SOAP. Valorizza
   `remote_response` con l'output **grezzo** del server (`raw_response` restituito da
   `call_credential_verify_soap()`), nel formato `"HTTP <status_code>\n<xml grezzo>"`.
   `None`/`NULL` se non è arrivata nessuna risposta HTTP reale (TCP down, eccezione di
   rete/timeout) — **nessun fallback** al testo sintetizzato `wsdlresponse`: se il
   server chiude la connessione prima di scrivere anche solo la status line HTTP
   (`RemoteDisconnected`), non c'è alcun output reale da riportare.
4. `update.auth_credential_log_end` — eseguito **solo se `code == "000"`** (a differenza
   delle prime tre, non gira su ogni richiesta). Valorizza `auth_validation` (= stesso
   valore di `auth_type`), `success` (hardcoded `1` nel controller su questo ramo) e
   `failure_reason` (hardcoded `None`/`NULL` su questo ramo, essendo per costruzione un
   caso di successo). Il caso `code != "000"` non chiama questa funzione —
   **comportamento ancora da definire** (vedi commento `# else: caso code != "000",
   comportamento da definire in seguito.` nel controller; test rimasto in sospeso,
   insieme al caso TCP down).

Tutte e quattro le operazioni vengono saltate silenziosamente (log warning, non errore)
se `auth_credential_log_id` è `None` (insert iniziale fallito) o se la relativa chiave in
`operations_sql` non è configurata.

Schema reale di `history.auth_credential_log` (scoperto per tentativi via i NOT NULL
violation restituiti da psycopg2 durante i test, non ispezionato a priori): `id, login,
login_at, request_id, score, login_source, success, connection_tcp (boolean),
remote_response, elapsed_time, updated_at, auth_type, auth_validation, failure_reason`.
**Non ha una colonna `created_at`** — usare `login_at` (valorizzata dall'insert) o
`updated_at` per calcoli di elapsed time, non `created_at` (assunzione naturale ma
sbagliata, causa `UndefinedColumn` a runtime). `login_source` resta NOT NULL ma non
pilotata da nessun parametro passato dal codice applicativo — se una query la referenzia
senza fornirla, verificare lato DB se ha un default, altrimenti l'insert/update fallisce
(fail-open: la richiesta prosegue comunque, semplicemente senza quella scrittura).
`success` invece **è** pilotata da codice, ma solo su `update.auth_credential_log_end`
(quindi solo quando si arriva a `code == "000"` — per tutte le altre richieste resta sul
default lato DB, se esiste, dato che le prime tre operazioni non la referenziano).

⚠️ **Nota storica di questa sessione**: la query `auth_credential_log_end` in
`config.yaml` ha avuto per un breve periodo un typo nel nome del parametro
(`%(succes)s` invece di `%(success)s`) mentre l'utente la scriveva — il codice deve
sempre rispecchiare esattamente i nomi dei placeholder scritti nella query in config,
typo inclusi, altrimenti `psycopg2` solleva `KeyError` a runtime (fail-open, quindi la
richiesta HTTP non si rompe, ma l'update in questione viene silenziosamente perso).

### elapsed_time

Tutti e tre gli endpoint (`credential_verify_portale`, `credential_verify`, `health`)
restituiscono `elapsed_time` (ms, tempo totale per evadere la richiesta — per
`credential_verify` include anche la sync della cache DB, non solo la chiamata SOAP).
In `health` il campo si chiamava `elapsed_ms`, rinominato per coerenza. Il campo è assente
sulle risposte 422 (la validazione fallisce prima di entrare nel controller). Tutti i codici
di risposta di tutti gli endpoint (inclusi 422/429/207/503) dichiarano esplicitamente
`content: {"application/json": ...}` nello schema OpenAPI di `app/main.py`.

## Check raggiungibilità SOAP

`app/services/soap_service.py::check_soap_listening(cfg)` verifica **solo** che l'host:porta di `soap.endpoint_url` sia in ascolto (connessione TCP aperta e chiusa subito) — nessuna richiesta HTTP/SOAP, nessun dato inviato. È condivisa da due punti:

- **`call_credential_verify_portale_soap()`**: la chiama come primo passo, prima di leggere il template e inviare la richiesta reale. Se il servizio non è in ascolto, ritorna subito `code: "300"` senza inviare le credenziali (`"700"` era il valore pre-rename, ormai stale in questa riga — schema attuale `000|500|501|200|300|503`, vedi sezione dedicata sotto).
- **`GET /health`** (default, `debug=false`): usa `check_soap_listening()` per il campo `soap` della risposta — nessuna chiamata reale, sicuro da pollare frequentemente.
- **`GET /health?debug=true`**: usa invece `_check_soap_login()` in `health_controller.py`, che chiama `call_credential_verify_portale_soap()` con login configurabile (`health.soap_check_login`) e password fittizia — **chiamata reale** al servizio di terzi, da non esporre a un monitoring automatico ad alta frequenza.

`handle_health()` accetta un parametro `debug: bool = False`; lo stato globale torna a poter essere `207 DEGRADED` (PG e SOAP non concordi), oltre a `200 UP` / `503 DOWN`.

## Schema `code` SOAP esteso — 501/503/`auth_success` (sessione 2026-08-11)

Su un fault HTTP 500 (`SOAP-ENV:Fault`), `call_credential_verify_portale_soap()` e
`call_credential_verify_soap()` (stessa logica identica su entrambe, in `soap_service.py`)
confrontano il `faultstring` con tre gruppi configurati in `config.yaml`, sezione `soap:`,
**in quest'ordine**:

1. `soap.auth_success` (lista di stringhe, nuova) — se una qualunque è contenuta nel
   `faultstring`, il fault è in realtà un **successo mascherato** (quirk noto del servizio
   esterno: alcune risposte positive arrivano comunque incapsulate in un HTTP 500 con
   `SOAP-ENV:Fault`) → `code: "000"`.
2. `soap.auth_error_string1` (default `"Errore durante l'autenticazione: matricola"`) →
   `code: "500"` = login/matricola non valida.
3. `soap.auth_error_string2` (default `"Errore durante l'autenticazione: credenziali non
   valide"`) → `code: "501"` = credenziali non valide (password errata).
4. Nessuno dei tre gruppi corrisponde → `code: "503"`.

**Schema `code` completo, aggiornato**: `000|500|501|200|300|503` (era `000|500|200|300`,
prima ancora `000|600|200|700` — vedi `README.md` per la tabella con `description`/`origine`
di ogni valore, inclusi i code composti `<origine><1-4>` del fallback su cache di
`/credential/verify`).

⚠️ **Punto di sicurezza fail-safe, non ovvio dal codice**: il ramo "nessuno dei tre gruppi
corrisponde" (`503`) **prima** di questa sessione era invece un default silenzioso a
`code: "000"` (successo) — un fault HTTP 500 non riconosciuto (typo, nuova versione del
servizio esterno, testo leggermente diverso da quello atteso) veniva trattato come
autenticazione riuscita. Corretto su richiesta esplicita dell'utente dopo revisione: un
esito non riconosciuto ora è sempre `503` (rifiuto/incertezza), mai un successo di default.

**`auth_error_string`** (singolare, vecchia chiave — usata dal codice prima di questa
sessione) è stata rimossa da `config.yaml` (`#auth_error_string: ...`, ora commentata) — non
più letta da nessuna delle due funzioni, sostituita interamente dallo schema a tre gruppi
sopra. **`soap.auth_success`** ha avuto un refuso (`auth_succes`, senza una "s") per un breve
periodo mentre l'utente scriveva la config — corretto nella stessa sessione prima che il
codice la referenziasse, quindi nessuna finestra in cui il refuso fosse effettivamente attivo
(diverso dal caso storico di `%(succes)s` in `operations_sql`, dove il refuso era già in
produzione — vedi sezione 2FA sotto).

**Impatto a valle su `credential_verify_controller.py::handle_credential_verify()`**
(l'endpoint `/credential/verify-portale`, senza cache/fallback, non è coinvolto qui): il
dispatcher che decide se tentare il fallback su cache locale (`_try_cache_fallback()`)
trattava come "rifiuto definitivo, mai fallback" solo `code == "500"`. Con l'introduzione di
`501` (anch'esso un rifiuto esplicito e definitivo delle credenziali, stesso principio di
`500`) e `503` (che invece **deve** poter attivare il fallback, essendo un esito SOAP non
determinato — stesso trattamento di `200`/`300`), sono stati necessari due aggiustamenti,
altrimenti un `501` reale avrebbe fatto **crashare** la richiesta con `KeyError` (finiva nel
ramo di fallback generico, ma `_FALLBACK_DESCRIPTIONS` non aveva — e tuttora non ha per
`501`, di proposito — una chiave per quel code):
- `501` ora trattato esattamente come `500` (nessun fallback su cache).
- `503` aggiunto a `_FALLBACK_DESCRIPTIONS` come quarto origin_code del fallback (accanto a
  `100`/`200`/`300`) — il code finale composto è quindi `5031`–`5034`.

## Gestione errori HTTP

`app/middleware.py` ha un `@app.errorhandler(Exception)` globale. Le `werkzeug.exceptions.HTTPException` (404, 405, ecc.) vengono lasciate propagare con il proprio status code; solo le eccezioni impreviste diventano `500`. Occhio a non tornare a un catch-all indiscriminato: prima del fix, qualunque 404/405 veniva riscritto in 500.

## Versionamento

`release.patch.build` calcolato in `app/config/__init__.py::load_config()`, letto da tre file nella root: `./release`, `./patch`, `./version` (quest'ultimo è il "build", auto-incrementato). Il `config.yaml` può sovrascriverli se `version.release`/`version.patch` sono valorizzati (oggi sono vuoti → si usano i file).

## Ambiente di sviluppo

**Non c'è `pip`/`venv` funzionante di default in questo ambiente** (`ensurepip` mancante dal `python3` di sistema). Per installare le dipendenze e verificare l'app:
```bash
python3 -m venv --without-pip /tmp/verify_venv
curl -sS -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
/tmp/verify_venv/bin/python3 /tmp/get-pip.py
/tmp/verify_venv/bin/pip install -r requirements.txt
```
In produzione l'app usa invece `/home/opadmin/.venv` (vedi `pystart.sh`).

**`config.yaml` non è hot-reloaded.** `load_config()` viene chiamato una sola volta,
dentro `create_app()`. L'auto-reload del dev server Flask/Werkzeug (`app.debug: true`)
osserva solo i file `.py`: modificare `config.yaml` (comprese le query in
`operations_sql`) **non** fa ripartire il processo e non ha alcun effetto sulle richieste
successive finché non si riavvia manualmente (kill del processo + `python run.py`). Le
modifiche ai file `.py`, invece, innescano regolarmente il riavvio automatico del dev
server — comportamento facile da confondere in fase di test iterativo, perché i log di
errore continuano a mostrare la versione precedente della query anche dopo aver salvato
il file corretto.

## Attenzione: dipendenze esterne reali raggiungibili da questo ambiente

Da questa sandbox sono **raggiungibili sistemi reali**, non mock:
- PostgreSQL di produzione `mit4medb01:5432/db_auth` (utente `auth`, config in `config.yaml`) — l'health check esegue query reali (sola lettura: `pg_stat_database`, `pg_stat_activity`)
- Endpoint SOAP reale `ilportaledellautomobilista.it` per l'autenticazione — chiamare `/credential/verify-portale`, `/credential/verify` o `GET /health?debug=true` invia una richiesta HTTP reale a un servizio esterno di terzi
- `/credential/verify`, su validazione SOAP riuscita (`code=="000"`), esegue anche una **scrittura reale** (INSERT o UPDATE) su `public.auth_credential_cache` — non è solo una chiamata esterna, è anche una modifica persistente al DB di produzione

`GET /health` senza `?debug=true` è invece sicuro anche a chiamate frequenti: usa solo `check_soap_listening()` (connessione TCP, nessun dato inviato), non un tentativo di login.

Prima di eseguire test end-to-end su `/credential/verify-portale` o `/health?debug=true`, tenerne conto: non sono chiamate verso un ambiente isolato/mock.

**Attenzione specifica per i test di validazione:** qualunque `login`/`password` che supera la validazione Pydantic prosegue automaticamente fino alla vera chiamata SOAP — non serve una credenziale "reale", basta rispettare il pattern configurato. Per testare la validazione in sicurezza usare **solo** input che devono fallire (attesi 422); non usare mai input che rispettano il pattern per verificare il "caso positivo", a meno che l'utente non autorizzi esplicitamente la chiamata reale.

## 2FA (TOTP app / HOTP mail) — sette endpoint, stesso processo

Integrato nello stesso processo/Flask app di Auth API (non un servizio separato),
sotto `/otp/*` (stesso prefisso versionato): `POST /otp/setup`, `PUT
/otp/setup/confirm`, `POST /otp/sendmailotp`, `POST /otp/verify`, `GET
/otp/status`, `POST /otp/disable` (questi ultimi due aggiunti in una sessione
successiva alla prima implementazione), `POST /otp/requestotp` (ex `/otp/sendotp`,
rinominato in una sessione successiva — retrocompatibilità legacy, vedi sotto).
Dettaglio completo (contratto, DDL, config.yaml, code) in `README.md`, sezione "2FA — TOTP
app / HOTP mail". Punti che *non* vanno riderivati dal codice:

- **Un solo metodo attivo per login, applicato come rifiuto esplicito, non
  più come sostituzione silenziosa**: nella prima implementazione, confermare
  un nuovo setup (`/otp/setup/confirm`) disattivava in silenzio un eventuale
  metodo già attivo (utile per il caso "utente che perde il device"). Su
  richiesta esplicita dell'utente, questo comportamento è stato **rimosso**:
  ora `POST /otp/setup` rifiuta subito (`code:"225"`, `409`) se esiste già un
  metodo attivo, *prima* di generare qualunque secret/QR — l'unico modo per
  liberare lo slot è l'esplicito `POST /otp/disable`. L'indice univoco DB
  (`otp_methods_one_active_per_login`) resta comunque come backstop
  fail-closed contro race condition fra il controllo applicativo e la
  scrittura (attivazione → `500`, non un secondo metodo attivato in silenzio).
- **`POST /otp/disable`**: `requested_by_login` (chi ha chiesto la
  disattivazione — persistito nella colonna
  `public.otp_methods.requested_by_login`, valorizzata solo su disattivazione
  insieme a `disabled_at`, e loggato) **non è più sempre obbligatorio come lo
  era inizialmente** — vedi ⚠️ più sotto (sessione 2026-08-11): ora è legato
  a `force`, vietato se `force=false`, obbligatorio se `force=true`. L'OTP
  (`code`) resta **sempre obbligatorio**, in nessun caso c'è un bypass senza
  OTP — `force` decide **su chi** viene verificato,
  tramite la stessa funzione condivisa (`_check_otp_code()` in
  `otp_controller.py`) usata da `/otp/verify` (nessuna logica duplicata,
  stessa semantica `app`/`mail`):
  - `force=false` (default): verificato su `login` (il target) — l'utente
    disattiva il proprio 2FA con il proprio codice.
  - `force=true`: verificato su `requested_by_login` **invece che** su
    `login` — un operatore/helpdesk prova la propria identità con il
    *proprio* 2FA quando il target ha perso l'accesso al proprio. Scelta
    presa **su richiesta esplicita dell'utente** dopo che la prima versione
    (force=true → nessun OTP richiesto affatto) era stata segnalata come il
    punto debole più serio dell'intero batch di modifiche: apriva un bypass
    completo del 2FA con l'unica barriera della Basic Auth applicativa. Ora
    l'azione resta sempre legata a un'identità con secondo fattore provato,
    solo non necessariamente quella del target.
- **`GET /otp/status`**: legge l'**ultima** riga `public.otp_methods` per una
  login (qualunque `status`, non filtrata su `active` come `_get_active_method()`
  usata dagli altri endpoint) — utile per un client che deve distinguere "mai
  configurato" (`status:"none"`) da "configurato ma non confermato"
  (`pending`) da "disattivato" (`disabled`). Sola lettura, nessun impatto
  sullo stato. **Espone il campo `method`** (`app`/`mail`, `null` solo su
  `status:"none"`) — inizialmente rimosso (stessa sessione precedente, per
  ridurre l'informazione di ricognizione disponibile a un chiamante con Basic
  Auth applicativa valida), **reintrodotto in una sessione successiva
  (2026-08-11) su richiesta esplicita dell'utente**: `operations_sql.select.
  otp_login_status` ora seleziona anche `method` (oltre a `status`),
  `OtpStatusResponse` ha di nuovo il campo. Trade-off di sicurezza discusso e
  accettato consapevolmente dall'utente, non una svista.

- Nato da un documento di riferimento allegato dall'utente
  (`otp/2FA_pyotp_integrazione.md` + `otp2fa.py`/`common.py`/`schema_2fa.sql`,
  cartella `otp/` non fa parte dell'app) usato **solo come esempio concettuale**
  — l'implementazione reale non riusa quel codice (stack SQLAlchemy/`api.json`/
  redis incompatibile con questo progetto), riscritta da zero seguendo i pattern
  già in uso qui (query in `config.yaml` con `%(nome)s`, pool psycopg2 esistente,
  MVC).
- Collocazione tabelle **decisa esplicitamente dall'utente**, diversa dal
  documento originale (che le raggruppava tutte in uno schema unico `otp`):
  `public.service_accounts`, `public.otp_methods` (entrambe in `public`, non
  `config` — decisione esplicita nonostante `otp_methods` contenga stato
  mutabile per utente, concettualmente diverso dai dati di riferimento statici
  già in `config`, es. `config.provinces`), `config.mail_templates`,
  `history.otp_requests`.
- Password dei service account: **hash via pgcrypto** (`crypt()`/`gen_salt('bf')`,
  colonna `passwd_hash`), non plaintext come nel documento originale — scelta
  esplicita dell'utente per poter cambiare password con un semplice `UPDATE`
  SQL, senza toccare codice Python. Verifica interamente lato query SQL
  (`operations_sql.select.otp_service_account`), non con `app/utils/security.py
  ::hash_password()` (SHA-256 senza salt, il suo stesso docstring dice
  esplicitamente "non idoneo a conservare credenziali persistenti").
- **Nessun rate limiting** sugli endpoint `/otp/*` — scelta esplicita
  dell'utente (era un "punto aperto" anche nel documento di riferimento
  originale, per il rischio di brute-force sulle 6 cifre di `/otp/verify`).
  Nota di contesto scoperta durante l'implementazione: `flask-limiter` è di
  fatto **interamente commentato/disattivato** in `app/main.py` — nessun
  endpoint del progetto (nemmeno `credential_verify_portale`/`credential_verify`,
  nonostante la documentazione li dica "rate limited") applica oggi un limite
  reale.
- **DDL non eseguito automaticamente**: `sql/otp_2fa_schema.sql` va lanciato
  manualmente sul DB (`db_auth`, stesso di tutto il resto del progetto — non un
  DB/utente separato come nel documento originale). La verifica applicativa
  (Basic Auth) è fail-closed, non fail-open, a differenza delle scritture di
  history/cache di `credential_verify_controller.py`: qui gli errori DB sono il
  dato primario dell'operazione, non un side-effect di audit.
  **Stato al 2026-08-10, verificato via query read-only**: DDL ormai applicato
  per intero — `public.service_accounts`, `public.otp_methods`,
  `config.mail_templates`, `history.otp_requests` esistono tutte (quest'ultima
  mancava ancora nelle sessioni precedenti, vedi memoria di progetto — creata
  nel frattempo dall'utente). Due colonne rinominate dall'utente rispetto allo
  schema originale in questo file: `public.service_accounts.client_id` →
  `client`, `history.otp_requests.client_id` → `client` (stessa parola per
  coincidenza, tabelle/colonne indipendenti, nessuna FK fra le due — occhio a
  non confonderle). `public.otp_methods.template_id` è stata droppata (vedi
  punto `template_id` sotto). Su `history.otp_requests`: `expires_at` è ora
  nullable e il CHECK su `purpose` include anche `'verify'` — verificato
  `pg_get_constraintdef`, entrambe le migrazioni applicate. Prima di assumere
  questo stato in una sessione futura, riverificare con una query read-only —
  in questo progetto lo stato del DDL è cambiato più volte fra una sessione e
  l'altra.
- Bug corretto durante l'implementazione (in `app/controllers/otp_controller.py`
  e `app/services/otp_service.py`, non in codice preesistente): le funzioni di
  sola lettura mancavano di `conn.rollback()` nel blocco `except` — dopo un
  errore SQL la connessione tornava al pool condiviso in stato "aborted",
  rischiando di corrompere richieste successive non correlate (incluse
  `/credential/verify`/`/health`). **Lo stesso pattern esiste ancora,
  inalterato, in `credential_verify_controller.py::_check_cache_credential`** —
  non toccato in questa sessione, possibile pulizia futura.

### Modifiche di una sessione successiva (2026-08-10) — non riderivare dal codice

- **`template_id` sostituisce `template_name`** in `/otp/setup` e
  `/otp/sendmailotp` — FK su `config.mail_templates.id`, non più su `.name`.
  **Non è (più) una colonna di `public.otp_methods`**: inizialmente lo era
  (semplice rename di `template_name`), ma si è scoperto che nessun punto del
  codice la rileggeva mai da lì (sia `/otp/setup` sia `/otp/sendmailotp`
  ricevono `template_id` nel body ad ogni chiamata — il messaggio può variare
  da un invio all'altro, non è più fissato al setup) — colonna quindi
  rimossa (`DROP COLUMN`, eseguito dall'utente). `template_id` resta solo un
  parametro di richiesta, mai persistito.
- **`request_id_ref` rinominato in `request_id`** in tutte le request/response
  `/otp/*` (`OtpSetupResponse`, `OtpSendMailResponse`, `OtpVerifyRequest`,
  `OtpDisableRequest`) — resta l'id (intero) della riga `history.otp_requests`
  per un codice mail specifico. **Da non confondere con `client_request_id`**
  (stringa, id di correlazione lato client, aggiunto in questa sessione a
  *tutti* gli endpoint `/otp/*` (sei all'epoca, sette da quando è stato
  aggiunto `/otp/sendotp` — stesso campo, stesso trattamento) con lo stesso
  pattern di `/credential/verify`/`/credential/verify-portale`, fallback su
  `flask.g.request_id`) — nomi simili, concetti indipendenti, coesistono
  nello stesso body (es. `OtpVerifyRequest`).
- **`otp2fa.debug_code`** (`config.yaml`, default `0`): quanto del codice OTP
  reale finisce in `history.otp_requests.code`. `0` → sempre `"******"`
  (default, nessuna cifra reale), `1` → mascherato con solo le ultime 2 cifre
  reali (`"****13"`), `2` → codice completo in chiaro — **livello 2 salva un
  segreto 2FA in chiaro in una tabella di history, mai in produzione**, solo
  per debug mirato; `create_app()` emette un `log.warning` esplicito
  all'avvio se `debug_code == 2`. Helper condiviso: `_masked_otp_code()` in
  `otp_controller.py`, usato sia dal flusso mail (`_insert_otp_request()`) sia
  dal nuovo log dei tentativi `app` sotto.
- **Log dei tentativi di verifica per `method='app'`** (`purpose='verify'` in
  `history.otp_requests`, nuovo — prima il metodo `app` non scriveva mai su
  questa tabella): a differenza del flusso mail, TOTP non ha un "invio"
  precedente da tracciare (il codice lo genera l'authenticator, non lo
  mandiamo noi) — ogni tentativo su `/otp/verify` o `/otp/disable` genera
  quindi una riga **nuova**, già con lo stato finale (`verified`/`failed`),
  mai `'pending'`, `counter_used`/`expires_at` sempre `NULL`. Agganciato dentro
  `_check_otp_code()` (condivisa da verify/disable), non nei singoli handler.
- **`/otp/setup/confirm` ora applica lo stesso controllo scadenza/stato** già
  presente in `_check_otp_code()` per il flusso mail-login, prima assente
  (gap segnalato e poi chiuso nella stessa sessione): per `method='mail'`, un
  codice scaduto (`code:"010"`) o un secondo tentativo su una riga già
  chiusa (`code:"240"`) vengono rifiutati **prima** di verificare l'HOTP —
  stesso comportamento one-shot già in vigore per `/otp/verify` mail (un
  tentativo, giusto o sbagliato, "brucia" la riga). Nuovo helper
  `_get_register_request()` (cerca la riga `purpose='register'` per
  `config_id`, senza bisogno che il client passi `request_id` — il confirm
  non l'ha mai richiesto). Se la riga non esiste (insert fallito fail-open
  all'invio), nessun gating: si procede solo sul controllo HOTP, comportamento
  invariato. Effetto collaterale: l'update `otp_request_verify_register`
  dentro `_activate_method()` è ormai per lo più un no-op difensivo (la riga
  è già marcata prima di arrivarci).
- **Ciclo di vita completo di `history.otp_requests.status`** per
  `purpose='register'/'login'/'verify'` (tabella dettagliata, non
  riassumibile qui senza perdere precisione): vedi `README.md`, sezione "Log
  delle richieste OTP — history.otp_requests".
- **`/credential/verify-portale` e `/credential/verify` ora dietro Basic Auth
  applicativa** — prima non richiedevano nessuna autenticazione (chiunque
  raggiungesse la rete poteva chiamarli). Stesso decorator/tabella di `/otp/*`
  (`require_service_account()`, `public.service_accounts`), aggiunto
  semplicemente sopra le route esistenti in `app/main.py`. Ordine dei
  controlli invariato rispetto agli altri endpoint decorati: flask-openapi3
  valida il body Pydantic **prima** di invocare la funzione (quindi prima
  del check Basic Auth) — un body con pattern invalido resta `422` anche
  senza credenziali applicative, non `401`. **Nessuna nuova scrittura DB
  aggiunta in questa sessione**: a differenza di `/otp/*`, questi due controller
  non tracciavano ancora `g.service_account` da nessuna parte (es. in
  `history.auth_credential_log`) — solo gate di accesso, non audit di chi ha
  chiamato. ⚠️ **Superato in una sessione successiva** (stesso 2026-08-11): è
  stata aggiunta una colonna `client` a `history.auth_credential_log`,
  valorizzata con `g.service_account` da entrambi i controller — stesso
  pattern già in uso per `history.otp_requests.client`. Vedi `README.md`,
  sezione "Log richieste su `history.auth_credential_log`", per lo schema
  aggiornato e i parametri passati da `_log_request_history()`.
- **Placeholder `{{EXPIRES_AT}}`** aggiunto al body dei template mail (oltre a
  `{{LOGIN}}`/`{{OTP}}`/`{{TIMEOUT_MINUTES}}`, `otp_service.py::send_otp_mail()`)
  — data/ora di scadenza del codice, formato `gg/mm/aaaa hh:mm`. Sostituzione
  con semplice `str.replace()`, non un template engine: un placeholder assente
  dal `body` è un no-op silenzioso, nessun errore/warning. Colto anche un
  disallineamento pre-esistente e sistemato nella stessa modifica: `expires_at`
  era ricalcolata da un `now()` Postgres *dopo* l'invio SMTP (poteva quindi
  differire di qualche secondo da quanto mostrato nella mail, se l'invio
  richiedeva tempo) — ora è calcolata **una sola volta in Python prima
  dell'invio** (`handle_otp_setup`/`handle_otp_sendmailotp`) e passata
  identica sia a `send_otp_mail()` sia all'`INSERT` su
  `history.otp_requests.expires_at` (query `insert.otp_request` in
  `config.yaml`, ora `%(expires_at)s` invece di `now() + make_interval(...)`).
  `_insert_otp_request()` ha quindi cambiato firma: parametro `timeout_seconds`
  → `expires_at`.
- **`POST /otp/sendotp`** (nuovo, endpoint settimo) — su richiesta esplicita
  dell'utente per retrocompatibilità con sistemi che non conoscono ancora il
  flusso separato `/otp/setup` + `/otp/sendmailotp`: una sola chiamata copre
  entrambi. Contratto di richiesta e risposta **deliberatamente diverso** dal
  resto di `/otp/*` (`template_name` non `template_id`, `response_id` non
  `request_id`, niente `config_id`) — scelta esplicita per compatibilità col
  chiamante legacy, non un'incoerenza da correggere.
  - Nessun metodo attivo per `login` (assente, `pending`, o `disabled` —
    questi ultimi due trattati **come assenti**, perché `_get_active_method()`
    filtra già su `status='active'`, nessuna gestione ad-hoc necessaria):
    crea un metodo `mail` **subito attivo** via `_insert_and_activate_method()`
    (stesso meccanismo del ramo `require_mail_confirmation=false` di
    `/otp/setup`, *indipendentemente* dal valore reale di quella config — il
    percorso "pending in attesa di conferma" non ha senso per un endpoint
    sincrono "dammi un codice ora") e invia subito un codice, riusando la
    stessa logica di `handle_otp_sendmailotp` (counter+1, `_insert_otp_request`
    con `purpose='login'`). Effetto collaterale noto e accettato: un'eventuale
    vecchia riga `otp_methods` pending/disabled per la stessa login resta
    orfana — nessun conflitto, l'indice unico `otp_methods_one_active_per_login`
    vincola solo le righe `active`.
  - Metodo `app` già attivo: **non** un errore (a differenza di
    `/otp/sendmailotp`, che risponde `code:"230"`) — su richiesta esplicita
    dell'utente, risponde comunque `code:"000"` con `response_id:null`, nessun
    invio mail reale (non c'è nulla da inviare per TOTP), nessuna riga
    `history.otp_requests` creata. Il chiamante legacy non deve sapere quale
    metodo sia realmente configurato.
  - Nuova query `select.otp_mail_template_by_name` (`config.yaml`) — stessa
    forma di `otp_mail_template` ma `WHERE name=%(template_name)s` invece di
    `WHERE id=%(template_id)s`; nuovo helper `_get_template_by_name()` in
    `otp_controller.py`, sorella di `_get_template()`.
- **`POST /otp/setup/confirm`** (era `PUT`) — cambiato su richiesta esplicita
  dell'utente dopo una discussione su `/otp/verify` (vedi punto sotto): `PUT`
  implica idempotenza (stessa chiamata ripetuta due volte deve avere lo
  stesso effetto), ma da quando è stato aggiunto il controllo scadenza/stato
  (sessione precedente) `confirm` è **one-shot** per `method='mail'` — una
  seconda chiamata identica trova la riga già chiusa e risponde `code:"240"`,
  un esito diverso dalla prima. Un client/proxy che assume `PUT` sicuro da
  ritentare automaticamente rischierebbe di "bruciare" un codice valido.
  `/otp/verify` è rimasto `POST` (lo era già, mai stato `PUT`) — la domanda
  originale dell'utente era se portarlo a `PUT` per coerenza con `confirm`;
  la risposta è stata l'opposto, portare `confirm` a `POST` per coerenza col
  resto di `/otp/*` (tutti gli endpoint azione, nessuna risorsa identificata
  via URL, sempre `POST`).
- **Protezione anti-replay TOTP** (`method='app'`) — nata proprio dalla
  discussione sopra su idempotenza: durante l'analisi è emerso che TOTP è
  stateless per costruzione (`pyotp.TOTP.verify()` controlla solo che il
  codice corrisponda alla finestra temporale corrente, nessuna protezione
  contro il riuso) — a differenza del flusso mail (HOTP), già one-shot
  perché ogni codice è legato a una riga `history.otp_requests` specifica.
  Nuova colonna `public.otp_methods.last_totp_step` (BIGINT, nullable):
  ultimo timestep TOTP verificato con successo per quel `config_id`. Nuovo
  `otp_service.py::verify_totp_with_step()` — necessario perché
  `pyotp.verify()` restituisce solo `True`/`False`, non **quale** step (fra
  quelli ammessi da `otp2fa.totp_valid_window`) ha prodotto il match:
  itera manualmente gli offset e usa `TOTP.timecode()` (pubblico in pyotp,
  verificato) per calcolare lo step esatto. Un secondo utilizzo dello
  stesso step (o di uno precedente) viene rifiutato con `code:"240"` —
  stesso code del flusso mail one-shot, riusato deliberatamente per
  coerenza semantica ("codice già utilizzato"), non un caso nuovo.
  Applicato in due punti: `_check_otp_code()` (rifiuta esplicitamente il
  replay, PRIMA del log) e `handle_otp_confirm()` (nessun rifiuto possibile
  qui — un config_id appena creato ha sempre `last_totp_step` NULL — ma
  persiste comunque lo step, altrimenti il primo codice usato per
  confermare resterebbe riusabile su `/otp/verify` subito dopo
  l'attivazione: **verificato dal vivo**, senza questo il primo `/otp/verify`
  con lo stesso codice del confirm avrebbe avuto successo). UPDATE
  (`operations_sql.update.otp_method_totp_step`) condizionale — solo se lo
  step nuovo è maggiore del salvato — e **fail-open**, a differenza di
  `_update_method_counter()` (HOTP) che blocca con `500`: un errore qui
  lascia riusabile solo quello specifico step per la sua finestra residua
  (pochi secondi), impatto molto minore di un counter HOTP non persistito.
  ⚠️ **Migrazione applicata con ritardo durante questa stessa sessione**: la
  colonna non esisteva ancora quando il codice è stato deployato (il
  reloader Werkzeug aveva già ricaricato `otp_controller.py` prima che
  l'utente lanciasse l'`ALTER TABLE`) — la query `select.otp_active_method`
  (usata da *tutti* gli endpoint che leggono il metodo attivo:
  verify/disable/sendmailotp/sendotp, non solo dal replay) falliva
  silenziosamente (fail-open esistente in `_get_active_method()`),
  facendo tornare "nessun metodo attivo" (`404`) anche per metodi
  realmente attivi — **regressione reale su funzionalità esistente**, non
  solo una feature nuova non ancora disponibile, per la finestra fra
  deploy del codice e applicazione della migrazione. Verificato dal vivo
  prima/dopo con lo stesso login di prova. Da tenere a mente per future
  modifiche che estendono `select.otp_active_method`: è la query più
  condivisa fra gli endpoint `/otp/*`, un suo cambiamento breaking ha un
  raggio d'azione più ampio di una query isolata a un solo endpoint.

### Modifiche di una sessione successiva (2026-08-11) — non riderivare dal codice

- **`POST /otp/sendotp` → `POST /otp/requestotp`** — rinominato su richiesta
  esplicita dell'utente, stesso trattamento esaustivo già applicato a
  `/verifycredential*` → `/credential/verify*` (funzione `handle_otp_sendotp`
  → `handle_otp_requestotp`, modelli `OtpSendOtpRequest`/`OtpSendOtpResponse`
  → `OtpRequestOtpRequest`/`OtpRequestOtpResponse`). Breaking change per
  client legacy esistenti — ironico, dato che l'endpoint esiste proprio per
  loro, ma la richiesta era esplicita.
- **`template_name` → `template_id`** nello stesso endpoint (contestuale al
  rename sopra) — allineato al resto di `/otp/*`: non più l'unico posto del
  progetto a referenziare `config.mail_templates` per nome. Query
  `operations_sql.select.otp_mail_template_by_name` e helper
  `_get_template_by_name()` **rimossi** (dead code, nessun altro chiamante):
  `handle_otp_requestotp()` ora usa `_get_template()`/`otp_mail_template`
  come tutti gli altri endpoint. Contratto di risposta resta invece
  volutamente diverso (`response_id` non `request_id`, niente `config_id`) —
  quella parte non è stata toccata.
- **`otp2fa.login_pattern`/`login_examples`** (`config.yaml`, nuovo) — inizialmente
  reso identico a `credential_verify_portale.login_pattern`/`credential_verify.
  login_pattern` (duplicato letterale fra le tre sezioni), applicato su richiesta
  esplicita dell'utente a **tutti** i campi login-like di `/otp/*`: `login`
  su `OtpSetupRequest`/`OtpSendMailRequest`/`OtpRequestOtpRequest`/
  `OtpVerifyRequest`/`OtpStatusQuery`, **e anche** `requested_by_login` su
  `OtpDisableRequest` (decisione esplicita dell'utente dopo che ho segnalato
  il conflitto con l'esempio già documentato `"helpdesk.op1"`, che non
  rispetta quel pattern — l'esempio è stato aggiornato di conseguenza).
  `app/models/otp_model.py` non è più interamente statico: i modelli con un
  campo login-like sono ora costruiti da `build_otp_models(cfg)` (stesso
  pattern già in uso per `build_credential_verify_portale_models`/
  `build_credential_verify_models`), chiamata in `create_app()` prima della
  registrazione delle route `/otp/*`. Le risposte e `OtpConfirmRequest`
  (nessun campo login, solo `config_id`) restano classi statiche invariate.
- ⚠️ **`otp2fa.login_pattern` cambiato di nuovo, sempre nella stessa sessione**
  — su ulteriore richiesta esplicita dell'utente, non è più identico a
  `credential_verify(_portale).login_pattern`: la sincronia impostata al punto
  precedente è stata rotta di proposito subito dopo. Nuovo pattern (default e
  `config.yaml`): `^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]+$` — qualunque stringa
  alfanumerica con almeno una lettera (ovunque nella stringa, non solo in
  testa, maiuscola o minuscola indifferentemente) e almeno una cifra, non più
  un prefisso fisso di lettere seguito da un numero di cifre determinato.
  `credential_verify_portale`/`credential_verify` **non toccati** — restano sul
  formato matricola `EE.../P0.../AG.../OP...`. Richiede lookahead, quindi
  ogni `create_model()` in `build_otp_models()` ha ora anche
  `__config__=ConfigDict(regex_engine="python-re")` (stesso motivo di
  `credential_verify_portale.password_pattern`: il motore Rust di default di
  Pydantic v2 non supporta i lookahead). Verificato dal vivo dopo riavvio del
  processo (`config.yaml` non è hot-reloaded): `"12A34b"`/`"EEAB12345"` → oltre
  la validazione (`401`, manca solo Basic Auth); `"ABCDEF"` (nessuna cifra) e
  `"123456"` (nessuna lettera) → `422`.
- ⚠️ **`requested_by_login` su `POST /otp/disable` — non più sempre
  obbligatorio, legato a `force`** (ulteriore richiesta esplicita
  dell'utente, stessa sessione): `force=false` (default) → deve essere
  **assente/vuoto**, `422` se fornito comunque; `force=true` → **obbligatorio**,
  `422` se assente. Prima era sempre obbligatorio indipendentemente da `force`
  (vedi sezione "sette endpoint" più sopra, ormai superata su questo punto).
  Nuovo `model_validator(mode="after")` su `OtpDisableRequest`
  (`_validate_disable_requester()` in `otp_model.py`) applica la regola,
  stesso pattern già in uso per `_validate_mail_fields()` di `OtpSetupRequest`.
  `handle_otp_disable()` (`otp_controller.py`) normalizza internamente
  `requested_by_login` su `login` quando `force=false` (`audit_requested_by`),
  **prima** di loggare e di chiamare `_disable_method()` — la colonna
  `public.otp_methods.requested_by_login` resta quindi sempre valorizzata in
  modo significativo (mai `NULL`), anche se il client non la manda più nel
  caso self-service. Verificato dal vivo (test_client): `force=false` +
  `requested_by_login` presente → `422`; `force=false` senza → oltre la
  validazione; `force=true` senza `requested_by_login` → `422`; `force=true`
  con → oltre la validazione.

## Deploy — Docker Swarm a 5 nodi (`mit4me01`..`mit4me05`), sessione 2026-08-31

⚠️ **Due file `docker-compose*` distinti, non riconciliati**: `docker-compose.yml`
(nel repo, template locale/dev, quello descritto sotto) e **`docker-compose-prod.yaml`**
(rivelato dall'utente a metà sessione — il file **realmente usato in produzione**,
non nel repo fino ad allora). Stack multi-servizio: `authmanager` (nginx, pubblica
`5005:80`, monta `api.conf`), `oldotpapi`, `robot4meV1api1` (script Python legacy),
`auth-api` (`image: auth-api:v1.2.2`, porta reale **3000**, `ports: "3002:3000"`,
rete esterna Swarm `produzione`). Nessuna sezione `build:` — solo `image:`. Per
qualunque modifica destinata alla produzione reale, il file da editare è
**`docker-compose-prod.yaml`**, non `docker-compose.yml` — un fix fatto solo su
uno dei due (es. l'healthcheck, vedi sotto) va copiato a mano sull'altro,
l'utente lo ha già dovuto fare una volta.

`docker-compose.yml` (esisteva già, vedi [[credential-verify-rename-and-soap-codes]]
per Dockerfile/build.sh iniziali) viene eseguito in due modi **non equivalenti**,
entrambi da tenere funzionanti:
- `docker compose up --build` in locale (singola macchina, sviluppo/test) — builda
  l'immagine al volo dalla sezione `build:`.
- `docker stack deploy -c docker-compose.yml <stack>` sul cluster Swarm a 5 nodi —
  **non builda mai**: Swarm ignora `build:` con un warning e si aspetta che
  l'immagine (`${IMAGE_NAME:-auth-api}:${VERSION_TAG:-v1.2.2}`) esista già in
  locale su ciascun nodo. Il comando reale usato dall'utente per attivare lo stack
  è `docker stack deploy -c <file-compose> <service>` (non `docker compose`).

Nessun registry condiviso dal cluster oggi — la distribuzione avviene con
`build.sh` (riscritto in questa sessione): build su `mit4me01`, poi
`docker save | scp | docker load` verso `mit4me02`..`mit4me05` (default,
override con `REMOTE_NODES="..."`, utente SSH con `SSH_USER=...`). Presuppone
SSH senza password già configurato verso i 4 nodi — nessuna gestione password
interattiva nello script. `--local-only` salta la distribuzione (comportamento
identico a prima di questa sessione, utile per test rapidi su una sola macchina).
Fail-**closed**, non fail-open, a differenza della maggior parte delle scritture
DB del progetto: se anche un solo nodo non riceve l'immagine (SSH irraggiungibile,
`scp`/`docker load` falliti), lo script termina con `exit 1` ed elenca i nodi
falliti — scelto deliberatamente per evitare che un task rischedulato su quel nodo
esegua in silenzio codice non allineato al resto dello stack.

`docker-compose.yml` ha ricevuto tre aggiunte, tutte per rendere il file valido
anche per lo stack Swarm senza rompere l'uso locale esistente:
- `version: "3.8"` esplicito in testa — richiesto da alcune versioni di
  `docker stack deploy` per riconoscere il file come Compose v3 (`docker compose`
  locale lo accetta comunque, al più un warning innocuo "attribute obsolete").
- `deploy.restart_policy.condition: any` — letta **solo** da `docker stack deploy`
  (equivalente Swarm di `restart: unless-stopped`, letta **solo** da `docker
  compose` locale). Nessuno dei due strumenti legge la chiave dell'altro: tenerle
  entrambe nel file è l'unico modo di coprire i due percorsi, non una ridondanza
  da ripulire.
- `deploy.placement.constraints` con un vincolo su `mit4me01` presente ma
  **commentato** — non attivo di default, disponibile se in futuro si vuole
  centralizzare i log su un nodo fisso invece di lasciarli sparsi (vedi sotto).

⚠️ **`docker stack deploy` non legge `.env` automaticamente**, a differenza di
`docker compose` — l'interpolazione delle `${VAR:-default}` nel compose usa solo
le variabili già esportate nella shell da cui parte il comando. Senza sourcare
`.env` a mano prima (`set -a; source .env; set +a`), ogni variabile ricade
silenziosamente sul proprio default — nessun errore, solo un possibile
disallineamento silenzioso (es. `VERSION_TAG` che punta a una versione diversa
da quella appena distribuita da `build.sh`).

⚠️ **Bind-mount dei log su 5 nodi**: `LOG_DIR:-./log-host` (→
`/var/log/mit4me/auth` nel container) è un path **locale al nodo** che riceve il
task — su Swarm il task può essere schedulato su uno qualunque dei 5 ad ogni
deploy/rischedulazione, quindi i log restano per-nodo, non centralizzati, a meno
del `deploy.placement.constraints` sopra (fissa il servizio a un nodo solo) o di
uno storage condiviso (NFS/volume driver di rete) — nessuna delle due è stata
attivata, solo predisposta nel file.

### `api.conf` (nginx) — fix redirect `/openapi` → porta 80

Bug reale trovato e fixato, stessa sessione. `flask-openapi3` registra la
Swagger UI con `url_prefix="/openapi"` + `rule="/"` → la route reale è
`/openapi/`, non `/openapi`: una richiesta a `/openapi` (come da
`location /openapi` in `api.conf`) genera sempre un redirect 308 automatico
di Flask/Werkzeug verso `/openapi/`. Il bug: `proxy_set_header Host $host;`
in nginx **esclude sempre la porta** dall'header `Host` inoltrato al backend
(nessun `X-Forwarded-Proto/Host/Port` era impostato) — Werkzeug costruiva
quindi il `Location` del redirect senza porta esplicita, e il browser la
interpretava come porta 80 di default, indipendentemente da quella reale.
Fix su tutti e 4 i blocchi `location` di `api.conf`: `Host $http_host`
(preserva la porta) + `X-Forwarded-Proto $scheme` + `X-Forwarded-Host
$http_host` + `X-Forwarded-Port $server_port`. **Da solo non bastava**:
serviva anche `ProxyFix` (werkzeug) aggiunto in `app/main.py::create_app()`
(`app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)`),
altrimenti Flask/Werkzeug ignora comunque gli header `X-Forwarded-*` anche
se nginx li manda. Verificato dal vivo su `172.17.22.25:5005`: `Location`
del redirect ora include la porta corretta, `200 OK` sulla Swagger UI finale.

### Tuning worker gunicorn / pool PostgreSQL — verificato sotto carico reale

Segnalazione di lentezza con 2 CPU/2G RAM assegnate al container. Diagnosi
tramite test di carico concorrente su `/health` (wall-clock via `curl -w
%{time_total}` confrontato con `elapsed_time` nel body): il gap fra i due
rivelava tempo speso in coda gunicorn (mai visto dal timer applicativo, che
parte solo dentro il controller), non lavoro lento — pattern a "onde" da N
richieste alla volta, N = numero di worker.

- **`GUNICORN_WORKERS` 4→8**: il `Dockerfile` ha `--workers 4` fisso, nessuna
  lettura di env var per quel parametro — fix applicato con un `command:`
  override in `docker-compose-prod.yaml` (bypassa il `CMD` senza rebuildare
  l'immagine), variabile configurabile senza toccare il file (default 8 se
  assente). Carico I/O-bound (query PostgreSQL, chiamate SOAP esterne — i
  worker sync passano la maggior parte del tempo bloccati in attesa, non a
  calcolare): più worker aiuta la concorrenza più delle CPU. RAM osservata
  sotto carico concorrente reale (20-40 richieste, sia `/health` semplice
  sia `/health?debug=true` con vera chiamata SOAP): solo ~380MB su 2048M
  assegnati — ampio margine, non ancora testato il percorso più pesante in
  RAM del progetto (`/otp/setup` method=`app`, QR PNG via Pillow).
- **`postgres.pool_min`/`pool_max` 5/10→1/3** per worker (`app/config/
  config.yaml`): ogni funzione che tocca il DB (`get_pg_connection()`/
  `release_pg_connection()`, tutti i controller/service) apre e rilascia la
  connessione in un blocco autonomo, mai annidato — e un worker gunicorn
  `sync` gestisce una sola richiesta alla volta, quindi non serve mai più
  di 1 connessione reale per worker in un dato istante. Il margine a 3
  (non 1 secco) lascia respiro per un eventuale bug futuro che tenga
  aperte 2 connessioni contemporaneamente. ⚠️ **`config.yaml` è copiato
  dentro l'immagine al build** (`COPY app/` nel Dockerfile), **non montato
  come volume** in `docker-compose-prod.yaml` — la modifica ha effetto solo
  dopo un rebuild+ridistribuzione dell'immagine (`build.sh`), non con un
  semplice restart del container esistente con l'immagine già presente sul
  nodo. Verificato dal vivo dopo il redeploy: `GET /health` espone ora
  `pool_min`/`pool_max` nel body di risposta (utile per verificare a
  colpo d'occhio quale config sia realmente attiva su un nodo, senza dover
  interrogare `pg_stat_activity`); sotto 20 richieste concorrenti, picco
  osservato 6 connessioni `active` / 8 totali — mai vicino al nuovo tetto
  teorico di `8 worker × pool_max:3 = 24` (era `8×10=80` prima del fix).

## Fuso orario — container UTC vs PostgreSQL Europe/Rome (sessione 2026-10-06)

⚠️ **Il container Docker gira in UTC, la sessione PostgreSQL (`SHOW timezone`) è
`Europe/Rome`, l'host (`run.py` in locale) è in CEST.** Un `datetime.now()` naive
in Python vale quindi ora locale in sviluppo ma UTC in produzione: un bug di fuso
non si riproduce mai lanciando `run.py` sull'host, solo nel container.

Bug reale trovato in produzione: **ogni OTP via mail nasceva già scaduto**.
`expires_at` era calcolata in `otp_controller.py` con `datetime.now()` naive (UTC
nel container) e passata a `INSERT ... expires_at` (colonna `timestamptz`):
Postgres la interpretava nel fuso di sessione, quindi 13:11 UTC → 13:11+02 → circa
2h nel passato rispetto a `created_at`. Effetto: `code:"010"` (scaduto) su
`/otp/verify`, `/otp/disable` e `/otp/setup/confirm` per il metodo `mail`, a
pochi secondi dall'invio; anche `{{EXPIRES_AT}}` nella mail mostrava l'ora UTC.
Metodo `app` (TOTP) non coinvolto. Verificato su `history.otp_requests` (id 22/23,
login P014452): `expires_at < created_at`. Le 3 verifiche mail riuscite di agosto
erano state fatte con `run.py` sull'host, prima del passaggio al container.

Correzioni, nessuna modifica a query/config:
- `otp_controller.py` (setup, sendmailotp, requestotp): `expires_at =
  datetime.now(timezone.utc) + timedelta(...)`, cioè un datetime con fuso
  esplicito, che psycopg2 passa con l'offset corretto.
- `otp_service.py::send_otp_mail()`: `{{EXPIRES_AT}}` formattato con
  `expires_at.astimezone(_MAIL_TZ)` (`pytz` `Europe/Rome`, stesso approccio di
  `app/utils/logger.py::_ROME_TZ`).
- `credential_verify_controller.py::_try_cache_fallback()`: stesso tipo di bug,
  sul lato opposto (in permissivo invece che restrittivo). `checkcache` restituisce
  `expires_at` come `::TIMESTAMP` naive in ora di Roma, confrontato con un
  `datetime.now()` naive UTC: la cache restava valida circa 2h oltre la mezzanotte
  prevista. Ora `expires_at` naive viene localizzato con `_DB_TZ`
  (`Europe/Rome`) e confrontato con `datetime.now(timezone.utc)`; se in futuro la
  query restituisse un `timestamptz`, il confronto resta corretto senza modifiche.

Verificati e **già corretti** (controllo su tutto il codice, stessa sessione):
`otp_service.py::verify_totp_with_step()` (con un datetime naive `pyotp.TOTP.timecode()`
usa `time.mktime()`, cioè il fuso locale del processo, coerente con `datetime.now()`),
`last_successful_login` (già `now(timezone.utc)`), `logger.py`, tutte le scadenze
calcolate lato SQL con `now()`.

**Regola per il futuro**: niente `datetime.now()` naive per valori che finiscono
nel DB o vengono confrontati con valori del DB. Usare `datetime.now(timezone.utc)`,
e localizzare esplicitamente (`Europe/Rome`) ogni timestamp naive letto dal DB.

⚠️ `otp2fa.require_mail_confirmation` è stato portato a `true` dall'utente nella
stessa sessione: anche il percorso `/otp/setup` (mail) → `/otp/setup/confirm` usa
quindi un codice con scadenza, e fallisce con `010` finché la correzione sopra
non è distribuita (`./build.sh` + `docker stack deploy`: sia il codice sia
`config.yaml` sono dentro l'immagine).

## Log applicativo — formato e regole (v1.2.3, sessione 2026-10-09)

Dettaglio in `README.md`, sezione Logging. Punti non ovvi:
- **Rotazione multi-processo**: `ConcurrentRotatingFileHandler` (`concurrent-log-handler`),
  non `RotatingFileHandler` — con 8 worker gunicorn sullo stesso file quest'ultimo
  perdeva righe a ogni rotazione. File di lock `.__api-auth.lock` accanto al log.
- **Campi fissi** di ogni riga: `asctime` (ms, Europe/Rome), `level`, `process_id`
  (PID worker), `thread_name`, `thread_id`, `logger`, `file` (path relativo alla root),
  `module`, `function`, `line`, `request_id`, `application`, `session_id`, `elapsed_ms`,
  `message`, `context` (gli `extra`).
- **`request_id`**: `client_request_id` (body/query) → header `X-Request-Id` → UUID4.
  L'header originale resta in `context.x_request_id` della riga d'ingresso.
- **`application`**: header `X-Application` → utente Basic Auth (letto PRIMA della
  verifica password) → null. `X-Application` facoltativo (`ApplicationHeader`,
  `app/models/common_model.py`), non dichiarato su `/health`.
- **`session_id`**: `client_session_id` (body/query), nessun fallback. Solo log, mai DB.
- `client_request_id`/`client_session_id`/`X-Application`: max 100 caratteri (422 se nel
  body/query; gli header vengono troncati, non rifiutati).
- **`elapsed_ms`**: 0 salvo "HTTP response inviata" (tempo totale), risposta/eccezione
  SOAP (solo la chiamata HTTP) e check TCP. SMTP non misurato.
- **Mascheramento** nei body loggati: `password`, `secret`, `qr_code_base64` ovunque;
  `code` solo nelle richieste `/otp/*` (nelle risposte è l'esito).

## Comandi utili

```bash
python3 -m py_compile $(find . -name "*.py" -not -path "*/__pycache__/*")   # verifica sintassi
python run.py                                                               # avvio locale (porta 3002)
./build.sh                                                                  # build + distribuzione sui 5 nodi Swarm
```

Nessuna suite di test automatizzata presente nel repo al momento.
