# SUMMARY — Auth API v1.p2.v1

## Versione corrente
| Campo   | Valore | Fonte |
|---------|--------|-------|
| Release | v1     | `./release` |
| Patch   | 2      | `./patch`   |
| Build   | 1      | `./version` (auto-incrementato) |

## Endpoint
| Metodo | URL | Descrizione |
|--------|-----|-------------|
| POST | /mit4me/auth/api/v1/verifycredentialportale | Autenticazione SOAP (rate limited) |
| GET  | /mit4me/auth/api/v1/health | Health check PostgreSQL + raggiungibilità SOAP (`?debug=true` per login reale) |
| GET  | /openapi | Swagger UI |

## Check raggiungibilità SOAP esterno

`app/services/soap_service.py::check_soap_listening(cfg)` apre una connessione TCP al
host:porta di `soap.endpoint_url` (nessuna richiesta HTTP/SOAP, nessun dato inviato) per
verificare solo che il servizio sia in ascolto. Usata in due punti:
- **`call_verifycredentialportale_soap()`**: pre-check prima di inviare la richiesta reale
  con le credenziali — se il servizio non è in ascolto, ritorna subito `code: "700"` senza
  inviare nulla.
- **`GET /health`**: nuovo query param `debug` (default `false`).
  - `debug=false` → check SOAP solo TCP (sicuro anche per polling frequente)
  - `debug=true` → login SOAP reale con `health.soap_check_login` (config.yaml) e password
    fittizia hardcoded — chiamata reale al servizio di terzi, stato globale può tornare
    `207 DEGRADED` oltre a `200 UP` / `503 DOWN`

## Modifiche build 19 (rispetto a v18)
- **Nome file di log**: `sportello.log` → **`api-sportello.log`** (configurabile in `logging.filename`)
- **X-Request-Id**: l'header HTTP viene letto da `app/middleware.py` e salvato in `flask.g.request_id`;
  `RequestIdFilter` (in `app/utils/request_context.py`) lo inietta automaticamente come campo `"requestid"`
  in **ogni riga di log** durante la richiesta — non serve passarlo manualmente in nessun `extra={}`.
  Se il client non invia l'header, viene generato un UUID4. L'header viene anche restituito nella risposta.
- **Path log assoluto o relativo**: `logging.dir` può essere un path assoluto (es. `/var/log/sportello`)
  oppure relativo alla root del progetto, gestito da `_resolve_log_dir()` in `app/utils/logger.py`.
- **Disabilitazione stdout**: nuovo parametro `logging.console_enabled` (default `true`).
  Se `false`, i log vengono scritti solo su file, nessun output su console.
- **base_path**: aggiornato a `/mit4me/sportello/api` (prefisso reale dell'ambiente di produzione)
- **postgres/redis**: parametri di connessione reali (host `mit4medb01`, redis porta `6378`)

## Formato log JSON (con requestid)
```json
{
  "asctime": "2026-06-12T09:49:24+02:00",
  "level": "INFO",
  "thread_id": 132903860176576,
  "logger": "sportello.middleware",
  "module": "middleware",
  "function": "log_request",
  "line": 36,
  "requestid": "24dc894f-9d46-400d-a431-da5c6afde458",
  "message": "HTTP request ricevuta",
  "context": {"http_method": "POST", "req_url": "..."}
}
```

## Bug risolti nelle build precedenti (riportati per memoria)
- **on_breach_response**: rimosso, non è parametro valido in flask-limiter 3.x
- **Health 503 "Pool non inizializzato"**: causato da `from db_pool import _pg_pool` che
  congela il riferimento a None. Risolto con getter `get_pg_pool()` / `get_redis_pool()`.
- **operations.json statement con `%(success)` senza `s`**: causa `ValueError: unsupported
  format character`. Ogni placeholder psycopg2 deve avere il suffisso `s`: `%(nome)s`.
- **URL 404 per prefisso mancante**: il client chiamava `/mit4me/sportello/api/...` ma il
  server registrava le route su `/sportello/api/...`. Risolto allineando `api.base_path`.

## Cronologia build
| Build | Note |
|-------|------|
| 1–11  | MVC base, pool PG+Redis, CRUD, operations.json array |
| 12–14 | elapsed_ms, TTL Redis, flask-limiter, health approfondito |
| 15–17 | Bug fix (limiter, cursori, init_pools, getter pool), rename getdate→selectdate |
| 18    | Regex login con formato AG, errori op_key significativi, base_path /mit4me |
| **19**| **api-sportello.log, X-Request-Id in ogni log, path assoluto, disabilita stdout** |
