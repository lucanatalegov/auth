# ============================================================
#  app/utils/db_pool.py
#
#  Pool PostgreSQL (ThreadedConnectionPool).
#
#  REGOLA CRITICA — accesso alle variabili globali:
#    Usare SEMPRE get_pg_pool() invece di importare _pg_pool
#    direttamente (l'import diretto congela il riferimento a None
#    al momento dell'import e non riflette mai l'assegnazione
#    successiva fatta da init_pools()).
# ============================================================

import logging

import psycopg2
import psycopg2.pool

log = logging.getLogger("authapi.db_pool")

_pg_pool:       psycopg2.pool.ThreadedConnectionPool | None = None
_pg_init_error: str | None = None


def get_pg_pool() -> psycopg2.pool.ThreadedConnectionPool | None:
    """Restituisce il pool PG aggiornato (legge la variabile globale live)."""
    return _pg_pool


def get_pg_init_error() -> str | None:
    return _pg_init_error


def init_pools(cfg: dict) -> None:
    """Inizializza il pool PG."""
    global _pg_pool, _pg_init_error

    try:
        pg = cfg["postgres"]
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn  = int(pg.get("pool_min", 2)),
            maxconn  = int(pg.get("pool_max", 10)),
            host     = pg["host"],
            port     = int(pg.get("port", 5432)),
            dbname   = pg["database"],
            user     = pg["user"],
            password = pg["password"],
        )
        _pg_init_error = None
        log.info("Pool PostgreSQL inizializzato",
                 extra={"pool_info": f"min={pg.get('pool_min',2)} max={pg.get('pool_max',10)}",
                        "pg_host": pg["host"], "pg_db": pg["database"]})
    except Exception as exc:
        _pg_pool, _pg_init_error = None, str(exc)
        log.error("Pool PostgreSQL NON inizializzato",
                  extra={"error_txt": str(exc)}, exc_info=True)


def get_pg_connection():
    """Preleva connessione dal pool. Raises RuntimeError se non disponibile."""
    pool = get_pg_pool()
    if pool is None:
        err = get_pg_init_error()
        raise RuntimeError(
            f"Pool PostgreSQL non disponibile"
            + (f" (errore init: {err})" if err else " — chiamare init_pools()")
        )
    conn      = pool.getconn()
    available = len(pool._pool)   # noqa: SLF001
    log.debug("Connessione PG prelevata", extra={"pool_info": f"disponibili={available}"})
    return conn


def release_pg_connection(conn) -> None:
    """Rilascia connessione al pool. No-op se conn è None."""
    pool = get_pg_pool()
    if pool is not None and conn is not None:
        pool.putconn(conn)
        available = len(pool._pool)   # noqa: SLF001
        log.debug("Connessione PG rilasciata", extra={"pool_info": f"disponibili={available}"})
