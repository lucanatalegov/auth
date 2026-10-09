# ============================================================
#  app/utils/logger.py
#
#  Logging JSON strutturato con fuso Europe/Rome.
#
#  Formato (linee guida pt.3):
#    asctime, level, process_id, thread_name, thread_id, logger, file, module,
#    function, line, request_id, application, session_id, elapsed_ms,
#    message
#
#  Caratteristiche:
#    - request_id: letto dall'header HTTP X-Request-Id tramite
#      RequestIdFilter. None se il log non è emesso durante una
#      richiesta HTTP (es. log di startup).
#    - logging.dir può essere un path ASSOLUTO o relativo alla root
#      del progetto.
#    - logging.console_enabled (bool, default True): se False,
#      nessun log su stdout — solo file.
#    - Rotazione con ConcurrentRotatingFileHandler (concurrent-log-handler),
#      non RotatingFileHandler: con piu' worker gunicorn sullo stesso file,
#      quest'ultimo fa ruotare il file a ogni processo per conto proprio
#      (righe perse, worker che scrivono sul file gia' ruotato). La versione
#      concurrent coordina scritture e rotazione fra processi con un file di
#      lock (.__<nome>.lock) nella stessa cartella del log.
#    - logging.filename: nome del file di log (default api-auth.log).
#
#  REGOLA: non usare mai in extra={} le chiavi in _LOGRECORD_RESERVED.
# ============================================================

import json
import logging
import os
import re
from datetime import datetime, timezone

import pytz
from concurrent_log_handler import ConcurrentRotatingFileHandler

from app.utils.request_context import RequestIdFilter

_ROME_TZ = pytz.timezone("Europe/Rome")

# Root del progetto (app/utils/logger.py → due livelli sopra app/): base per
# il campo "file", path relativo del sorgente che ha emesso la riga.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_LOGRECORD_RESERVED: frozenset[str] = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text",
    "filename", "funcName", "levelname", "levelno", "lineno",
    "message", "module", "msecs", "msg",
    "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName",
    "taskName",  # Python >= 3.12: task asyncio, sempre None qui (Flask/gunicorn sync)
})

_MASK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'("password"\s*:\s*)"([^"]*)"', re.IGNORECASE), r'\1"********"'),
    (re.compile(r'(<[^>]*[Pp]assword[^>]*>)[^<]*(</)',           re.IGNORECASE), r'\1********\2'),
    (re.compile(r'_MYPASSWORD_',                                  re.IGNORECASE), '********'),
]


def _mask_sensitive(text: str) -> str:
    for pattern, replacement in _MASK_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    """Formatter JSON strutturato con timestamp Rome e request_id."""

    def formatTime(self, record: logging.LogRecord, datefmt: str = None) -> str:  # noqa: N802
        utc_dt  = datetime.fromtimestamp(record.created, tz=timezone.utc)
        rome_dt = utc_dt.astimezone(_ROME_TZ)
        return rome_dt.isoformat(timespec="milliseconds")

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "asctime":   self.formatTime(record),
            "level":     record.levelname,
            "process_id": record.process,   # PID del worker gunicorn
            "thread_name": record.threadName,
            "thread_id": record.thread,
            "logger":    record.name,
            "file":      _relative_path(record.pathname),
            "module":    record.module,
            "function":  record.funcName,
            "line":      record.lineno,
            "request_id": getattr(record, "request_id", None),
            "application": getattr(record, "application", None),
            "session_id": getattr(record, "session_id", None),
            # 0 salvo: risposta HTTP al client (tempo totale, middleware) e
            # risposta di un servizio esterno (SOAP, check TCP) — passato
            # come extra={"elapsed_ms": ...} da chi emette la riga.
            "elapsed_ms": getattr(record, "elapsed_ms", None) or 0,
            "message":   _mask_sensitive(record.getMessage()),
        }
        extra = {
            k: v for k, v in record.__dict__.items()
            if k not in _LOGRECORD_RESERVED
            and k not in ("request_id", "application", "session_id", "elapsed_ms")
            and not k.startswith("_")
        }
        if extra:
            log_entry["context"] = extra
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False, default=str)


def _relative_path(pathname: str) -> str:
    """Path del sorgente relativo alla root del progetto (es.
    "app/services/soap_service.py"). Fuori dal progetto (librerie: werkzeug,
    gunicorn, ...) resta il path assoluto, invece di una catena di "../"."""
    path = os.path.abspath(pathname)
    if path.startswith(_PROJECT_ROOT + os.sep):
        return os.path.relpath(path, _PROJECT_ROOT)
    return pathname


def _resolve_log_dir(log_dir: str, root: str) -> str:
    """
    Risolve il path della cartella di log.
    Path assoluto → usato tal quale. Path relativo → relativo alla root.
    """
    if os.path.isabs(log_dir):
        return log_dir
    return os.path.join(root, log_dir)


def setup_logging(cfg: dict) -> None:
    """
    Inizializza il sistema di logging dell'applicazione.

    Parametri letti da cfg['logging']:
      level            — livello minimo (default INFO)
      dir              — cartella log: assoluta o relativa alla root
      filename         — nome file di log (default api-auth.log)
      max_bytes        — dimensione massima per file (rotazione)
      backup_count     — numero massimo di file ruotati conservati
      console_enabled  — bool, default True

    Applica RequestIdFilter a tutti gli handler per includere il
    campo request_id in ogni riga di log.
    """
    log_cfg = cfg["logging"]
    level   = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)

    log_dir = _resolve_log_dir(log_cfg["dir"], cfg.get("_root", "."))
    os.makedirs(log_dir, exist_ok=True)

    filename = log_cfg.get("filename", "api-auth.log")
    log_path = os.path.join(log_dir, filename)

    formatter      = JsonFormatter()
    request_filter = RequestIdFilter()

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # --- Handler su file (sempre attivo, rotazione sicura fra processi) ----
    fh = ConcurrentRotatingFileHandler(
        filename    = log_path,
        maxBytes    = int(log_cfg.get("max_bytes",    5 * 1024 * 1024)),
        backupCount = int(log_cfg.get("backup_count", 5)),
        encoding    = "utf-8",
    )
    fh.setFormatter(formatter)
    fh.setLevel(level)
    fh.addFilter(request_filter)
    root.addHandler(fh)

    # --- Handler su console (disabilitabile da config) ----------------------
    console_enabled = bool(log_cfg.get("console_enabled", True))
    if console_enabled:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        ch.setLevel(level)
        ch.addFilter(request_filter)
        root.addHandler(ch)

    logging.getLogger("authapi.utils.logger").info(
        "Logging inizializzato",
        extra={
            "log_path":        log_path,
            "log_dir_is_abs":  os.path.isabs(log_cfg["dir"]),
            "console_enabled": console_enabled,
        },
    )
