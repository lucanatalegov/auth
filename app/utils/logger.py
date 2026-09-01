# ============================================================
#  app/utils/logger.py
#
#  Logging JSON strutturato con fuso Europe/Rome.
#
#  Formato (linee guida pt.3):
#    asctime, level, thread_id, logger, module, function, line,
#    requestid, message
#
#  Caratteristiche:
#    - requestid: letto dall'header HTTP X-Request-Id tramite
#      RequestIdFilter. None se il log non è emesso durante una
#      richiesta HTTP (es. log di startup).
#    - logging.dir può essere un path ASSOLUTO o relativo alla root
#      del progetto.
#    - logging.console_enabled (bool, default True): se False,
#      nessun log su stdout — solo file con rotation.
#    - logging.filename: nome del file di log (default api-auth.log).
#
#  REGOLA: non usare mai in extra={} le chiavi in _LOGRECORD_RESERVED.
# ============================================================

import json
import logging
import logging.handlers
import os
import re
from datetime import datetime, timezone

import pytz

from app.utils.request_context import RequestIdFilter

_ROME_TZ = pytz.timezone("Europe/Rome")

_LOGRECORD_RESERVED: frozenset[str] = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text",
    "filename", "funcName", "levelname", "levelno", "lineno",
    "message", "module", "msecs", "msg",
    "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName",
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
    """Formatter JSON strutturato con timestamp Rome e requestid."""

    def formatTime(self, record: logging.LogRecord, datefmt: str = None) -> str:  # noqa: N802
        utc_dt  = datetime.fromtimestamp(record.created, tz=timezone.utc)
        rome_dt = utc_dt.astimezone(_ROME_TZ)
        return rome_dt.isoformat(timespec="seconds")

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "asctime":   self.formatTime(record),
            "level":     record.levelname,
            "thread_name": record.threadName,
            "thread_id": record.thread,
            "logger":    record.name,
            "module":    record.module,
            "function":  record.funcName,
            "line":      record.lineno,
            "requestid": getattr(record, "requestid", None),
            "message":   _mask_sensitive(record.getMessage()),
        }
        extra = {
            k: v for k, v in record.__dict__.items()
            if k not in _LOGRECORD_RESERVED
            and k != "requestid"
            and not k.startswith("_")
        }
        if extra:
            log_entry["context"] = extra
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False, default=str)


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
      max_bytes        — dimensione massima per file (rotation)
      backup_count     — numero massimo di file ruotati conservati
      console_enabled  — bool, default True

    Applica RequestIdFilter a tutti gli handler per includere il
    campo requestid in ogni riga di log.
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

    # --- Handler su file (sempre attivo) ------------------------------------
    fh = logging.handlers.RotatingFileHandler(
        filename    = log_path,
        maxBytes    = int(log_cfg.get("max_bytes",    5 * 1024 * 1024)),
        backupCount = int(log_cfg.get("backup_count", 10)),
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
