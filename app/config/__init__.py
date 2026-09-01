# ============================================================
#  app/config/__init__.py
#  Carica YAML + file versioning
# ============================================================

import os
import yaml


def _read_file(path: str, fallback: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
            return content if content else fallback
    except (OSError, IOError):
        return fallback


def load_config(config_path: str = None) -> dict:
    """
    Carica la configurazione completa dell'applicazione.
    Priorità release/patch: YAML (se valorizzato) > file ./release, ./patch.

    cfg['_root'] è la root del progetto, usata da logger.py per
    risolvere logging.dir quando è un path relativo.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    )))

    if config_path is None:
        config_path = os.path.join(root, "app", "config", "config.yaml")

    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    cfg.setdefault("version", {})
    cfg["version"]["release"] = (
        cfg["version"].get("release")
        or _read_file(os.path.join(root, "release"), "v1")
    )
    cfg["version"]["patch"] = (
        cfg["version"].get("patch")
        or _read_file(os.path.join(root, "patch"), "1")
    )
    cfg["version"]["build"] = _read_file(os.path.join(root, "version"), "1")

    cfg["_root"] = root
    cfg["soap"]["template_file"] = os.path.join(
        root, cfg["soap"]["template_file"]
    )
    # logging.dir NON viene pre-concatenato qui: la risoluzione
    # (assoluto vs relativo) avviene in app/utils/logger.py
    # tramite _resolve_log_dir(cfg['logging']['dir'], cfg['_root']).

    return cfg
