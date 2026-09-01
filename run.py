# ============================================================
#  run.py — avvio server di sviluppo
#  Produzione: gunicorn --workers 4 --bind 0.0.0.0:3002 "main:app"
# ============================================================
from app.config import load_config
from main import app

if __name__ == "__main__":
    cfg   = load_config()
    host  = cfg["app"].get("host",  "0.0.0.0")
    port  = int(cfg["app"].get("port",  3002))
    debug = bool(cfg["app"].get("debug", False))
    app.run(host=host, port=port, debug=debug)
