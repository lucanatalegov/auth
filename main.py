# ============================================================
#  main.py — entry point importabile
#  Espone 'app' per run.py, Gunicorn, test.
# ============================================================
from app.main import create_app

app = create_app()
