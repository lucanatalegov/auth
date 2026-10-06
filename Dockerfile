# syntax=docker/dockerfile:1
#
# Auth API — immagine Docker
# Build:  docker build -t auth-api:1.2.2 .
# Run:    docker run -p 3002:3002 auth-api:1.2.2
#
# NOTA: al momento della stesura di questo Dockerfile, python:3.14.7 è una
# versione molto recente — alcuni pacchetti in requirements.txt hanno
# componenti nativi (psycopg2-binary, pydantic-core, Pillow per qrcode[pil])
# e potrebbero non avere ancora wheel precompilate per l'ABI cp314 su tutte
# le architetture. Lo stage "builder" installa i toolchain di compilazione
# come fallback nel caso pip debba costruirle da sorgente; se le wheel
# esistono già vengono usate quelle e i toolchain restano comunque solo
# nello stage builder (non gonfiano l'immagine finale).

########################################
# Stage 1 — builder: risolve e installa le dipendenze Python
########################################
# Immagine di partenza per QUESTO stage soltanto — "AS builder" gli dà un nome
# richiamabile più sotto (COPY --from=builder), ma questo stage non finisce
# nell'immagine finale: serve solo a compilare/scaricare i pacchetti.
FROM python:3.14.7-slim AS builder

# build-essential = gcc/make/ecc., necessari se pip deve compilare da sorgente
# un pacchetto che non ha una wheel precompilata per questa versione/architettura
# (rischio concreto qui: Python 3.14.7 è recentissima, vedi nota sopra).
# libpq-dev = header di compilazione di libpq, richiesti per compilare
# psycopg2 nel caso non sia disponibile come wheel "binary" già pronta.
# rm -rf /var/lib/apt/lists/* nella stessa RUN (non in una RUN separata):
# tiene la cache apt fuori dal layer Docker, altrimenti resterebbe comunque
# nella cronologia dei layer anche se cancellata dopo.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Cartella di lavoro per questo stage — non è /app apposta, per non confondersi
# con la WORKDIR /app dello stage runtime più sotto (sono due filesystem
# separati, il nome uguale non avrebbe creato conflitti, ma la differenza
# rende più chiaro leggendo il file quale stage si sta guardando).
WORKDIR /build

# Copiamo SOLO requirements.txt a questo punto (non tutto il codice): così,
# se cambi un file .py ma non le dipendenze, Docker riusa la cache del layer
# "pip install" sottostante invece di re-installare tutto da capo ad ogni build.
COPY requirements.txt .

# --user installa i pacchetti in ~/.local (qui /root/.local, dato che questo
# stage gira come root) invece che nei path di sistema — così nello stage 2
# possiamo copiare quella cartella con un singolo COPY --from=builder, senza
# portarci dietro compilatori/header che sono serviti solo per costruirli.
# gunicorn non è elencato in requirements.txt (lì c'è solo il server di
# sviluppo Flask) ma è il server usato in produzione — vedi README.md/pystart.sh.
RUN pip install --no-cache-dir --user -r requirements.txt gunicorn


########################################
# Stage 2 — runtime: immagine finale, senza toolchain di compilazione
########################################
# Si riparte da python:3.14.7-slim "pulita": build-essential/libpq-dev dello
# stage 1 non esistono qui, quindi non pesano sull'immagine che verrà
# effettivamente distribuita/eseguita.
FROM python:3.14.7-slim AS runtime

# UID/GID dell'utente "authapi", personalizzabili in fase di build (default
# 1000/1000 — verificato empiricamente essere anche quanto useradd assegna
# da solo senza questi parametri, su questa immagine base pulita). Utile per
# far combaciare i permessi con un utente host, es. per bind-mount di volumi
# (logs/, config.yaml) dove i file scritti dal container devono restare
# leggibili/scrivibili anche fuori dal container:
#   docker build --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t auth-api .
ARG UID=1000
ARG GID=1000

# libpq5 = libreria runtime richiesta da psycopg2-binary (libpq-dev serviva
# solo per compilare nello stage builder — a runtime basta la sola libreria
# condivisa, non gli header/tool di sviluppo).
# groupadd/useradd: creiamo un utente non privilegiato ("authapi") — l'immagine
# di default gira come root, evitarlo è una precauzione standard (un processo
# compromesso nel container non ha comunque permessi di root nell'immagine).
# Gruppo creato esplicitamente con --gid (non lasciato al comportamento
# automatico di useradd) perché ora UID e GID sono due valori indipendenti
# passabili da fuori, non più garantito che coincidano come nel caso di default.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${GID}" authapi \
    && useradd --create-home --uid "${UID}" --gid "${GID}" authapi

WORKDIR /app

# Copia solo i pacchetti Python già installati nello stage builder (niente
# compilatori, niente cache pip, niente sorgenti scaricati per compilare) —
# questo è il punto centrale del multi-stage build: l'immagine finale ottiene
# le dipendenze pronte all'uso senza pagarne il costo di build.
COPY --from=builder /root/.local /home/authapi/.local

# Codice applicativo, copiato in modo mirato file-per-file/cartella-per-cartella
# (non un generico "COPY . ." che prenderebbe anche otp/, .claude/, __pycache__,
# CLAUDE.md/README.md — quest'ultimo in particolare descrive dettagli interni
# su DB/endpoint di produzione, da non spedire dentro un'immagine).
COPY app/                   ./app/
COPY main.py run.py         ./
COPY release patch version  ./
COPY templates/             ./templates/
COPY sql/                   ./sql/

# logs/ deve esistere perché il logger dell'app ci scrive dentro fin
# dall'avvio (vedi app/utils/logger.py); chown finale così l'utente non-root
# "authapi" può scrivere sia lì sia sul resto di /app appena copiato.
# /var/log/mit4me/auth: config.yaml (logging.dir) punta a questo path
# ASSOLUTO di produzione — setup_logging() prova a crearlo incondizionatamente
# ad ogni avvio, anche con logging.console_enabled:true; senza questo
# mkdir+chown ogni worker gunicorn crasha subito con PermissionError
# (verificato dal vivo). Se monti /var/log/mit4me da host con "-v" a runtime,
# questo chown viene comunque "coperto" dai permessi della cartella montata —
# per questo conviene far coincidere UID/GID del container (--build-arg
# UID/GID) con quelli del proprietario della cartella sull'host.
RUN mkdir -p logs /var/log/mit4me/auth \
    && chown -R authapi:authapi /app /var/log/mit4me/auth

# Dichiara /var/log/mit4me/auth come mount point esterno: un bind-mount da
# host ("docker run -v /host/path:/var/log/mit4me/auth ...") o un volume
# nominato ci scrivono sopra il file di log dell'app, così sopravvive al
# ciclo di vita del container e resta consultabile dall'host. Senza un
# -v esplicito su "docker run", Docker crea comunque qui un volume anonimo,
# preservando i permessi impostati dal chown sopra (a differenza di un layer
# normale dell'immagine, che verrebbe scartato con il container).
# Il chown sopra resta comunque necessario: se invece si monta una cartella
# host, i permessi effettivi sono quelli della cartella montata, non quelli
# dell'immagine — da qui il consiglio di far coincidere UID/GID del
# container (--build-arg UID/GID, vedi sopra) con quelli del proprietario
# della cartella sull'host.
VOLUME ["/var/log/mit4me/auth"]

# Da qui in poi il container gira come utente non privilegiato, non più root.
USER authapi
# PATH: i pacchetti pip --user finiscono in ~/.local/bin, che non è nel PATH
# di default — senza questa riga il comando "gunicorn" non verrebbe trovato.
# PYTHONDONTWRITEBYTECODE: niente file .pyc scritti nell'immagine/container
# (inutili in un container che non viene riavviato più volte sullo stesso fs).
# PYTHONUNBUFFERED: stdout/stderr di Python non bufferizzati — i log escono
# subito verso "docker logs" invece di restare in un buffer interno.
ENV PATH=/home/authapi/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Porta su cui gunicorn resta in ascolto, personalizzabile in fase di build
# (default 3002, coerente con config.yaml app.port — ma occhio: gunicorn NON
# legge affatto config.yaml per il bind, solo run.py/il server di sviluppo lo
# fa; questo PORT è indipendente e governa solo il --bind qui sotto).
# ENV (non solo ARG) perché deve restare leggibile anche a runtime, sia dallo
# script della CMD sotto sia — volendo — sovrascrivibile senza rebuildare
# l'immagine, con "docker run -e PORT=8080 -p 8080:8080 ...".
ARG PORT=3002
ENV PORT=${PORT}

# EXPOSE supporta l'espansione di ARG/ENV: qui documenta la porta realmente
# scelta in build, non più fissa a 3002 — resta comunque solo metadata, va
# sempre abbinata a "-p <porta>:<porta>" (o equivalente) su "docker run"/compose.
EXPOSE ${PORT}

# GET /health senza ?debug=true è sicuro da pollare ad alta frequenza: usa
# solo un check TCP verso il SOAP esterno, nessuna chiamata reale (vedi CLAUDE.md).
# start-period=10s: tempo di grazia iniziale per l'avvio di gunicorn prima che
# un primo fallimento conti contro il container (evita falsi "unhealthy" nei
# primi secondi di boot). Porta letta da os.environ (non hardcoded) per restare
# coerente qualunque sia il PORT effettivo, sia di build sia di run.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','3002'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/mit4me/auth/api/v1/health', timeout=3).status == 200 else 1)"

# Comando di avvio in produzione (stesso comando documentato in README.md/
# pystart.sh) — non "python run.py" (quello è solo per lo sviluppo locale,
# server Flask singolo-thread/debug).
# Forma shell con "exec" esplicito (non il classico CMD in forma JSON/exec):
# serve per poter espandere ${PORT} a runtime, letta dall'ambiente del
# container. "exec" davanti a gunicorn evita di lasciarlo come figlio della
# shell — diventa lui il PID 1, così riceve correttamente SIGTERM su
# "docker stop" invece che vederlo fermarsi solo sulla shell wrapper.
CMD ["sh", "-c", "exec gunicorn --workers 4 --bind 0.0.0.0:${PORT} main:app"]
