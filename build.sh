#!/usr/bin/env bash
# ============================================================
#  build.sh — costruisce l'immagine Docker di Auth API e la
#  distribuisce sugli altri nodi dello Swarm (mit4me02..mit4me05)
#  via "docker save | scp | docker load".
#
#  Perché: "docker stack deploy" (Swarm mode) NON builda mai
#  immagini — ignora del tutto la sezione "build:" del compose
#  file con un warning e si limita a fare "pull" (o a usare la
#  cache locale se il pull fallisce, es. nessun registry
#  configurato). Senza un registry condiviso dal cluster, l'unico
#  modo per far sì che tutti i nodi abbiano l'immagine è costruirla
#  una volta sola qui (pensato per essere lanciato da mit4me01) e
#  copiarla sugli altri nodi esplicitamente — questo script fa
#  esattamente questo, di default ad ogni esecuzione.
#
#  Uso:
#    ./build.sh                              # build + distribuzione sui 5 nodi (default)
#    ./build.sh --local-only                 # solo build locale, nessuna distribuzione
#    ./build.sh --uid 1001 --gid 1001         # utente container con UID/GID diversi
#    ./build.sh --port 8080                   # gunicorn in ascolto su 8080 invece di 3002
#    ./build.sh --uid 1001 --gid 1001 --port 8080 dev   # combinabili + tag extra "dev"
#    IMAGE_NAME=foo ./build.sh
#    REMOTE_NODES="mit4me02 mit4me03" ./build.sh          # sottoinsieme dei nodi
#    SSH_USER=opadmin ./build.sh                          # utente SSH per scp/ssh
#    ./build.sh --keep-tar                                # non cancella il .tar.gz locale a fine corsa
#
#  Presuppone accesso SSH senza password (chiave già in
#  authorized_keys sui 5 nodi, o agent) dal nodo dove lanci lo
#  script verso mit4me02..mit4me05 — nessuna gestione password
#  interattiva qui. Se lo lanci da una macchina diversa da
#  mit4me01 lo script continua comunque (solo un warning): quello
#  che conta è che il daemon Docker locale sia quello con
#  l'immagine appena buildata, non il nome host in sé.
# ============================================================
set -euo pipefail

usage() {
    cat <<EOF
Uso: $(basename "$0") [--uid UID] [--gid GID] [--port PORT] [--local-only] [--keep-tar] [tag-extra]

  --uid UID       UID dell'utente "authapi" nel container (default: 1000)
  --gid GID       GID dell'utente "authapi" nel container (default: 1000)
  --port PORT     Porta su cui gunicorn resta in ascolto (default: 3002)
  --local-only    Solo build locale — salta save/scp/load sugli altri nodi
  --keep-tar      Non cancellare il .tar.gz locale generato per la distribuzione
  tag-extra       Tag aggiuntivo da assegnare alla stessa immagine (opzionale)

Variabili d'ambiente:
  IMAGE_NAME      Nome immagine (default: auth-api)
  REMOTE_NODES    Nodi verso cui distribuire, separati da spazio
                   (default: "mit4me02 mit4me03 mit4me04 mit4me05")
  SSH_USER        Utente SSH per scp/ssh verso i nodi (default: nessuno,
                   usa l'utente corrente / la config di ~/.ssh/config)
  REMOTE_TMP_DIR  Cartella remota temporanea per il .tar.gz (default: /tmp)
EOF
}

# Nomi diversi da UID/GID: in bash "UID" è una variabile builtin READONLY
# (l'UID dell'utente che esegue lo script) — riusarla qui darebbe errore.
UID_VAL=1000
GID_VAL=1000
PORT_VAL=3002
EXTRA_TAG=""
LOCAL_ONLY=0
KEEP_TAR=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uid)
            UID_VAL="$2"; shift 2 ;;
        --gid)
            GID_VAL="$2"; shift 2 ;;
        --port)
            PORT_VAL="$2"; shift 2 ;;
        --local-only)
            LOCAL_ONLY=1; shift ;;
        --keep-tar)
            KEEP_TAR=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        --)
            shift; break ;;
        -*)
            echo "Opzione sconosciuta: $1" >&2; usage >&2; exit 1 ;;
        *)
            EXTRA_TAG="$1"; shift ;;
    esac
done

# Si posiziona nella cartella dello script, indipendentemente da dove viene
# lanciato — così "docker build ." usa sempre la root del progetto come
# contesto, dove stanno Dockerfile, requirements.txt, app/, ecc.
cd "$(dirname "${BASH_SOURCE[0]}")"

# Nome immagine personalizzabile via variabile d'ambiente, default "auth-api".
IMAGE_NAME="${IMAGE_NAME:-auth-api}"

# Nodi di destinazione della distribuzione — mit4me01 (dove gira lo script)
# escluso di proposito, ha già l'immagine appena buildata in locale.
read -r -a REMOTE_NODES_ARR <<< "${REMOTE_NODES:-mit4me02 mit4me03 mit4me04 mit4me05}"
SSH_USER="${SSH_USER:-}"
REMOTE_TMP_DIR="${REMOTE_TMP_DIR:-/tmp}"

# Versione letta dagli stessi file usati a runtime da app/config/__init__.py
# (release/patch/version → "v1.2.1"), così il tag dell'immagine resta
# allineato alla versione che l'app riporta in GET /health senza doverla
# duplicare a mano qui. Nessun tag "latest": ogni build resta identificata
# solo dalla propria versione (ed eventuale tag extra passato come argomento).
RELEASE="$(tr -d '[:space:]' < release)"
PATCH="$(tr -d '[:space:]' < patch)"
BUILD="$(tr -d '[:space:]' < version)"
VERSION_TAG="${RELEASE}.${PATCH}.${BUILD}"

# Solo informativo: lo script funziona comunque se lanciato altrove, ma la
# build va sempre eseguita sul nodo il cui daemon Docker locale è quello che
# vuoi distribuire — su questo cluster è per convenzione mit4me01.
CURRENT_HOST="$(hostname -s 2>/dev/null || hostname)"
if [[ "${LOCAL_ONLY}" -eq 0 && "${CURRENT_HOST}" != "mit4me01" ]]; then
    echo "==> ATTENZIONE: hostname locale è '${CURRENT_HOST}', non 'mit4me01'." >&2
    echo "    La distribuzione userà comunque l'immagine buildata QUI — se non è" >&2
    echo "    questo il nodo di build previsto, interrompi e rilancia da mit4me01." >&2
fi

echo "==> Build immagine: ${IMAGE_NAME}:${VERSION_TAG}"
echo "    UID=${UID_VAL} GID=${GID_VAL} PORT=${PORT_VAL}"
docker build \
    --build-arg UID="${UID_VAL}" \
    --build-arg GID="${GID_VAL}" \
    --build-arg PORT="${PORT_VAL}" \
    -t "${IMAGE_NAME}:${VERSION_TAG}" .

# Tag aggiuntivo opzionale passato come ultimo argomento posizionale
# (es. ./build.sh --port 8080 dev)
if [[ -n "${EXTRA_TAG}" ]]; then
    echo "==> Tag aggiuntivo: ${IMAGE_NAME}:${EXTRA_TAG}"
    docker tag "${IMAGE_NAME}:${VERSION_TAG}" "${IMAGE_NAME}:${EXTRA_TAG}"
fi

echo "==> Fatto. Immagini disponibili:"
docker images "${IMAGE_NAME}"

if [[ "${LOCAL_ONLY}" -eq 1 ]]; then
    echo
    echo "==> --local-only: nessuna distribuzione sugli altri nodi."
    echo "==> Avvio d'esempio:"
    echo "    docker run -p ${PORT_VAL}:${PORT_VAL} ${IMAGE_NAME}:${VERSION_TAG}"
    exit 0
fi

# ------------------------------------------------------------
#  Distribuzione sugli altri nodi: docker save | scp | docker load
# ------------------------------------------------------------
# "docker save" include in un solo tar sia il tag di versione sia l'eventuale
# tag extra (se referenziano la stessa image id, come qui, il tar li porta
# entrambi senza duplicare i layer) — così ogni nodo riceve esattamente gli
# stessi tag disponibili in locale su mit4me01.
SAVE_REFS=("${IMAGE_NAME}:${VERSION_TAG}")
if [[ -n "${EXTRA_TAG}" ]]; then
    SAVE_REFS+=("${IMAGE_NAME}:${EXTRA_TAG}")
fi

TAR_BASENAME="${IMAGE_NAME}-${VERSION_TAG}.tar.gz"
TAR_PATH="/tmp/${TAR_BASENAME}"

echo
echo "==> Esporto l'immagine in ${TAR_PATH} (${SAVE_REFS[*]})..."
docker save "${SAVE_REFS[@]}" | gzip > "${TAR_PATH}"
echo "    Dimensione: $(du -h "${TAR_PATH}" | cut -f1)"

# Cleanup del tar locale a fine esecuzione, a meno di --keep-tar — via trap
# così scatta anche se un nodo fallisce e lo script esce prima della fine.
cleanup_local_tar() {
    if [[ "${KEEP_TAR}" -eq 0 && -f "${TAR_PATH}" ]]; then
        rm -f "${TAR_PATH}"
    fi
}
trap cleanup_local_tar EXIT

FAILED_NODES=()
OK_NODES=()

for node in "${REMOTE_NODES_ARR[@]}"; do
    target="${node}"
    if [[ -n "${SSH_USER}" ]]; then
        target="${SSH_USER}@${node}"
    fi

    echo
    echo "==> [${node}] Verifico raggiungibilità SSH..."
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${target}" true 2>/dev/null; then
        echo "    [${node}] SSH non raggiungibile (chiave mancante / nodo down?) — salto." >&2
        FAILED_NODES+=("${node}")
        continue
    fi

    echo "==> [${node}] Copio ${TAR_BASENAME}..."
    if ! scp -q "${TAR_PATH}" "${target}:${REMOTE_TMP_DIR}/${TAR_BASENAME}"; then
        echo "    [${node}] scp fallita — salto." >&2
        FAILED_NODES+=("${node}")
        continue
    fi

    echo "==> [${node}] docker load..."
    if ! ssh "${target}" "gunzip -c '${REMOTE_TMP_DIR}/${TAR_BASENAME}' | docker load && rm -f '${REMOTE_TMP_DIR}/${TAR_BASENAME}'"; then
        echo "    [${node}] docker load fallito sul nodo remoto — salto." >&2
        FAILED_NODES+=("${node}")
        continue
    fi

    echo "    [${node}] OK — ${IMAGE_NAME}:${VERSION_TAG} caricata."
    OK_NODES+=("${node}")
done

echo
echo "==> Riepilogo distribuzione ${IMAGE_NAME}:${VERSION_TAG}"
echo "    OK:      ${OK_NODES[*]:-nessuno}"
if [[ "${#FAILED_NODES[@]}" -gt 0 ]]; then
    echo "    FALLITI: ${FAILED_NODES[*]}" >&2
    echo >&2
    echo "==> ATTENZIONE: cluster NON allineato — i nodi falliti sopra restano" >&2
    echo "    con la vecchia immagine (o nessuna). Rilancia lo script (anche solo" >&2
    echo "    per quei nodi, con REMOTE_NODES=\"...\") prima di fare" >&2
    echo "    'docker stack deploy', altrimenti un task schedulato lì userà" >&2
    echo "    codice non allineato al resto dello stack." >&2
    exit 1
fi

echo
echo "==> Tutti i nodi allineati. Prossimo passo:"
echo "    docker stack deploy -c docker-compose.yml <nome-stack>"
