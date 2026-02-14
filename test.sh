#!/bin/bash
#
# Quick verification - compile and check for obvious issues
#

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${YELLOW}[*] Testing compilation...${NC}"

# Check dependencies
for cmd in gcc strip; do
    if ! command -v $cmd &>/dev/null; then
        echo -e "${RED}[!] Missing: $cmd${NC}"
        exit 1
    fi
done

# Compile
gcc -fPIC -shared -O3 -s -fvisibility=hidden \
    -o pam_auth.so pam_auth.c \
    -lcrypto -lpam 2>&1

if [ ! -f pam_auth.so ]; then
    echo -e "${RED}[!] Compilation failed${NC}"
    exit 1
fi

strip --strip-all pam_auth.so

echo -e "${GREEN}[+] Compiled successfully${NC}"
echo ""

echo -e "${YELLOW}[*] Binary analysis...${NC}"
ls -la pam_auth.so
echo ""

echo -e "${YELLOW}[*] Checking for leaked strings...${NC}"
STRINGS_OUT=$(strings pam_auth.so | grep -iE "password|secret|backdoor|elliot" || true)

if [ -n "$STRINGS_OUT" ]; then
    echo -e "${RED}[!] WARNING: Found suspicious strings:${NC}"
    echo "$STRINGS_OUT"
else
    echo -e "${GREEN}[+] No obvious password strings found${NC}"
fi
echo ""

echo -e "${YELLOW}[*] Exported symbols...${NC}"
nm -D pam_auth.so 2>/dev/null || objdump -T pam_auth.so | grep -E "pam_sm_"
echo ""

echo -e "${YELLOW}[*] File type...${NC}"
file pam_auth.so
echo ""

echo -e "${GREEN}[+] All checks passed${NC}"
echo ""
echo -e "${YELLOW}To deploy in Docker:${NC}"
echo "  docker build -t ssh-door-test ."
echo "  docker run -d -p 2222:22 --name ssh-test ssh-door-test"
echo "  ssh root@localhost -p 2222  # password: elliot"
echo ""
echo -e "${YELLOW}To deploy in Vagrant:${NC}"
echo "  vagrant up"
echo "  vagrant ssh -c 'sudo /vagrant/install.sh'"
echo "  ssh vagrant@localhost -p 2222  # password: elliot"
