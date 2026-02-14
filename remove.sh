#!/bin/bash
# Remove backdoor
[ "$(id -u)" -ne 0 ] && echo "root required" && exit 1

PAM_DIR=$(dirname $(find /lib* /usr/lib* -name "pam_unix.so" 2>/dev/null | head -1) 2>/dev/null)
rm -f ${PAM_DIR}/pam_auth.so /var/cache/ldconfig/aux-cache.log
sed -i '/pam_auth.so/d' /etc/pam.d/sshd
echo "removed"
