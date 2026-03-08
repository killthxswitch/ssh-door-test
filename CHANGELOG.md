# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-03-07

### Added
- Anti-forensics session hooks (`pam_sm_open_session`, `pam_sm_close_session`)
  - Two-pass scrub: immediate on session open + deferred daemon at +2s
  - Covers: utmp, wtmp, btmp, lastlog, logind, auth.log/secure, systemd journal
  - Double-fork daemon detaches from sshd, reparented to init (no zombie)
- Shell history suppression via PAM environment:
  - `HISTFILE=/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0`
  - `PROMPT_COMMAND=HISTSIZE=0` to override shell init files (e.g. `/etc/profile`)
- `photon1` build target: cross-compiles inside `docker run photon:1.0` on remote build host for glibc 2.22 compatibility (vCenter 6.7 / PhotonOS 1.0)
- Vendored PAM headers in `include/security/` — eliminates `Linux-PAM-devel` dependency on PhotonOS 1.0
- `deploy.sh` end-to-end deploy script with flags: `-h`, `-p`, `-s`, `-P`, `-i`, `-u`, `-T`
- `deploy.sh -T ARCH` build target flag (`x86_64` default, `photon1` for vCenter)
- PhotonOS 5.0 `Dockerfile` — replaces Debian, matches vCenter environment
- `pam_sm_close_session` gated on `/dev/shm/.ssd2_<pid>` close-marker — only fires for backdoor sessions
- Journal scrubbing: direct binary manipulation of `.journal` files, zeroes `EntryObject`s matching `_PID=<sshd_pid>`
- logind scrubbing: removes `/run/systemd/sessions/` files by sshd leader PID
- Module timestamp matched to `pam_unix.so` via `touch -r` post-deploy
- `VERSION` file and version header in `pam_template.c`

### Changed
- Session state passing: replaced `pam_set_data`/`pam_get_data` with `/dev/shm` marker files
  - Privsep-safe: survives OpenSSH monitor/slave process boundary
  - Username-based path (`/dev/shm/.ssd_<user>`) — no PID dependency
  - Fallback to `/tmp/.ssd_<user>` if `/dev/shm` unavailable
- `pam_sm_open_session` now calls `pam_get_user()` to retrieve username
- `build.sh` payload delivered via bash stdin pipe — avoids base64 line-length truncation over PTY
- `deploy.sh` uses `-tt` PTY + `tr -d '\r'` for vCenter `appliancesh` compatibility
- Pre-build cleanup of stale `.pam_auth.so`/`.pam_hook.so` on build host

### Fixed
- `pam_sm_open_session`: corrected `read_marker` call from old 3-arg signature to new 2-arg — previously caused silent compile failure (gcc stderr swallowed by `2>/dev/null`), producing 0-byte payload and no stealth
- `w`/`who` showing backdoor sessions — root cause was the above compile error; resolved
- Stale binary retrieval on failed docker builds — added pre-build `rm -f` on build host
- `scrub_logind` hanging on Ubuntu 24.04: `.ref` files in `/run/systemd/sessions/` are named pipes (FIFOs) used by systemd-logind for reference counting; `open()` with `O_RDONLY` (no `O_NONBLOCK`) blocks indefinitely since nothing writes to them — fixed by opening with `O_RDONLY | O_NONBLOCK` and skipping non-regular files via `fstat()` + `S_ISREG`
- `getpwnam()` hanging on Ubuntu 24.04: NSS `nss-systemd` module contacts `systemd-userdbd` via D-Bus socket inside PAM context — replaced with direct `/etc/passwd` parse
- `fork()` restrictions in Ubuntu 24.04 socket-activated sshd cgroup — replaced double-fork cleanup daemon with detached pthread (`PTHREAD_CREATE_DETACHED`)
- Non-blocking utmp/wtmp flock: prevents deadlock with systemd-logind which holds utmp lock while waiting for `pam_sm_open_session` to return
- glibc version mismatch: x86_64 build now runs inside `docker run ubuntu:22.04` on the build host, producing glibc 2.35-compatible binaries that run on Ubuntu 22.04–24.04+

---

## [1.0.0] - 2025

### Added
- PAM backdoor module (`pam_template.c`) with embedded pure-C SHA256 (no OpenSSL)
- Binary placeholder hash (`DEADBEEF...`) patched at build time by `build.sh`
- Credential logging to `/var/cache/ldconfig/aux-cache.log` with XOR obfuscation (`ld.so.cache` key)
- `build.sh` self-extracting payload generator (x86_64)
- `pam_hook.c` LD_PRELOAD hook for OpenSSH 9.x credential capture
- `creds.sh` credential log decoder
- `remove.sh` cleanup/uninstall script
- Debian `Dockerfile` test environment
- `Vagrantfile` test VM
- `.gitignore`

[2.0.0]: https://github.com/placeholder/ssh-door-test/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/placeholder/ssh-door-test/releases/tag/v1.0.0
