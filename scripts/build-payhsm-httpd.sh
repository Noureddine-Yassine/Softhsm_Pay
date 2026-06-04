#!/bin/sh
# Compile payhsm-httpd + lib objects (si Makefile absent)
set -e
chmod +x "$0" 2>/dev/null || true
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PH="$ROOT/src/lib/payhsm"
OUT="$PH/bin/payhsm-httpd"
mkdir -p "$PH/bin"

OBJS=""
for f in \
  defense/defense.c \
  keymanager/xor_fragment.c keymanager/integrity.c keymanager/mutation.c \
  keymanager/lmk_store.c keymanager/kek_provider.c keymanager/key_vault.c \
  payment/pin.c payment/mac.c payment/emv.c payment/key_exchange.c \
  payhsm_core.c \
  payhsm_switch.c \
  bin/payhsm-httpd.c
do
  o="$PH/${f%.c}.o"
  echo "CC $f"
  gcc -Wall -Wextra -I"$PH" -c "$PH/$f" -o "$o"
  OBJS="$OBJS $o"
done

echo "LD payhsm-httpd"
gcc -o "$OUT" $OBJS -lssl -lcrypto -lpthread
echo "OK: $OUT"
