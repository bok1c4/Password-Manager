#!/usr/bin/env bash
# Two-device lifecycle rehearsal against the
# docker rig in docker/compose.test.yml — ZERO real secrets, throwaway DB.
#
# The five assertions:
#   1. A creates 3 entries and reads them all back           (exit 11 on fail)
#   2. pre-enroll: only 1 device registered; B cannot decrypt (exit 12)
#   3. enroll B (fingerprint asserted) -> B decrypts ALL      (exit 13)
#   4. revoke B + rotate (scripted consent --rotate)          (exit 14)
#   5. B fails on each entry; A still round-trips each;
#      every blob is v2; B has zero wraps left                (exit 15)
#
# Infra problems exit 20. PWMGR_KEEP=1 keeps the stack up afterwards.
#   make test-devices
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$HERE/docker/compose.test.yml")

cleanup() {
  if [ "${PWMGR_KEEP:-0}" != "1" ]; then
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  else
    echo "[*] PWMGR_KEEP=1 — stack left running (down: ${COMPOSE[*]} down -v)"
  fi
}
trap cleanup EXIT

fail() { echo "[FAIL] $2" >&2; exit "$1"; }

# bash -c, NOT a login shell: profile output would pollute captured output.
dexec() { # <service> <command...>
  local svc="$1"
  shift
  "${COMPOSE[@]}" exec -T "$svc" bash -c "$*"
}

echo "[*] bringing up the rig (build on first run)"
"${COMPOSE[@]}" up -d --build --wait db deviceA deviceB \
  || "${COMPOSE[@]}" up -d --build db deviceA deviceB

echo "[*] waiting for device ready sentinels"
for d in deviceA deviceB; do
  ok=0
  for _ in $(seq 1 60); do
    if dexec "$d" "test -f /shared/$d.ready" 2>/dev/null; then ok=1; break; fi
    sleep 2
  done
  [ "$ok" -eq 1 ] || fail 20 "$d never became ready"
done

FPR_A="$(dexec deviceA 'cat /shared/deviceA.fpr')"
FPR_B="$(dexec deviceA 'cat /shared/deviceB.fpr')"
echo "[*] A=$FPR_A B=$FPR_B"

echo "[*] step 0: only deviceA migrates (founding = A)"
dexec deviceA 'pwmgr migrate' || fail 20 "migrate failed on deviceA"

echo "[*] step 1: A creates 3 entries and reads them back"
SECRETS=("alpha-secret-1" "bravo-secret-2" "charlie-secret-3")
IDS=()
for i in 0 1 2; do
  id="$(printf '%s\n' "${SECRETS[$i]}" | dexec deviceA "pwmgr entry add --note note$i")" \
    || fail 11 "entry add $i failed"
  IDS+=("$id")
  got="$(dexec deviceA "pwmgr entry show $id")" || fail 11 "A cannot read entry $id"
  [ "$got" = "${SECRETS[$i]}" ] || fail 11 "A read mismatch on entry $id"
done
echo "    ids: ${IDS[*]}"

echo "[*] step 2: pre-enroll negative — 1 device; B cannot decrypt"
NDEV="$(dexec deviceA 'pwmgr device list --porcelain' | wc -l)"
[ "$NDEV" -eq 1 ] || fail 12 "expected 1 device pre-enroll, found $NDEV"
if dexec deviceB "pwmgr entry show ${IDS[0]}" >/dev/null 2>&1; then
  fail 12 "B decrypted entry ${IDS[0]} BEFORE being enrolled"
fi

echo "[*] step 3: A enrolls B (fingerprint asserted) -> B decrypts all"
dexec deviceA "pwmgr device add deviceB /shared/deviceB.pub.asc --fpr $FPR_B" \
  || fail 13 "device add failed"
for i in 0 1 2; do
  got="$(dexec deviceB "pwmgr entry show ${IDS[$i]}")" \
    || fail 13 "B cannot decrypt entry ${IDS[$i]} after enrollment"
  [ "$got" = "${SECRETS[$i]}" ] || fail 13 "B read mismatch on entry ${IDS[$i]}"
done
NKB="$(dexec deviceA "PGPASSWORD=test-only psql -h db -U pwmgr -d pwmgr_test -tAc \
  \"SELECT count(*) FROM password_keys pk JOIN devices d ON d.id=pk.device_id \
    WHERE d.name='deviceB'\"")"
[ "$NKB" -eq 3 ] || fail 13 "expected 3 wraps for B, found $NKB"

echo "[*] step 4: revoke B + rotate (scripted consent)"
dexec deviceA 'pwmgr device revoke deviceB --rotate' || fail 14 "revoke --rotate failed"

echo "[*] step 5: B locked out; A still reads; all blobs v2; B has 0 wraps"
for i in 0 1 2; do
  if dexec deviceB "pwmgr entry show ${IDS[$i]}" >/dev/null 2>&1; then
    fail 15 "B STILL decrypts entry ${IDS[$i]} after revoke+rotate"
  fi
  got="$(dexec deviceA "pwmgr entry show ${IDS[$i]}")" \
    || fail 15 "A cannot decrypt entry ${IDS[$i]} post-rotation"
  [ "$got" = "${SECRETS[$i]}" ] || fail 15 "A read mismatch post-rotation"
done
NV2="$(dexec deviceA "PGPASSWORD=test-only psql -h db -U pwmgr -d pwmgr_test -tAc \
  \"SELECT count(*) FROM passwords WHERE password LIKE 'v2:%'\"")"
[ "$NV2" -eq 3 ] || fail 15 "expected 3 v2 blobs, found $NV2"
NKB2="$(dexec deviceA "PGPASSWORD=test-only psql -h db -U pwmgr -d pwmgr_test -tAc \
  \"SELECT count(*) FROM password_keys pk JOIN devices d ON d.id=pk.device_id \
    WHERE d.name='deviceB'\"")"
[ "$NKB2" -eq 0 ] || fail 15 "B still holds $NKB2 wraps after revoke"

echo
echo "[OK] all five lifecycle assertions passed (3 entries, 2 devices)"
