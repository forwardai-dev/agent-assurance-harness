#!/usr/bin/env bash
# Agent Assurance Harness — full local test.
# Run from the repo root:   bash test-all.sh
# Then paste the block under "PASTE EVERYTHING BELOW" back to your reviewer.
set +e
cd "$(cd "$(dirname "$0")" && pwd)" 2>/dev/null || true

PASS=0; FAIL=0; SUMMARY=""

aah_() {  # prefer the installed console script; fall back to the module. PYTHONPATH=. so
          # module targets under examples/ import from the repo root either way.
  if command -v aah >/dev/null 2>&1; then PYTHONPATH="${PYTHONPATH}:." aah "$@"
  else PYTHONPATH="${PYTHONPATH}:." python3 -m aah.cli.main "$@"; fi
}
rec() {   # $1 name   $2 rc   $3 optional-detail
  local mark
  if [ "$2" -eq 0 ]; then PASS=$((PASS + 1)); mark="PASS"; else FAIL=$((FAIL + 1)); mark="FAIL"; fi
  printf '  [%s] %s%s\n' "$mark" "$1" "${3:+  ($3)}"
  SUMMARY="${SUMMARY}  [${mark}] ${1}${3:+  (${3})}
"
}
hr() { printf '%s\n' "------------------------------------------------------------"; }

hr; echo "Agent Assurance Harness — full local test"; hr
echo "python : $(python3 --version 2>&1)"
echo "os     : $(uname -srm)"
echo "HEAD   : $(git log --oneline -1 2>/dev/null || echo 'n/a')"; hr

echo "[1] install"
python3 -m pip install -e . >/tmp/aah_install.log 2>&1
rec "pip install -e ." $?
hr

echo "[2] test suite (pytest)"
PT="$(python3 -m pytest tests -q 2>&1)"; rc=$?
printf '%s\n' "$PT" | tail -1
rec "pytest tests" $rc "$(printf '%s' "$PT" | grep -oE '[0-9]+ (passed|failed)[^)]*' | tail -1)"
hr

echo "[3] lint + types (skipped if not installed)"
python3 -m ruff --version >/dev/null 2>&1 && { python3 -m ruff check src tests examples >/tmp/aah_ruff.log 2>&1; rec "ruff check" $?; } || echo "  (ruff not installed — skipped)"
python3 -m mypy --version >/dev/null 2>&1 && { python3 -m mypy src >/tmp/aah_mypy.log 2>&1; rec "mypy src" $?; } || echo "  (mypy not installed — skipped)"
hr

echo "[4] demo.sh (offline story)"
D="$(bash demo.sh 2>&1)"
printf '%s' "$D" | grep -q 'GATE: PASS';          rec "demo: safe agent -> PASS" $?
printf '%s' "$D" | grep -q 'GATE: FAIL';          rec "demo: vulnerable agent -> FAIL" $?
printf '%s' "$D" | grep -q 'TAMPER-EVIDENT ONLY'; rec "demo: no trust anchor -> TAMPER-EVIDENT ONLY" $?
printf '%s' "$D" | grep -q 'VERIFIED';            rec "demo: pinned key -> VERIFIED" $?
printf '%s' "$D" | grep -q 'VERIFICATION FAILED'; rec "demo: forgery -> caught" $?
hr

echo "[5] reference agent (same agent, two profiles)"
NA="$(aah_ run --target-module examples.agents.support_agent:make_naive   --out /tmp/aah_na 2>&1)"
printf '%s' "$NA" | grep -q 'GATE: FAIL'; rec "make_naive  -> GATE: FAIL" $?
GU="$(aah_ run --target-module examples.agents.support_agent:make_guarded --out /tmp/aah_gu 2>&1)"
printf '%s' "$GU" | grep -q 'GATE: PASS'; rec "make_guarded -> GATE: PASS" $?
hr

echo "[6] trust-anchor verify (the core claim)"
aah_ run --target mock --out /tmp/aah_v >/dev/null 2>&1
aah_ verify /tmp/aah_v/evidence.json >/tmp/aah_vn.log 2>&1; vn=$?
[ "$vn" -eq 3 ]; rec "verify with NO anchor -> exit 3 / TAMPER-EVIDENT ONLY" $? "exit $vn"
KEY="$(python3 -c "import json;print(json.load(open('/tmp/aah_v/evidence.json'))['seal']['public_key_hex'])" 2>/dev/null)"
aah_ verify /tmp/aah_v/evidence.json --trusted-key "$KEY" >/tmp/aah_va.log 2>&1; va=$?
[ "$va" -eq 0 ]; rec "verify --trusted-key -> exit 0 / VERIFIED" $? "exit $va"
hr

echo "RESULT: ${PASS} passed, ${FAIL} failed"
hr; echo
echo "================= PASTE EVERYTHING BELOW BACK ================="
echo "HEAD  : $(git log --oneline -1 2>/dev/null)"
echo "env   : $(python3 --version 2>&1) | $(uname -srm)"
echo "RESULT: ${PASS} passed, ${FAIL} failed"
printf '%s' "$SUMMARY"
if [ "$FAIL" -ne 0 ]; then
  echo "---- pytest tail (for any failures) ----"
  printf '%s\n' "$PT" | tail -25
fi
echo "=============================================================="
