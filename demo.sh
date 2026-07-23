#!/usr/bin/env bash
# Agent Assurance Harness — end-to-end demo. Fully offline, no API keys.
#   ./demo.sh
set -e
export PYTHONPATH="${PYTHONPATH:-src}"
AAH="python3 -m aah.cli.main"

echo "== 1) Assess a governed subrogation-intake agent (safe profile) =="
$AAH run --target arbiter --out out | sed 's/^/   /'

echo
echo "== 2) Same agent, vulnerable profile -> the gate FAILS =="
$AAH run --target arbiter --vulnerable --out out-vuln | sed -n '1,3p;/reasons/,$p' | sed 's/^/   /'

echo
echo "== 3) Re-verify the PASS evidence OFFLINE — the trust-anchor distinction =="
echo "   (a) with NO trust anchor -> TAMPER-EVIDENT ONLY (bytes intact, author unproven):"
$AAH verify out/evidence.json | sed 's/^/      /' || true
KEY=$(python3 -c "import json;print(json.load(open('out/evidence.json'))['seal']['public_key_hex'])")
echo "   (b) pinning the producer's key -> VERIFIED (authorship established):"
$AAH verify out/evidence.json --trusted-key "$KEY" | sed 's/^/      /'

echo
echo "== 4) Forge it: flip a failing security finding to PASS + rewrite the verdict =="
python3 - <<'PY'
import json
b = json.load(open("out-vuln/evidence.json"))
for f in b["seal"]["payload"]["findings"]:
    if f["axis"] == "security" and not f["passed"]:
        f["passed"] = True
        break
b["seal"]["payload"]["gate"]["verdict"] = "PASS"          # forged verdict
json.dump(b, open("out-vuln/forged.json", "w"))
print("   forged: one security finding -> passed, verdict -> PASS")
PY

echo
echo "== 5) Re-verify the forgery -> caught THREE independent ways, offline =="
$AAH verify out-vuln/forged.json | sed 's/^/   /' || true
echo
echo "That is the whole thesis: a forged evidence object cannot survive offline re-verification."
