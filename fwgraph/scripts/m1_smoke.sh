#!/usr/bin/env bash
# M1 integration smoke test:
#   build a synthetic firmware (tar.gz with busybox-mips + busybox-armv7l +
#   a text file), upload it to the orchestrator, poll until done, and verify
#   the manifest (mips/32/be + arm/32/le).
# Prereq: orchestrator running (scripts/run_orchestrator.sh) and the EMBA
# docker image pulled (docker images | grep embeddedanalyzer).
set -euo pipefail

FWGRAPH_ROOT="${FWGRAPH_ROOT:-/home/tankuku/firmware-graph/fwgraph}"
SAMPLES="${SAMPLES:-/home/tankuku/firmware-graph/samples}"
cd "$FWGRAPH_ROOT"

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi
PORT="${ORCH_PORT:-8000}"
TOKEN="${ORCH_TOKEN:-}"
BASE="http://127.0.0.1:${PORT}"
PY=".venv/bin/python"

[[ -f "$SAMPLES/busybox-mips" ]] || { echo "missing sample: $SAMPLES/busybox-mips" >&2; exit 1; }
[[ -f "$SAMPLES/busybox-armv7l" ]] || { echo "missing sample: $SAMPLES/busybox-armv7l" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/rootfs/bin" "$WORK/rootfs/etc"
cp "$SAMPLES/busybox-mips" "$WORK/rootfs/bin/busybox"
cp "$SAMPLES/busybox-armv7l" "$WORK/rootfs/bin/busybox-arm"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$WORK/rootfs/etc/passwd"
tar -czf "$WORK/fw-m1-smoke.tar.gz" -C "$WORK/rootfs" .
echo "[smoke] synthetic firmware: $WORK/fw-m1-smoke.tar.gz ($(stat -c%s "$WORK/fw-m1-smoke.tar.gz") bytes)"

echo "[smoke] uploading to $BASE/firmware ..."
UPLOAD_OUT="$(curl -sf -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@${WORK}/fw-m1-smoke.tar.gz;filename=fw-m1-smoke.tar.gz" \
  "$BASE/firmware")"
echo "[smoke] upload response: $UPLOAD_OUT"
JOB_ID="$("$PY" -c 'import sys, json; print(json.load(sys.stdin)["job_id"])' <<<"$UPLOAD_OUT")"
echo "[smoke] job_id=$JOB_ID"

STATUS=""
for i in $(seq 1 240); do
  STATUS="$(curl -sf -H "Authorization: Bearer ${TOKEN}" "$BASE/jobs/$JOB_ID" \
    | "$PY" -c 'import sys, json; print(json.load(sys.stdin)["status"])')"
  echo "[smoke] poll #$i: status=$STATUS"
  [[ "$STATUS" == "done" || "$STATUS" == "failed" ]] && break
  sleep 15
done

if [[ "$STATUS" != "done" ]]; then
  echo "[smoke] FAILED: final status=$STATUS" >&2
  curl -s -H "Authorization: Bearer ${TOKEN}" "$BASE/jobs/$JOB_ID" \
    | "$PY" -c 'import sys, json; j=json.load(sys.stdin); print(j.get("error")); print("\n".join(j.get("log_tail", [])))' >&2
  exit 1
fi

echo "[smoke] verifying manifest ..."
curl -sf -H "Authorization: Bearer ${TOKEN}" "$BASE/jobs/$JOB_ID/manifest" > "$WORK/manifest.json"
"$PY" - "$WORK/manifest.json" <<'EOF'
import json, sys

manifest = json.load(open(sys.argv[1]))
print(json.dumps(manifest["stats"], indent=2))
found = {(b["arch"], b["bits"], b["endianness"]) for b in manifest["binaries"]}
errors = []
for want, name in [(("mips", 32, "be"), "busybox-mips"), (("arm", 32, "le"), "busybox-armv7l")]:
    if want not in found:
        errors.append(f"missing {name}: expected arch/bits/endianness {want}")
if errors:
    for e in errors:
        print("[smoke] FAILED:", e, file=sys.stderr)
    sys.exit(1)
print("[smoke] OK: manifest contains mips/32/be and arm/32/le binaries")
EOF
echo "[smoke] PASSED (job $JOB_ID)"
