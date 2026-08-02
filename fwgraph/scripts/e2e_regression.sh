#!/usr/bin/env bash
# e2e_regression.sh — fwgraph full-pipeline regression (M6).
#
# Synthetic firmware (2x busybox ELF + 1 text file, tar.gz) ->
# upload -> [auto] extract -> [auto] decompile -> ailift tags (capped) -> graph
# -> attack surface -> routes -> verify query/source contracts.
#
# Runs on the Ubuntu VM. Cost control: AI_MAX_FUNCS_PER_BIN=20 per binary.
# Usage: bash fwgraph/scripts/e2e_regression.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TOKEN="$(grep '^ORCH_TOKEN=' .env | cut -d= -f2-)"
BASE="${E2E_BASE:-http://127.0.0.1:8000}"
WORK="$(mktemp -d /tmp/fwgraph_e2e.XXXXXX)"
REPORT="docs/e2e-report.txt"
PASS=0; FAIL=0
declare -a LINES

say()  { echo "$*"; LINES+=("$*"); }
check(){ # check <label> <0|1>
  if [ "$2" -eq 0 ]; then say "PASS  $1"; PASS=$((PASS+1));
  else say "FAIL  $1"; FAIL=$((FAIL+1)); fi
}
api()  { curl -s -H "Authorization: Bearer $TOKEN" "$BASE$1"; }
post() { curl -s -X POST -H "Authorization: Bearer $TOKEN" "$BASE$1" "${@:2}"; }

wait_status() { # wait_status <job> <target1,target2> <timeout_s>
  local job="$1" targets="$2" limit="$3" t=0 st
  while [ $t -lt "$limit" ]; do
    st="$(api /jobs/$job | python3 -c 'import json,sys;print(json.load(sys.stdin).get("status",""))' 2>/dev/null)"
    case ",$targets," in *",$st,"*) echo "$st"; return 0;; esac
    if [ "$st" = "failed" ]; then echo "failed"; return 1; fi
    sleep 20; t=$((t+20))
  done
  echo "timeout"; return 1
}

say "== fwgraph e2e regression $(date -Is)"
say "workdir: $WORK"

# --- 0. restart orchestrator with capped AI budget -----------------------
say "-- restart orchestrator with AI_MAX_FUNCS_PER_BIN=20"
[ -f data/orchestrator.pid ] && kill "$(cat data/orchestrator.pid)" 2>/dev/null
sleep 2
AI_MAX_FUNCS_PER_BIN=20 bash scripts/run_orchestrator.sh >/dev/null
sleep 3
api /healthz | grep -q ok
check "orchestrator healthz" $?

# --- 1. synthetic firmware ----------------------------------------------
mkdir -p "$WORK/rootfs/bin" "$WORK/rootfs/etc"
cp ~/firmware-graph/samples/busybox-mips   "$WORK/rootfs/bin/busybox"
cp ~/firmware-graph/samples/busybox-armv7l "$WORK/rootfs/bin/busybox-arm"
echo 'root:x:0:0:root:/root:/bin/sh' > "$WORK/rootfs/etc/passwd"
( cd "$WORK/rootfs" && tar czf "$WORK/fw.tar.gz" . )
JOB="$(post /firmware -F "file=@$WORK/fw.tar.gz" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("job_id",""))')"
say "job: $JOB"
[ -n "$JOB" ]; check "upload accepted" $?

# --- 2. extract + decompile (auto chain) ---------------------------------
ST="$(wait_status "$JOB" decompiled 2400)"
say "status after auto chain: $ST"
[ "$ST" = "decompiled" ]; check "extract+decompile chain" $?

MAN="$(api /jobs/$JOB/manifest)"
echo "$MAN" | python3 -c '
import json,sys
d=json.load(sys.stdin)
bins=d.get("binaries") or []
archs=sorted({b.get("arch") for b in bins})
ok = len(bins)>=2 and "mips" in archs and "arm" in archs
print("OK" if ok else "BAD", archs)' | tee "$WORK/man.check"
grep -q OK "$WORK/man.check"; check "manifest: 2 ELFs, mips+arm" $?

DS="$(cat data/pseudocode/$JOB/decompile_summary.json 2>/dev/null)"
echo "$DS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
tot=d.get("total_functions",0); dec=d.get("total_decompiled",0)
r = dec/tot if tot else 0
print("OK" if r>0.95 else "BAD", f"{dec}/{tot}={r:.3f}")' | tee "$WORK/ds.check"
grep -q OK "$WORK/ds.check"; check "decompile success rate >95%" $?

# --- 3. ailift (capped at 20/bin) ----------------------------------------
post /jobs/$JOB/ailift >/dev/null
ST="$(wait_status "$JOB" ailifted 1800)"
say "status after ailift: $ST"
[ "$ST" = "ailifted" ]; check "ailift chain" $?

api /jobs/$JOB/ailift | python3 -c '
import json,sys
d=json.load(sys.stdin)
s=d.get("summary",{})
tagged=sum(b.get("tagged",0) for b in (s.get("binaries") or {}).values())
sent=sum(b.get("llm_sent",0) for b in (s.get("binaries") or {}).values())
done=(d.get("registry") or {}).get("done",0)
samples=d.get("tag_samples") or []
renamed=[x.get("new_name") for x in samples if x.get("new_name")]
print("OK" if tagged>0 and done>0 and not renamed else "BAD",
      f"tagged={tagged} done={done} sent={sent} renamed={renamed[:3]}")' | tee "$WORK/ai.check"
grep -q OK "$WORK/ai.check"; check "ailift tags done, no new names" $?

# --- 4. graph -------------------------------------------------------------
post /jobs/$JOB/graph >/dev/null
ST="$(wait_status "$JOB" routed 1800)"
say "status after graph: $ST"
[ "$ST" = "routed" ]; check "graph+attack+routes chain" $?

python3 - "$JOB" <<'EOF' | tee "$WORK/gr.check"
import json,sys
job=sys.argv[1]
g=json.load(open(f"data/cbm/{job}/graph_done.json"))
idx=g.get("index",{})
tree=g.get("tree",{})
ok = idx.get("nodes",0)>0 and idx.get("edges",0)>0 and tree.get("files_copied",0)>0
print("OK" if ok else "BAD",
      f"nodes={idx.get('nodes')} edges={idx.get('edges')} files={tree.get('files_copied')}")
EOF
grep -q OK "$WORK/gr.check"; check "graph nodes/edges/files >0" $?

api /jobs/$JOB/attack | python3 -c '
import json,sys
d=json.load(sys.stdin); s=(d.get("summary") or {}).get("analysis") or {}
print("OK" if s.get("paths_returned",0)>0 else "BAD", s)' | tee "$WORK/as.check"
grep -q OK "$WORK/as.check"; check "attack paths generated" $?

api /jobs/$JOB/routes | python3 -c '
import json,sys
d=json.load(sys.stdin); s=(d.get("summary") or {}).get("injection") or {}
print("OK" if "routes" in s and "inserted" in s else "BAD", s)' | tee "$WORK/rt.check"
grep -q OK "$WORK/rt.check"; check "route scan completed" $?

# --- 5. query layer --------------------------------------------------------
FUNCS="$(api "/jobs/$JOB/functions")"
TAGNAME="$(echo "$FUNCS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d.get("functions") or d if isinstance(d,list) else d.get("functions",[])
for f in items:
    n=f.get("name") if f.get("domain") or f.get("libc_equiv") else ""
    if n: print(n); break
' 2>/dev/null)"
say "sample tagged function: $TAGNAME"
[ -n "$TAGNAME" ]; check "functions endpoint has semantic tags" $?

post "/graph/query" -H 'Content-Type: application/json' \
  -d "{\"job_id\":\"$JOB\",\"op\":\"search\",\"pattern\":\"$TAGNAME\",\"label\":\"Function\"}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("OK" if d.get("total",0)>0 else "BAD", "total=",d.get("total"))' | tee "$WORK/q.check"
grep -q OK "$WORK/q.check"; check "graph search hits tagged function" $?

SRC_MD5="$(echo "$FUNCS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d.get("functions") or []
for f in items:
    if f.get("domain") or f.get("libc_equiv"): print(f.get("md5") or f.get("binary","")); break
' 2>/dev/null)"
SRC_ADDR="$(echo "$FUNCS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for f in d.get("functions",[]):
    if f.get("domain") or f.get("libc_equiv"): print(f.get("addr","")); break
' 2>/dev/null)"
api "/jobs/$JOB/functions/$SRC_MD5/$SRC_ADDR/source" | head -1 | grep -q '^// addr='
check "pseudocode source has // addr= header" $?

# --- 6. restore orchestrator ----------------------------------------------
say "-- restore orchestrator (normal env)"
[ -f data/orchestrator.pid ] && kill "$(cat data/orchestrator.pid)" 2>/dev/null
sleep 2
bash scripts/run_orchestrator.sh >/dev/null
sleep 3
api /healthz | grep -q ok
check "orchestrator restored" $?

say ""
say "== RESULT: PASS=$PASS FAIL=$FAIL (job $JOB kept in data/)"
printf '%s\n' "${LINES[@]}" > "$REPORT"
[ $FAIL -eq 0 ]
