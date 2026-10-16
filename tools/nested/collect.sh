#!/bin/sh
# tools/nested/collect.sh — raccoglie il pacchetto di log da riportare a
# Claude Code (§7.6). Lo esegue Marietto dal BE principale dopo i test.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${STAGE:=/nested/stage}"
: "${NESTED_ROOT:=/nested}"
LOGS="$NESTED_ROOT/logs"
CRASH="$NESTED_ROOT/crash"

PROVA=0
[ "${1:-}" = "--prova" ] && PROVA=1
say() { echo "[collect $(date '+%H:%M:%S')] $*"; }
run() { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }

STAMP=$(date '+%Y%m%d-%H%M%S')
OUT="$LOGS/report-$STAMP"
run "mkdir -p '$OUT'"

say "MANIFEST, uname, kldstat"
run "cp '$STAGE/current/MANIFEST' '$OUT/MANIFEST' 2>/dev/null || true"
run "uname -a > '$OUT/uname.txt' 2>&1 || true"
run "kldstat -v > '$OUT/kldstat.txt' 2>&1 || true"

say "sysctl rilevanti"
run "sysctl hw.vmm.vmx.debug_trace hw.vmm.qemu_mode_mask vm.pmap.ept_ipat \
    debug.debugger_on_panic > '$OUT/sysctl.txt' 2>&1 || true"

say "riassunti e seriali dei test kvm-unit-tests"
run "cp '$LOGS'/kut-*-riassunto.txt '$OUT/' 2>/dev/null || true"
run "cp '$LOGS'/kut-*.serial '$LOGS'/kut-*.stderr '$OUT/' 2>/dev/null || true"

say "crash dump (se presenti)"
run "cp '$CRASH'/core.txt.* '$CRASH'/info.* '$OUT/' 2>/dev/null || true"

# aggregazione DTrace delle probe nested, se richiesta
if [ "${1:-}" = "--dtrace" ] || [ "${2:-}" = "--dtrace" ]; then
	say "aggregazione DTrace vmm:vmx:nested:*"
	run "dtrace -n 'vmm:vmx:nested::{ @[probename] = count(); }' \
	    -c 'sleep 1' > '$OUT/dtrace-nested.txt' 2>&1 || true"
fi

say "report markdown"
if [ "$PROVA" = 0 ]; then
	{
		echo "# Report collaudo nested $STAMP"
		echo; echo '## MANIFEST'; echo '```'; cat "$OUT/MANIFEST" 2>/dev/null; echo '```'
		echo; echo '## uname'; echo '```'; cat "$OUT/uname.txt" 2>/dev/null; echo '```'
		echo; echo '## sysctl'; echo '```'; cat "$OUT/sysctl.txt" 2>/dev/null; echo '```'
		echo; echo '## riassunti kvm-unit-tests'; echo '```'
		cat "$OUT"/kut-*-riassunto.txt 2>/dev/null; echo '```'
	} > "$OUT.md" 2>&1
	run "tar -C '$LOGS' -cJf '$OUT.tar.xz' 'report-$STAMP'"
	say "pacchetto: $OUT.tar.xz  +  $OUT.md"
fi
say "FATTO. Riporta a Claude Code $OUT.md (e il .tar.xz se serve)."
