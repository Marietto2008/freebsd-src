#!/bin/sh
# tools/nested/load.sh — carica vmm-restore.ko da $STAGE nel BE di collaudo e
# imposta i tunable (§7.5 del piano nested). Lo esegue Marietto, come root,
# nel BE di collaudo. Claude Code NON lo esegue mai senza --prova.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${STAGE:=/nested/stage}"
: "${NESTED_ROOT:=/nested}"
LOGS="$NESTED_ROOT/logs"

PROVA=0
[ "${1:-}" = "--prova" ] && PROVA=1

say() { echo "[load $(date '+%F %H:%M:%S')] $*"; }
run() { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }

# --- controlli preliminari ------------------------------------------------
if [ "$PROVA" = 0 ]; then
	[ "$(id -u)" -eq 0 ] || { echo "serve root" >&2; exit 1; }
	# nessuna VM attiva: caricare/scaricare vmm con VM vive panica.
	if [ -d /dev/vmm ] && [ -n "$(ls -A /dev/vmm 2>/dev/null)" ]; then
		echo "ERRORE: ci sono VM attive in /dev/vmm; fermale prima." >&2
		exit 1
	fi
	# BE di collaudo, non il principale (euristica: deve esistere il dataset).
	cur=$(bectl list -c name 2>/dev/null | awk 'NR==2{print $1}' || true)
	say "BE attivo (informativo): ${cur:-ignoto}"
fi

KO="$STAGE/current/vmm-restore.ko"
[ "$PROVA" = 1 ] || [ -f "$KO" ] || { echo "manca $KO (fai prima build.sh)" >&2; exit 1; }

mkdir -p "$LOGS" 2>/dev/null || true
LOG="$LOGS/load-$(date '+%Y%m%d-%H%M%S').txt"

say "scarico un eventuale vmm gia' caricato"
run "kldstat -q -m vmm && kldunload vmm || true"

# tunable del modulo, PRIMA del load (§7.5). Valori diversi solo a richiesta.
say "imposto i tunable del modulo"
run "kenv hw.vmm.vmx.debug_trace=0"
run "kenv hw.vmm.qemu_mode_mask=15"
run "kenv hw.vmm.vlapic_debug_lowvec=0"

say "carico $KO (MAI da /boot, MAI in loader.conf)"
run "kldload '$KO'"

say "verifiche (§7.5)"
run "sysctl hw.vmm.vmx.debug_trace hw.vmm.qemu_mode_mask vm.pmap.ept_ipat"
run "kldstat -v | grep -i vmm || true"
if [ "$PROVA" = 0 ]; then
	{
		echo "=== load $(date '+%F %T') ==="
		uname -a
		kldstat -v | grep -i vmm || true
		sysctl hw.vmm.vmx.debug_trace hw.vmm.qemu_mode_mask \
		    vm.pmap.ept_ipat debug.debugger_on_panic 2>/dev/null || true
	} > "$LOG" 2>&1
	say "log in $LOG"
fi
say "FATTO. La capability nested resta SPENTA finche' non la accende la VM."
