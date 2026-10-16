#!/bin/sh
# tools/nested/session-setup.sh — setup UNA TANTUM del BE di collaudo (§8 del
# piano nested). Lo esegue Marietto come root, nel BE di collaudo. Niente va
# eseguito a mano fuori da qui. Claude Code: solo --prova.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${NESTED_ROOT:=/nested}"
CRASH="$NESTED_ROOT/crash"

PROVA=0
[ "${1:-}" = "--prova" ] && PROVA=1
say() { echo "[setup $(date '+%H:%M:%S')] $*"; }
run() { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }

if [ "$PROVA" = 0 ]; then
	[ "$(id -u)" -eq 0 ] || { echo "serve root" >&2; exit 1; }
fi

run "mkdir -p '$CRASH' '$NESTED_ROOT/logs' '$NESTED_ROOT/kut' '$NESTED_ROOT/images'"

# --- crash dump (§8.3) ----------------------------------------------------
# VMMSNOOP ha ZSTDIO -> dumpon_flags=-Z. dumpdir su /nested fuori dai BE.
say "configuro i crash dump (rc.conf del BE di collaudo)"
run "sysrc dumpdev=AUTO"
run "sysrc dumpdir='$CRASH'"
run "sysrc dumpon_flags='-Z'"

# --- sysctl del BE di collaudo (§8.3) -------------------------------------
# debugger_on_panic=0: con DDB nel kernel, a 1 il panic resta fermo in ddb
# sul framebuffer Intel (che puo' essere rotto) -> nessun dump. Vedi la
# memoria "PANIC invisibili" del 14-15/10.
say "sysctl.conf: debugger_on_panic=0 + panic_reboot_wait_time=5"
run "sysrc -f /etc/sysctl.conf debug.debugger_on_panic=0"
run "sysrc -f /etc/sysctl.conf kern.panic_reboot_wait_time=5"
# applico subito nella sessione corrente
run "sysctl debug.debugger_on_panic=0 || true"
run "sysctl kern.panic_reboot_wait_time=5 || true"

# --- gdb per crashinfo ----------------------------------------------------
say "gdb per crashinfo (se manca)"
run "pkg info -e gdb || pkg install -y gdb"

# --- nota sul dumpdev -----------------------------------------------------
say "verifica: dumpdev su una partizione di swap VERA, dimensionata vs physmem"
run "sysctl hw.physmem"
run "swapinfo -h || true"

say "FATTO. Prima del PRIMO test: prova il dump con"
say "    sysctl debug.kdb.panic=1"
say "al riavvio devono esserci vmcore.0 e core.txt.0 in $CRASH, e il sistema"
say "deve essere tornato al BE principale (bectl activate -t nested-test)."
