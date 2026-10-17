#!/bin/sh
# tools/nested/kut-run.sh — runner di kvm-unit-tests per l'accel bhyve, al
# posto di run_tests.sh/x86/run (§7.4). Legge una lista kut-<fase>.list
# (nome | file.flat | args | qemu_params | smp | mem | timeout) e lancia ogni
# test con il QEMU di $STAGE. Lo esegue Marietto. --prova mostra i comandi.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${STAGE:=/nested/stage}"
: "${NESTED_ROOT:=/nested}"
: "${TEST_CPUS:=}"
KUT="$NESTED_ROOT/kut"
LOGS="$NESTED_ROOT/logs"
QEMU="$STAGE/current/bin/qemu-system-x86_64"
# QEMU ignora QEMU_DATADIR: senza -L non trova bios-256k.bin ed esce subito.
: "${QEMU_SRC:=/mnt/linuxulator2/vm/nested-work/qemu-nested}"
PCBIOS="$QEMU_SRC/pc-bios"
NESTED_PROP=""		# vuoto = capability spenta; "nested=on" per accenderla

usage() {
	echo "uso: $0 [--prova] [--nested] <lista.list>" >&2
	echo "  es: $0 tools/nested/kut-f1.list" >&2
	exit 2
}

PROVA=0
while [ $# -gt 0 ]; do
	case "$1" in
	--prova) PROVA=1; shift;;
	--nested) NESTED_PROP=",nested=on"; shift;;
	-*) usage;;
	*) break;;
	esac
done
[ $# -eq 1 ] || usage
LIST="$1"
[ -f "$LIST" ] || { echo "lista inesistente: $LIST" >&2; exit 1; }

[ "$PROVA" = 1 ] || [ -x "$QEMU" ] || { echo "manca $QEMU (build.sh)" >&2; exit 1; }
mkdir -p "$LOGS" 2>/dev/null || true
STAMP=$(date '+%Y%m%d-%H%M%S')

# cpuset solo se TEST_CPUS e' impostato
cpuset_pfx=""
[ -n "$TEST_CPUS" ] && cpuset_pfx="cpuset -l $TEST_CPUS"

say() { echo "[kut $(date '+%H:%M:%S')] $*"; }

# riga: nome|file|args|qemu_params|smp|mem|timeout  (campi vuoti ammessi)
while IFS='|' read -r name file args qparams smp mem tmo; do
	case "$name" in ''|'#'*) continue;; esac
	name=$(echo "$name" | sed 's/[[:space:]]*$//')
	file=$(echo "$file" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
	: "${smp:=1}"; : "${mem:=256}"; : "${tmo:=90}"
	ser="$LOGS/kut-$STAMP-$name.serial"
	err="$LOGS/kut-$STAMP-$name.stderr"
	cmd="$cpuset_pfx timeout -k 1s ${tmo}s '$QEMU' \
	  -L '$PCBIOS' --no-reboot -nodefaults -accel bhyve${NESTED_PROP} \
	  -device pc-testdev -device isa-debug-exit,iobase=0xf4,iosize=0x4 \
	  -display none -serial stdio -device pci-testdev \
	  -smp ${smp} -m ${mem} ${qparams} \
	  -kernel '$KUT/${file}' -append '${args}'"
	if [ "$PROVA" = 1 ]; then
		echo "  PROVA[$name]> $cmd"
		continue
	fi
	say "test $name ($file)"
	# QEMU: exit code = (codice<<1)|1 -> 1=PASS, 3=FAIL, 124=timeout
	set +e
	# </dev/null: con -serial stdio QEMU leggerebbe dalla lista stessa (lo
	# stdin del ciclo), mangiando l'inizio della riga successiva.
	eval "$cmd" < /dev/null > "$ser" 2> "$err"
	rc=$?
	set -e
	summary=$(grep '^SUMMARY:' "$ser" 2>/dev/null | tail -1 || true)
	# rc=1 e' anche il codice di QEMU che fallisce PRIMA di avviare il guest
	# (es. BIOS non trovato): PASS solo se il guest ha stampato il SUMMARY.
	case "$rc" in
	1) if [ -n "$summary" ]; then verdict=PASS; else verdict="ERR(qemu,no-summary)"; fi;;
	3) verdict=FAIL;;
	124) verdict=TIMEOUT;;
	*) verdict="ERR($rc)";;
	esac
	printf '  %-28s %s  %s\n' "$name" "$verdict" "$summary"
	echo "$name $verdict rc=$rc $summary" >> "$LOGS/kut-$STAMP-riassunto.txt"
done < "$LIST"

[ "$PROVA" = 0 ] && say "riassunto: $LOGS/kut-$STAMP-riassunto.txt" || true
