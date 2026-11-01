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
: "${QEMU_SRC:=/mnt/linuxulator2/vm/wsl2/fbsd/qemu-nested}"
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
	# Limite diagnostico (parere #51 §10): un test gia' noto come FAIL puo'
	# stampare centinaia di migliaia di righe (vmx_pf_vpid_test sul modulo
	# difettoso: 79 MB, timeout). L'awk tiene per intero le prime
	# KUT_FAIL_KEEP righe "FAIL", poi conta le altre senza stamparle; le righe
	# non-FAIL passano tutte. Il log resta piccolo e il verdetto non cambia.
	: "${KUT_FAIL_KEEP:=200}"
	# /bin/sh non ha PIPESTATUS: QEMU scrive in un file grezzo, cosi' si
	# cattura il SUO codice d'uscita; poi l'awk filtra nel log definitivo e
	# il grezzo viene SVUOTATO (non cancellato: niente rm, regola dell'utente).
	eval "$cmd" < /dev/null > "$ser.raw" 2> "$err"
	rc=$?
	awk -v keep="$KUT_FAIL_KEEP" '
		# Oltre il limite si tace il blocco d_errore (riga FAIL e il suo
		# dump "Dump mapping" / "----L..."), contandolo; tutto il resto
		# passa (SUMMARY, PASS, righe di avanzamento).
		/FAIL/ { nf++; if (nf <= keep) { print; q=0 } else q=1; next }
		q && (/^Dump mapping/ || /^-+L/ || /^-+[0-9]/ || /^$/) { next }
		{ q=0; print }
		END { if (nf > keep) printf "[... %d blocchi FAIL ulteriori non stampati (limite %d) ...]\n", nf-keep, keep }
	' "$ser.raw" > "$ser"
	: >| "$ser.raw"
	set -e
	summary=$(grep '^SUMMARY:' "$ser" 2>/dev/null | tail -1 || true)
	nfail=$(grep -c 'FAIL' "$ser" 2>/dev/null || echo 0)
	# FAIL di CORRETTEZZA (traduzione errata) distinto dal TIMEOUT DIAGNOSTICO
	# (raccolta non finita in tempo), anche quando coincidono (parere #51 §10).
	case "$rc" in
	1) if [ -n "$summary" ]; then verdict=PASS; else verdict="ERR(qemu,no-summary)"; fi;;
	3) verdict=FAIL;;
	124) if echo "$summary$nfail" | grep -q '[1-9]'; then verdict="FAIL(timeout-diag)"; else verdict=TIMEOUT; fi;;
	*) verdict="ERR($rc)";;
	esac
	printf '  %-28s %s  %s\n' "$name" "$verdict" "$summary"
	echo "$name $verdict rc=$rc $summary" >> "$LOGS/kut-$STAMP-riassunto.txt"
done < "$LIST"

[ "$PROVA" = 0 ] && say "riassunto: $LOGS/kut-$STAMP-riassunto.txt" || true
