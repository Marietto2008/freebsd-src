#!/bin/sh
# Ricarica vmm-restore e lancia una lista di kvm-unit-tests in nested.
# uso: ./test.sh [lista] [sonda]
#   ./test.sh                     kut-f2b.list, nessuna sonda
#   ./test.sh kut-f2b.list 5      con la sonda 5 (traccia EXTINT) -> sonda5.txt
#   ./test.sh kut-interrupt.list  un solo test
set -e
cd "$(dirname "$0")"
LIST=${1:-kut-f2b.list}
PROBE=${2:-0}

[ -f "$LIST" ] || { echo "ERRORE: lista inesistente: $LIST"; exit 1; }

# la sonda e' un tunable: va impostata PRIMA del kldload; tolta sempre all'uscita
trap 'kenv -u hw.vmm.vmx.nested_probe 2>/dev/null || true' EXIT
if [ "$PROBE" != 0 ]; then
	kenv hw.vmm.vmx.nested_probe="$PROBE"
fi

if bhyvectl --vm=vm2 --destroy 2>/dev/null; then
	echo "vm2 distrutta"
fi

# se il kldunload fallisce NON si prosegue: si testerebbe il modulo vecchio
if kldstat -q -n vmm-restore; then
	if ! kldunload vmm-restore; then
		echo "ERRORE: kldunload fallito, resta caricato il modulo vecchio"
		exit 1
	fi
	echo "scaricato vmm-restore"
fi
kldload vmm-restore
echo "caricato vmm-restore"

# buffer dei messaggi vuoto: il file della sonda contiene solo questa esecuzione
sysctl -q kern.msgbuf_clear=1 >/dev/null
./kut-run.sh --nested "$LIST"

if [ "$PROBE" != 0 ]; then
	dmesg | grep "nested_probe" > "sonda$PROBE.txt" || true
	echo "sonda $PROBE -> $(pwd)/sonda$PROBE.txt"
fi
