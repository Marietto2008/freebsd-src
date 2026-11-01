# NB parere #106: NON per le corse vere (legge il contatore quando legge la seriale, cioe' a VM
# finita: delta 0 ovunque). Le corse usano ptpad-drive.py. Resta per il collaudo offline P5.
# ptpad-assembla.sh -- Claude 27/10/2026, parere #101. Nucleo di raccolta del test PTP-HOLD,
# separato dal runner cosi' da collaudarlo con un contatore FINTO (test-ptpad.sh P5). Combina la
# serie di L1 (file serial) con le fotografie del contatore host nested_ept_mmio_emulated e lo
# stato terminale, nel formato letto da ptpad_an.py.
#   ctr_leggi()      -> stampa il valore corrente del contatore (sovrascrivibile nel mock)
#   ptpad_assembla <serial.txt> <stato: alive|bhyve_died> <out.txt>
# La fotografia e' approssimata: si legge il contatore quando si incontra "PTPAD CASE" (before)
# e quando si incontra la riga "PTPAD L1" dello stesso caso (after). Con UNA vCPU e nessun altro
# MMIO fra i casi, il delta isola il movsq del caso. L'ultimo caso senza "PTPAD L1" e stato
# bhyve_died -> nessuna fotografia after, TERM bhyve_died (l'oracolo lo gestisce).
ctr_leggi() { sysctl -n hw.vmm.vmx.nested_ept_mmio_emulated 2>/dev/null || echo 0; }

# ptpad_assembla <serial.txt> <stato> <out.txt> [piano: es. B,C,A,A_D,D_DATA]
ptpad_assembla() {
	serial=$1; stato=$2; out=$3; piano=${4:-}
	: >| "$out"
	[ -n "$piano" ] && printf 'PLAN cases=%s\n' "$piano" >> "$out"
	caso=""
	while IFS= read -r riga; do
		case "$riga" in
		"PTPAD CASE "*)
			caso=${riga#PTPAD CASE }
			printf 'CASE %s\n' "$caso" >> "$out"
			printf 'CTR before=%s\n' "$(ctr_leggi)" >> "$out"
			;;
		"PTPAD L1 "*)
			printf '%s\n' "${riga#PTPAD }" >> "$out"
			printf 'CTR after=%s\n' "$(ctr_leggi)" >> "$out"
			printf 'TERM alive\n' >> "$out"
			caso=""
			;;
		esac
	done < "$serial"
	# caso aperto senza L1: morte prima della risposta (tipico dei casi D con H2)
	if [ -n "$caso" ]; then
		printf 'CTR after=%s\n' "$(ctr_leggi)" >> "$out"
		printf 'TERM %s\n' "$stato" >> "$out"
	fi
}
