# l2-ciclo.sh -- Claude 27/10/2026, parere #95 §4.3: ciclo delle finestre di LIVELLO 2 durante la
# compilazione. Incluso (.) da run-dedup95-8vp-prova.sh. Ogni finestra e' un processo dtrace
# SEPARATO (dedup95l2.d, esce da solo dopo L2_MS ms): fuori dalle finestre vm_gpa_hold non e'
# abilitata. Usa dal braccio: O, L2, L2_MS, L2_K, L2_GAP, vm_viva.
#   l2_avvia <pid>   parte in background: attende L2_GAP s, una finestra, ... fino a L2_K
#   l2_ferma         segnale di stop (file) e ATTESA del ciclo (al piu' L2_GAP s + una finestra)
# Registro: $O/l2-finestre.txt, una riga per finestra con l'esito di dtrace.
L2P=""
l2_ciclo() {
	i=1
	while [ "$i" -le "$L2_K" ]; do
		sleep "$L2_GAP"
		[ -e "$O/l2-stop" ] && break
		vm_viva || { echo "VM non viva: ciclo fermato" >> "$O/l2-finestre.txt"; break; }
		dtrace -s "$L2" "$1" "$L2_MS" -o "$O/l2-05-$i.txt" 2> "$O/l2-05-$i.err"
		echo "finestra $i $(date +%T) rc=$?" >> "$O/l2-finestre.txt"
		i=$((i + 1))
	done
}
l2_avvia() {
	[ -n "$1" ] || { echo "nessun pid: livello 2 non avviato" >> "$O/l2-finestre.txt"; return 0; }
	: >> "$O/l2-finestre.txt"
	l2_ciclo "$1" &
	L2P=$!
}
l2_ferma() {
	[ -n "$L2P" ] || return 0
	: > "$O/l2-stop"
	wait "$L2P" 2>/dev/null
	L2P=""
}
