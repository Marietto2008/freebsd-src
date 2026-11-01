#!/bin/sh
# test-l2-ciclo.sh -- Claude 27/10/2026, parere #95: collaudo di l2-ciclo.sh SENZA VM e senza
# DTrace vero: un dtrace finto (nel PATH) registra gli argomenti, scrive il file -o e dura come
# una finestra. Casi: C1 ciclo completo (K finestre, argomenti giusti); C2 stop a meta' (meno
# finestre, l2_ferma ASPETTA); C3 VM morta (il ciclo si ferma); C4 nessun pid (non parte).
# Uso: test-l2-ciclo.sh <cartella di lavoro vuota>
T=$(cd "$(dirname "$0")" && pwd)
B=${1:?cartella}
mkdir -p "$B/bin" || exit 1
nf=0
ok() { echo "  ok      $1"; }
ko() { echo "  ERRATO  $1"; nf=$((nf + 1)); }
cat >| "$B/bin/dtrace" <<'FINTODTRACE95'
#!/bin/sh
# dtrace finto: -s <script> <pid> <ms> -o <file>
echo "args $*" >> "$FINTO_LOG"
o=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && o=$2; shift; done
sleep 0.1
echo "finestra finta" >> "$o"
FINTODTRACE95
chmod +x "$B/bin/dtrace"
PATH=$B/bin:$PATH; export PATH
corri() {	# $1 cartella, $2 K, $3 GAP, $4 vm viva (1|0), $5 pid, $6 stop dopo s (vuoto = mai)
	O=$1; mkdir -p "$O"; FINTO_LOG=$O/dtrace.log; export FINTO_LOG
	L2=/finto/dedup95l2.d; L2_MS=100; L2_K=$2; L2_GAP=$3
	VIVA=$4
	vm_viva() { [ "$VIVA" = 1 ]; }
	. "$T/l2-ciclo.sh"
	l2_avvia "$5"
	[ -n "$6" ] && sleep "$6"
	t0=$(date +%s)
	l2_ferma
	ATTESA=$(( $(date +%s) - t0 ))
	NF=$(/usr/bin/grep -c '^finestra' "$O/l2-finestre.txt" 2>/dev/null)
}
echo "C1: ciclo completo"
corri "$B/c1" 3 0.2 1 4242 2
[ "$NF" = 3 ] && ok "3 finestre registrate" || ko "finestre: $NF"
/usr/bin/grep -q '^args -s /finto/dedup95l2.d 4242 100 -o .*/l2-05-3.txt$' "$B/c1/dtrace.log" && ok "argomenti: script, pid, ms, -o l2-05-N.txt" || ko "argomenti: $(tail -1 "$B/c1/dtrace.log")"
[ -s "$B/c1/l2-05-1.txt" ] && [ -e "$B/c1/l2-05-1.err" ] && ok "file .txt e .err per finestra" || ko "file per finestra"
echo "C2: stop a meta'"
corri "$B/c2" 50 0.3 1 4242 1
[ "$NF" -ge 1 ] && [ "$NF" -lt 50 ] && ok "fermato dopo $NF finestre su 50" || ko "finestre: $NF"
[ -e "$B/c2/l2-stop" ] && ok "file di stop creato" || ko "stop"
pgrep -f "l2-05-" > /dev/null && ko "processi del ciclo ancora vivi dopo l2_ferma" || ok "l2_ferma ha ASPETTATO il ciclo"
echo "C3: VM morta"
corri "$B/c3" 5 0.1 0 4242 0.5
[ "$NF" = 0 ] && /usr/bin/grep -q 'VM non viva' "$B/c3/l2-finestre.txt" && ok "nessuna finestra, ciclo fermato" || ko "C3: $NF"
echo "C4: nessun pid"
corri "$B/c4" 5 0.1 1 '' ''
/usr/bin/grep -q 'nessun pid' "$B/c4/l2-finestre.txt" && [ ! -e "$B/c4/dtrace.log" ] && ok "livello 2 non avviato" || ko "C4"
echo "controlli errati: $nf"
[ $nf -eq 0 ]
