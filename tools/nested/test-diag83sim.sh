#!/bin/sh
# test-diag83sim.sh -- Claude 26/10/2026 notte, parere #83 §2: collaudo OFFLINE
# di diag83 + verdetto-b1race.py con DTrace VERO (pid provider) e THREAD veri:
# diag83sim.c esegue gli scenari, diag83sim.d (stesso nucleo di diag83.d) li
# traccia, l'oracolo da' il PATH. Per ogni scenario: verdetto atteso e motivo
# atteso (sottostringa dell'uscita). Nessuna VM.
T=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp}
/usr/local/bin/python3 $T/gen-diag83.py $OUT >/dev/null || exit 1
/usr/bin/cc -O0 -Wall -Wextra -Werror -pthread -o $OUT/diag83sim $T/diag83sim.c || exit 1
: >| $OUT/vuoto.serial
nfail=0
while read n scen att motivo; do
	case "$n" in ''|'#'*) continue;; esac
	d=$OUT/s$n; mkdir -p $d
	sudo -n /usr/sbin/dtrace -q -s $OUT/diag83sim.d -o $d/diag83.out \
	    -c "$OUT/diag83sim $n $d/prima $d/dopo" 2>| $d/diag83.err >/dev/null
	r=$(/usr/local/bin/python3 $T/verdetto-b1race.py $scen $d/diag83.out $d/diag83.err \
	    $OUT/vuoto.serial $d/prima $d/dopo --exec diag83sim 2>&1)
	got=$(echo "$r" | /usr/bin/sed -n 's/^PATH=\([A-Z_]*\).*/\1/p')
	if [ "$got" = "$att" ] && echo "$r" | /usr/bin/grep -qF -- "$motivo"; then e=ok; else e=ERRATO; nfail=$((nfail + 1)); fi
	printf '%-3s %s %-18s %-36s %s\n' "$n" "$scen" "$got" "$motivo" "$e"
	echo "$r" | /usr/bin/grep -E '^(TRACCIA|INTEGRITA|ESCLUSE|DESIGNATA|RETRY2)' | /usr/bin/sed 's/^/      | /'
	[ $e = ERRATO ] && { echo "     atteso: $att / $motivo"; echo "$r" | /usr/bin/sed 's/^/     ! /'; }
done <<'EOF'
# n scen atteso motivo
1  B PATH_PASS         INTEGRITA OK
2  B PATH_INCONCLUSIVE intervalli sovrapposti
3  B PATH_PASS         tid=[
4  B PATH_INCONCLUSIVE annidamenti: 1
5  B PATH_INCONCLUSIVE ingressi senza ritorno: 1
6  B PATH_INCONCLUSIVE chiusura fallita: inj
7  E PATH_PASS         RETRY2_SUCCESS=NOT_COVERED
8  B PATH_INCONCLUSIVE radici=2
9  A PATH_PASS         INTEGRITA OK
10 B PATH_INCONCLUSIVE intervalli sovrapposti
EOF
echo "scenari errati: $nfail"
[ $nfail -eq 0 ]
