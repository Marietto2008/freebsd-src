#!/bin/sh
# test-diag77sim.sh -- Claude 26/10/2026, parere #76 §3: collaudo OFFLINE della
# macchina a stati di diag77 su eventi simulati (nessuna VM). Per ogni scenario
# confronta i due verdetti L0 con quelli attesi; esce 1 al primo disaccordo.
T=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp}
/usr/local/bin/python3 $T/gen-diag77.py $OUT >/dev/null || exit 1
/usr/bin/cc -O0 -Wall -Wextra -Werror -o $OUT/diag77sim $T/diag77sim.c || exit 1
nfail=0
while read n leaf s2 nome; do
	case "$n" in ''|'#'*) continue;; esac
	r=$(sudo -n /usr/sbin/dtrace -q -s $OUT/diag77sim.d 0x40fca1 0x40fb5b 0x40fcbf -c "$OUT/diag77sim $n" 2>&1)
	gl=$(echo "$r" | /usr/bin/grep -oE 'L0_LEAF_[A-Z_]+' | /usr/bin/tail -1)
	gs=$(echo "$r" | /usr/bin/grep -oE 'L0_S2_[A-Z_]+' | /usr/bin/tail -1)
	if [ "$gl" = "$leaf" ] && [ "$gs" = "$s2" ]; then esito=ok; else esito=ERRATO; nfail=$((nfail + 1)); fi
	printf '%-2s %-44s %-22s %-20s %s\n' "$n" "$nome" "$gl" "$gs" "$esito"
	[ "$esito" = ERRATO ] && echo "$r" | /usr/bin/sed 's/^/     | /'
done <<'EOF'
1  L0_LEAF_PASS          L0_S2_PASS          corsa corretta
2  L0_LEAF_NOT_OBSERVED  L0_S2_NOT_OBSERVED  nessuna sonda osservata
3  L0_LEAF_PASS          L0_S2_PASS          due contesti (ignorati)
4  L0_LEAF_INCONCLUSIVE  L0_S2_INCONCLUSIVE  sonda cambiata stesso contesto
5  L0_LEAF_NOT_OBSERVED  L0_S2_PASS          install di stage1 non vista
6  L0_LEAF_FAIL          L0_S2_NOT_OBSERVED  stage1 riflessa da L0
7  L0_LEAF_FAIL          L0_S2_PASS          foglia nuova = vecchia
8  L0_LEAF_FAIL          L0_S2_PASS          PTE letta != foglia installata
9  L0_LEAF_PASS          L0_S2_FAIL          scrittura concessa senza riflessione
10 L0_LEAF_FAIL          L0_S2_PASS          nessun wipe prima di stage1
EOF
echo "scenari errati: $nfail"
[ $nfail -eq 0 ]
