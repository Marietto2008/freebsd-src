#!/bin/sh
# test-diag79sim.sh -- Claude 26/10/2026, parere #80 §4.5: collaudo OFFLINE di
# diag79 su eventi simulati (DTrace vero, pid provider, nessuna VM). Per ogni
# scenario confronta i cinque verdetti L0 con quelli attesi.
T=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp}
/usr/local/bin/python3 $T/gen-diag79.py $OUT >/dev/null || exit 1
/usr/bin/cc -O0 -Wall -Wextra -Werror -o $OUT/diag79sim $T/diag79sim.c || exit 1
nfail=0
while read n remap wrev ord p1 p2 nome; do
	case "$n" in ''|'#'*) continue;; esac
	r=$(sudo -n /usr/sbin/dtrace -q -s $OUT/diag79sim.d 0x40fca1 0x40fb5b 0x40fcbf -c "$OUT/diag79sim $n" 2>&1)
	g() { echo "$r" | /usr/bin/sed -n "s/^$1=//p" | /usr/bin/tail -1; }
	got="$(g L0_REMAP) $(g L0_W_REVOKE) $(g L0_INVEPT_ORDER) $(g L0_PATH_STAGE1) $(g L0_PATH_STAGE2)"
	if [ "$got" = "$remap $wrev $ord $p1 $p2" ]; then e=ok; else e=ERRATO; nfail=$((nfail + 1)); fi
	printf '%-2s %-40s %-52s %s\n' "$n" "$nome" "$got" "$e"
	[ $e = ERRATO ] && { echo "     atteso: $remap $wrev $ord $p1 $p2"; echo "$r" | /usr/bin/sed 's/^/     | /'; }
done <<'EOF'
# n  REMAP        W_REVOKE     ORDER        PATH1   PATH2   nome
1  PASS         PASS         PASS         PARTIAL PARTIAL parziale corretto
2  PASS         PASS         PASS         FULL    FULL    fallback completo corretto
3  PASS         PASS         PASS         FULL    FULL    vept_keep=0 (svuotamento)
4  FAIL         PASS         PASS         UNKNOWN PARTIAL nessuna invalidazione prima di stage1
5  FAIL         PASS         PASS         UNKNOWN PARTIAL foglia vecchia rimasta
6  PASS         PASS         FAIL         PARTIAL PARTIAL INVEPT fisico assente
7  PASS         PASS         FAIL         PARTIAL PARTIAL INVEPT tardivo
8  FAIL         PASS         PASS         PARTIAL PARTIAL HPA errata a stage1
9  PASS         FAIL         PASS         PARTIAL PARTIAL installazione indebita in revoca
10 PASS         PASS         PASS         PARTIAL PARTIAL page walk allo stesso RIP a stage1
11 INCONCLUSIVE INCONCLUSIVE INCONCLUSIVE PARTIAL PARTIAL EPTP02 cambiato
12 PASS         PASS         INCONCLUSIVE PARTIAL PARTIAL CPU cambiata
13 INCONCLUSIVE INCONCLUSIVE INCONCLUSIVE UNKNOWN UNKNOWN sonda cambiata (stage1 non avviene sulla sonda legata)
14 INCONCLUSIVE PASS         PASS         PARTIAL PARTIAL esito di stage1 mancante
15 NOT_OBSERVED NOT_OBSERVED NOT_OBSERVED UNKNOWN UNKNOWN nessuna sonda osservata
16 PASS         PASS         PASS         PARTIAL PARTIAL altri contesti ignorati
17 PASS         FAIL         PASS         PARTIAL PARTIAL scrittura concessa senza riflessione
18 FAIL         NOT_OBSERVED PASS         PARTIAL UNKNOWN stage1 riflessa da L0
EOF
echo "scenari errati: $nfail"
[ $nfail -eq 0 ]
