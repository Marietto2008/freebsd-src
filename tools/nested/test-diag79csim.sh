#!/bin/sh
# test-diag79csim.sh -- Claude 26/10/2026 notte: collaudo OFFLINE di diag79c
# (DTrace vero, pid provider, nessuna VM). Scenari 1-19 = regressione di diag79b
# (modalita' 0, stage2 presente); 20 = solo stage1 (_rax/_sentinel); 21-24 = _np.
T=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp}
/usr/local/bin/python3 $T/gen-diag79c.py $OUT >/dev/null || exit 1
/usr/bin/cc -O0 -Wall -Wextra -Werror -o $OUT/diag79csim $T/diag79csim.c || exit 1
nfail=0
while read n a3 a4 np remap wrev ord p1 p2 nome; do
	case "$n" in ''|'#'*) continue;; esac
	r=$(sudo -n /usr/sbin/dtrace -q -s $OUT/diag79csim.d 0x40fca1 0x40fb5b $a3 $a4 -c "$OUT/diag79csim $n" 2>&1)
	g() { echo "$r" | /usr/bin/sed -n "s/^$1=//p" | /usr/bin/tail -1; }
	got="$(g L0_NP) $(g L0_REMAP) $(g L0_W_REVOKE) $(g L0_INVEPT_ORDER) $(g L0_PATH_STAGE1) $(g L0_PATH_STAGE2)"
	if [ "$got" = "$np $remap $wrev $ord $p1 $p2" ]; then e=ok; else e=ERRATO; nfail=$((nfail + 1)); fi
	printf '%-2s %-38s %-58s %s\n' "$n" "$nome" "$got" "$e"
	[ $e = ERRATO ] && { echo "     atteso: $np $remap $wrev $ord $p1 $p2"; echo "$r" | /usr/bin/sed 's/^/     | /'; }
done <<'EOF'
# n  $3       $4 NP           REMAP        W_REVOKE     ORDER        PATH1   PATH2   nome
1  0x40fcbf 0  NA           PASS         PASS         PASS         PARTIAL PARTIAL parziale corretto
2  0x40fcbf 0  NA           PASS         PASS         PASS         FULL    FULL    fallback completo corretto
3  0x40fcbf 0  NA           PASS         PASS         PASS         FULL    FULL    vept_keep=0
4  0x40fcbf 0  NA           FAIL         PASS         PASS         UNKNOWN PARTIAL nessuna invalidazione prima di s1
5  0x40fcbf 0  NA           FAIL         PASS         PASS         UNKNOWN PARTIAL foglia vecchia rimasta
6  0x40fcbf 0  NA           PASS         PASS         FAIL         PARTIAL PARTIAL INVEPT fisico assente
7  0x40fcbf 0  NA           PASS         PASS         FAIL         PARTIAL PARTIAL INVEPT tardivo
8  0x40fcbf 0  NA           FAIL         PASS         PASS         PARTIAL PARTIAL HPA errata a stage1
9  0x40fcbf 0  NA           PASS         FAIL         PASS         PARTIAL PARTIAL installazione indebita in revoca
10 0x40fcbf 0  NA           PASS         PASS         PASS         PARTIAL PARTIAL page walk allo stesso RIP a s1
11 0x40fcbf 0  NA           INCONCLUSIVE INCONCLUSIVE INCONCLUSIVE PARTIAL PARTIAL EPTP02 cambiato
12 0x40fcbf 0  NA           PASS         PASS         INCONCLUSIVE PARTIAL PARTIAL CPU cambiata
13 0x40fcbf 0  NA           INCONCLUSIVE INCONCLUSIVE INCONCLUSIVE UNKNOWN UNKNOWN sonda cambiata
14 0x40fcbf 0  NA           INCONCLUSIVE PASS         PASS         PARTIAL PARTIAL esito di stage1 mancante
15 0x40fcbf 0  NA           NOT_OBSERVED NOT_OBSERVED NOT_OBSERVED UNKNOWN UNKNOWN nessuna sonda osservata
16 0x40fcbf 0  NA           PASS         PASS         PASS         PARTIAL PARTIAL altri contesti ignorati
17 0x40fcbf 0  NA           PASS         FAIL         PASS         PARTIAL PARTIAL scrittura concessa
18 0x40fcbf 0  NA           FAIL         NOT_OBSERVED PASS         PARTIAL UNKNOWN stage1 riflessa da L0
19 0x40fcbf 0  NA           PASS         PASS         PASS         PARTIAL PARTIAL senza uscite in L1
20 0        0  NA           PASS         NA           PASS         PARTIAL NA      solo stage1 (_rax/_sentinel)
21 0        1  PASS         NA           NA           PASS         PARTIAL NA      _np corretto
22 0        1  FAIL         NA           NA           PASS         PARTIAL NA      _np: L0 installa la sonda
23 0        1  INCONCLUSIVE NA           NA           PASS         PARTIAL NA      _np: REFLECT non registrato
24 0        1  FAIL         NA           NA           PASS         UNKNOWN NA      _np: foglia vecchia rimasta
EOF
echo "scenari errati: $nfail"
[ $nfail -eq 0 ]
