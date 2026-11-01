#!/bin/sh
# test-run-b1race-mock.sh -- Claude 26/10/2026 notte, pareri #83 §5 e #84
# §§3-4: prova dall'inizio alla fine di run-b1race-27125.sh con sysctl, dtrace
# e kut-run FINTI (mock-b1race.py) e un finto QEMU (processo con
# "qemu-system-x86_64 -smp 1" nella riga di comando). Nessuna VM, nessun sysctl
# reale scritto; reali e in sola lettura: hash del modulo e del flat, ps, fstat.
# Otto corse: R1 regolare; R2 guasti misti + ripristino fallito; R3 SIGTERM in
# B; R4 FAIL in A (cancello); R5 -smp non campionabile in A (cancello); R6 QEMU
# sopravvive a kut-run (attesa); R7 QEMU oltre il timeout; R8 VM gia' viva.
# Uso: test-run-b1race-mock.sh <cartella di lavoro vuota>
T=$(cd "$(dirname "$0")" && pwd)
W=/mnt/linuxulator2/vm/wsl2/fbsd
B=${1:?cartella}
D83=$(/sbin/sha256 -q $T/diag83.d); VER=$(/sbin/sha256 -q $T/verdetto-b1race.py)
QPAT='[q]emu-system-x86_64 -smp'
nf=0
prepara() {	# $1 = cartella della corsa
	M=$1; mkdir -p $M/logs $M/vmm
	: >| $M/vmm/vm0
	/usr/local/bin/python3 $T/mock-b1race.py init $M/state
	printf '#!/bin/sh\nexec /usr/local/bin/python3 %s/mock-b1race.py sysctl %s/state "$@"\n' $T $M >| $M/msysctl
	# finto dtrace: allo stop annota se un QEMU era ancora vivo (barriera di chiusura)
	printf '#!/bin/sh\n[ "$1" = -e ] && exit 0\nout=$4\necho "== TRACCIA PRONTA == finto" > $out\ntrap '"'"'/bin/ps -axww -o command= | /usr/bin/grep -q "%s" && echo "QEMU_VIVO_ALLO_STOP" >> %s/stop-con-qemu; cat %s/state.trace >> $out 2>/dev/null; echo "== TRACCIA CHIUSA ==" >> $out; exit 0'"'"' TERM\nwhile :; do sleep 0.2; done\n' "$QPAT" $M $M >| $M/mdtrace
	printf '#!/bin/sh\neval v=\\${$#}\nsleep $v\n' >| $M/qemu-system-x86_64
	printf '#!/bin/sh\neval "$(/usr/local/bin/python3 %s/mock-b1race.py piano %s/state)"\n[ $Q = 1 ] && /bin/sh %s/qemu-system-x86_64 -smp 1 -m 1024 $V &\n/usr/local/bin/python3 %s/mock-b1race.py kut %s/state %s/logs %s/vmm\n[ $STACCA = 1 ] || wait\n' $T $M $M $T $M $M $M >| $M/mkut
	chmod +x $M/msysctl $M/mdtrace $M/mkut
	/usr/local/bin/python3 - $W/run-b1race-27125.sh $M/run.sh $M $D83 $VER "$QPAT" <<'EOF'
import sys
src, dst, M, d83, ver, qpat = sys.argv[1:]
s = open(src).read()
rep = [
 ('D83_SHA=@D83_SHA@', 'D83_SHA=' + d83), ('VER_SHA=@VER_SHA@', 'VER_SHA=' + ver),
 ('EV=$W/evidenze-b1race-27125/serie-1', 'EV=%s/ev' % M),
 ("VMPAT='[b]hyve|[q]emu-system'", "VMPAT='%s'" % qpat),
 ('sudo -n /sbin/sysctl', M + '/msysctl'), ('/sbin/sysctl', M + '/msysctl'),
 ('sudo -n /usr/sbin/dtrace', M + '/mdtrace'),
 ('sudo -n env TEST_CPUS=6 /bin/sh $W/kutvpid/kut-run.sh', M + '/mkut'),
 ('sudo -n /usr/sbin/cpucontrol', 'echo cpucontrol'), ('sudo -n kill', 'kill'),
 ('sudo -n /bin/ps', '/bin/ps'),
 ('/dev/vmm', M + '/vmm'), ('$W/logs', M + '/logs'),
]
for a, b in rep:
	assert a in s, a
	s = s.replace(a, b)
assert 'sudo -n /sbin/sysctl' not in s and '/usr/sbin/dtrace' not in s and 'kut-run.sh' not in s and 'bhyve' not in s.split('VMPAT=')[1].split('\n')[0]
open(dst, 'w').write(s)
EOF
}
atteso() {	# $1 file, $2 descrizione, $3 regex
	if /usr/bin/grep -qE -- "$3" $1 2>/dev/null; then echo "  ok      $2"; else echo "  ERRATO  $2 (manca /$3/)"; nf=$((nf + 1)); fi
}
assente() {	# $1 file, $2 descrizione, $3 regex
	if /usr/bin/grep -qE -- "$3" $1 2>/dev/null; then echo "  ERRATO  $2 (presente /$3/)"; nf=$((nf + 1)); else echo "  ok      $2"; fi
}
uscita() {	# $1 codice, $2 atteso
	[ "$1" = "$2" ] && echo "  ok      codice d'uscita $1" || { echo "  ERRATO  codice d'uscita $1 (atteso $2)"; nf=$((nf + 1)); }
}
blocco() {	# $1 riepilogo, $2 prova -> righe della prova
	/usr/bin/awk -v p="$2" '$0 ~ "^== "p" " {f=1; next} /^== |^STOP|^RIPRISTINO|^CAMPAGNA|^FINE/{f=0} f' $1
}
quiete() {	# nessun finto QEMU vivo fra una corsa e l'altra
	i=0; while /bin/ps -axww -o command= | /usr/bin/grep -q "$QPAT" && [ $i -lt 100 ]; do i=$((i + 1)); sleep 0.2; done
}
stato_iniziale() {	# $1 cartella
	[ "$(/usr/local/bin/python3 $T/mock-b1race.py sysctl $1/state -n hw.vmm.vmx.vept_keep hw.vmm.vmx.vept_test_race | /usr/bin/tr '\n' ' ')" = "0 0 " ] \
	    && echo "  ok      stato finto riportato ai valori iniziali" || { echo "  ERRATO  stato finto non ripristinato"; nf=$((nf + 1)); }
}
corri() {	# $1 nome, $2 guasti, [$3 BARR_TIMEOUT]
	quiete; prepara $B/$1
	MOCK_GUASTI=$2 BARR_TIMEOUT=${3:-60} /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; rc=$?
	R=$B/$1/ev/riepilogo.txt
}

echo "R1: tutto regolare"
corri r1 ''
uscita $rc 0
for p in A B C D E; do
	blocco $R $p > $B/r1/blk-$p
	atteso $B/r1/blk-$p "$p FUNCTIONAL_PASS" '^   FUNCTIONAL=FUNCTIONAL_PASS'
	atteso $B/r1/blk-$p "$p PATH_PASS" '^   PATH=PATH_PASS'
	atteso $B/r1/blk-$p "$p INTEGRITA OK" '^   INTEGRITA OK'
	atteso $B/r1/blk-$p "$p smp richiesto 1 = eseguito 1" '^   SMP richiesto=1 eseguito=1'
	atteso $B/r1/ev/$p/manifest.txt "$p manifest col seriale" 'seriale kut-'
	for k in FINESTRA_PRIMA AVVIO CHIUSURA DTRACE_CHIUSO FINESTRA_DOPO; do
		atteso $B/r1/ev/$p/barriere.txt "$p barriera $k" "^BARRIERA_$k=OK$"
	done
done
atteso $B/r1/blk-E "E RETRY2_SUCCESS=NOT_COVERED" 'RETRY2_SUCCESS=NOT_COVERED'
atteso $R "CAMPAGNA=PASS, 5/5, uscita 0" '^CAMPAGNA=PASS RIPRISTINO=OK PROVE=5/5 USCITA=0$'
atteso $B/r1/ev/baseline.txt "nodi preesistenti e -smp richiesto nella baseline" 'preesistenti: vm0'
assente $B/r1/stop-con-qemu "DTrace mai fermato con QEMU vivo" 'QEMU_VIVO'
stato_iniziale $B/r1

echo "R2: guasti noserC, overlapD, nodoE, riprfail"
corri r2 noserC,overlapD,nodoE,riprfail
uscita $rc 2
for p in C D E; do blocco $R $p > $B/r2/blk-$p; done
atteso $B/r2/blk-C "C: seriale assente -> FUNCTIONAL_INCONCLUSIVE" '^   FUNCTIONAL=FUNCTIONAL_INCONCLUSIVE'
atteso $R "C: seriale dichiarato assente" '^== C .*seriale=SERIALE-ASSENTE'
atteso $B/r2/blk-C "C: PATH resta PASS (traccia integra)" '^   PATH=PATH_PASS'
atteso $B/r2/blk-D "D: sovrapposizione -> PATH_INCONCLUSIVE" '^   PATH=PATH_INCONCLUSIVE .*intervalli sovrapposti'
atteso $B/r2/blk-E "E: nodo nuovo segnalato" 'ATTENZIONE: nodi .*vmm cambiati oltre vm2: vm7'
atteso $R "E: STOP per nodo nuovo" '^STOP: nodi .*vmm cambiati oltre vm2'
atteso $R "RIPRISTINO=FALLITO ha precedenza: uscita 2, stato conservato" '^CAMPAGNA=INCONCLUSIVE RIPRISTINO=FALLITO PROVE=5/5 USCITA=2$'

echo "R3: SIGTERM durante la prova B"
quiete; prepara $B/r3
MOCK_GUASTI= /bin/sh $B/r3/run.sh > $B/r3/uscita.txt 2>&1 &
pid=$!
i=0; until /usr/bin/grep -q '^== A ' $B/r3/ev/riepilogo.txt 2>/dev/null || [ $i -gt 150 ]; do i=$((i + 1)); sleep 0.2; done
sleep 0.5; kill -TERM $pid; wait $pid; rc=$?
R=$B/r3/ev/riepilogo.txt
uscita $rc 143
atteso $R "INTERROTTO (TERM)" '^INTERROTTO \(TERM\)'
n=$(/usr/bin/grep -c '^RIPRISTINO=' $R)
[ "$n" = 1 ] && echo "  ok      ripristino eseguito una volta sola" || { echo "  ERRATO  ripristini: $n"; nf=$((nf + 1)); }
atteso $R "CAMPAGNA=INTERROTTA, uscita 143" '^CAMPAGNA=INTERROTTA RIPRISTINO=OK PROVE=[0-9]/5 USCITA=143$'
stato_iniziale $B/r3
/bin/ps -axww -o command= | /usr/bin/grep -F "$B/r3/mdtrace" | /usr/bin/grep -v grep && { echo "  ERRATO  dtrace finto ancora vivo"; nf=$((nf + 1)); }

echo "R4: FAIL inatteso in A -> cancello"
corri r4 failA
uscita $rc 1
atteso $R "A FUNCTIONAL_FAIL" '^   FUNCTIONAL=FUNCTIONAL_FAIL'
atteso $R "STOP al cancello A" '^STOP: cancello A non superato'
atteso $R "CAMPAGNA=FAIL, 1/5, uscita 1" '^CAMPAGNA=FAIL RIPRISTINO=OK PROVE=1/5 USCITA=1$'
[ -d $B/r4/ev/B ] && { echo "  ERRATO  la prova B e' partita"; nf=$((nf + 1)); } || echo "  ok      B-E non eseguite"
stato_iniziale $B/r4

echo "R5: -smp non campionabile in A -> cancello"
corri r5 nosmp
uscita $rc 3
atteso $R "A PATH_INCONCLUSIVE per -smp" '^   PATH=PATH_INCONCLUSIVE .*-smp NON verificato'
atteso $R "A FUNCTIONAL resta PASS" '^   FUNCTIONAL=FUNCTIONAL_PASS'
atteso $R "CAMPAGNA=INCONCLUSIVE, 1/5, uscita 3" '^CAMPAGNA=INCONCLUSIVE RIPRISTINO=OK PROVE=1/5 USCITA=3$'

echo "R6: in B QEMU sopravvive 4 s a kut-run (attesa, poi stop di DTrace)"
corri r6 lingerB
uscita $rc 0
atteso $B/r6/ev/B/barriere.txt "B barriera di chiusura OK dopo l'attesa" '^BARRIERA_CHIUSURA=OK$'
assente $B/r6/stop-con-qemu "DTrace fermato solo a QEMU uscito" 'QEMU_VIVO'
atteso $R "CAMPAGNA=PASS" '^CAMPAGNA=PASS RIPRISTINO=OK PROVE=5/5 USCITA=0$'

echo "R7: in B QEMU sopravvive 8 s, timeout di chiusura 2 s"
corri r7 hangB 2
uscita $rc 3
atteso $B/r7/ev/B/barriere.txt "B barriera di chiusura NO" '^BARRIERA_CHIUSURA=NO'
atteso $R "B PATH_INCONCLUSIVE per la barriera" '^   PATH=PATH_INCONCLUSIVE .*barriera chiusura'
atteso $R "STOP per VM ancora viva" '^STOP: VM ancora viva dopo la prova B'
atteso $R "CAMPAGNA=INCONCLUSIVE, 2/5, uscita 3" '^CAMPAGNA=INCONCLUSIVE RIPRISTINO=OK PROVE=2/5 USCITA=3$'
stato_iniziale $B/r7

echo "R8: VM gia' viva all'avvio"
quiete; prepara $B/r8
/bin/sh $B/r8/qemu-system-x86_64 -smp 1 -m 1024 6 &
sleep 0.5
MOCK_GUASTI= /bin/sh $B/r8/run.sh > $B/r8/uscita.txt 2>&1; rc=$?
R=$B/r8/ev/riepilogo.txt
uscita $rc 4
atteso $R "STOP per VM viva" '^STOP: processo VM vivo'
atteso $R "CAMPAGNA=NON_ESEGUITA, uscita 4" '^CAMPAGNA=NON_ESEGUITA RIPRISTINO=OK PROVE=0/5 USCITA=4$'
[ -d $B/r8/ev/A ] && { echo "  ERRATO  la prova A e' partita"; nf=$((nf + 1)); } || echo "  ok      nessuna prova avviata"
quiete
echo "controlli errati: $nf"
[ $nf -eq 0 ]
