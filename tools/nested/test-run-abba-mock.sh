#!/bin/sh
# test-run-abba-mock.sh -- Claude 27/10/2026, parere #85 §3.4: prova
# dall'inizio alla fine di run-abba-retry-2vp.sh SENZA VM e senza toccare il
# sistema: sysctl in un file di stato, swapoff/swapon, dtrace -e e cpucontrol
# finti, /dev/vmm in una cartella. Il braccio finto COPIA i bracci REALI di
# logs/abbavpid-20261025-2021 (dati veri per l'analizzatore) e ne corregge
# solo vept_scan_retries in configurazione.txt.
# Corse: R1 regolare; R2 CORRETTEZZA nel braccio 2; R3 INCOMPLETA nel braccio
# 3; R4 CONFIG nel braccio 1; R5 ripristino fallito; R6 VM viva all'avvio;
# R7 SIGTERM durante il braccio 2.
# Uso (da marietto; legge i dati reali via sudo, in sola lettura):
#   test-run-abba-mock.sh <cartella di lavoro vuota>
T=$(cd "$(dirname "$0")" && pwd)
W=/mnt/linuxulator2/vm/nested-work
REAL=$W/logs/abbavpid-20261025-2021
B=${1:?cartella}
mkdir -p $B/fixture || exit 1
for k in 1-N 2-T 3-T 4-N; do
	[ -d $B/fixture/$k ] || sudo -n /bin/cp -R $REAL/$k $B/fixture/$k
done
sudo -n /usr/sbin/chown -R marietto $B/fixture && /bin/chmod -R u+rw,a+r $B/fixture
# il run.out reale contiene l'«OUTPUT ... COMPLETA» di allora: non deve finire nel braccio finto
for k in 1-N 2-T 3-T 4-N; do
	[ -n "$B" ] && [ -f "$B/fixture/$k/run.out" ] && /bin/mv "$B/fixture/$k/run.out" "$B/fixture/$k/run-originale.out"
done
for k in 1-N 2-T 3-T 4-N; do	# misura del lavoro (#86): SINTETICA e identica, le serie del 25/10 non l'avevano
	printf 'AZIONI_CC=2610\nAZIONI_TOT=3015\nCONFIG=abc\nMAKEFILE=def\nSORGENTI=61234\nSORGENTI_KB=987654\nGCC=12.2.0\nMAKE=GNU_Make_4.3\nNPROC=2\nLAVORO-FINE\n' >| $B/fixture/$k/kbuild-lavoro.txt
done
CARICO_VERO=$( (cd $W/faseA && /sbin/sha256 -r kbuild4.sh kbuild-lavoro.sh gapmem.sh gapmon.c memmon.c) | /sbin/sha256 -q)
K="vept_keep vept_verify_hpa vept_test_race vept_scan_hold_keep vept_scan_retries nested_shadow_vmcs nested_shadow_verify nested_fast_field_validate nested_shadow_inject nested_vpid_track nested_vpid12_flush"
nf=0
prepara() {	# $1 cartella della corsa
	M=$1; mkdir -p $M/vmm $M/logs
	: >| $M/vmm/vm0:12
	# stato dei sysctl finti: valori iniziali come sull'host oggi (0 0 0 0 1 0 0 0 0 0 0)
	printf 'vept_keep 0\nvept_verify_hpa 0\nvept_test_race 0\nvept_scan_hold_keep 0\nvept_scan_retries 1\nnested_shadow_vmcs 0\nnested_shadow_verify 0\nnested_fast_field_validate 0\nnested_shadow_inject 0\nnested_vpid_track 0\nnested_vpid12_flush 0\nvept_scan_budget_us 2000\nvm.stats.vm.v_free_count 768398\nvm.stats.vm.v_inactive_count 4489532\nhw.pagesize 4096\n' >| $M/stato
	case ",$MOCK_GUASTI," in *,pocamem,*) /usr/bin/sed -i '' 's/^vm.stats.vm.v_inactive_count .*/vm.stats.vm.v_inactive_count 1000/; s/^vm.stats.vm.v_free_count .*/vm.stats.vm.v_free_count 1000/' $M/stato;; esac
	# swap finto: «dispositivo usatoKB attivo»; swapvuoto parte a 0
	u=813364; case ",$MOCK_GUASTI," in *,swapvuoto,*) u=0;; esac
	echo "/dev/gptid/finto $u 1" >| $M/swap
	cat >| $M/fswapctl <<FINTOSW
#!/bin/sh
echo "Device:       1024-blocks     Used:"
/usr/bin/awk '\$3 == 1 {print \$1, 3944436, \$2}' $M/swap
FINTOSW
	cat >| $M/fswapinfo <<FINTOSW
#!/bin/sh
echo "Device          1K-blocks     Used    Avail Capacity"
/usr/bin/awk '\$3 == 1 {print \$1, 3944436, \$2, 3944436 - \$2, "0%"}' $M/swap
FINTOSW
	cat >| $M/fswapoff <<FINTOSW
#!/bin/sh
case ",\$MOCK_GUASTI," in *,swapfail,*) /usr/bin/sed -i '' 's/ 1\$/ 0/' $M/swap; echo "swapoff: Cannot allocate memory" >&2; exit 1;; esac
/usr/bin/sed -i '' 's/ [0-9]* 1\$/ 0 0/' $M/swap
FINTOSW
	cat >| $M/fswapon <<FINTOSW
#!/bin/sh
case ",\$MOCK_GUASTI," in *,swapperso,*) exit 1;; esac
/usr/bin/sed -i '' "s|^\$1 \\([0-9]*\\) 0\$|\$1 \\1 1|" $M/swap
FINTOSW
	chmod +x $M/fswapctl $M/fswapinfo $M/fswapoff $M/fswapon
	cat >| $M/msysctl <<EOF
#!/bin/sh
# sysctl finto su $M/stato; MOCK_GUASTI=riprfail: nested_shadow_vmcs non torna a 0
n=0; [ "\$1" = -n ] && { n=1; shift; }
rc=0
for a in "\$@"; do
	k=\${a%%=*}; k=\${k#hw.vmm.vmx.}
	case "\$a" in
	*=*) v=\${a#*=}
		case ",\$MOCK_GUASTI," in *,riprfail,*) [ "\$k" = nested_shadow_vmcs ] && [ "\$v" = 0 ] && continue;; esac
		/usr/bin/grep -q "^\$k " $M/stato || { echo "sysctl: unknown oid \$a" >&2; rc=1; continue; }
		/usr/bin/sed -i '' "s/^\$k .*/\$k \$v/" $M/stato ;;
	kern.osrelease) [ \$n = 1 ] && echo finto || echo "kern.osrelease: finto" ;;
	*) v=\$(/usr/bin/awk -v k="\$k" '\$1==k {print \$2}' $M/stato)
		[ -n "\$v" ] || { rc=1; continue; }
		case "\$k" in *.*) p="";; *) p=hw.vmm.vmx.;; esac
		[ \$n = 1 ] && echo "\$v" || echo "\$p\$k: \$v" ;;
	esac
done
exit \$rc
EOF
	# braccio finto: copia un braccio reale, retry corretto, esito secondo MOCK_GUASTI
	cat >| $M/prova <<EOF
#!/bin/sh
i=\${O##*/}; i=\${i%%-*}
case \$i in 1) S=1-N;; 2) S=2-T;; 3) S=3-T;; 4) S=4-N;; esac
/bin/cp -R $B/fixture/\$S/. "\$O"/
/usr/bin/sed -i '' "/vept_scan_retries:/d" "\$O/configurazione.txt"
echo "vept_scan_retries: \$R" >> "\$O/configurazione.txt"
# come il braccio vero: scrive la configurazione (l'orchestratore deve poi ripristinarla)
$M/msysctl hw.vmm.vmx.vept_keep=1 hw.vmm.vmx.vept_verify_hpa=1 hw.vmm.vmx.vept_scan_retries=\$R hw.vmm.vmx.nested_shadow_vmcs=1 hw.vmm.vmx.nested_vpid_track=1 > /dev/null
case ",\$MOCK_GUASTI,:\$i" in *,lav3,*:3) /usr/bin/sed -i '' 's/^AZIONI_CC=.*/AZIONI_CC=2500/' "\$O/kbuild-lavoro.txt";; esac
trap 'echo "OUTPUT \$O INCOMPLETA interrotto (TERM)"; exit 0' TERM
case ",\$MOCK_GUASTI,:\$i" in
*,lento2,*:2) /bin/sleep 6 & wait \$! ;;
esac
case ",\$MOCK_GUASTI,:\$i" in
*,corr2,*:2) echo "OUTPUT \$O CORRETTEZZA 04-ext4" ;;
*,inc3,*:3) echo "OUTPUT \$O INCOMPLETA WSL non ha risposto" ;;
*,conf1,*:1) echo "OUTPUT \$O CONFIG sysctl riletti diversi" ;;
*) echo "OUTPUT \$O COMPLETA" ;;
esac
EOF
	mkdir -p $M/bin; /usr/bin/cc -O0 -Wall -Wextra -Werror -o $M/bin/qemu-system-x86_64 $T/fintavm.c || exit 1
	chmod +x $M/msysctl $M/prova
	LAT=$(/sbin/sha256 -q $T/abba-invept-lat.d); AN=$(/sbin/sha256 -q $W/abba_retry_an.py); PR=$(/sbin/sha256 -q $M/prova)
	/usr/local/bin/python3 - $W/run-abba-retry-2vp.sh $M/run.sh $M $LAT $PR $AN $CARICO_VERO <<'PYEOF'
import sys
src, dst, M, lat, pr, an, car = sys.argv[1:]
s = open(src).read()
for x in ('LAT_SHA=@LAT_SHA@', 'PROVA_SHA=@PROVA_SHA@', 'AN_SHA=@AN_SHA@'):
	if x not in s:	# gia' sostituiti nel file vero: si rimettono i segnaposto
		pass
import re
s = re.sub(r'^LAT_SHA=.*$', 'LAT_SHA=' + lat, s, flags=re.M)
s = re.sub(r'^PROVA_SHA=.*$', 'PROVA_SHA=' + pr, s, flags=re.M)
s = re.sub(r'^AN_SHA=.*$', 'AN_SHA=' + an, s, flags=re.M)
s = re.sub(r'^CARICO_SHA=.*$', 'CARICO_SHA=' + car, s, flags=re.M)
rep = [
 ('[ "$(id -u)" = 0 ] ||', 'true ||'),
 ('BASE=$B/logs/abba-retry2vp-', 'BASE=%s/logs/abba-retry2vp-' % M),
 ('PROVA=$B/run-abba-retry-prova.sh', 'PROVA=%s/prova' % M),
 ('dtrace -e -s', 'true'),
 ('cpucontrol -m 0x8b /dev/cpuctl6; cpucontrol -i 0x1 /dev/cpuctl6', 'echo cpucontrol-finto'),
 ('/dev/vmm', M + '/vmm'),
]
for a, b in rep:
	assert a in s, a
	s = s.replace(a, b)
s = re.sub(r'(?<![\w/.-])sysctl ', M + '/msysctl ', s)
for x in ('swapctl', 'swapinfo', 'swapoff', 'swapon'):
	s = re.sub(r'(?<![\w/.-])%s ' % x, '%s/f%s ' % (M, x), s)
for bad in ('cpucontrol -', 'dtrace -e'):
	assert bad not in s, bad
open(dst, 'w').write(s)
PYEOF
}
atteso() { if /usr/bin/grep -qE -- "$3" $1 2>/dev/null; then echo "  ok      $2"; else echo "  ERRATO  $2 (manca /$3/)"; nf=$((nf + 1)); fi; }
uscita() { [ "$1" = "$2" ] && echo "  ok      codice d'uscita $1" || { echo "  ERRATO  codice d'uscita $1 (atteso $2)"; nf=$((nf + 1)); }; }
iniziale() {
	v=$(for k in $K; do /usr/bin/awk -v k=$k '$1==k {print $2}' $1/stato; done | tr '\n' ' ')
	[ "$v" = "0 0 0 0 1 0 0 0 0 0 0 " ] && echo "  ok      sysctl finti riportati ai valori iniziali" || { echo "  ERRATO  sysctl finti: $v"; nf=$((nf + 1)); }
}
corri() {	# $1 nome, $2 guasti (esportati PRIMA di preparare: alcuni guasti agiscono sullo stato iniziale)
	MOCK_GUASTI=$2; export MOCK_GUASTI
	prepara $B/$1
	PAUSA=0 SWAP_ASSESTA=0 /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; rc=$?
	R=$(/bin/ls -d $B/$1/logs/abba-retry2vp-*/riepilogo.txt 2>/dev/null | head -1)
	D=$(dirname "$R")
}

echo "R1: regolare (4 bracci reali copiati)"
corri r1 ''
uscita $rc 0
atteso $R "CAMPAGNA=COMPLETA 4/4" '^CAMPAGNA=COMPLETA RIPRISTINO=OK BRACCI=4/4 USCITA=0$'
atteso $D/bracci.txt "sequenza A1 B1 B2 A2 con retry 1 2 2 1" '^4 A 1 COMPLETA$'
atteso $D/bracci.txt "braccio 2 = B retry 2" '^2 B 2 COMPLETA$'
atteso $D/analisi.txt "analizzatore: struttura ABBA OK" '^struttura ABBA: OK$'
atteso $D/analisi.txt "analizzatore: controlli di correttezza OK in A1" '^controlli A1   OK$'
atteso $D/analisi.txt "analizzatore: retry 2 letto nei bracci B" 'B1\(2-B, retry=2\)'
atteso $D/analisi.txt "analizzatore: verdetto MIGLIORA (dati reali -57/-14 s)" '^VERDETTO_PRESTAZIONI=MIGLIORA'
atteso $D/analisi.txt "analizzatore: compilazione reale 1244.9 s in A1" '^compilazione s +1244\.9'
atteso $R "riepilogo col verdetto" '^VERDETTO_PRESTAZIONI='
atteso $D/SHA256SUMS "SHA256SUMS di tutta la cartella" 'analisi.txt'
atteso $D/analisi.txt "WORKLOAD_COMPARABILE=SI" '^WORKLOAD_COMPARABILE=SI$'
atteso $D/analisi.txt "EVIDENZA presente" '^EVIDENZA='
atteso $D/swap-1.txt "swap: ciclo eseguito (813364 KB usati)" 'swap usato 813364 KB, memoria disponibile'
atteso $D/swap-1.txt "swap: dispositivo di nuovo attivo dopo il ciclo" '^/dev/gptid/finto 3944436 0$'
atteso $D/baseline.txt "baseline con gli hash del carico" 'kbuild-lavoro.sh'
iniziale $B/r1

echo "R2: correttezza nel braccio 2"
corri r2 corr2
uscita $rc 1
atteso $R "STOP per correttezza" '^STOP: correttezza nel braccio 2'
atteso $R "CAMPAGNA=FERMATA_CORRETTEZZA" '^CAMPAGNA=FERMATA_CORRETTEZZA RIPRISTINO=OK BRACCI=1/4 USCITA=1$'
[ -d $D/3-B ] && { echo "  ERRATO  il braccio 3 e' partito"; nf=$((nf + 1)); } || echo "  ok      bracci 3-4 non eseguiti"
iniziale $B/r2

echo "R3: braccio 3 incompleto"
corri r3 inc3
uscita $rc 3
atteso $R "CAMPAGNA=INCOMPLETA 2/4" '^CAMPAGNA=INCOMPLETA RIPRISTINO=OK BRACCI=2/4 USCITA=3$'
atteso $D/analisi.txt "analisi parziale: struttura ABBA NO" '^struttura ABBA: NO'
atteso $D/analisi.txt "analisi parziale: INCONCLUSIVE" '^VERDETTO_PRESTAZIONI=INCONCLUSIVE'

echo "R4: CONFIG nel braccio 1"
corri r4 conf1
uscita $rc 3
atteso $R "STOP al braccio 1" '^STOP: braccio 1 non completo: CONFIG'
atteso $R "CAMPAGNA=INCOMPLETA 0/4" '^CAMPAGNA=INCOMPLETA RIPRISTINO=OK BRACCI=0/4 USCITA=3$'

echo "R5: ripristino che non attecchisce"
corri r5 riprfail
uscita $rc 2
atteso $R "RIPRISTINO=FALLITO, stato COMPLETA conservato" '^CAMPAGNA=COMPLETA RIPRISTINO=FALLITO BRACCI=4/4 USCITA=2$'

echo "R6: VM viva all'avvio"
MOCK_GUASTI=; export MOCK_GUASTI
prepara $B/r6
$B/r6/bin/qemu-system-x86_64 -smp 1 -m 1024 4 &
sleep 0.5
PAUSA=0 SWAP_ASSESTA=0 /bin/sh $B/r6/run.sh > $B/r6/uscita.txt 2>&1; rc=$?
R=$(/bin/ls -d $B/r6/logs/abba-retry2vp-*/riepilogo.txt | head -1)
uscita $rc 4
atteso $R "STOP per VM viva" '^STOP: processo VM vivo'
atteso $R "CAMPAGNA=NON_ESEGUITA" '^CAMPAGNA=NON_ESEGUITA RIPRISTINO=OK BRACCI=0/4 USCITA=4$'
wait

echo "R7: SIGTERM durante il braccio 2"
MOCK_GUASTI=lento2; export MOCK_GUASTI
prepara $B/r7
PAUSA=0 SWAP_ASSESTA=0 /bin/sh $B/r7/run.sh > $B/r7/uscita.txt 2>&1 &
pid=$!
k=0; until /usr/bin/grep -q '######## braccio 2' $B/r7/logs/abba-retry2vp-*/riepilogo.txt 2>/dev/null || [ $k -gt 100 ]; do k=$((k + 1)); sleep 0.2; done
sleep 1; kill -TERM $pid; wait $pid; rc=$?
R=$(/bin/ls -d $B/r7/logs/abba-retry2vp-*/riepilogo.txt | head -1); D=$(dirname $R)
uscita $rc 143
atteso $R "INTERROTTO (TERM)" '^INTERROTTO \(TERM\)'
atteso $R "CAMPAGNA=INTERROTTA" '^CAMPAGNA=INTERROTTA RIPRISTINO=OK BRACCI=1/4 USCITA=143$'
n=$(/usr/bin/grep -c '^RIPRISTINO=' $R); [ "$n" = 1 ] && echo "  ok      un solo ripristino" || { echo "  ERRATO  ripristini $n"; nf=$((nf + 1)); }
iniziale $B/r7
echo "R8: swap gia' vuoto (nessun ciclo)"
corri r8 swapvuoto
uscita $rc 0
atteso $D/swap-1.txt "nessun ciclo swapoff/swapon" "swap gia' vuoto: nessun ciclo"

echo "R9: swapoff fallisce prima del braccio 1"
corri r9 swapfail
uscita $rc 4
atteso $R "STOP con la causa" '^STOP: normalizzazione dello swap prima del braccio 1: .*swapoff fallito'
atteso $R "CAMPAGNA=NON_ESEGUITA" '^CAMPAGNA=NON_ESEGUITA RIPRISTINO=OK BRACCI=0/4 USCITA=4$'
/usr/bin/grep -q ' 1$' $B/r9/swap && echo "  ok      dispositivo di swap riattivato dopo il fallimento" || { echo "  ERRATO  dispositivo di swap rimasto spento"; nf=$((nf + 1)); }

echo "R10: dispositivo di swap non torna"
corri r10 swapperso
uscita $rc 4
atteso $R "STOP dispositivi diversi" '^STOP: normalizzazione dello swap prima del braccio 1: dispositivi di swap diversi'

echo "R11: memoria insufficiente per svuotare lo swap"
corri r11 pocamem
uscita $rc 4
atteso $R "STOP memoria" '^STOP: normalizzazione dello swap prima del braccio 1: memoria disponibile'
/usr/bin/grep -q '813364 1$' $B/r11/swap && echo "  ok      swap non toccato" || { echo "  ERRATO  swap toccato"; nf=$((nf + 1)); }

echo "R12: lavoro diverso nel braccio 3 (meno oggetti compilati)"
corri r12 lav3
uscita $rc 3
atteso $D/analisi.txt "WORKLOAD_COMPARABILE=NO" '^WORKLOAD_COMPARABILE=NO \(AZIONI_CC'
atteso $D/analisi.txt "prestazioni INCOMPLETA" '^VERDETTO_PRESTAZIONI=INCOMPLETA'
atteso $R "COMPLETA declassata a INCOMPLETA" '^CAMPAGNA=INCOMPLETA RIPRISTINO=OK BRACCI=4/4 USCITA=3$'

echo "controlli errati: $nf"
[ $nf -eq 0 ]
