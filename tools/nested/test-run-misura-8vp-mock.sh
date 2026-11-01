#!/bin/sh
# test-run-misura-8vp-mock.sh -- Claude 27/10/2026, parere #88: collaudo dell'involucro
# run-misura-8vp.sh parametrico (braccio A/B) SENZA VM e senza toccare il sistema: sysctl, swap,
# mount, dtrace -e, cpucontrol e il braccio stesso sono finti. Corse: M1 braccio B regolare
# (retry 2 passato al braccio, cartella misura-8vp-B-*); M2 budget 4000 -> STOP; M3 disco non in
# scrittura -> STOP; M4 MISURA_R=3 -> uscita 4; M5 braccio A (predefinito) regolare.
# Uso: test-run-misura-8vp-mock.sh <cartella di lavoro vuota>
W=/mnt/linuxulator2/vm/wsl2/fbsd
B=${1:?cartella}
nf=0
prepara() {	# $1 cartella, $2 budget, $3 modo di mount (rw|ro)
	M=$1; mkdir -p $M/vmm $M/logs $M/img
	: >| $M/img/Windows11.img; echo dati >> $M/img/Windows11.img
	printf 'vept_keep 0\nvept_verify_hpa 0\nvept_test_race 0\nvept_scan_hold_keep 0\nvept_scan_retries 1\nnested_shadow_vmcs 0\nnested_shadow_verify 0\nnested_fast_field_validate 0\nnested_shadow_inject 0\nnested_vpid_track 0\nnested_vpid12_flush 0\nvept_scan_budget_us %s\nhw.pagesize 4096\nvm.stats.vm.v_free_count 1000000\nvm.stats.vm.v_inactive_count 1000000\n' "$2" >| $M/stato
	cat >| $M/msysctl <<FINTOSYS
#!/bin/sh
n=0; [ "\$1" = -n ] && { n=1; shift; }
for a in "\$@"; do
	k=\${a%%=*}; k=\${k#hw.vmm.vmx.}
	case "\$a" in
	*=*) case ",\$MOCK_GUASTI," in *,nobudget,*) [ "\$k" = vept_scan_budget_us ] && continue;; esac
		/usr/bin/sed -i '' "s/^\$k .*/\$k \${a#*=}/" $M/stato ;;
	*) v=\$(/usr/bin/awk -v k="\$k" '\$1==k {print \$2}' $M/stato); [ -n "\$v" ] || exit 1
		[ \$n = 1 ] && echo "\$v" || echo "\$k: \$v" ;;
	esac
done
FINTOSYS
	printf '#!/bin/sh\necho "/dev/da0p2 /mnt/da0p2 ufs %s 2 2"\n' "$3" >| $M/fmount
	printf '#!/bin/sh\necho "Device: 1024-blocks Used:"\necho "/dev/finto 100 0"\n' >| $M/fswapctl
	printf '#!/bin/sh\necho "Device 1K-blocks Used Avail Capacity"\necho "/dev/finto 100 0 100 0%%"\n' >| $M/fswapinfo
	# braccio finto: registra cio' che riceve, esito COMPLETA
	printf '#!/bin/sh\necho "MOD=$MOD R=$R O=$O budget=$(%s/msysctl -n hw.vmm.vmx.vept_scan_budget_us)" > %s/braccio-ricevuto.txt\nmkdir -p "$O"\ntrap '"'"'echo "OUTPUT $O INCOMPLETA interrotto (TERM)"; exit 0'"'"' TERM\ncase ",$MOCK_GUASTI," in *,lento,*) /bin/sleep 8 & wait $! ;; esac\necho "OUTPUT $O COMPLETA"\n' $M $M >| $M/prova
	chmod +x $M/msysctl $M/fmount $M/fswapctl $M/fswapinfo $M/prova
	PR=$(/sbin/sha256 -q $M/prova)
	/usr/local/bin/python3 - $W/run-misura-8vp.sh $M/run.sh $M $PR <<'PYFINTO'
import re, sys
src, dst, M, pr = sys.argv[1:]
s = open(src).read()
s = re.sub(r'^PROVA_SHA=.*$', 'PROVA_SHA=' + pr, s, flags=re.M)
rep = [
 ('[ "$(id -u)" = 0 ] ||', 'true ||'),
 ('BASE=$B/logs/misura-8vp-', 'BASE=%s/logs/misura-8vp-' % M),
 ('PROVA=$B/run-misura-8vp-prova.sh', 'PROVA=%s/prova' % M),
 ('[ "$(sha256 -q /boot/kernel/vmm-restore.ko)" = "$MOD_SHA" ] ||', 'true ||'),
 ('[ "$(sha256 -q $N/12-Windows-11-vm12-senza-gpu-8vp)" = "$VM8_SHA" ] ||', 'true ||'),
 ('[ "$(sha256 -q $N/abba-invept-lat.d)" = "$LAT_SHA" ] ||', 'true ||'),
 ('[ "$( (cd $B/faseA && sha256 -r $CARICO) | sha256 -q)" = "$CARICO_SHA" ] ||', 'true ||'),
 ('dtrace -e -s', 'true'),
 ('cpucontrol -m 0x8b /dev/cpuctl6; cpucontrol -i 0x1 /dev/cpuctl6', 'echo cpucontrol-finto'),
 ('/mnt/da0p2/bhyve/img/Windows/11/Windows11.img', M + '/img/Windows11.img'),
 ('/dev/vmm', M + '/vmm'),
]
for a, b in rep:
	assert a in s, a
	s = s.replace(a, b)
s = re.sub(r'(?<![\w/.-])sysctl ', M + '/msysctl ', s)
s = re.sub(r'(?<![\w/.-])mount -p', M + '/fmount', s)
for x in ('swapctl', 'swapinfo'):
	s = re.sub(r'(?<![\w/.-])%s ' % x, '%s/f%s ' % (M, x), s)
assert 'swapoff' in s  # non viene raggiunto: swap gia' vuoto
open(dst, 'w').write(s)
PYFINTO
}
atteso() { if /usr/bin/grep -qE -- "$3" "$1" 2>/dev/null; then echo "  ok      $2"; else echo "  ERRATO  $2 (manca /$3/)"; nf=$((nf + 1)); fi; }
uscita() { [ "$1" = "$2" ] && echo "  ok      codice d'uscita $1" || { echo "  ERRATO  codice d'uscita $1 (atteso $2)"; nf=$((nf + 1)); }; }
corri() {	# $1 nome, $2 budget iniziale, $3 rw|ro, $4 MISURA_R (vuoto = predefinito), $5 MISURA_BUDGET, $6 guasti
	prepara $B/$1 $2 $3
	MOCK_GUASTI=$6; export MOCK_GUASTI
	if [ -n "$4" ]; then MISURA_R=$4 MISURA_BUDGET=${5:-2000} /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; else /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; fi
	rc=$?
	R=$(/bin/ls -d $B/$1/logs/misura-8vp-*/riepilogo.txt 2>/dev/null | head -1)
}
echo "M1: braccio B regolare"
corri m1 2000 rw 2
uscita $rc 0
atteso "$R" "cartella misura-8vp-B" '.'
case "$R" in *misura-8vp-B-*) echo "  ok      cartella col nome del braccio B";; *) echo "  ERRATO  cartella: $R"; nf=$((nf + 1));; esac
atteso $B/m1/braccio-ricevuto.txt "il braccio riceve MOD=B R=2, cartella 1-B, budget 2000" '^MOD=B R=2 O=.*/1-B budget=2000$'
atteso "$R" "riepilogo dichiara braccio B, retry 2, budget 2000 riletto" 'braccio B \(vept_scan_retries=2, budget 2000 us riletto\)'
atteso "$R" "MISURA=COMPLETA" '^MISURA=COMPLETA RIPRISTINO=OK USCITA=0'
echo "M2: budget 4000 (una leva per volta)"
corri m2 4000 rw 2
uscita $rc 4
atteso "$R" "STOP sul budget iniziale non standard" '^STOP: vept_scan_budget_us iniziale diverso da 2000'
[ -e $B/m2/braccio-ricevuto.txt ] && { echo "  ERRATO  il braccio e' partito"; nf=$((nf + 1)); } || echo "  ok      braccio non avviato"
echo "M3: disco della VM non in scrittura"
corri m3 2000 ro 2
uscita $rc 4
atteso "$R" "STOP sul disco" '^STOP: /dev/da0p2 non montato in scrittura'
echo "M4: MISURA_R=3"
corri m4 2000 rw 3
uscita $rc 4
atteso $B/m4/uscita.txt "messaggio sul parametro" 'combinazione non prevista: MISURA_R=3'
echo "M5: braccio A predefinito"
corri m5 2000 rw ''
uscita $rc 0
atteso $B/m5/braccio-ricevuto.txt "il braccio riceve MOD=A R=1" '^MOD=A R=1 O=.*/1-A budget=2000$'
iniziale() { [ "$(/usr/bin/awk '$1=="vept_scan_budget_us" {print $2}' $1/stato) $(/usr/bin/awk '$1=="vept_scan_retries" {print $2}' $1/stato)" = "2000 1" ] && echo "  ok      budget e retry rimessi a 2000 / 1" || { echo "  ERRATO  stato finale: $(/usr/bin/grep -E 'budget|retries' $1/stato | tr '\n' ' ')"; nf=$((nf + 1)); }; }
echo "M6: braccio D (retry 2, budget 4000)"
corri m6 2000 rw 2 4000 ''
uscita $rc 0
case "$R" in *misura-8vp-D-*) echo "  ok      cartella col nome del braccio D";; *) echo "  ERRATO  cartella: $R"; nf=$((nf + 1));; esac
atteso $B/m6/braccio-ricevuto.txt "il braccio vede budget 4000 e riceve MOD=D R=2" '^MOD=D R=2 O=.*/1-D budget=4000$'
atteso "$R" "riepilogo: budget 4000 riletto" 'braccio D \(vept_scan_retries=2, budget 4000 us riletto\)'
atteso "$R" "ripristino verificato col budget nell'elenco" '^RIPRISTINO=OK .*ora: .* 2000 +attesi: .* 2000'
iniziale $B/m6
echo "M7: la scrittura del budget non attecchisce"
corri m7 2000 rw 2 4000 nobudget
uscita $rc 4
atteso "$R" "STOP: budget non applicato" '^STOP: vept_scan_budget_us=4000 non applicato'
[ -e $B/m7/braccio-ricevuto.txt ] && { echo "  ERRATO  il braccio e' partito"; nf=$((nf + 1)); } || echo "  ok      braccio non avviato"
echo "M8: combinazione non ammessa (budget 3000)"
corri m8 2000 rw 2 3000 ''
uscita $rc 4
atteso $B/m8/uscita.txt "messaggio sulla combinazione" 'combinazione non prevista: MISURA_R=2 MISURA_BUDGET=3000'
echo "M9: SIGTERM durante il braccio D"
prepara $B/m9 2000 rw
MOCK_GUASTI=lento; export MOCK_GUASTI
MISURA_R=2 MISURA_BUDGET=4000 /bin/sh $B/m9/run.sh > $B/m9/uscita.txt 2>&1 &
pid=$!
k=0; until [ -e $B/m9/braccio-ricevuto.txt ] || [ $k -gt 100 ]; do k=$((k + 1)); sleep 0.1; done
sleep 1; kill -TERM $pid; wait $pid; rc=$?
R=$(/bin/ls -d $B/m9/logs/misura-8vp-*/riepilogo.txt | head -1)
uscita $rc 143
atteso "$R" "MISURA=INTERROTTA" '^MISURA=INTERROTTA RIPRISTINO=OK USCITA=143'
iniziale $B/m9
echo "controlli errati: $nf"
[ $nf -eq 0 ]
