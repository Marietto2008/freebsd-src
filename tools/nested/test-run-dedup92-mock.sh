#!/bin/sh
# test-run-dedup92-mock.sh -- Claude 27/10/2026, parere #92 §7: collaudo dell'involucro
# run-dedup92-8vp.sh SENZA VM e senza toccare il sistema (derivato da
# test-run-misura-8vp-mock.sh): sysctl, swap, mount, df, dtrace -e, cpucontrol e il braccio
# sono finti. Corse: D1 braccio A regolare; D2 MISURA_R=2 -> uscita 4; D3 vept_diag acceso ->
# STOP; D4 meno di 2 GiB liberi -> STOP; D5 budget iniziale non standard -> STOP; D6 disco non
# in scrittura -> STOP; D7 SIGTERM durante il braccio -> INTERROTTA col ripristino.
# Uso: test-run-misura-8vp-mock.sh <cartella di lavoro vuota>
W=/mnt/linuxulator2/vm/nested-work
B=${1:?cartella}
nf=0
prepara() {	# $1 cartella, $2 budget, $3 modo di mount (rw|ro)
	M=$1; mkdir -p $M/vmm $M/logs $M/img
	: >| $M/img/Windows11.img; echo dati >> $M/img/Windows11.img
	printf 'vept_diag %s\nvept_keep 0\nvept_verify_hpa 0\nvept_test_race 0\nvept_scan_hold_keep 0\nvept_scan_retries 1\nnested_shadow_vmcs 0\nnested_shadow_verify 0\nnested_fast_field_validate 0\nnested_shadow_inject 0\nnested_vpid_track 0\nnested_vpid12_flush 0\nvept_scan_budget_us %s\nhw.pagesize 4096\nvm.stats.vm.v_free_count 1000000\nvm.stats.vm.v_inactive_count 1000000\n' "${4:-0}" "$2" >| $M/stato
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
	printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Avail Capacity Mounted on"\necho "finto 9000000 1 %s 1%% /x"\n' "${5:-5000000}" >| $M/fdf
	printf '#!/bin/sh\necho "Device: 1024-blocks Used:"\necho "/dev/finto 100 0"\n' >| $M/fswapctl
	printf '#!/bin/sh\necho "Device 1K-blocks Used Avail Capacity"\necho "/dev/finto 100 0 100 0%%"\n' >| $M/fswapinfo
	# braccio finto: registra cio' che riceve, esito COMPLETA
	printf '#!/bin/sh\necho "MOD=$MOD R=$R O=$O budget=$(%s/msysctl -n hw.vmm.vmx.vept_scan_budget_us)" > %s/braccio-ricevuto.txt\nmkdir -p "$O"\ntrap '"'"'echo "OUTPUT $O INCOMPLETA interrotto (TERM)"; exit 0'"'"' TERM\ncase ",$MOCK_GUASTI," in *,lento,*) /bin/sleep 8 & wait $! ;; esac\necho "OUTPUT $O COMPLETA"\n' $M $M >| $M/prova
	chmod +x $M/fdf $M/msysctl $M/fmount $M/fswapctl $M/fswapinfo $M/prova
	PR=$(/sbin/sha256 -q $M/prova)
	/usr/local/bin/python3 - $W/run-dedup92-8vp.sh $M/run.sh $M $PR <<'PYFINTO'
import re, sys
src, dst, M, pr = sys.argv[1:]
s = open(src).read()
s = re.sub(r'^PROVA_SHA=.*$', 'PROVA_SHA=' + pr, s, flags=re.M)
rep = [
 ('[ "$(id -u)" = 0 ] ||', 'true ||'),
 ('BASE=$B/logs/dedup92-8vp-', 'BASE=%s/logs/dedup92-8vp-' % M),
 ('PROVA=$B/run-dedup92-8vp-prova.sh', 'PROVA=%s/prova' % M),
 ('[ "$(sha256 -q /boot/kernel/vmm-restore.ko)" = "$MOD_SHA" ] ||', 'true ||'),
 ('readelf -n /boot/kernel/vmm-restore.ko 2>/dev/null | /usr/bin/grep -q "Build ID: $MOD_BUILDID" ||', 'true ||'),
 ('[ "$(sha256 -q $N/12-Windows-11-vm12-senza-gpu-8vp)" = "$VM8_SHA" ] ||', 'true ||'),
 ('[ "$(sha256 -q $LAT)" = "$LAT_SHA" ] ||', 'true ||'),
 ('LIBERI=$(df -k', 'LIBERI=$(%s/fdf -k' % M),
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
corri() {	# $1 nome, $2 budget iniziale, $3 rw|ro, $4 MISURA_R (vuoto = predefinito), $5 MISURA_BUDGET, $6 guasti, $7 vept_diag, $8 KB liberi
	prepara $B/$1 $2 $3 "$7" "$8"
	MOCK_GUASTI=$6; export MOCK_GUASTI
	if [ -n "$4" ]; then MISURA_R=$4 MISURA_BUDGET=${5:-2000} /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; else /bin/sh $B/$1/run.sh > $B/$1/uscita.txt 2>&1; fi
	rc=$?
	R=$(/bin/ls -d $B/$1/logs/dedup92-8vp-*/riepilogo.txt 2>/dev/null | head -1)
}
iniziale() { [ "$(/usr/bin/awk '$1=="vept_scan_budget_us" {print $2}' $1/stato) $(/usr/bin/awk '$1=="vept_scan_retries" {print $2}' $1/stato)" = "2000 1" ] && echo "  ok      budget e retry rimessi a 2000 / 1" || { echo "  ERRATO  stato finale: $(/usr/bin/grep -E 'budget|retries' $1/stato | tr '\n' ' ')"; nf=$((nf + 1)); }; }
nonavviato() { [ -e $1/braccio-ricevuto.txt ] && { echo "  ERRATO  il braccio e' partito"; nf=$((nf + 1)); } || echo "  ok      braccio non avviato"; }
echo "D1: braccio A regolare"
corri d1 2000 rw ''
uscita $rc 0
case "$R" in *dedup92-8vp-A-*) echo "  ok      cartella dedup92-8vp-A";; *) echo "  ERRATO  cartella: $R"; nf=$((nf + 1));; esac
atteso $B/d1/braccio-ricevuto.txt "il braccio riceve MOD=A R=1, cartella 1-A, budget 2000" '^MOD=A R=1 O=.*/1-A budget=2000$'
atteso "$R" "riepilogo: braccio A, retry 1, budget 2000 riletto" 'braccio A \(vept_scan_retries=1, budget 2000 us riletto\)'
atteso "$R" "MISURA=COMPLETA" '^MISURA=COMPLETA RIPRISTINO=OK USCITA=0'
atteso "$(dirname "$R")/baseline.txt" "baseline con l'hash della traccia" '^traccia [0-9a-f]{64}$'
iniziale $B/d1
echo "D2: MISURA_R=2 (solo A ammesso)"
corri d2 2000 rw 2
uscita $rc 4
atteso $B/d2/uscita.txt "messaggio: solo il braccio A" 'parere #92: solo il braccio A'
nonavviato $B/d2
echo "D3: vept_diag acceso"
corri d3 2000 rw '' '' '' 1
uscita $rc 4
atteso "$R" "STOP su vept_diag" '^STOP: vept_diag acceso'
nonavviato $B/d3
echo "D4: meno di 2 GiB liberi in logs/"
corri d4 2000 rw '' '' '' 0 1000000
uscita $rc 4
atteso "$R" "STOP sullo spazio" '^STOP: meno di 2 GiB liberi'
nonavviato $B/d4
echo "D5: budget iniziale non standard"
corri d5 4000 rw ''
uscita $rc 4
atteso "$R" "STOP sul budget iniziale" '^STOP: vept_scan_budget_us iniziale diverso da 2000'
nonavviato $B/d5
echo "D6: disco della VM non in scrittura"
corri d6 2000 ro ''
uscita $rc 4
atteso "$R" "STOP sul disco" '^STOP: /dev/da0p2 non montato in scrittura'
echo "D7: SIGTERM durante il braccio"
prepara $B/d7 2000 rw
MOCK_GUASTI=lento; export MOCK_GUASTI
/bin/sh $B/d7/run.sh > $B/d7/uscita.txt 2>&1 &
pid=$!
k=0; until [ -e $B/d7/braccio-ricevuto.txt ] || [ $k -gt 100 ]; do k=$((k + 1)); sleep 0.1; done
sleep 1; kill -TERM $pid; wait $pid; rc=$?
R=$(/bin/ls -d $B/d7/logs/dedup92-8vp-*/riepilogo.txt | head -1)
uscita $rc 143
atteso "$R" "MISURA=INTERROTTA" '^MISURA=INTERROTTA RIPRISTINO=OK USCITA=143'
iniziale $B/d7
echo "controlli errati: $nf"
[ $nf -eq 0 ]
