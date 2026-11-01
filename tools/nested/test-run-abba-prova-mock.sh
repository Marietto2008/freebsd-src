#!/bin/sh
# test-run-abba-prova-mock.sh -- Claude 27/10/2026, parere #85 §3: prova
# dall'inizio alla fine di run-abba-retry-prova.sh (UN braccio) SENZA VM e
# senza Windows. Finti: ssh/scp verso Windows (w, cpw), il bhyve (processo con
# "bhyve ... vm0:12" nella riga di comando, che si spegne quando Windows riceve
# "shutdown"), sysctl (file di stato con i contatori), bhyvectl, dtrace,
# vmstat, tsecho, mount, guardia-win. Attese lunghe azzerate. Reali e in sola
# lettura: ps, fstat, cpuset -g, sha256, kldstat, swapinfo.
# Corse: P1 regolare; P2 mismatch HPA durante ext4; P3 WSL muto; P4 sysctl
# che non attecchisce (nessuna VM deve partire); P5 SIGTERM durante ext4;
# P6 VM gia' viva.
# Uso: test-run-abba-prova-mock.sh <cartella di lavoro vuota>
T=$(cd "$(dirname "$0")" && pwd)
W=/mnt/linuxulator2/vm/wsl2/fbsd
B=${1:?cartella}
nf=0
prepara() {	# $1 cartella
	M=$1; mkdir -p $M/vmm $M/win $M/bin
	/usr/bin/cc -O0 -Wall -Wextra -Werror -o $M/bin/bhyve $T/fintavm.c || exit 1
	cat >| $M/stato <<EOF
vept_keep 0
vept_verify_hpa 0
vept_test_race 0
vept_scan_hold_keep 0
vept_scan_retries 1
nested_shadow_vmcs 0
nested_shadow_verify 0
nested_fast_field_validate 0
nested_shadow_inject 0
nested_vpid_track 0
nested_vpid12_flush 0
nested_sh_faults 0
nested_sh_entry_after_fault 0
vept_keep_verify_mismatch 0
vpid02_off_vcpus 0
vept_scan_retry_2_success 0
EOF
	# sysctl finto; guasti: norcfg (vept_scan_retries non si scrive),
	# mm4 (alla prima lettura dopo l'avvio di ext4 il mismatch diventa 1)
	cat >| $M/msysctl <<EOF
#!/bin/sh
n=0; [ "\$1" = -n ] && { n=1; shift; }
for a in "\$@"; do
	k=\${a%%=*}; k=\${k#hw.vmm.vmx.}
	case "\$a" in
	*=*) v=\${a#*=}
		case ",\$MOCK_GUASTI," in *,norcfg,*) [ "\$k" = vept_scan_retries ] && continue;; esac
		/usr/bin/sed -i '' "s/^\$k .*/\$k \$v/" $M/stato ;;
	hw.vmm.vmx) /usr/bin/awk '{print "hw.vmm.vmx." \$1 ": " \$2}' $M/stato ;;
	dev.cpu) echo "dev.cpu.0.freq: 4698" ;;
	vm.stats.vm.*|hw.pagesize) echo 1 ;;
	*) case ",\$MOCK_GUASTI," in *,mm4,*) [ "\$k" = vept_keep_verify_mismatch ] && [ -e $M/win/ext4-avviata ] && /usr/bin/sed -i '' "s/^vept_keep_verify_mismatch .*/vept_keep_verify_mismatch 1/" $M/stato;; esac
		case ",\$MOCK_GUASTI," in *,vpoff4,*) [ "\$k" = vpid02_off_vcpus ] && [ -e $M/win/ext4-avviata ] && /usr/bin/sed -i '' "s/^vpid02_off_vcpus .*/vpid02_off_vcpus 1/" $M/stato;; esac
		v=\$(/usr/bin/awk -v k="\$k" '\$1==k {print \$2}' $M/stato)
		[ \$n = 1 ] && echo "\$v" || echo "hw.vmm.vmx.\$k: \$v" ;;
	esac
done
EOF
	# finto bhyve: programma di NOME bhyve con vm0:12 negli argomenti; vive finche' Windows non e' spento
	cat >| $M/avvia-vm <<EOF
#!/bin/sh
: >| $M/vmm/vm0:12
SPENTO=$M/win/spento exec $M/bin/bhyve -c 2 -m 32G vm0:12
EOF
	# finto Windows: w <comando>, cpw <da> <a>
	cat >| $M/fw <<EOF
#!/bin/sh
c="\$*"
case "\$c" in
*"echo pronto"*) echo pronto ;;
*"shutdown /s"*) : >| $M/win/spento ;;
*gapmem.sh*) : >| $M/win/ext4-avviata ;;
*) : ;;
esac
EOF
	cat >| $M/fcpw <<EOF
#!/bin/sh
da=\$1; a=\$2
case "\$da" in
*wsl-args.txt) /usr/bin/grep -q gapmem.sh "\$da" && : >| $M/win/ext4-avviata ;;
*wsl-log.txt) case ",\$MOCK_GUASTI," in *,wslmuto,*) exit 1;; esac; printf 'Linux\n2\n2\nWSL-OK\n' > "\$a" ;;
*gapmem-A.log) [ -e $M/win/ext4-avviata ] || exit 1
	case ",\$MOCK_GUASTI," in *,lento4,*) [ -e $M/win/lento-passato ] || { : >| $M/win/lento-passato; printf 'RISCALDAMENTO-FINE\n' > "\$a"; exit 0; };; esac
	printf 'RISCALDAMENTO-FINE\nCICLO 1 dd 1.0\nCICLO 1 ok 2.0\nCICLO 2 dd 3.0\nCICLO 2 ok 4.0\nGAP-FINE\n' > "\$a" ;;
*gapmem-gapmon-A.txt) printf 'BUCO 12 ms\n' > "\$a" ;;
*kbuild.log) printf 'real\t20m1.5s\nkernel rc=0\nKBUILD-FINE\n' > "\$a" ;;
*kbuild-lavoro.txt) case ",\$MOCK_GUASTI," in *,lavmuto,*) exit 1;; esac
	printf 'AZIONI_CC=2610\nAZIONI_TOT=3015\nCONFIG=abc\nMAKEFILE=def\nSORGENTI=61234\nSORGENTI_KB=987654\nGCC=12.2.0\nMAKE=GNU_Make_4.3\nNPROC=2\nLAVORO-FINE\n' > "\$a" ;;
*marietto@win11*) : ;;
*) : ;;
esac
EOF
	# finto dtrace: PRONTA subito, CONTA/ISTOGRAMMI/CHIUSA al SIGTERM
	cat >| $M/fdtrace <<EOF
#!/bin/sh
out=""; while [ \$# -gt 0 ]; do [ "\$1" = -o ] && out=\$2; shift; done
echo "== LATENZA PRONTA == pid=1" > "\$out"
case ",\$MOCK_GUASTI,:\$out" in *,drop5,*:*lat-05.txt) echo "dtrace: 3 drops on CPU 1" >&2 ;; esac
trap 'printf "CONTA n=3\nCONTA servizio_somma=300000\nCONTA reale_somma=300000\n== ISTOGRAMMA reale ==\n  100000 |@@@ 3\n== ISTOGRAMMA servizio ==\n  100000 |@@@ 3\n== LATENZA CHIUSA ==\n" >> "\$out"; exit 0' TERM
while :; do sleep 0.2; done
EOF
	printf '#!/bin/sh\nwhile :; do sleep 1; done\n' >| $M/attesa
	printf '#!/bin/sh\necho "vcpu stats"\nprintf "total number of vm exits\\t100\\n"\n' >| $M/fbhyvectl
	chmod +x $M/msysctl $M/avvia-vm $M/fw $M/fcpw $M/fdtrace $M/attesa $M/fbhyvectl
	/usr/local/bin/python3 - $W/run-abba-retry-prova.sh $M/prova.sh $M <<'PYEOF'
import re, sys
src, dst, M = sys.argv[1:]
s = open(src).read()
rep = [
 ('\ncpw() { sshpass', '\ncpw() { %s/fcpw "$@"; }\ncpw_vero() { sshpass' % M),
 ('\nw() { sshpass', '\nw() { %s/fw "$@"; }\nw_vero() { sshpass' % M),
 ('sh "$N/12-Windows-11-vm12-senza-gpu"', 'sh %s/avvia-vm' % M),
 ('LAT=$N/abba-invept-lat.d', 'LAT=%s/fdtrace' % M),
 ('dtrace -s "$LAT" "$p"', '%s/fdtrace -s "$LAT" "$p"' % M),
 ('vmstat -w 1 >', '%s/attesa >' % M),
 ('python3 "$C/tsecho.py" 7123', '%s/attesa' % M),
 ('mount | /usr/bin/grep -q "/mnt/da0p2" || mount -t ufs /dev/da0p2 /mnt/da0p2', 'true'),
 ('sh "$B/guardia-win.sh" aggiorna', 'echo guardia-finta'),
 ('sh "$B/guardia-win.sh" riprendi', 'echo guardia-finta'),
 ('/dev/vmm', M + '/vmm'),
]
for a, b in rep:
	assert a in s, a
	s = s.replace(a, b)
s = re.sub(r'(?<![\w/.-])sysctl ', M + '/msysctl ', s)
s = re.sub(r'(?<![\w/.-])bhyvectl ', M + '/fbhyvectl ', s)
s = re.sub(r'\bsleep (90|120|30|20|10|5|3)\b', 'sleep 0', s)
for bad in ('sshpass -f /home/marietto/.config/claude-wsl2/password-windows ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR marietto@win11 "$@"',):
	assert ('w_vero() { ' + bad) in s or bad not in s
open(dst, 'w').write(s)
PYEOF
}
atteso() { if /usr/bin/grep -qE -- "$3" "$1" 2>/dev/null; then echo "  ok      $2"; else echo "  ERRATO  $2 (manca /$3/ in $(basename "$1"))"; nf=$((nf + 1)); fi; }
assente() { if /usr/bin/grep -qE -- "$3" "$1" 2>/dev/null; then echo "  ERRATO  $2"; nf=$((nf + 1)); else echo "  ok      $2"; fi; }
nessuna_vm() { /bin/ps -ax -o comm= -o args= | /usr/bin/awk -v b="$1/bin/bhyve" '$1 == "bhyve" && index($0, b)' | /usr/bin/grep -q . && { echo "  ERRATO  finto bhyve ancora vivo"; nf=$((nf + 1)); } || echo "  ok      nessun finto bhyve vivo alla fine"; }
pulizia() {	# spegne i finti bhyve rimasti da corse precedenti (igiene del test)
	for d in $B/p*/win; do [ -d "$d" ] && : >| "$d/spento"; done
	sleep 0.5
}
corri() {	# $1 nome, $2 guasti
	pulizia
	prepara $B/$1
	O=$B/$1/out R=2 MOD=B MOCK_GUASTI=$2 /bin/sh $B/$1/prova.sh 480 2 > $B/$1/run.out 2>&1
	P=$B/$1
}

echo "P1: braccio regolare"
corri p1 ''
atteso $P/run.out "esito COMPLETA" '^OUTPUT .* COMPLETA$'
atteso $P/out/configurazione.txt "sysctl riletti = attesi (retry 2)" "riletti: 1 1 0 0 2 1 0 0 0 1 0 $"
atteso $P/out/lat-04.txt "latenza ext4 chiusa" '== LATENZA CHIUSA =='
atteso $P/out/lat-05.txt "latenza compilazione chiusa" '== LATENZA CHIUSA =='
atteso $P/out/fasi.txt "fasi 01..07 registrate" '^FASE 07-fine'
atteso $P/out/fasi.txt "misura del lavoro in una fase sua (fuori dal tempo di compilazione)" '^FASE 05b-misura-lavoro'
atteso $P/out/kbuild-lavoro.txt "kbuild-lavoro.txt copiato" '^LAVORO-FINE$'
atteso $P/out/checkpoint.txt "lavoro riportato nel checkpoint" '^AZIONI_CC=2610$'
atteso $P/out/checkpoint.txt "compilazione rc=0" 'kernel rc=0'
atteso $P/out/checkpoint.txt "spegnimento ordinato" 'spegnimento ordinato'
atteso $P/out/foto.txt "foto con frequenza CPU" 'dev.cpu.0.freq'
atteso $P/out/foto.txt "foto con affinita' del bhyve" '^cpuset: '
n=$(/usr/bin/find $P/out -type f ! -perm -a+r | /usr/bin/grep -c .); [ "$n" = 0 ] && echo "  ok      tutti i file leggibili (a+r)" || { echo "  ERRATO  $n file non leggibili"; nf=$((nf + 1)); }
nessuna_vm $P
sudo -n /usr/local/bin/python3 $W/abba_retry_an.py --lat $P/out/lat-05.txt > $P/lat.txt 2>&1
atteso $P/lat.txt "il lettore di latenze legge il file del braccio" "'n': 3"

echo "P2: mismatch HPA durante ext4"
corri p2 mm4
atteso $P/run.out "esito CORRETTEZZA" '^OUTPUT .* CORRETTEZZA'
atteso $P/out/checkpoint.txt "checkpoint col mismatch" 'mismatch HPA 1'
assente $P/out/fasi.txt "compilazione NON avviata" '05-compilazione'
atteso $P/out/checkpoint.txt "Windows spento comunque" 'spegnimento ordinato'
nessuna_vm $P

echo "P3: WSL muto"
corri p3 wslmuto
atteso $P/run.out "esito INCOMPLETA (WSL)" '^OUTPUT .* INCOMPLETA WSL non ha risposto$'
assente $P/out/fasi.txt "ext4 NON avviata" '04-ext4'
nessuna_vm $P

echo "P4: sysctl che non attecchisce"
corri p4 norcfg
atteso $P/run.out "esito CONFIG (retry riletto 1 invece di 2)" "^OUTPUT .* CONFIG .*riletti '1 1 0 0 1 1 0 0 0 1 0 ' diversi"
assente $P/out/fasi.txt "nessuna VM avviata" '01-avvio'
nessuna_vm $P

echo "P5: SIGTERM durante ext4"; pulizia
prepara $B/p5
O=$B/p5/out R=1 MOD=A MOCK_GUASTI=lento4 /bin/sh $B/p5/prova.sh 480 2 > $B/p5/run.out 2>&1 &
pid=$!
k=0; until /usr/bin/grep -q 'FASE 04-ext4' $B/p5/out/fasi.txt 2>/dev/null || [ $k -gt 150 ]; do k=$((k + 1)); sleep 0.2; done
sleep 1; kill -TERM $pid; wait $pid
P=$B/p5
atteso $P/run.out "esito INCOMPLETA interrotto" '^OUTPUT .* INCOMPLETA interrotto \(TERM\)$'
atteso $P/out/checkpoint.txt "interruzione registrata" 'INTERROTTO \(TERM\)'
atteso $P/out/lat-04.txt "latenza ext4 chiusa anche interrotta" '== LATENZA CHIUSA =='
[ -e $B/p5/win/spento ] && echo "  ok      Windows spento in modo ordinato (comando shutdown via ssh)" || { echo "  ERRATO  Windows non spento"; nf=$((nf + 1)); }
nessuna_vm $P

echo "P6: VM gia' viva"; pulizia
prepara $B/p6
SPENTO=$B/p6/win/spento $B/p6/bin/bhyve -c 2 vm0:12 &
sleep 0.5
O=$B/p6/out R=1 MOD=A /bin/sh $B/p6/prova.sh 480 2 > $B/p6/run.out 2>&1
P=$B/p6
atteso $P/run.out "esito CONFIG per VM viva" '^OUTPUT .* CONFIG processo VM vivo prima del braccio$'
assente $P/out/fasi.txt "nessuna nuova VM" '01-avvio'
: >| $B/p6/win/spento; wait
echo "P7: misura del lavoro assente"
corri p7 lavmuto
atteso $P/run.out "esito INCOMPLETA (lavoro)" '^OUTPUT .* INCOMPLETA misura del lavoro assente$'
atteso $P/out/checkpoint.txt "Windows spento comunque" 'spegnimento ordinato'
nessuna_vm $P

echo "P8: VPID02 spento durante ext4 (non comparabile, NON correttezza)"
corri p8 vpoff4
atteso $P/run.out "esito INCOMPLETA non comparabile" '^OUTPUT .* INCOMPLETA non comparabile: VPID02 spento su 1 vCPU'
assente $P/run.out "non classificato come CORRETTEZZA" '^OUTPUT .* CORRETTEZZA'
nessuna_vm $P

echo "P9: drop di DTrace nella compilazione"
corri p9 drop5
atteso $P/run.out "esito INCOMPLETA latenza" '^OUTPUT .* INCOMPLETA latenza compilazione mancante'
assente $P/out/fasi.txt "misura del lavoro non eseguita dopo lo stop" '05b-misura-lavoro'
nessuna_vm $P
pulizia

echo "controlli errati: $nf"
[ $nf -eq 0 ]
