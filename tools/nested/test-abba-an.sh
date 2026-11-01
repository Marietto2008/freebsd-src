#!/bin/sh
# test-abba-an.sh -- Claude 27/10/2026, pareri #85-#86: collaudo di
# abba_retry_an.py su serie ABBA REALI del 24-25/10 (tempi, contatori, kbuild.log
# e gapmem veri). Le serie di allora non hanno kbuild-lavoro.txt (misura nuova del
# #86): nelle COPIE se ne aggiunge uno SINTETICO identico nei quattro bracci
# (dichiarato), e in un caso uno diverso nel braccio 3. Soglie di EVIDENZA
# fissate prima, non toccate qui.
# Uso: test-abba-an.sh <cartella di lavoro vuota>   (legge i log via sudo, sola lettura)
AN=/mnt/linuxulator2/vm/wsl2/fbsd/abba_retry_an.py
L=/mnt/linuxulator2/vm/wsl2/fbsd/logs
B=${1:?cartella}
nf=0
LAV='AZIONI_CC=2610
AZIONI_TOT=3015
CONFIG=0000000000000000000000000000000000000000000000000000000000000000
MAKEFILE=1111111111111111111111111111111111111111111111111111111111111111
SORGENTI=61234
SORGENTI_KB=987654
GCC=12.2.0
MAKE=GNU_Make_4.3
NPROC=2
LAVORO-FINE'
copia() {	# copia <serie> <bracci...>: copia leggibile con kbuild-lavoro.txt sintetico
	s=$1; shift
	mkdir -p $B/$s
	for k in "$@"; do
		[ -d $B/$s/$k ] || sudo -n /bin/cp -R $L/$s/$k $B/$s/$k
		printf '%s\n' "$LAV" | sudo -n /usr/bin/tee $B/$s/$k/kbuild-lavoro.txt > /dev/null
	done
	sudo -n /usr/sbin/chown -R marietto $B/$s && /bin/chmod -R u+rw,a+r $B/$s
}
atteso() {	# atteso <uscita> <descrizione> <regex>
	if echo "$1" | /usr/bin/grep -qE -- "$3"; then echo "  ok      $2"; else echo "  ERRATO  $2 (manca /$3/)"; nf=$((nf + 1)); fi
}
copia abbavpid-20261025-2021 1-N 2-T 3-T 4-N
copia abba-20261025-0317 1-A 3-C 6-C 8-A
copia abba-20261024-2132 1-A 2-B 3-C 6-C 7-B 8-A

echo "VPID track 0/1 (25/10): coppie -57 / -14 s"
r=$(/usr/local/bin/python3 $AN $B/abbavpid-20261025-2021 --mappa N=A,T=B --retry A=1,B=1)
atteso "$r" "WORKLOAD_COMPARABILE=SI" '^WORKLOAD_COMPARABILE=SI$'
atteso "$r" "MIGLIORA" '^VERDETTO_PRESTAZIONI=MIGLIORA'
atteso "$r" "percentuali sul proprio A: -4.57% e -1.16%" 'd1=B1-A1 -57\.0 s \(-4\.57% di A1\), d2=B2-A2 -13\.9 s \(-1\.16% di A2\)'
atteso "$r" "EVIDENZA=DA_REPLICARE (conservativo 1.16%)" '^EVIDENZA=DA_REPLICARE \(effetto conservativo 1\.16%'
atteso "$r" "latenze dichiarate non disponibili (serie vecchia)" 'A1  comp non disponibile'

echo "shadow 0/1 (25/10, bracci A e C): coppie -572 / -120 s"
r=$(/usr/local/bin/python3 $AN $B/abba-20261025-0317 --mappa C=B --retry A=1,B=1)
atteso "$r" "MIGLIORA" '^VERDETTO_PRESTAZIONI=MIGLIORA'
atteso "$r" "EVIDENZA=DA_REPLICARE (|D| 346 entro la dispersione 442)" '^EVIDENZA=DA_REPLICARE'

echo "shadow 0/1 (24/10, bracci A e C): coppie -358 / -521 s"
r=$(/usr/local/bin/python3 $AN $B/abba-20261024-2132 --mappa C=B,B=X --retry A=1,B=1)
atteso "$r" "MIGLIORA" '^VERDETTO_PRESTAZIONI=MIGLIORA'
atteso "$r" "EVIDENZA=SUGGESTIVA (conservativo >= 3%, |D| > dispersione)" '^EVIDENZA=SUGGESTIVA'

echo "S0 0/1 (24/10, bracci A e B): coppie -178 / +128 s"
r=$(/usr/local/bin/python3 $AN $B/abba-20261024-2132 --mappa C=X --retry A=1,B=1)
atteso "$r" "INCONCLUSIVE" '^VERDETTO_PRESTAZIONI=INCONCLUSIVE \(compilazione CONTRADDITTORIO'
atteso "$r" "EVIDENZA=NESSUNA" '^EVIDENZA=NESSUNA$'

echo "lavoro diverso nel braccio 3 (AZIONI_CC 2500 invece di 2610)"
mkdir -p $B/diverso && /bin/cp -R $B/abbavpid-20261025-2021/. $B/diverso/
/usr/bin/sed -i '' 's/^AZIONI_CC=2610$/AZIONI_CC=2500/' $B/diverso/3-T/kbuild-lavoro.txt
r=$(/usr/local/bin/python3 $AN $B/diverso --mappa N=A,T=B --retry A=1,B=1)
atteso "$r" "WORKLOAD_COMPARABILE=NO con la chiave" "^WORKLOAD_COMPARABILE=NO \(AZIONI_CC \['2500', '2610'\]"
atteso "$r" "verdetto INCOMPLETA, non MIGLIORA" '^VERDETTO_PRESTAZIONI=INCOMPLETA'

echo "misura del lavoro assente in un braccio (LAVORO-FINE mancante)"
mkdir -p $B/assente && /bin/cp -R $B/abbavpid-20261025-2021/. $B/assente/
/usr/bin/sed -i '' '/^LAVORO-FINE$/d' $B/assente/2-T/kbuild-lavoro.txt
r=$(/usr/local/bin/python3 $AN $B/assente --mappa N=A,T=B --retry A=1,B=1)
atteso "$r" "WORKLOAD_COMPARABILE=NON_VERIFICABILE" '^WORKLOAD_COMPARABILE=NON_VERIFICABILE \(braccio 2: kbuild-lavoro.txt\)'

echo "controlli errati: $nf"
[ $nf -eq 0 ]
