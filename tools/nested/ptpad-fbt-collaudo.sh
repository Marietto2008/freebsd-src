#!/bin/sh
# ptpad-fbt-collaudo.sh -- Claude 27/10/2026, parere #107 §4/§5.4. Collaudo SENZA VM della traccia
# ptpad-fbt.d sul FreeBSD installato: (1) i marcatori fstatat del processo indicato come driver
# arrivano nella STESSA istanza DTrace, con etichetta e pid giusti; (2) lo stesso fstatat da un pid
# ESTRANEO non viene registrato; (3) nessuna sonda FBT scatta senza VM; (4) PRONTA e CHIUSA presenti,
# stderr di dtrace VUOTO; (5) l'execname reale del QEMU installato e' quello del predicato;
# (6) la correlazione del driver (fbt_per_caso) accetta la traccia vera.
# Abilita sonde in sola lettura per pochi secondi. Nessuna VM, nessun sysctl, nessun modulo.
# Uso: ptpad-fbt-collaudo.sh <cartella> [script]   uscita 0 = tutto ok
# #142: script facoltativo (default ptpad-fbt.d); con ptpad-fbt-ripfix-nested.d anche: riga SONDE FATALI presente e
# nessuna sonda del latch (fatal/fatalret/veptunemul) senza VM. Quello script compila SOLO col modulo RIPFIX caricato.
N=$(cd "$(dirname "$0")" && pwd)
O=${1:?cartella}
FBTS=${2:-$N/ptpad-fbt.d}
QEMU=/mnt/linuxulator2/vm/wsl2/fbsd/stage/current/bin/qemu-system-x86_64
PY=/usr/local/bin/python3
mkdir -p "$O" || exit 1
nf=0
ok() { echo "  ok      $*"; }
no() { echo "  ERRATO  $*"; nf=$((nf+1)); }

# marcatore: aspetta il via, poi tre confini come il driver
$PY -c "
import os, time
while not os.path.exists('$O/via'): time.sleep(0.05)
for m in ('ack-B', 'l1-B', 'fine'):
    try: os.stat('/nonexistent/ptpad-mark/' + m)
    except OSError: pass
" &
PM=$!
: >| "$O/fbt.txt"
sudo -n /usr/sbin/dtrace -q -s "$FBTS" -o "$O/fbt.txt" $PM 2> "$O/fbt.err" &
DT=$!
sudo -n /usr/sbin/dtrace -q -n 'BEGIN { printf("== EXEC PRONTA ==\n"); }
proc:::exec-success { printf("EXEC comm=%s pid=%d\n", execname, pid); }' -o "$O/exec.txt" 2> "$O/exec.err" &
DE=$!
i=0
until grep -q '== FBT PRONTA ==' "$O/fbt.txt" 2>/dev/null && grep -q '== EXEC PRONTA ==' "$O/exec.txt" 2>/dev/null; do
	i=$((i + 1)); [ $i -gt 60 ] && { no "dtrace non pronto"; break; }; sleep 0.25
done
# estraneo: stesso percorso, altro pid
$PY -c "
import os
try: os.stat('/nonexistent/ptpad-mark/estraneo')
except OSError: pass
"
touch "$O/via"
wait $PM
"$QEMU" -version > "$O/qemu-version.txt" 2>&1
sleep 0.5
sudo -n kill -TERM $DT $DE; wait $DT $DE 2>/dev/null
echo "pid marcatore $PM" > "$O/pid.txt"

grep -q '== FBT CHIUSA ==' "$O/fbt.txt" && ok "traccia PRONTA e CHIUSA" || no "manca CHIUSA"
[ -s "$O/fbt.err" ] && no "stderr di dtrace non vuoto: $(head -3 $O/fbt.err)" || ok "stderr di dtrace vuoto"
m=$(grep 'k=mark' "$O/fbt.txt" | sed 's/.* pid=\([0-9]*\) .* m=\(.*\)/\1:\2/' | sort | tr '\n' ' ')
atteso=$(printf '%s\n' "$PM:ack-B" "$PM:fine" "$PM:l1-B" | sort | tr '\n' ' ')
[ "$m" = "$atteso" ] && ok "tre marcatori dal pid del driver ($m)" || no "marcatori: '$m' invece di '$atteso'"
grep -q 'm=estraneo' "$O/fbt.txt" && no "marcatore di un pid ESTRANEO registrato" || ok "marcatore di un pid estraneo NON registrato"
grep -qE 'k=(mmio|walk)' "$O/fbt.txt" && no "sonde FBT scattate SENZA VM" || ok "nessuna sonda FBT senza VM"
if grep -q 'RIPFIX-INIZIO' "$FBTS"; then
	grep -q '== FBT SONDE FATALI ==' "$O/fbt.txt" && ok "script RIPFIX: sonde del latch ARMATE (riga SONDE FATALI)" || no "script RIPFIX senza la riga SONDE FATALI"
	grep -qE 'k=(fatal|fatalret|veptunemul) ' "$O/fbt.txt" && no "sonde del latch scattate SENZA VM" || ok "nessuna sonda del latch senza VM"
fi
grep -q '^FBT CONTA' "$O/fbt.txt" && no "aggregato FBT non vuoto: $(grep '^FBT CONTA' $O/fbt.txt)" || ok "aggregati FBT vuoti"
ec=$(sed -n 's/^EXEC comm=\(qemu[^ ]*\) .*/\1/p' "$O/exec.txt" | head -1)
pr=$(sed -n 's/.*execname == "\([^"]*\)".*/\1/p' "$FBTS" | sort -u | tr '\n' ' ')
[ -n "$ec" ] && [ "$pr" = "$ec " ] && ok "execname reale di QEMU '$ec' = predicato ($(head -1 $O/qemu-version.txt))" || no "execname reale '$ec', predicato '$pr'"
[ -s "$O/exec.err" ] && no "stderr della traccia exec non vuoto" || ok "stderr della traccia exec vuoto"
$PY - "$N/ptpad-drive.py" "$O/fbt.txt" "$PM" > "$O/correlazione.txt" 2>&1 <<'FINE_CORR_COLL_G7'
import importlib.util, sys
sp = importlib.util.spec_from_file_location('drv', sys.argv[1])
d = importlib.util.module_from_spec(sp); sp.loader.exec_module(d)
c = d.fbt_per_caso(open(sys.argv[2]).read(), int(sys.argv[3]), set(), ['B'], ['B'])
print('correlazione', c)
sys.exit(0 if c == {'B': (0, 0)} else 1)
FINE_CORR_COLL_G7
[ $? = 0 ] && ok "fbt_per_caso sulla traccia VERA: $(cat $O/correlazione.txt)" || no "correlazione sulla traccia vera: $(cat $O/correlazione.txt)"
echo "controlli errati: $nf"
[ $nf -eq 0 ]
