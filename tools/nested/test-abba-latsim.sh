#!/bin/sh
# test-abba-latsim.sh -- Claude 27/10/2026, parere #85 §3.2.4: collaudo OFFLINE
# di abba-invept-lat.d e del lettore di latenze di abba_retry_an.py con DTrace
# VERO (pid provider) su abba-invept-latsim.c. Confronta conteggi esatti e
# intervalli plausibili per massimi e percentili. Nessuna VM.
T=$(cd "$(dirname "$0")" && pwd)
AN=/mnt/linuxulator2/vm/wsl2/fbsd/abba_retry_an.py
OUT=${1:-/tmp}
/usr/local/bin/python3 $T/gen-abba-lat.py $OUT >/dev/null || exit 1
/usr/bin/cc -O0 -Wall -Wextra -Werror -o $OUT/abba-invept-latsim $T/abba-invept-latsim.c || exit 1
sudo -n /usr/sbin/dtrace -s $OUT/abba-invept-latsim.d -o $OUT/lat.txt -c $OUT/abba-invept-latsim 2>| $OUT/lat.err >/dev/null
/usr/local/bin/python3 - $AN $OUT/lat.txt $OUT/lat.err <<'EOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('an', sys.argv[1]); an = importlib.util.module_from_spec(spec)
sys.argv_salvati = sys.argv; spec.loader.exec_module(an)
r = an.latenze(open(sys.argv[2]).read())
err = open(sys.argv[3]).read().strip()
nf = 0
def c(nome, ok, v):
	global nf
	nf += not ok
	print('  %-46s %-14s %s' % (nome, v, 'ok' if ok else 'ERRATO'))
c('traccia chiusa', r is not None, r is not None)
if r is None:
	print(open(sys.argv[2]).read()); sys.exit(1)
c('stderr di DTrace vuoto', err == '', repr(err[:60]))
c('n = 308 (300+5+2+1 col rientro)', r['n'] == 308, r['n'])
c('rientri = 1', r.get('annidate', 0) == 1, r.get('annidate', 0))
c('servizio > 2 ms = 5 (le 3 ms su CPU)', r['servizio_2ms'] == 5, r['servizio_2ms'])
c('servizio > 16 ms = 0 (il sonno NON e servizio)', r['servizio_16ms'] == 0, r['servizio_16ms'])
c('reale > 2 ms = 7 (5 su CPU + 2 sonni)', r['reale_2ms'] == 7, r['reale_2ms'])
c('reale > 16 ms = 2 (i sonni)', r['reale_16ms'] == 2, r['reale_16ms'])
c('operazioni con fuori CPU >= 2', r['con_offcpu'] >= 2, r['con_offcpu'])
c('fuori CPU totale >= 40 ms', r['offcpu_somma'] >= 40e6, '%.1f ms' % (r['offcpu_somma'] / 1e6))
c('reale max in [20, 40] ms', 20e6 <= r['reale_max'] <= 40e6, '%.1f ms' % (r['reale_max'] / 1e6))
c('servizio max in [3, 5] ms', 3e6 <= r['servizio_max'] <= 5e6, '%.2f ms' % (r['servizio_max'] / 1e6))
c('servizio p50 in [36, 50] us', 36e3 <= r['servizio_p50'] <= 50e3, '%.1f us' % (r['servizio_p50'] / 1e3))
c('servizio p99 in [2.7, 3.5] ms (5+1 lunghe su 308)', 2.7e6 <= r['servizio_p99'] <= 3.5e6, '%.2f ms' % (r['servizio_p99'] / 1e3 / 1e3))
c('reale p99.9 in [18, 40] ms', 18e6 <= r['reale_p99_9'] <= 40e6, '%.1f ms' % (r['reale_p99_9'] / 1e6))
c('istogrammi: 308 campioni ciascuno', r['reale_n'] == 308 and r['servizio_n'] == 308, (r['reale_n'], r['servizio_n']))
c('numerosita coerente (n = istogrammi)', r['coerente'] is True, r['coerente'])
c('p50 servizio: bucket [lo, hi) con hi > lo', r['servizio_p50_hi'] > r['servizio_p50'], '[%.1f, %.1f) us' % (r['servizio_p50'] / 1e3, r['servizio_p50_hi'] / 1e3))
c('p99.9 segnalato instabile (308 op: <10 in coda)', r['coda_instabile'] is True, r['coda_instabile'])
print('controlli errati: %d' % nf)
sys.exit(1 if nf else 0)
EOF
