#!/bin/sh
# test-dedup92.sh -- Claude 27/10/2026, pareri #92 §7 e #93: suite OFFLINE del livello 1.
# Nessuna VM, nessun sysctl scritto, nessuna sonda abilitata nel kernel.
#   P1 il dedup92.d rivisto e' ESATTAMENTE l'uscita di gen-dedup92.py
#   P2 dedup92.d compila sul modulo installato (dtrace -e: compila, non abilita),
#      solo se il modulo e' 27125f004917 (altrimenti SALTATO, dichiarato)
#   P3 DTrace VERO sul simulatore, scenario pulito: valori ESATTI (chiave primaria = EPTP12
#      completo, secondaria = base, gruppi a 1 e 5 ms, catena, stesso vCPU, riuso,
#      ALL_CONTEXT, ritentativo, sonno, FULL, classi), chiusura esatta
#   P4 DTrace VERO, un difetto per corsa (8 corse): ognuno fa fallire ESATTAMENTE i
#      controlli attesi
#   P4b DTrace VERO, BORDI: dtrace -p attaccato a meta' di un'operazione e fermato a meta'
#      di un'altra: ritorni e veptkeep orfani VALIDI al bordo d'inizio, operazioni aperte
#   P4c DTrace VERO, #95 §2: primo e ultimo GT a meta' di operazioni con 8 thread che incrementano
#      insieme (ops all'ingresso, radici 20 ms dopo); il gemello oltre il massimo fallisce
#   P5 tracce sintetiche: tentativi (#93 §3: 235/100, 200/100 con tentativo vuoto, ntr=0,
#      ntr saturo), bordi con intervalli dimostrati (#93 §4), chiave primaria/secondaria e
#      classi (#93 §5), regola di decisione pre-registrata (#93 §6), finestra ancorata,
#      estremi, marcatori, drop, errori di indirizzo, malformate, file accodato, record
#      perso, negativi, allarmi di perturbazione
#   P8 LIVELLO 2 (#95, #96): compila sul modulo; DTrace vero: finestra lunga/corta (intervallo
#      ATTIVO dai tick), bordo vero con -p (ORPH, operazioni aperte), R_pages e Q_cpu_proxy contro
#      valori calcolati dal disegno; due siti verificati SEPARATAMENTE; marcatori/END/drop; censura
#      sinistra e destra; insiemi vuoti/identici/disgiunti; campione e decisione; perturbazione
#      (elapsed contro vtimestamp, race, mix)
#   P6 lettura del braccio A REALE (sola lettura) come base della perturbazione
#   P7 involucro finto (test-run-dedup92-mock.sh)
#   P9 ciclo delle finestre di livello 2 (test-l2-ciclo.sh, dtrace finto)
#   P10 involucro del livello 2 finto (test-run-dedup95-mock.sh)
# Uso: test-dedup92.sh <cartella di lavoro vuota>
T=$(cd "$(dirname "$0")" && pwd)
W=/mnt/linuxulator2/vm/nested-work
AN=$W/dedup92_an.py
OUT=${1:?cartella}
mkdir -p "$OUT" || exit 1
nf=0
ok() { echo "  ok      $1"; }
ko() { echo "  ERRATO  $1"; nf=$((nf + 1)); }

echo "P1: dedup92.d = uscita del generatore"
mkdir -p "$OUT/gen"
/usr/local/bin/python3 $T/gen-dedup92.py "$OUT/gen" > /dev/null || ko "generatore"
[ "$(sha256 -q "$OUT/gen/dedup92.d")" = "$(sha256 -q $T/dedup92.d)" ] && ok "dedup92.d identica" || ko "dedup92.d diversa dall'uscita del generatore"

echo "P2: compilazione sul modulo installato"
if [ "$(sha256 -q /boot/kernel/vmm-restore.ko 2>/dev/null)" = 149fa57e4e38c765ece111601eaf94ea785627844db215d2285e27888733d6b9 ]; then
	sudo -n /usr/sbin/dtrace -e -s $T/dedup92.d 1 > "$OUT/compila.txt" 2>&1 && ok "dtrace -e: compila (sonde e simboli risolti)" || { ko "non compila"; cat "$OUT/compila.txt"; }
else
	echo "  SALTATO modulo installato diverso da 27125f004917"
fi

echo "P3: simulatore, scenario pulito (DTrace vero)"
/usr/bin/cc -O0 -Wall -Wextra -Werror -pthread -o "$OUT/dedup92sim" $T/dedup92sim.c || exit 1
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup92sim.d" -c "$OUT/dedup92sim pulito" > "$OUT/pulito.txt" 2> "$OUT/pulito.err"
for d in 1 2 3 4 5 6 7 8; do
	sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup92sim.d" -c "$OUT/dedup92sim $d" > "$OUT/difetto$d.txt" 2> "$OUT/difetto$d.err"
done
# P4b: attacco a meta' operazione (dopo 0,45 s) e SIGTERM al SOLO dtrace (un secondo TERM
# inoltrato da sudo lo farebbe uscire senza END) a meta' di un'altra
"$OUT/dedup92sim" bordo & SP=$!
sleep 0.45
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup92sim.d" -p $SP > "$OUT/bordo.txt" 2> "$OUT/bordo.err" & DP=$!
sleep 1.5
sudo -n pkill -TERM -f "^/usr/sbin/dtrace -s $OUT/gen/dedup92sim.d -p $SP"
wait $DP; wait $SP
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup92sim.d" -c "$OUT/dedup92sim gt" > "$OUT/gt.txt" 2> "$OUT/gt.err"
/usr/local/bin/python3 - "$AN" "$OUT" <<'PYTEST93P3'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('an', sys.argv[1]); an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)
O = sys.argv[2]
nf = 0
def c(nome, ok, v=''):
	global nf
	nf += not ok
	print('  %-62s %-24s %s' % (nome, str(v)[:24], 'ok' if ok else 'ERRATO'))
P = an.leggi(open(O + '/pulito.txt').read())
C = an.integrita(P, open(O + '/pulito.err').read(), 8, 1)
ko = [n for n, k, _ in C if not k]
c('tutti i %d controlli d\'integrita\' passano' % len(C), not ko, ko)
B = an.bilancio(P, 1, 8)
c('registro: 20 contatori, 16 BOUND_EXACT (punti), 4 di tempo BOUND_NOT_PROVEN', len(B) == 20 and sum(b[5] == 'BOUND_EXACT' for b in B) == 16 and sum(b[5] == 'BOUND_NOT_PROVEN' and b[3] is None for b in B) == 4, [b[5][6:9] for b in B])
c('finestra = GT (letti a traccia attiva)', an.finestra(P)[2] == 'GT', an.finestra(P)[2])
A = an.analizza(P, 1)
c('operazioni 31, radici 33', (A['op'], A['radici']) == (31, 33), (A['op'], A['radici']))
c('tipi {1: 30, 2: 1}, radici per op {1: 30, 3: 1}', dict(A['tipi']) == {1: 30, 2: 1} and dict(A['radici_per_op']) == {1: 30, 3: 1})
c('conservate 31, svuotate 2, motivi RACE + OVERFL', (A['conservate'], A['svuotate'], dict(A['motivi'])) == (31, 2, {'RACE': 1, 'OVERFL': 1}), dict(A['motivi']))
c('derivazione: EXACT 32, NO_SCAN 1', dict(A['derivazione']) == {'EXACT': 32, 'NO_SCAN': 1}, dict(A['derivazione']))
c('tentativi {0: 1, 1: 30, 2: 2}', dict(A['tent']) == {0: 1, 1: 30, 2: 2}, dict(A['tent']))
c('conservate con nc = 0: 20; letture 204', (A['vuote'], A['letture']) == (20, 204), (A['vuote'], A['letture']))
c('svuotamenti tracciati 2', A['svuotamento_n'] == 2, A['svuotamento_n'])
g1, g5 = A['gruppi'][1000000], A['gruppi'][5000000]
b1, b5 = A['gruppi_base'][1000000], A['gruppi_base'][5000000]
c('PRIMARIA 1 ms: 8 gruppi (S1 = 2 x 4), 9 singoli', (g1['gruppi'], g1['singoli'], dict(g1['membri'])) == (8, 9, {2: 4, 4: 4}), (g1['gruppi'], g1['singoli']))
c('PRIMARIA 5 ms: 9 gruppi (+ catena {0,3}), 7 singoli', (g5['gruppi'], g5['singoli'], dict(g5['membri'])) == (9, 7, {2: 5, 4: 4}), (g5['gruppi'], g5['singoli']))
c('SECONDARIA (base) 1 ms: 7 gruppi (S1 = 1 x 8)', (b1['gruppi'], dict(b1['membri'])) == (7, {2: 4, 4: 2, 8: 1}), dict(b1['membri']))
c('SECONDARIA 5 ms: 8 gruppi', (b5['gruppi'], dict(b5['membri'])) == (8, {2: 5, 4: 2, 8: 1}), dict(b5['membri']))
c('catena 0/3/7 a 5 ms: ampiezza max < 5 ms', 2e6 < max(g5['spread']) < 5e6, max(g5['spread']))
c('COUNTERS_MATCH 1 ms: 6 (nc=0 4, nc>0 2)', (g1['cm'], g1['cm_classi']['nc=0'][0], g1['cm_classi']['nc>0'][0]) == (6, 4, 2), g1['cm'])
c('COUNTERS_MATCH 5 ms: 7 (nc=0 5, nc>0 2)', (g5['cm'], g5['cm_classi']['nc=0'][0], g5['cm_classi']['nc>0'][0]) == (7, 5, 2), g5['cm'])
c('classi 1 ms: nc=0 4, nc>0 3 (S9), FULL 0, MISTO 1 (S10)', {k: v[0] for k, v in g1['classi'].items()} == {'nc=0': 4, 'nc>0': 3, 'FULL': 0, 'MISTO': 1}, {k: v[0] for k, v in g1['classi'].items()})
c('estremi: 0 <= S-max <= S-min', 0 <= g1['lo'] <= g1['hi'], (g1['lo'], g1['hi']))
L = an.carica_lat(O + '/pulito.txt')
c('latenze leggibili da abba_retry_an (n 31, coerenti)', L and L['n'] == 31 and L['coerente'], L and L['n'])
c('sonno di 20 ms: reale > 16 ms = 1, servizio > 16 ms = 0', L['reale_16ms'] == 1 and L.get('servizio_16ms', 0) == 0)
c('fuori CPU >= 15 ms nell\'operazione del sonno', any(o['offt'] >= 15e6 for o in P['O']), max(o['offt'] for o in P['O']))
print('P4: un difetto per corsa (DTrace vero)')
CH = ['chiusura ops_s (operazioni single-context)', 'chiusura r' + 'm (radici colpite)', 'chiusura rk (radici conservate)',
	'chiusura part (conservate (B1))', 'chiusura ok0 (riuscite al tentativo 1)', 'chiusura bytes (byte di EPT12 letti)']
ATTESI = {
	1: {'rientri = 0', 'ritorni orfani solo al bordo d\'inizio (<= 1 per thread)', 'veptkeep orfane solo al bordo d\'inizio (prima della ORPH)',
		'invept2 coerente col ritorno (puntatore kept)'} | set(CH),
	2: {'veptkeep orfane solo al bordo d\'inizio (prima della ORPH)'},
	3: {'vcpuid struttura = vcpuid sonda (offset +0x2c0)'},
	4: {'invept2 coerente col ritorno (puntatore kept)'},
	5: set(CH),
	6: {'radici = svuotate + conservate (per operazione)'},
	7: {'contatori per vCPU non negativi (nessun flush dentro)', 'fb in {0,RACE,VERIFY}: h1 multiplo di ntr, h2 <= h1', CH[5]},
	8: {'invept2 mai mancante prima dell\'operazione successiva del thread'},
}
NOMI = {1: 'rientro', 2: 'veptkeep orfana fuori dal bordo', 3: 'vcpuid incoerente (offset)', 4: 'invept2 incoerente',
	5: 'operazione persa', 6: 'ritorno incoerente', 7: 'flush dentro l\'operazione', 8: 'invept2 mancante'}
for d, att in ATTESI.items():
	P = an.leggi(open('%s/difetto%d.txt' % (O, d)).read())
	C = an.integrita(P, open('%s/difetto%d.err' % (O, d)).read(), 8, 1)
	ko = {n for n, k, _ in C if not k}
	c('%d %s: falliscono esattamente %d controlli' % (d, NOMI[d], len(att)), ko == att, sorted(ko - att) + sorted(att - ko))
print('P4b: bordi con DTrace vero (attacco e arresto a meta\' operazione)')
P = an.leggi(open(O + '/bordo.txt').read())
C = an.integrita(P, open(O + '/bordo.err').read(), 8, 1)
ko = {n for n, k, _ in C if not k}
o_ok, o_ko, k_ok, k_ko = an.bordi(P)
c('traccia chiusa, stderr vuoto', P['chiusa'] and open(O + '/bordo.err').read() == '')
c('2 ritorni orfani VALIDI (uno per thread, prima del primo ingresso)', (len(o_ok), len(o_ko)) == (2, 0), (len(o_ok), len(o_ko)))
c('2 veptkeep orfane VALIDE (prima della ORPH del thread)', (len(k_ok), len(k_ko)) == (2, 0), (len(k_ok), len(k_ko)))
ap = P['conti'].get('nb', 0) - P['conti'].get('no', 0)
c('operazioni aperte alla fine: 1 o 2 (2 thread)', 1 <= ap <= 2, ap)
c('#94 §1.2: TUTTI i controlli passano (nessuna perdita accusata)', not ko, sorted(ko))
B = {b[0]: b for b in an.bilancio(P, 1, 8)}
dentro = sum((r['h1'] + r['h2']) * 4096 for r in P['R'] if (r['tid'], r['t0']) in {(o['tid'], o['t0']) for o in P['O']})
c('le ORPH hanno letto DOPO la prima fotografia >= 2 x 5 x 2 pagine', B['bytes'][2] - dentro >= 2 * 5 * 2 * 4096, (B['bytes'][2] - dentro) // 4096)
c('quei contatori sono BOUND_COMPATIBLE (non esatti, non falliti)', all(B[k][5] == 'BOUND_COMPATIBLE' for k in ('ops_s', 'bytes', 'r' + 'm')), [B[k][5] for k in ('ops_s', 'bytes')])
import re as _re
gem = _re.sub(r'^(ORPH|KORPH) .*\n', '', open(O + '/bordo.txt').read(), flags=_re.M)
gem = _re.sub(r'CONTI (orph|korph|inv2orph)=\s*\d+', r'CONTI \1=0', gem)
gem = _re.sub(r'CONTI nb=\s*\d+', 'CONTI nb=%d' % P['conti']['no'], gem)
Pg = an.leggi(gem)
Cg = an.integrita(Pg, '', 8, 1)
kog = {n for n, k, _ in Cg if not k}
c('gemello: STESSO delta globale, nessun evento di bordo -> chiusura FALLISCE', any(n.startswith('chiusura ops_s') for n in kog) and any(n.startswith('chiusura bytes') for n in kog), sorted(kog)[:2])
print('P4c: #95 §2, primo e ultimo GT a meta\' di operazioni, 8 thread concorrenti (DTrace vero)')
P = an.leggi(open(O + '/gt.txt').read())
C = an.integrita(P, open(O + '/gt.err').read(), 8, 1)
ko = {n for n, k, _ in C if not k}
c('tutti i controlli passano', not ko, sorted(ko))
B = {b[0]: b for b in an.bilancio(P, 1, 8)}
gi, gf, _ = an.finestra(P)
c('primo GT: ops contate (8), radici non ancora (0)', (gi['ops_s'], gi['r' + 'm']) == (8, 0), (gi['ops_s'], gi['r' + 'm']))
c('ultimo GT: 16 ops, 8 radici (seconda ondata a meta\')', (gf['ops_s'], gf['r' + 'm']) == (16, 8), (gf['ops_s'], gf['r' + 'm']))
c('ops_s, rm, bytes BOUND_COMPATIBLE con intervallo da 0', all(B[k][5] == 'BOUND_COMPATIBLE' and B[k][3] == 0 for k in ('ops_s', 'r' + 'm', 'bytes')), [B[k][5][6:9] for k in ('ops_s', 'bytes')])
c('intervallo di lettura dei GT misurato (ta > t)', all(x['ta'] > x['t'] for x in P['GT']), max(x['ta'] - x['t'] for x in P['GT']))
import re as _re
ultimo = sorted(P['GT'], key=lambda x: x['t'])[-1]
gem = open(O + '/gt.txt').read().replace('GT t=%d ta=%d ops_s=%d ' % (ultimo['t'], ultimo['ta'], ultimo['ops_s']), 'GT t=%d ta=%d ops_s=%d ' % (ultimo['t'], ultimo['ta'], gi['ops_s'] + 17))
Cg = an.integrita(an.leggi(gem), '', 8, 1)
c('gemello: delta ops 17 oltre il massimo dell\'intervallo [0, 16]: FAIL', any(n.startswith('chiusura ops_s') for n, k, _ in Cg if not k))
sys.exit(1 if nf else 0)
PYTEST93P3
[ $? -eq 0 ] || nf=$((nf + 1))

echo "P5: tracce sintetiche"
/usr/local/bin/python3 - "$AN" <<'PYTEST93P5'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('an', sys.argv[1]); an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)
nf = 0
def c(nome, ok, v=''):
	global nf
	nf += not ok
	print('  %-62s %-24s %s' % (nome, str(v)[:24], 'ok' if ok else 'ERRATO'))
MS = 1000000
E = 0x123000
T0 = 10 * MS		# tutti i tempi dopo il primo GT (t = 0) + margine
def rad(nc=0, ntr=4, sv=100000, fb=0, h1=None, h2=None):
	if h1 is None:
		h1 = 0 if fb & an.FB_PRIMA else ntr
	if h2 is None:
		h2 = 0 if fb & an.FB_PRIMA else min(ntr, h1)
	return dict(fb=fb, ntr=ntr, nc=nc, h1=h1, h2=h2, sv=sv)
def traccia(ops, pid=100, chiusa=True, g0doppio=False, drop_r=None, orph=(), korph=(), aperte=(), extra_g=None, rd=None, gt=True, gt_larghezza=500):
	"""ops: (vc, t0, eptp, [rad...], pid opzionale). orph: (vc, t); korph: (vc, t, fb);
	aperte: (vc, t0, [rad...]) = ingresso visto, R viste, nessun ritorno.
	G1 = contributi delle operazioni complete + extra_g (bordi)."""
	L = ['== LATENZA PRONTA == pid=%d' % pid]
	g = dict.fromkeys(an.G_NOMI, 0)
	nR = 0
	def radici(tid, vc, t0, v0, e, rr, pref):
		nonlocal nR
		vt = v0
		for j, r in enumerate(rr):
			vt += r['sv']
			if nR != drop_r:
				L.append('R tid=%d t0=%d k=%d vc=%d e=%x live=10 inv=0 nr=%d nc=%d fb=%x ntr=%d ns=%d t=%d vt=%d h1=%d h2=%d hr=0 hn=0'
					% (tid, t0, j + 1, vc, e, 0 if r['fb'] else r['nc'], r['nc'], r['fb'], r['ntr'], r['sv'], t0 + vt - v0, vt, r['h1'], r['h2']))
			nR += 1
			g['rm'] += 1
			g['bytes'] += (r['h1'] + r['h2']) * 4096
			lo, hi, _ = an.tentativi(dict(r), 1)
			g['rd'] += max(lo - 1, 0) if rd is None else 0
			if r['fb']:
				g['full'] += 1; g['rf'] += 1; g['race'] += bool(r['fb'] & 0x40)
				g['esaur'] += r['fb'] == 0x40 and lo >= 2
				g['budget'] += r['fb'] == 0x40 and lo <= 1
				g['nonrace'] += r['fb'] not in (0x40, 0x400) and not r['fb'] & an.FB_PRIMA and lo >= 2
			else:
				g['part'] += 1; g['rk'] += 1; g['ok%d' % (lo - 1)] += 1
		return vt
	for i, op in enumerate(ops):
		vc, t0, e, rr = op[:4]
		p = op[4] if len(op) > 4 else pid
		tid, v0, t0 = 1000 + vc, 10 ** 9 * (i + 1), t0 + T0
		g['ops_s'] += 1
		vt = radici(tid, vc, t0, v0, e, rr, 'R')
		w = sum(1 for r in rr if r['fb'])
		L.append('O tid=%d pid=%d cpu=0 vc=%d ty=1 e=%x t0=%d t1=%d v0=%d sv=%d off=0 offt=0 nk=%d w=%d kept=%d nw=%d wt=0 wv=0 '
			'h1=%d h2=%d hr=0 hn=0 rh1=0 rh2=0 rhr=0 rhn=0 vcm=0'
			% (tid, p, vc, e, t0, t0 + vt - v0 + 1000, v0, vt - v0, len(rr), w, len(rr) - w, w,
			sum(r['h1'] for r in rr), sum(r['h2'] for r in rr)))
	for vc, t, fb in korph:
		L.append('KORPH tid=%d t=%d vc=%d e=%x fb=%x ntr=1' % (1000 + vc, t + T0, vc, E, fb))
	for vc, t in orph:
		L.append('ORPH tid=%d t=%d w=0' % (1000 + vc, t + T0))
	for vc, t0, rr in aperte:
		radici(1000 + vc, vc, t0 + T0, 7 * 10 ** 12, E, rr, 'R')
	if rd is not None:
		g['rd'] = rd
	for k, v in (extra_g or {}).items():
		g[k] += v
	gl = 'G0 t=0 ' + ' '.join('%s=0' % x for x in an.G_NOMI)
	L.insert(1, gl)
	if g0doppio:
		L.insert(2, gl)
	L.append('G1 t=9 ' + ' '.join('%s=%d' % (x, g[x]) for x in an.G_NOMI))
	if gt:
		L.append('GT t=0 ta=%d ' % gt_larghezza + ' '.join('%s=0' % x for x in an.G_NOMI))
		L.append('GT t=%d ta=%d ' % (10 ** 12, 10 ** 12 + gt_larghezza) + ' '.join('%s=%d' % (x, g[x]) for x in an.G_NOMI))
	L += ['CONTA n=%d' % len(ops), 'CONTI nb=%d' % (len(ops) + len(aperte)), 'CONTI no=%d' % len(ops), 'CONTI nr=%d' % nR,
		'CONTI orph=%d' % len(orph), 'CONTI korph=%d' % len(korph), 'CONTI inv2=%d' % len(ops), 'CONTI inv2orph=%d' % len(orph)]
	if chiusa:
		L.append('== LATENZA CHIUSA ==')
	return '\n'.join(L) + '\n'
def ver(t, err='', nvcpu=8, retries=1):
	P = an.leggi(t)
	C = an.integrita(P, err, nvcpu, retries)
	return P, {n for n, k, _ in C if not k}
base = traccia([(0, 0, E | 0x5e, [rad()]), (1, 100000, E | 0x5e, [rad()])])
P, ko = ver(base)
c('traccia sintetica valida: nessun controllo fallisce', not ko, sorted(ko))
print(' -- tentativi (#93 §3)')
T = lambda **k: an.tentativi(dict(dict(fb=0, ntr=4, h1=4), **k), 1)
c('ntr=100, h1=235, UNREAD -> 3, DERIVED_CONDITIONAL', T(fb=0x08, ntr=100, h1=235) == (3, 3, 'DERIVED_CONDITIONAL'), T(fb=0x08, ntr=100, h1=235))
c('ntr=100, h1=200, UNREAD, retries 2 (3o vuoto?) -> [2, 3] ATTEMPTS_NOT_PROVEN', an.tentativi(dict(fb=0x08, ntr=100, h1=200), 2) == (2, 3, 'ATTEMPTS_NOT_PROVEN'), an.tentativi(dict(fb=0x08, ntr=100, h1=200), 2))
c('  ... con retries 1 un 3o tentativo non esiste: [2, 2]', T(fb=0x08, ntr=100, h1=200) == (2, 2, 'ATTEMPTS_NOT_PROVEN'), T(fb=0x08, ntr=100, h1=200))
c('ntr=0 conservata -> NO_TRACKED_TABLES, nessuna divisione', T(ntr=0, h1=0) == (1, 1, 'NO_TRACKED_TABLES'), T(ntr=0, h1=0))
c('ntr=65535 saturo -> ATTEMPTS_NOT_PROVEN', T(fb=0x40, ntr=65535, h1=131070)[2] == 'ATTEMPTS_NOT_PROVEN', T(fb=0x40, ntr=65535, h1=131070))
c('RACE, h1=2 x ntr -> 2, EXACT', T(fb=0x40, ntr=4, h1=8) == (2, 2, 'EXACT'))
c('svuotata prima della scansione -> 0, NO_SCAN', T(fb=0x04, ntr=7, h1=0) == (0, 0, 'NO_SCAN'))
P, ko = ver(traccia([(0, 0, E, [rad(fb=0x08, ntr=100, h1=235, h2=100)])], rd=2), retries=2)
c('traccia con la radice 235/100 (retries 2): nessun FALSO errore d\'integrita\'', not ko, sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(fb=0x08, ntr=100, h1=200, h2=100)])], rd=1), retries=2)
c('200/100 non dimostrata: rd = 1 accettato', not ko, sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(fb=0x08, ntr=100, h1=200, h2=100)])], rd=2), retries=2)
c('  e rd = 2 accettato (intervallo, non un numero inventato)', not ko, sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(fb=0x08, ntr=100, h1=200, h2=100)])], rd=3), retries=2)
c('  rd = 3 fuori intervallo: FAIL', any(n.startswith('chiusura rd ') for n in ko), sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(ntr=0, h1=0, h2=0)])]))
c('traccia con ntr=0: nessun errore', not ko, sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(ntr=4, h1=6, h2=4)])]))
c('conservata con h1=6, ntr=4 (il sorgente lo esclude): FAIL', 'fb in {0,RACE,VERIFY}: h1 multiplo di ntr, h2 <= h1' in ko, sorted(ko))
P, ko = ver(traccia([(0, 0, E, [rad(fb=0x04, ntr=4, h1=3, h2=0)])]))
c('svuotata prima della scansione ma con letture: FAIL', 'svuotate prima della scansione: nessuna lettura' in ko, sorted(ko))
A = an.analizza(ver(traccia([(0, 0, E, [rad(fb=0x08, ntr=100, h1=200, h2=100)]), (1, 0, E, [rad()])], rd=1))[0], 1)
c('derivazione separata dalla completezza: NOT_PROVEN 1, EXACT 1', dict(A['derivazione']) == {'ATTEMPTS_NOT_PROVEN': 1, 'EXACT': 1}, dict(A['derivazione']))
print(' -- bordi (#93 §4)')
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], korph=[(1, 400, 0)], extra_g={'ops_s': 1, 'rm': 1, 'rk': 1, 'part': 1, 'ok0': 1, 'bytes': 8 * 4096}))
c('inizio: ORPH + KORPH validi, contatori dentro l\'intervallo: PASS', not ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], korph=[(1, 400, 0)]))
c('  ... e con contributo 0 (incrementi prima di G0): PASS', not ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], korph=[(1, 400, 0)],
	extra_g={'ops_s': 0, 'r' + 'm': 1, 'rk': 1, 'part': 1, 'ok0': 1, 'bytes': 2 * 5 * 4096}))
c('#94 §1.2 sintetico: ORPH con 5+5 letture DOPO G: PASS', not ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], extra_g={'r' + 'm': 1, 'rk': 1, 'part': 1, 'ok0': 1, 'bytes': 2 * 5 * 4096}))
c('  gemello senza eventi di bordo: FAIL', any(n.startswith('chiusura bytes') for n in ko), sorted(ko)[:2])
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], extra_g={'bytes': 4 * 2 * 2 * 2048 * 4096 + 4096}))
c('ORPH oltre il massimo per operazione (letture): FAIL', any(n.startswith('chiusura bytes') for n in ko), sorted(ko)[:2])
t = traccia([(0, -T0 - 50000, E, [rad()]), (1, 1000, E, [rad()])])
P, ko = ver(t)
c('operazione a cavallo del primo GT, contatore SENZA il suo contributo: PASS', not ko, sorted(ko))
B = {b[0]: b for b in an.bilancio(P, 1, 8)}
c('  ... e il contatore e\' BOUND_COMPATIBLE', B['ops_s'][5] == 'BOUND_COMPATIBLE', B['ops_s'][5])
P, ko = ver(traccia([(0, 1000, E, [rad()])], extra_g={'ops_s': 1}, gt=False))
c('solo G0/G1 (ripiego) e contatore oltre: BOUND_NOT_PROVEN, NON certificata', any(n.startswith('chiusura ops_s') for n in ko) and an.bilancio(P, 1, 8)[0][5] == 'BOUND_NOT_PROVEN', an.bilancio(P, 1, 8)[0][5])
P, ko = ver(traccia([(0, 1000, E, [rad()])], gt=False))
c('solo G0/G1 e chiusura esatta: BOUND_EXACT, PASS', not ko and an.bilancio(P, 1, 8)[0][5] == 'BOUND_EXACT')
P, ko = ver(traccia([(0, 1000, E, [rad()])], gt_larghezza=2 * MS))
c('#95 §2: GT letto in 2 ms (> 1 ms): non delimita, BOUND_NOT_PROVEN e FAIL', an.bilancio(P, 1, 8)[0][5] == 'BOUND_NOT_PROVEN' and 'intervallo di lettura dei GT: 0 <= ta - t <= 1 ms' in ko, an.bilancio(P, 1, 8)[0][5])
P, ko = ver(traccia([(1, 1000, E, [rad()])], orph=[(1, 5000)]))
c('ORPH DOPO il primo ingresso del thread: FAIL', 'ritorni orfani solo al bordo d\'inizio (<= 1 per thread)' in ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], korph=[(2, 400, 0)]))
c('KORPH senza ORPH nel suo thread: FAIL', 'veptkeep orfane solo al bordo d\'inizio (prima della ORPH)' in ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], korph=[(1, 400 + i, 0) for i in range(5)]))
c('5 KORPH in un thread (> VEPT_NROOTS): FAIL', 'veptkeep orfane solo al bordo d\'inizio (prima della ORPH)' in ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], orph=[(1, 500)], extra_g={'ops_s': 2}))
c('inizio: contatore operazioni oltre l\'intervallo: FAIL', any(n.startswith('chiusura ops_s') for n in ko), sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], aperte=[(1, 9000, [rad()])], extra_g={'ops_s': 1}))
c('fine: un\'operazione aperta con una R vista: PASS', not ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], aperte=[(1, 9000, [])], extra_g={'ops_s': 1, 'r' + 'm': 4, 'rk': 4, 'part': 4, 'ok0': 4, 'bytes': 4 * 4 * 2048 * 4096}))
c('fine: aperta, 4 radici al tetto delle letture: PASS', not ko, sorted(ko))
P, ko = ver(traccia([(0, 1000, E, [rad()])], aperte=[(1, 9000, [])], extra_g={'ops_s': 1, 'r' + 'm': 5}))
c('fine: 5 radici per un\'operazione aperta (> 4): FAIL', any(n.startswith('chiusura r' + 'm ') for n in ko), sorted(ko))
P, ko = ver(traccia([(i, 1000, E, [rad()]) for i in range(2)], aperte=[(i, 9000, []) for i in range(3)], extra_g={'ops_s': 3}), nvcpu=2)
c('fine: 3 aperte con 2 vCPU: FAIL', 'operazioni aperte alla fine: 0 <= nb - no <= vCPU' in ko, sorted(ko))
t = traccia([(0, 1000, E, [rad()]), (1, 2000, E, [rad()])])
t = t.replace('O tid=1001', 'X tid=1001').replace('CONTI nb=2', 'CONTI nb=1').replace('CONTI no=2', 'CONTI no=1').replace('CONTA n=2', 'CONTA n=1').replace('CONTI inv2=2', 'CONTI inv2=1')
P, ko = ver(t)
c('R senza O e senza operazioni aperte: FAIL', 'R senza O solo nelle operazioni aperte alla fine' in ko, sorted(ko))
print(' -- gruppi: chiave primaria e classi (#93 §5)')
P, _ = ver(traccia([(0, 0, E | 0x5e, [rad()]), (1, 0, E | 0x1e, [rad()]), (2, 0, (E + 0x1000) | 0x5e, [rad()])]))
A = an.analizza(P, 1)
c('attributi diversi: PRIMARIA nessun gruppo, SECONDARIA 1', (A['gruppi'][MS]['gruppi'], A['gruppi_base'][MS]['gruppi']) == (0, 1))
P, _ = ver(traccia([(0, 0, E, [rad(nc=0)]), (1, 0, E, [rad(nc=0)]), (0, 9 * MS, E + 0x1000, [rad(nc=2)]), (1, 9 * MS, E + 0x1000, [rad(nc=0)]),
	(0, 30 * MS, E + 0x2000, [rad(fb=0x40, ntr=4, h1=8)]), (1, 30 * MS, E + 0x2000, [rad(fb=0x40, ntr=4, h1=8)]),
	(0, 60 * MS, E + 0x3000, [rad(fb=0x40, ntr=4, h1=8)]), (1, 60 * MS, E + 0x3000, [rad()])], rd=4))
A = an.analizza(P, 1)['gruppi'][MS]
c('classi: nc=0 1, nc>0 1, FULL 1, MISTO 1', {k: v[0] for k, v in A['classi'].items()} == {'nc=0': 1, 'nc>0': 1, 'FULL': 1, 'MISTO': 1}, {k: v[0] for k, v in A['classi'].items()})
c('COUNTERS_MATCH solo nel gruppo nc=0 (nc 2/0 no, FULL no)', (A['cm'], A['cm_classi']['nc=0'][0]) == (1, 1), A['cm'])
P, _ = ver(traccia([(0, 0, E, [rad()]), (1, 4 * MS, E, [rad()]), (2, 8 * MS, E, [rad()])]))
A = an.analizza(P, 1)
c('catena 0/4/8 ms a 5 ms: {0,4} + {8}', (A['gruppi'][5 * MS]['gruppi'], A['gruppi'][5 * MS]['singoli']) == (1, 1))
P, _ = ver(traccia([(0, 0, E, [rad()]), (1, 5 * MS, E, [rad()])]))
c('bordo della finestra: 5,000 ms dentro', an.analizza(P, 1)['gruppi'][5 * MS]['gruppi'] == 1)
P, _ = ver(traccia([(0, 0, E, [rad()]), (1, 5 * MS + 1, E, [rad()])]))
c('5 ms + 1 ns fuori', an.analizza(P, 1)['gruppi'][5 * MS]['gruppi'] == 0)
P, _ = ver(traccia([(0, 0, E, [rad()]), (0, 200000, E, [rad()]), (1, 500000, E, [rad()])]))
A = an.analizza(P, 1)['gruppi'][MS]
c('stesso vCPU due volte: {0a,1} + {0b}', (A['gruppi'], A['singoli']) == (1, 1))
P, _ = ver(traccia([(0, 0, E, [rad()], 100), (1, 0, E, [rad()], 200)]))
c('VM (pid) diverse: nessun gruppo', an.analizza(P, 1)['gruppi'][MS]['gruppi'] == 0)
P, _ = ver(traccia([(0, 0, E, [rad(sv=100000)]), (1, 1000, E, [rad(sv=200000)]), (2, 2000, E, [rad(sv=600000)])]))
A = an.analizza(P, 1)['gruppi'][MS]
c('estremi del modello: S=900, S-max=300, S-min=800 us', (A['servizio'], A['lo'], A['hi']) == (900000, 300000, 800000))
P, _ = ver(traccia([(0, 0, E, [rad(sv=300000)]), (1, 100000, E, [rad()])]))
c('sovrapposti 1', an.analizza(P, 1)['gruppi'][MS]['sovrapposti'] == 1)
print(' -- decisione pre-registrata (#93 §6)')
def Ad(q1, cm1, q5, nc5=0.0):
	g = lambda q, cm, nc: {'quota': q, 'quota_cm_nei_gruppi': cm, 'servizio': 100.0,
		'classi': {'nc=0': [0, 0], 'nc>0': [0, 100.0 * nc], 'FULL': [0, 0], 'MISTO': [0, 0]}}
	return {'gruppi': {1000000: g(q1, cm1, 0), 5000000: g(q5, 0, nc5)}}
c('1 ms 35%, CM 60% -> PROGETTARE_LIVELLO_2', an.decisione(Ad(.35, .6, .4), True, False) == 'PROGETTARE_LIVELLO_2')
c('1 ms 35%, CM 40% -> ANALISI_OFFLINE', an.decisione(Ad(.35, .4, .4), True, False) == 'ANALISI_OFFLINE')
c('1 ms 5%, 5 ms 8% -> DEPRIORITIZZARE', an.decisione(Ad(.05, .9, .08), True, False) == 'DEPRIORITIZZARE')
c('1 ms 5%, 5 ms 15% -> ANALISI_OFFLINE (entrambe le finestre)', an.decisione(Ad(.05, .9, .15), True, False) == 'ANALISI_OFFLINE')
c('#94 §6: 1 ms 5%, 5 ms 8% con nc>0 forte -> DEPRIORITIZZARE (nessun veto)', an.decisione(Ad(.05, .9, .08, .6), True, False) == 'DEPRIORITIZZARE')
c('  ... e NC_POSITIVE_CLUSTER resta come etichetta separata', an.nc_positive_cluster(Ad(.05, .9, .08, .6)) is True)
c('1 ms 20% -> ANALISI_OFFLINE', an.decisione(Ad(.20, .9, .3), True, False) == 'ANALISI_OFFLINE')
c('PROGETTARE + perturbazione -> ANALISI_OFFLINE PERTURBATION_SUSPECTED', an.decisione(Ad(.35, .6, .4), True, True) == 'ANALISI_OFFLINE PERTURBATION_SUSPECTED')
c('traccia INCOMPLETA -> NESSUNA_DECISIONE', an.decisione(Ad(.35, .6, .4), False, False).startswith('NESSUNA_DECISIONE'))
print(' -- integrita\' del file')
_, ko = ver(traccia([(0, 0, E, [rad()])], chiusa=False))
c('senza marcatore di chiusura: FAIL', 'traccia aperta e chiusa (marcatori)' in ko)
_, ko = ver(base, err='dtrace: 17 drops on CPU 3\n')
c('drop su stderr: FAIL', 'stderr di DTrace vuoto (drop, errori di indirizzo)' in ko)
_, ko = ver(base, err='dtrace: error on enabled probe ID 4: invalid address (0x0) in action #10\n')
c('dereferenziamento invalido su stderr: FAIL', 'stderr di DTrace vuoto (drop, errori di indirizzo)' in ko)
_, ko = ver(base.replace(' hr=0 hn=0\n', ' hr=0\n', 1))
c('R con un campo mancante: FAIL (malformata, non promossa)', 'righe malformate = 0' in ko and 'righe R = CONTI nr' in ko)
_, ko = ver(traccia([(0, 0, E, [rad()])], g0doppio=True))
c('G0 doppio (file accodato): FAIL', 'righe malformate = 0' in ko)
_, ko = ver(traccia([(0, 0, E, [rad()]), (1, 0, E, [rad()])], drop_r=1))
c('una R persa: FAIL', {'righe R = CONTI nr', 'radici = svuotate + conservate (per operazione)'} <= ko and any(n.startswith('chiusura rm ') for n in ko), sorted(ko)[:3])
P = an.leggi(base.replace('h1=4 h2=4 hr=0', 'h1=18446744073709550616 h2=4 hr=0', 1))
c('senza segno enorme letto come negativo (-1000)', P['R'][0]['h1'] == -1000)
P, _ = ver(traccia([(0, 0, E, [rad(nc=0, sv=100000)]), (1, 0, E, [rad(nc=1, sv=300000)])]))
A = an.analizza(P, 1)
c('nc = 0: 1 su 2, servizio 100 us su 400', (A['vuote'], A['vuote_servizio'], A['servizio_radici']) == (1, 100000, 400000))
r = {k: a for k, b, m, v, a in an.perturbazione({'servizio_media': 1150, 'race_per_1000': 30, 'full_per_1000': 47}, {'servizio_media': 1000, 'race_per_1000': 45, 'full_per_1000': 45.7, 'compilazione_s': 691})}
c('perturbazione: servizio +15% e race -33% ALLARME, full +3% no', r == {'servizio_media': True, 'race_per_1000': True, 'full_per_1000': False}, r)
r = {k: a for k, b, m, v, a in an.perturbazione({'servizio_media': 1030}, {'servizio_media': 1000})}
c('servizio +3%: nessun allarme', r == {'servizio_media': False}, r)
sys.exit(1 if nf else 0)
PYTEST93P5
[ $? -eq 0 ] || nf=$((nf + 1))

echo "P8: LIVELLO 2 (#95, #96): finestre ATTIVE, GPA, censura, metriche, perturbazione"
sudo -n /usr/sbin/dtrace -e -s $T/dedup95l2.d 1 100 > "$OUT/l2-compila.txt" 2>&1 && ok "dedup95l2.d compila sul modulo installato (caller = vmx_vept_invept+0xcb8/+0x10eb)" || ko "dedup95l2.d non compila"
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup95l2sim.d" -c "$OUT/dedup92sim lungo" 1200 > "$OUT/l2-lunga.txt" 2> "$OUT/l2-lunga.err"
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup95l2sim.d" -c "$OUT/dedup92sim pulito" 300 > "$OUT/l2-corta.txt" 2> "$OUT/l2-corta.err"
"$OUT/dedup92sim" bordo & SP=$!
sleep 0.45
sudo -n /usr/sbin/dtrace -s "$OUT/gen/dedup95l2sim.d" -p $SP 700 > "$OUT/l2-bordo.txt" 2> "$OUT/l2-bordo.err"
wait $SP
/usr/local/bin/python3 - "$W/dedup95l2_an.py" "$OUT" <<'PYTEST96L2'
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location('l2', sys.argv[1]); l2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(l2)
an = l2.an
O = sys.argv[2]
nf = 0
def c(nome, ok, v=''):
	global nf
	nf += not ok
	print('  %-64s %-22s %s' % (nome, str(v)[:22], 'ok' if ok else 'ERRATO'))
def ko(testo, err=''):
	P = l2.leggi(testo)
	return P, {n for n, k, _ in l2.integrita(P, err) if not k}
MS = 1000000
t = open(O + '/l2-lunga.txt').read()
P, k = ko(t, open(O + '/l2-lunga.err').read())
c('finestra lunga (timer 1200 ms): COMPLETE', not k, sorted(k))
c('intervallo ATTIVO = primo..ultimo tick, durata 1200 ms (+-2)', abs((P['b'] - P['a']) / 1e6 - 1200) <= 2 and P['a'] > P['richiesta'], (P['b'] - P['a']) / 1e6)
c('righe I = operazioni, tutte agganciate esattamente (0 aperte)', len(P['I']) == 31 and not l2.aperte(P), (len(P['I']), len(l2.aperte(P))))
c('H = 204 = h1 + h2 (siti 3, verifica, esclusi)', len(P['H']) == 204, len(P['H']))
x, ov = l2.misure(P, MS)
R, Q, Qg = l2.rapporti(x)
c('1 ms: 8 gruppi VALIDI, 0 censurati; N 76, U 64', (x['gruppi'], x['censurati_sx'] + x['censurati_dx'], x['N'], x['U']) == (8, 0, 76, 64), (x['gruppi'], x['N'], x['U']))
c('R_pages = 12/76 (per disegno)', abs(R - 12 / 76) < 1e-12, '%.4f' % R)
# Q_cpu_proxy calcolato in modo INDIPENDENTE dal disegno: S1, VP i legge le tabelle i..i+3
sr = an.servizio_radici(P['R'], P['O'])
qd = {0: .25, 2: .5, 4: .5, 6: .25, 1: .25, 3: .5, 5: .5, 7: .25}
hh = l2.insiemi(P)
s1 = [r for r in P['R'] if any(g >> 32 == 0xf0 for g in hh[(r['tid'], r['t0'], r['k'])]['p1'])]	# regione COMUNE di S1
c('  (radici di S1 riconosciute dalla regione comune: 8)', len(s1) == 8, len(s1))
atteso = sum(sr[id(r)] * qd[r['vc']] for r in s1) / sum(sr.values())
c('Q_cpu_proxy = sum s_i q_i / sum s (q dal disegno: .25/.5/.5/.25)', abs(Q - atteso) < 1e-12, '%.4f / %.4f' % (Q, atteso))
c('Q_cpu_proxy_grouped ha denominatore ristretto ai gruppi (>= Q)', Qg >= Q, '%.4f' % Qg)
P, k = ko(open(O + '/l2-corta.txt').read(), open(O + '/l2-corta.err').read())
c('finestra corta (300 ms): COMPLETE, intervallo 300 ms', not k and abs((P['b'] - P['a']) / 1e6 - 300) <= 2, sorted(k))
P, k = ko(open(O + '/l2-bordo.txt').read(), open(O + '/l2-bordo.err').read())
o_ok = an.bordi(P)[0]
c('bordo vero (-p, 700 ms): COMPLETE, ORPH valide all\'inizio', not k and len(o_ok) == 2, (sorted(k), len(o_ok)))
c('  ... operazioni APERTE alla fine riconosciute (I senza O)', len(l2.aperte(P)) >= 1, len(l2.aperte(P)))
# --- mutazioni fail-closed
P0 = l2.leggi(t)
h = [y for y in P0['H'] if y['p'] == 2][0]
riga = 'H tid=%d t0=%d k=%d p=2 gpa=%x\n' % (h['tid'], h['t0'], h['k'], h['gpa'])
m = t.replace(riga, riga.replace(' p=2 ', ' p=1 '), 1)
m = re.sub(r'CONTI nh1=\s*(\d+)', lambda z: 'CONTI nh1=%d' % (int(z.group(1)) + 1), m)
m = re.sub(r'CONTI nh2=\s*(\d+)', lambda z: 'CONTI nh2=%d' % (int(z.group(1)) - 1), m)
_, k = ko(m)
c('#96 §2: una H spostata dal sito 2 al sito 1 (H1+H2 invariato): FAIL su ENTRAMBI', {'sito +0xcb8: per radice H1 = h1 (VST_H_SCAN1)', 'sito +0x10eb: per radice H2 = h2 (VST_H_SCAN2)'} <= k, sorted(k)[:2])
_, k = ko(re.sub(r'^ATTIVA fine=\d+\n', '', t, flags=re.M))
c('marcatore ATTIVA fine assente: INCOMPLETE', 'marcatori della finestra ATTIVA (inizio e fine)' in k)
_, k = ko(t.replace('== LATENZA CHIUSA ==', ''))
c('END assente: INCOMPLETE', 'traccia aperta e chiusa (marcatori)' in k)
_, k = ko(t, 'dtrace: 3 drops on CPU 1\n')
c('drop: INCOMPLETE', 'stderr di DTrace vuoto (drop, errori di indirizzo)' in k)
# --- censura dei gruppi (sintetica): finestra attiva [a, b]
def finto(ops, a=10 * MS, b=110 * MS, aperte=()):
	L = ['FINESTRA richiesta=%d ms=100' % (a - 1000), 'ATTIVA inizio=%d' % a, 'ATTIVA fine=%d' % b]
	for i, (vc, t0, e, gs) in enumerate(ops):
		tid, v0 = 1000 + vc, 10 ** 9 * (i + 1)
		L.append('I tid=%d t0=%d' % (tid, t0))
		L.append('R tid=%d t0=%d k=1 vc=%d e=%x live=1 inv=0 nr=0 nc=0 fb=0 ntr=%d ns=1000 t=%d vt=%d h1=%d h2=0 hr=0 hn=0' % (tid, t0, vc, e, len(gs), t0 + 1000, v0 + 1000, len(gs)))
		L += ['H tid=%d t0=%d k=1 p=1 gpa=%x' % (tid, t0, g) for g in gs]
		L.append('O tid=%d pid=1 cpu=0 vc=%d ty=1 e=%x t0=%d t1=%d v0=%d sv=1000 off=0 offt=0 nk=1 w=0 kept=1 nw=0 wt=0 wv=0 h1=%d h2=0 hr=0 hn=0 rh1=0 rh2=0 rhr=0 rhn=0 vcm=0' % (tid, vc, e, t0, t0 + 2000, v0, len(gs)))
	for vc, t0 in aperte:
		L.append('I tid=%d t0=%d' % (1000 + vc, t0))
	return l2.leggi('\n'.join(L) + '\n')
E1 = 0x111000
G = lambda P: l2.misure(P, MS)[0]
x = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [2, 3])]))
c('gruppo lontano dai bordi: VALIDO; R = 1/4; q = .5/.5', (x['gruppi'], x['N'], x['U']) == (1, 4, 3), (x['gruppi'], x['N'], x['U']))
x = G(finto([(0, 10 * MS + 500000, E1, [1]), (1, 10 * MS + 600000, E1, [1])]))
c('censura SINISTRA: ancora a meno di W dall\'inizio attivo', (x['gruppi'], x['censurati_sx']) == (0, 1), (x['gruppi'], x['censurati_sx']))
x = G(finto([(2, 10 * MS + 200000, E1, [9]), (3, 11 * MS, E1, [8]), (0, 11 * MS + 500000, E1, [1]), (1, 11 * MS + 600000, E1, [1])]))
c('censura SINISTRA: catena 10,2/11,0/11,5/11,6 ms, nessun punto sicuro: {11,5;11,6} censurato', (x['gruppi'], x['censurati_sx']) == (0, 2), (x['gruppi'], x['censurati_sx']))
x = G(finto([(0, 109 * MS + 500000, E1, [1]), (1, 109 * MS + 600000, E1, [1])]))
c('censura DESTRA: ancora + W oltre la fine attiva', (x['gruppi'], x['censurati_dx']) == (0, 1), (x['gruppi'], x['censurati_dx']))
x = G(finto([(0, 50 * MS, E1, [1]), (1, 50 * MS + 100, E1, [1])], aperte=[(3, 50 * MS + 500000)]))
c('censura DESTRA: operazione APERTA entro ancora + W', (x['gruppi'], x['censurati_dx']) == (0, 1), (x['gruppi'], x['censurati_dx']))
# --- formule (#96 §5)
x = G(finto([(0, 30 * MS, E1, []), (1, 30 * MS + 100, E1, [])]))
R, Q, Qg = l2.rapporti(x)
c('insiemi VUOTI: N = 0 -> R_pages n/d, q = 0', R is None and Q == 0, (R, Q))
x = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [1, 2])]))
R, Q, Qg = l2.rapporti(x)
c('insiemi IDENTICI (coppia): R = 0,5, q = 0,5, uguali 1', abs(R - .5) < 1e-12 and abs(Qg - .5) < 1e-12 and x['uguali'] == 1, (R, Qg))
x = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [3, 4])]))
R, Q, Qg = l2.rapporti(x)
c('insiemi DISGIUNTI: R = 0, Q = 0', R == 0 and Q == 0, (R, Q))
# --- #97 §3: unione delle GPA PER GRUPPO, mai globale; m_g locale
E2 = 0x222000
x = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [3, 4]), (0, 60 * MS, E1, [1, 2]), (1, 60 * MS + 100, E1, [3, 4])]))
R, Q, Qg = l2.rapporti(x)
c('#97: G1 e G2 separati, {1,2}/{3,4} in entrambi: N 8, U 4+4, R 0, Q 0 (globale darebbe 50%)', (x['gruppi'], x['N'], x['U'], R, Q) == (2, 8, 8, 0, 0), (x['N'], x['U'], R))
x = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [3, 4]), (0, 60 * MS, E1, [1, 2]), (1, 60 * MS + 100, E1, [2, 3])]))
R, Q, Qg = l2.rapporti(x)
c('#97: coppia condivisa SOLO in G2 ({1,2}/{2,3}): N 8, U 4+3, R 1/8, q .25/.25 solo in G2', (x['N'], x['U']) == (8, 7) and abs(R - 1 / 8) < 1e-12 and abs(Qg - (0 + 0 + .25 + .25) / 4) < 1e-12, (x['N'], x['U'], round(R, 4), round(Qg, 4)))
xa = G(finto([(0, 30 * MS, E1, [1, 2]), (1, 30 * MS + 100, E1, [3, 4])]))
xb = G(finto([(0, 230 * MS, E1, [1, 2]), (1, 230 * MS + 100, E1, [3, 4])], a=200 * MS, b=300 * MS))
from collections import Counter as _C
xs = _C(); xs.update(xa); xs.update(xb)
R, Q, Qg = l2.rapporti(xs)
c('#97: le STESSE GPA in due finestre diverse: aggregato N 8, U 8, R 0', (xs['N'], xs['U'], R) == (8, 8, 0), (xs['N'], xs['U'], R))
x = G(finto([(0, 10 * MS + 300000, E1, [5, 6]), (1, 10 * MS + 400000, E1, [5, 6]), (0, 50 * MS, E2, [1, 2]), (1, 50 * MS + 100, E2, [3, 4])]))
R, Q, Qg = l2.rapporti(x)
c('#97: gruppo CENSURATO con insiemi identici escluso da N, U e q: R 0', (x['gruppi'], x['censurati_sx'], x['N'], x['U'], R, Q) == (1, 1, 4, 4, 0, 0), (x['gruppi'], x['censurati_sx'], x['N'], R))
x = G(finto([(0, 30 * MS, E1, []), (1, 30 * MS + 100, E1, [3, 4])]))
c('#97 §4: radici con insieme vuoto contate (1)', x['vuoti'] == 1, x['vuoti'])
t2 = open(O + '/l2-lunga.txt').read()
prima_i = re.search(r'^I tid=\d+ t0=\d+\n', t2, re.M).group(0)
_, k = ko(t2.replace(prima_i, prima_i + prima_i, 1))
c('#97 §2: riga I duplicata (collisione di chiave): INCOMPLETE', 'chiavi (tid, t0) uniche nelle righe I e O (nessuna collisione)' in k, sorted(k)[:2])
# --- campione e decisione (#96 §3, §5)
c('decisione: campione insufficiente -> NESSUNA_DECISIONE', l2.decisione(False, [], .6, .4) == 'NESSUNA_DECISIONE')
c('decisione: perturbazione sospetta -> NESSUNA_DECISIONE', l2.decisione(True, ['elapsed'], .6, .4) == 'NESSUNA_DECISIONE')
c('decisione: R 5%, Q 5% -> DEPRIORITIZZARE', l2.decisione(True, [], .05, .05) == 'DEPRIORITIZZARE')
c('decisione: R 5%, Q 15% -> ANALISI_OFFLINE', l2.decisione(True, [], .05, .15) == 'ANALISI_OFFLINE')
c('decisione: R 60%, Q 35% -> PROGETTARE_SOLO_AUDIT_STATICO', l2.decisione(True, [], .6, .35) == 'PROGETTARE_SOLO_AUDIT_STATICO')
c('decisione: R 60%, Q 20% (pagine si, CPU no) -> ANALISI_OFFLINE', l2.decisione(True, [], .6, .2) == 'ANALISI_OFFLINE')
c('soglie del campione pre-registrate: 15 finestre, 100 gruppi', (l2.MIN_FINESTRE, l2.MIN_GRUPPI) == (15, 100))
# --- perturbazione (#96 §4): traccia di livello 1 sintetica, finestre attive note
def l1(ops):
	L = []
	for i, (t0, el, sv, ntr, fb) in enumerate(ops):
		L.append('R tid=%d t0=%d k=1 vc=0 e=1000 live=1 inv=0 nr=0 nc=0 fb=%x ntr=%d ns=1 t=%d vt=1 h1=%d h2=%d hr=0 hn=0' % (7, t0, fb, ntr, t0 + 1, ntr, ntr))
		L.append('O tid=7 pid=1 cpu=0 vc=0 ty=1 e=1000 t0=%d t1=%d v0=0 sv=%d off=0 offt=0 nk=1 w=%d kept=%d nw=0 wt=0 wv=0 h1=%d h2=%d hr=0 hn=0 rh1=0 rh2=0 rhr=0 rhn=0 vcm=0' % (t0, t0 + el, sv, 1 if fb else 0, 0 if fb else 1, ntr, ntr))
	return '\n'.join(L) + '\n'
def pert(dentro, fuori):
	ops = [(100 * MS + i * 1000000, el, sv, n, fb) for i, (el, sv, n, fb) in enumerate(dentro)]
	ops += [(500 * MS + i * 1000000, el, sv, n, fb) for i, (el, sv, n, fb) in enumerate(fuori)]
	open(O + '/l1-sint.txt', 'w').write(l1(ops))
	return l2.perturbazione(O + '/l1-sint.txt', [(100 * MS - 1, 100 * MS + len(dentro) * 1000000)])
base = [(900000, 800000, 300, 0)] * 20
p = pert(base, base * 3)
c('dentro = fuori: nessun allarme', not p['sospetta'], p['sospetta'])
p = pert([(1100000, 800000, 300, 0)] * 20, base * 3)
c('ELAPSED +22% con SERVIZIO identico: sospetta (vtimestamp non lo vede)', p['sospetta'] == ['elapsed'] and abs(p['servizio']) < 1e-9, (p['sospetta'], round(p['elapsed'], 3)))
p = pert([(900000, 800000, 300, 0x40)] * 10 + [(900000, 800000, 300, 0)] * 10, [(900000, 800000, 300, 0x40)] * 10 + base * 5)
c('race per radice +150%: sospetta (race)', 'race' in p['sospetta'], p['sospetta'])
p = pert([(900000, 800000, 700, 0)] * 20, base * 3)
c('mix diverso (ntr >= 500 solo dentro): sospetta (mix, strati insufficienti)', 'mix' in p['sospetta'], p['sospetta'])
sys.exit(1 if nf else 0)
PYTEST96L2
[ $? -eq 0 ] || nf=$((nf + 1))

echo "P6: braccio A reale come base (sola lettura)"
/usr/local/bin/python3 - "$AN" <<'PYTEST93P6'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('an', sys.argv[1]); an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)
b = an.base_A('/mnt/linuxulator2/vm/nested-work/logs/misura-8vp-20261027-0933')
nf = 0
def c(nome, ok, v=''):
	global nf
	nf += not ok
	print('  %-62s %-24s %s' % (nome, str(v)[:24], 'ok' if ok else 'ERRATO'))
c('race per 1000 INVEPT = 1000 * 17916 / 393801', abs(b['race_per_1000'] - 1000 * 17916 / 393801) < 1e-9, '%.3f' % b['race_per_1000'])
c('svuotate per 1000 = 1000 * 18018 / 393801', abs(b['full_per_1000'] - 1000 * 18018 / 393801) < 1e-9, '%.3f' % b['full_per_1000'])
c('servizio medio letto (ns, tra 0,5 e 3 ms)', b['servizio_media'] == b['servizio_media'] and 500e3 < b['servizio_media'] < 3e6, '%.0f' % b['servizio_media'])
c('compilazione letta (s)', b['compilazione_s'] and 600 < b['compilazione_s'] < 800, b['compilazione_s'])
sys.exit(1 if nf else 0)
PYTEST93P6
[ $? -eq 0 ] || nf=$((nf + 1))

echo "P7: involucro finto"
mkdir -p "$OUT/mock"
sh $T/test-run-dedup92-mock.sh "$OUT/mock" > "$OUT/mock.txt" 2>&1 && ok "test-run-dedup92-mock.sh: $(grep -c '  ok ' "$OUT/mock.txt") controlli ok" || { ko "involucro finto"; grep ERRATO "$OUT/mock.txt"; }

echo "P9: ciclo delle finestre di livello 2 (dtrace finto)"
mkdir -p "$OUT/ciclo"
sh $T/test-l2-ciclo.sh "$OUT/ciclo" > "$OUT/ciclo.txt" 2>&1 && ok "test-l2-ciclo.sh: $(grep -c '  ok ' "$OUT/ciclo.txt") controlli ok" || { ko "ciclo"; grep ERRATO "$OUT/ciclo.txt"; }

echo "P10: involucro del livello 2 finto"
mkdir -p "$OUT/mock95"
sh $T/test-run-dedup95-mock.sh "$OUT/mock95" > "$OUT/mock95.txt" 2>&1 && ok "test-run-dedup95-mock.sh: $(grep -c '  ok ' "$OUT/mock95.txt") controlli ok" || { ko "involucro 95"; grep ERRATO "$OUT/mock95.txt"; }

echo "gruppi di controlli errati: $nf"
[ $nf -eq 0 ]
