#!/usr/local/bin/python3
# verdetto-b1race.py -- Claude 26/10/2026 notte, parere #82 §2-3 e parere #83
# §§2-3: verdetti SEPARATI per una prova b1_race.
#  FUNCTIONAL (seriale del test + mismatch HPA da sysctl): conta OGNI riga
#    FAIL/XPASS del seriale; il solo negativo ammesso e' «iniezioni viste
#    dall'L1» FAIL nella prova A. Seriale incompleto, asserzioni mancanti,
#    duplicate o contraddittorie -> FUNCTIONAL_INCONCLUSIVE; fallimenti veri ->
#    FUNCTIONAL_FAIL. Mai promozioni a PASS.
#  PATH (traccia diag83: OPB/OPE di TUTTE le invocazioni di vmx_vept_invept):
#    integrita' della traccia (pronta, chiusa, nessun drop, conteggi END =
#    righe, nessun ingresso senza ritorno, ritorno senza ingresso,
#    annidamento, veptkeep fuori operazione, un solo processo e un solo
#    eseguibile), NESSUNA sovrapposizione fra intervalli (anche di thread
#    diversi), CHIUSURA (somma dei delta per operazione = delta globale da
#    sysctl per ognuno dei 14 contatori). Se manca una di queste: i delta non
#    sono attribuibili -> PATH_INCONCLUSIVE. L'operazione designata (B-E) deve
#    essere esterna, esclusiva, non annidata, con nkeep == 1 e vcpuid coerente.
# Uso: verdetto-b1race.py <A..E> <diag83.out> <diag83.err> <seriale> <prima> <dopo>
#        [--qemu-args FILE] [--exec NOME] [--margin-ns N]
#      verdetto-b1race.py --autotest [seriale_reale_A]
import re, sys

RACE = 0x40
CTR = ['inj', 'rd', 'ok0', 'ok1', 'ok2', 'esaur', 'budget', 'nonrace', 'racefb',
    'a1ns', 'a2ns', 'partial', 'full', 'mism']
SYM = dict(inj='vept_test_race_injected', rd='vept_scan_retries_done',
    ok0='vept_scan_first_pass_ok', ok1='vept_scan_retry_1_success',
    ok2='vept_scan_retry_2_success', esaur='vept_scan_retry_exhausted',
    budget='vept_scan_retry_budget_fallback', nonrace='vept_scan_retry_nonrace_fallback',
    racefb='vept_keep_scan_race_fallbacks', a1ns='vept_t_attempt1_ns',
    a2ns='vept_t_attempt2_ns', partial='vept_keep_partial_invepts',
    full='vept_keep_full_fallbacks', mism='vept_keep_verify_mismatch')
B1 = ['nessuna foglia vecchia conservata', 'nessuna EPT violation ingiustificata',
    "iniezioni viste dall'L1", 'contenuto delle pagine intatto']
VISTE = "iniezioni viste dall'L1"
ORD = {'PASS': 0, 'INCONCLUSIVE': 1, 'FAIL': 2}

def kv(l):
	d = {}
	for k, v in re.findall(r'(\w+)=(\S+)', l):
		try:
			d[k] = int(v, 0)
		except ValueError:
			d[k] = v
	return d

def sysctl_file(testo):
	r = {}
	for l in testo.splitlines():
		m = re.match(r'^(\w+):\s*(-?\d+)\s*$', l)
		if m:
			r[m.group(1)] = int(m.group(2))
	return r

# ---------------------------------------------------------------- FUNCTIONAL
def funzionale(scen, seriale, mismatch, inj_globale):
	fail, inc = [], []
	seriale = seriale.replace('\r', '')
	righe = re.findall(r'^(PASS|FAIL|XPASS|XFAIL|SKIP): (.*)$', seriale, re.M)
	b1 = {}
	for kind, txt in righe:
		m = re.match(r'^B1 corsa: (.*) \((.*)\)$', txt)
		if m and m.group(1) in B1:
			b1.setdefault(m.group(1), []).append((kind, m.group(2)))
	ammesso = 1 if scen == 'A' else 0
	inattesi = []
	consumato = 0
	for kind, txt in righe:
		if kind not in ('FAIL', 'XPASS'):
			continue
		# la PRIMA riga «viste» la giudica solo la logica dedicata sotto:
		# in A e' il negativo ammesso, in B-E FAIL o INCONCLUSIVE secondo le
		# iniezioni del kernel (parere #83 §3.3); una seconda e' inattesa
		if txt.startswith('B1 corsa: ' + VISTE + ' (') and not consumato:
			consumato = 1
			continue
		inattesi.append('%s: %s' % (kind, txt))
	if inattesi:
		fail.append('righe FAIL inattese: %d (%s)' % (len(inattesi), ' | '.join(inattesi[:5])))
	if not re.search(r'^B1RACE: pronto$', seriale, re.M):
		inc.append('seriale incompleto: manca «B1RACE: pronto»')
	mf = re.search(r'^B1RACE: fine, voci senza W viste (\d+),', seriale, re.M)
	if not mf:
		inc.append('seriale incompleto: manca «B1RACE: fine»')
	# kvm-unit-tests: «SUMMARY: N tests» e, SOLO se ce ne sono, «, M unexpected
	# failures» (poi eventuali expected failures / skipped): assente = 0
	ms = [(n, (re.search(r'(\d+) unexpected failures', r) or [0, '0'])[1])
	    for n, r in re.findall(r'^SUMMARY: (\d+) tests(.*)$', seriale, re.M)]
	if len(ms) != 1:
		inc.append('SUMMARY assente o ripetuto (%d)' % len(ms))
	for k in B1:
		v = b1.get(k, [])
		if len(v) == 0:
			inc.append('asserzione assente: %s' % k)
		elif len(v) > 1:
			inc.append('asserzione ripetuta %d volte: %s' % (len(v), k))
	for k in B1:
		v = b1.get(k, [])
		if len(v) != 1:
			continue
		kind = v[0][0]
		if k == VISTE:
			if scen == 'A' and kind != 'FAIL':
				fail.append('A: iniezioni viste %s senza race richiesta' % kind)
			elif scen != 'A' and kind != 'PASS':
				if inj_globale == 0:
					inc.append('race non attivata (iniezioni del kernel 0): iniezioni viste %s' % kind)
				else:
					fail.append('iniezioni del kernel %d ma L1 non le vede (%s)' % (inj_globale, kind))
		elif kind != 'PASS':
			pass		# gia' contata fra le righe FAIL inattese
	if mf and len(b1.get(VISTE, [])) == 1 and b1[VISTE][0][1] != mf.group(1):
		inc.append('contraddizione: fine dice %s voci senza W, l\'asserzione %s' % (mf.group(1), b1[VISTE][0][1]))
	if len(ms) == 1:
		n_fail = sum(1 for k, _ in righe if k in ('FAIL', 'XPASS'))
		su = int(ms[0][1])
		if su > n_fail:
			fail.append('SUMMARY: %d fallimenti, righe FAIL contate %d' % (su, n_fail))
		elif su < n_fail:
			inc.append('contraddizione: SUMMARY %d fallimenti, righe FAIL %d' % (su, n_fail))
	if mismatch != 0:
		fail.append('mismatch HPA %d' % mismatch)
	if fail:
		return 'FUNCTIONAL_FAIL', fail + inc
	if inc:
		return 'FUNCTIONAL_INCONCLUSIVE', inc
	return 'FUNCTIONAL_PASS', ['solo negativo atteso: %s' % ('«iniezioni viste» FAIL' if ammesso else 'nessuno')]

# ---------------------------------------------------------------- TRACCIA
def traccia(testo, errtesto, prima, dopo, exec_atteso, margin, smp, smp_lista=None, barriere=None):
	"""Ritorna (operazioni esterne, problemi globali, info). smp_lista: vCPU
	RICHIESTE dalla lista (None = non verificare); smp: vCPU della riga di
	comando di QEMU realmente eseguita (None = non campionata). barriere:
	{nome: 'OK'|altro} dal runner (parere #84 §4)."""
	prob, info = [], {}
	if smp_lista is not None:
		if smp is None:
			prob.append('-smp NON verificato: riga di comando di QEMU non campionata (richiesto %d)' % smp_lista)
		elif smp != smp_lista:
			prob.append('-smp eseguito %d diverso dal richiesto %d' % (smp, smp_lista))
	if barriere is not None:
		if not barriere:
			prob.append('barriere di acquisizione non registrate')
		for k, v in sorted(barriere.items()):
			if v != 'OK':
				prob.append('barriera %s: %s' % (k, v))
	if '== TRACCIA PRONTA ==' not in testo:
		prob.append('traccia non pronta')
	if '== TRACCIA CHIUSA ==' not in testo:
		prob.append('traccia non chiusa')
	drop = [l for l in errtesto.splitlines() if re.search(r'drop', l, re.I)]
	if drop:
		prob.append('DTrace ha perso eventi: %s' % '; '.join(drop[:3]))
	altro = [l for l in errtesto.splitlines() if l.strip() and not re.search(r'drop', l, re.I)]
	if altro:
		prob.append('stderr di DTrace non vuoto: %s' % '; '.join(altro[:3]))
	opb, ope, nest, orph, korph, conti = [], [], [], [], [], {}
	for l in testo.splitlines():
		t = l.split(' ', 1)[0]
		if t == 'OPB': opb.append(kv(l))
		elif t == 'OPE': ope.append(kv(l))
		elif t == 'NEST': nest.append(kv(l))
		elif t == 'ORPH': orph.append(kv(l))
		elif t == 'KORPH': korph.append(kv(l))
		elif t == 'CONTI':
			conti.update(kv(l))
	if conti.get('begin', 0) != len(opb):
		prob.append('righe OPB %d, conteggio END %d' % (len(opb), conti.get('begin', 0)))
	if conti.get('end', 0) != len(ope):
		prob.append('righe OPE %d, conteggio END %d' % (len(ope), conti.get('end', 0)))
	if nest or conti.get('nest', 0):
		prob.append('annidamenti: %d' % max(len(nest), conti.get('nest', 0)))
	if orph or conti.get('orph', 0):
		prob.append('ritorni senza ingresso: %d' % max(len(orph), conti.get('orph', 0)))
	if korph or conti.get('korph', 0):
		prob.append('veptkeep fuori operazione: %d' % max(len(korph), conti.get('korph', 0)))
	chiavi_e = {(o['tid'], o['t0']) for o in ope}
	senza_ret = [b for b in opb if (b['tid'], b['t0']) not in chiavi_e]
	if senza_ret:
		prob.append('ingressi senza ritorno: %d' % len(senza_ret))
	chiavi_b = {(b['tid'], b['t0']) for b in opb}
	senza_ing = [o for o in ope if (o['tid'], o['t0']) not in chiavi_b]
	if senza_ing:
		prob.append('OPE senza OPB: %d' % len(senza_ing))
	pids = sorted({b['pid'] for b in opb} | {o['pid'] for o in ope})
	execs = sorted({str(b.get('exec')) for b in opb} | {str(o.get('exec')) for o in ope})
	if len(pids) > 1:
		prob.append('piu\' processi: %s' % pids)
	if execs and execs != [exec_atteso]:
		prob.append('eseguibili inattesi: %s' % execs)
	ext = sorted([o for o in ope if o.get('d') == 1 and not o.get('interna')], key=lambda o: o['t0'])
	for o in ext:
		o['tent'] = 1 + o['rd']
	# intervalli: tutte le operazioni chiuse, gli ingressi senza ritorno fino
	# all'infinito, i ritorni senza ingresso dall'inizio
	INF = 1 << 63
	iv = [(o['t0'], o['t1'], o['tid'], o['t0']) for o in ope]
	iv += [(b['t0'], INF, b['tid'], b['t0']) for b in senza_ret]
	iv += [(0, r['t1'], r['tid'], -1) for r in orph]
	iv.sort()
	# coppie sovrapposte: fra thread DIVERSI con margine (sfasamento fra CPU,
	# durata della sonda); nello STESSO thread le operazioni sono sequenziali
	# per costruzione e si sovrappongono solo se annidate (margine 0)
	sovr, coinvolti = 0, set()
	for i in range(len(iv)):
		a1, b1, tid1, k1 = iv[i]
		for j in range(i + 1, len(iv)):
			a2, b2, tid2, k2 = iv[j]
			if a2 >= b1 + margin:
				break
			if a2 < b1 + (0 if tid1 == tid2 else margin):
				sovr += 1
				coinvolti.add((tid1, k1)); coinvolti.add((tid2, k2))
	for o in ext:
		o['escl'] = (o['tid'], o['t0']) not in coinvolti
	if sovr:
		prob.append('intervalli sovrapposti: %d (margine %d ns)' % (sovr, margin))
	# chiusura
	glob = {}
	manca = [c for c in CTR if SYM[c] not in prima or SYM[c] not in dopo]
	if manca:
		prob.append('contatori assenti da prima/dopo: %s' % manca)
	else:
		glob = {c: dopo[SYM[c]] - prima[SYM[c]] for c in CTR}
		diff = ['%s glob %d somma %d' % (c, glob[c], sum(o[c] for o in ext)) for c in CTR
		    if glob[c] != sum(o[c] for o in ext)]
		if diff:
			prob.append('chiusura fallita: %s' % '; '.join(diff))
	vcpus = sorted({o['vcpuid'] for o in ext if o.get('vcpuid', -1) >= 0})
	tids = sorted({o['tid'] for o in ext})
	if smp is not None and len(vcpus) > smp:
		prob.append('vcpuid osservati %s oltre -smp %d' % (vcpus, smp))
	info.update(ops=len(ext), pids=pids, tids=tids, vcpus=vcpus, smp=smp, glob=glob,
	    conti=conti, sovr=sovr, execs=execs)
	return ext, prob, info

# ---------------------------------------------------------------- PATH
def idonea(o):
	r = []
	if not o['escl']: r.append('non esclusiva')
	if o.get('dirty'): r.append('annidata')
	if o.get('nkeep') != 1: r.append('radici=%d' % o.get('nkeep', -1))
	if o.get('vcbad'): r.append('vcpu incoerente')
	return r

def percorso(scen, ops, prob):
	"""Ritorna (verdetto, note, operazione designata o None, esclusioni, cov2)."""
	note = []
	escl = {}
	for o in ops:
		for r in idonea(o):
			escl[r] = escl.get(r, 0) + 1
	el = [o for o in ops if not idonea(o)]
	cov2 = sum(1 for o in el if o['ok2'] >= 1)
	if prob:
		return 'PATH_INCONCLUSIVE', ['delta non attribuibili: ' + '; '.join(prob)], None, escl, 0
	if not ops:
		return 'PATH_INCONCLUSIVE', ['nessuna operazione registrata'], None, escl, cov2
	S = lambda k: sum(o[k] for o in ops)
	if any(o['nonrace'] > 0 for o in ops):
		return 'PATH_FAIL', ['fallback per causa diversa da race'], None, escl, cov2
	if scen == 'A':
		ok = S('inj') == 0 and S('rd') == 0 and S('full') == 0 and S('partial') > 0
		return ('PATH_PASS' if ok else 'PATH_FAIL'), ['su %d operazioni: inj %d ritentativi %d full %d partial %d' % (len(ops), S('inj'), S('rd'), S('full'), S('partial'))], None, escl, cov2
	if S('inj') == 0:
		return 'PATH_INCONCLUSIVE', ['race mai iniettata'], None, escl, cov2
	lim = {'B': 1, 'C': 2, 'D': 2, 'E': 3}[scen]
	if any(o['tent'] > lim for o in ops):
		return 'PATH_FAIL', ['piu\' tentativi del massimo %d' % lim], None, escl, cov2
	if any(o['full'] > 0 and o['racefb'] > 0 and o['fb'] != RACE for o in ops):
		return 'PATH_FAIL', ['fallback race con motivi diversi da RACE (0x40)'], None, escl, cov2
	if scen == 'B':
		q = [o for o in el if o['inj'] >= 1 and o['tent'] == 1 and o['racefb'] == 1 and o['full'] == 1 and o['fb'] == RACE and o['budget'] == 0]
	elif scen == 'C':
		if any(o['racefb'] > 0 for o in ops):
			return 'PATH_FAIL', ['svuotamento per race con una sola iniezione e un ritentativo'], None, escl, cov2
		q = [o for o in el if o['inj'] >= 1 and o['tent'] == 2 and o['ok1'] == 1 and o['full'] == 0 and o['a1ns'] > 0]
	elif scen == 'D':
		q = [o for o in el if o['inj'] >= 2 and o['tent'] == 2 and o['esaur'] == 1 and o['racefb'] == 1 and o['full'] == 1 and o['fb'] == RACE and o['budget'] == 0 and o['a1ns'] > 0]
	else:
		q = [o for o in el if o['tent'] == 3 and o['inj'] == 3 and o['esaur'] == 1 and o['racefb'] == 1 and o['full'] == 1 and o['fb'] == RACE and o['budget'] == 0 and o['a2ns'] > 0]
		if not q and any(o['budget'] > 0 for o in ops):
			return 'PATH_INCONCLUSIVE', ['terzo tentativo saltato per budget'], None, escl, cov2
	if not q:
		return 'PATH_INCONCLUSIVE', ['nessuna operazione IDONEA (esterna, esclusiva, nkeep 1) col percorso atteso'], None, escl, cov2
	return 'PATH_PASS', ['%d operazioni idonee col percorso atteso' % len(q)], q[0], escl, cov2

# ---------------------------------------------------------------- verdetto
def verdetto(scen, tr, err, ser, prima, dopo, exec_atteso='qemu-system-x86_64', margin=20000, smp=None, smp_lista=None, barriere=None):
	ops, prob, info = traccia(tr, err, prima, dopo, exec_atteso, margin, smp, smp_lista, barriere)
	mm = (dopo.get(SYM['mism'], 0) - prima.get(SYM['mism'], 0)) if SYM['mism'] in prima and SYM['mism'] in dopo else 0
	ig = (dopo.get(SYM['inj'], 0) - prima.get(SYM['inj'], 0)) if SYM['inj'] in prima and SYM['inj'] in dopo else -1
	f, fn = funzionale(scen, ser, mm, ig)
	p, pn, des, escl, c2 = percorso(scen, ops, prob)
	out = ['FUNCTIONAL=%s %s' % (f, '; '.join(fn)), 'PATH=%s %s' % (p, '; '.join(pn))]
	if scen == 'E':
		out.append('RETRY2_SUCCESS=%s (operazioni idonee con successo al 2o ritentativo: %d)' % ('COVERED' if c2 and not prob else 'NOT_COVERED', c2))
	out.append('TRACCIA operazioni=%d pid=%s tid=%s vcpuid=%s smp=%s eseguibili=%s sovrapposizioni=%d conti=%s' % (
	    info['ops'], info['pids'], info['tids'], info['vcpus'], info['smp'], info['execs'], info['sovr'],
	    ','.join('%s:%s' % kvp for kvp in sorted(info['conti'].items()))))
	out.append('INTEGRITA %s' % ('OK' if not prob else 'NO: ' + '; '.join(prob)))
	out.append('SMP richiesto=%s eseguito=%s' % (smp_lista, smp))
	out.append('DELTA_GLOBALI %s' % ' '.join('%s=%d' % (c, info['glob'][c]) for c in CTR if info['glob'].get(c)))
	out.append('ESCLUSE %s' % (', '.join('%s: %d' % x for x in sorted(escl.items())) or 'nessuna'))
	inj_ops = [o for o in ops if o['inj'] > 0]
	out.append('INIEZIONI in %d operazioni; contesti (pid,tid,vcpuid,idonea): %s' % (len(inj_ops),
	    sorted({(o['pid'], o['tid'], o.get('vcpuid'), not idonea(o)) for o in inj_ops})))
	if des:
		out.append('DESIGNATA pid=%d tid=%d cpu=%d vcpuid=%d t0=%d t1=%d durata_ns=%d %s fb=%#x nkeep=%d' % (
		    des['pid'], des['tid'], des['cpu'], des['vcpuid'], des['t0'], des['t1'], des['t1'] - des['t0'],
		    ' '.join('%s=%d' % (c, des[c]) for c in CTR) + ' tent=%d' % des['tent'], des['fb'], des['nkeep']))
	return f, p, out

# ---------------------------------------------------------------- autotest
class Gen:
	"""Traccia sintetica nel formato di diag83.d."""
	def __init__(s):
		s.t, s.l, s.nb, s.ne, s.extra, s.glob = 1000, [], 0, 0, {}, {c: 0 for c in CTR}
	def op(s, tid=101, pid=7, vc=0, nkeep=1, fb=0, dirty=0, vcbad=0, dur=500, gap=1000000, t0=None, **d):
		b = dict(inj=0, rd=0, ok0=1, ok1=0, ok2=0, esaur=0, budget=0, nonrace=0, racefb=0,
		    a1ns=0, a2ns=0, partial=1, full=0, mism=0)
		if d.get('full') and 'partial' not in d: b['partial'] = 0
		if (d.get('rd') or d.get('full')) and 'ok0' not in d: b['ok0'] = 0
		b.update(d)
		if t0 is None:
			s.t += gap; t0 = s.t; s.t += dur
		s.l.append('OPB tid=%d pid=%d cpu=3 t0=%d d=1 vcpup=0xfffff80001000000 type=1 eptp=0x29215e01e exec=qemu-system-x86_64' % (tid, pid, t0))
		s.l.append('OPE tid=%d pid=%d cpu=3 t0=%d t1=%d d=1 dirty=%d nkeep=%d fb=%#x vcpuid=%d vcbad=%d ret=0 %s exec=qemu-system-x86_64' % (
		    tid, pid, t0, t0 + dur, dirty, nkeep, fb, vc, vcbad, ' '.join('%s=%d' % (c, b[c]) for c in CTR)))
		s.nb += 1; s.ne += 1
		for c in CTR: s.glob[c] += b[c]
		return s
	def testo(s, chiusa=True, conti=True):
		r = ['== TRACCIA PRONTA == diag83.d'] + s.l
		if conti:
			r += ['CONTI begin=%d' % s.nb, 'CONTI end=%d' % s.ne] + ['CONTI %s=%d' % x for x in s.extra.items()]
		if chiusa: r.append('== TRACCIA CHIUSA ==')
		return '\n'.join(r) + '\n'
	def pd(s, extra=None):
		p = {SYM[c]: 1000 + i for i, c in enumerate(CTR)}
		d = {SYM[c]: p[SYM[c]] + s.glob[c] + (extra or {}).get(c, 0) for c in CTR}
		return p, d

def autotest(reale=None, realeB=None):
	nf = 0
	def chk(nome, got, att, note=''):
		nonlocal nf
		ok = got == att
		nf += not ok
		print('  %-46s %-24s %s' % (nome, got, 'ok' if ok else 'ERRATO (atteso %s) %s' % (att, note)))
	Bop = dict(inj=1, racefb=1, full=1, fb=0x40)
	Cop = dict(inj=1, rd=1, ok1=1, a1ns=300)
	Dop = dict(inj=2, rd=1, esaur=1, racefb=1, a1ns=300, full=1, fb=0x40)
	Eop = dict(inj=3, rd=2, esaur=1, racefb=1, a1ns=300, a2ns=300, full=1, fb=0x40)
	def P(nome, scen, g, att, err='', extra=None, smp=None, chiusa=True, conti=True, testo=None, smp_lista=None, barriere=None):
		p, d = g.pd(extra)
		ops, prob, info = traccia(testo if testo is not None else g.testo(chiusa, conti), err, p, d, 'qemu-system-x86_64', 20000, smp, smp_lista, barriere)
		v, n, des, e, c = percorso(scen, ops, prob)
		chk(nome, v, att, n)
	print('PATH (matrice del parere #82, ora con traccia diag83):')
	P('A corretto', 'A', Gen().op().op(), 'PATH_PASS')
	P('A con iniezione', 'A', Gen().op(inj=1), 'PATH_FAIL')
	P('B corretto', 'B', Gen().op().op(**Bop), 'PATH_PASS')
	P('B con un ritentativo', 'B', Gen().op(**Cop), 'PATH_FAIL')
	P('B race mai iniettata', 'B', Gen().op(), 'PATH_INCONCLUSIVE')
	P('C corretto', 'C', Gen().op().op(**Cop), 'PATH_PASS')
	P('C con svuotamento per race', 'C', Gen().op(**Cop).op(**Dop), 'PATH_FAIL')
	P('D corretto', 'D', Gen().op(**Cop).op(**Dop), 'PATH_PASS')
	P('D motivi diversi da RACE', 'D', Gen().op(**dict(Dop, fb=0x44)), 'PATH_FAIL')
	P('D fallback non race', 'D', Gen().op(inj=2, rd=1, nonrace=1, full=1, fb=0x8), 'PATH_FAIL')
	P('E corretto (3 tentativi)', 'E', Gen().op(**Cop).op(**Eop), 'PATH_PASS')
	P('E terzo saltato per budget', 'E', Gen().op(inj=2, rd=1, esaur=1, budget=1, racefb=1, a1ns=1, full=1, fb=0x40), 'PATH_INCONCLUSIVE')
	P('E solo due tentativi', 'E', Gen().op(**Dop), 'PATH_INCONCLUSIVE')
	P('E con quattro tentativi', 'E', Gen().op(inj=4, rd=3), 'PATH_FAIL')
	P('E solo op ambigue (nkeep 2)', 'E', Gen().op(nkeep=2, **Eop), 'PATH_INCONCLUSIVE')
	P('E nessuna operazione', 'E', Gen(), 'PATH_INCONCLUSIVE')
	print('PATH: esclusivita\' e integrita\' (parere #83 §2):')
	g = Gen().op(); g.op(**Bop); t0b = g.t - 500
	g.op(tid=102, vc=1, t0=t0b + 200, dur=100)
	P('B sovrapposta da altro thread stessa VM', 'B', g, 'PATH_INCONCLUSIVE')
	g = Gen().op(**Bop).op(tid=102, vc=1, gap=5000000)
	P('B, due thread NON sovrapposti', 'B', g, 'PATH_PASS')
	g = Gen().op(**Bop); g.l.append('OPB tid=101 pid=7 cpu=3 t0=%d d=1 vcpup=0x1 type=1 eptp=0x1 exec=qemu-system-x86_64' % (g.t + 900000)); g.nb += 1
	P('ingresso senza ritorno', 'B', g, 'PATH_INCONCLUSIVE')
	g = Gen().op(**Bop); g.l.append('ORPH tid=101 pid=7 cpu=3 t1=500 ret=0 exec=qemu-system-x86_64'); g.extra['orph'] = 1
	P('ritorno senza ingresso', 'B', g, 'PATH_INCONCLUSIVE')
	g = Gen().op(dirty=1, **Bop); g.l.append('NEST tid=101 pid=7 cpu=3 t=1 d=2'); g.extra['nest'] = 1
	P('annidamento', 'B', g, 'PATH_INCONCLUSIVE')
	g = Gen().op(**Bop); g.l.append('KORPH tid=101 pid=7 cpu=3 t=1 vcpuid=0'); g.extra['korph'] = 1
	P('veptkeep fuori operazione', 'B', g, 'PATH_INCONCLUSIVE')
	P('drop di DTrace', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', err='dtrace: 12 drops on CPU 5')
	P('dynamic variable drops', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', err='dtrace: 3 dynamic variable drops')
	P('chiusura: inj cambiato fuori', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', extra={'inj': 1})
	P('chiusura: rd cambiato fuori', 'E', Gen().op(**Eop), 'PATH_INCONCLUSIVE', extra={'rd': 1})
	P('conteggio END diverso (riga persa)', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE',
	    testo=Gen().op(**Bop).testo().replace('CONTI begin=1', 'CONTI begin=2'))
	P('traccia non chiusa', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', chiusa=False)
	P('due processi', 'B', Gen().op(**Bop).op(pid=8), 'PATH_INCONCLUSIVE')
	P('vcpuid oltre -smp 1', 'B', Gen().op(**Bop).op(tid=102, vc=1), 'PATH_INCONCLUSIVE', smp=1)
	P('vcpu incoerente nell\'op', 'B', Gen().op(vcbad=1, **Bop), 'PATH_INCONCLUSIVE')
	P('sovrapposizione entro il margine', 'B', Gen().op(**Bop).op(tid=102, gap=10000), 'PATH_INCONCLUSIVE')
	P('stesso thread, operazioni a 5 us', 'B', Gen().op(gap=5000).op(gap=5000, **Bop).op(gap=5000), 'PATH_PASS')
	print('PATH: barriere e -smp eseguito (parere #84 §4):')
	BOK = dict(avvio='OK', chiusura='OK', finestra_prima='OK', finestra_dopo='OK')
	P('B con smp verificato e barriere OK', 'B', Gen().op(**Bop), 'PATH_PASS', smp=1, smp_lista=1, barriere=BOK)
	P('B con -smp non campionato', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', smp=None, smp_lista=1, barriere=BOK)
	P('B con -smp eseguito 2 su richiesto 1', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', smp=2, smp_lista=1, barriere=BOK)
	P('B con QEMU vivo alla chiusura', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', smp=1, smp_lista=1, barriere=dict(BOK, chiusura='NO qemu vivo dopo 60 s'))
	P('B con VM viva nella finestra di lettura', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', smp=1, smp_lista=1, barriere=dict(BOK, finestra_dopo='NO'))
	P('B con barriere non registrate', 'B', Gen().op(**Bop), 'PATH_INCONCLUSIVE', smp=1, smp_lista=1, barriere={})
	g = Gen().op(**Bop); t = g.t
	g.op(t0=t - 300, dur=100)
	P('stesso thread, intervalli incrociati', 'B', g, 'PATH_INCONCLUSIVE')
	print('FUNCTIONAL (parere #83 §3):')
	base = ("B1RACE: pronto\nB1RACE: fine, voci senza W viste %(n)s, violation 0, estranee 0\n"
	    "PASS: B1 corsa: nessuna foglia vecchia conservata (0)\n"
	    "PASS: B1 corsa: nessuna EPT violation ingiustificata (0, 0)\n"
	    "%(v)s: B1 corsa: iniezioni viste dall'L1 (%(n)s)\n"
	    "PASS: B1 corsa: contenuto delle pagine intatto (0)\n"
	    "SUMMARY: 102415 tests, %(f)s unexpected failures\n")
	serA = base % dict(n=0, v='FAIL', f=1)
	serB = base % dict(n=4, v='PASS', f=0)
	def F(nome, scen, ser, att, mm=0, inj=1):
		v, n = funzionale(scen, ser, mm, inj)
		chk(nome, v, att, n)
	F('1. A: solo il negativo atteso', 'A', serA, 'FUNCTIONAL_PASS', inj=0)
	F('2. A: secondo FAIL inatteso (altra asserz.)', 'A', serA.replace('PASS: B1 corsa: nessuna foglia', 'FAIL: B1 corsa: nessuna foglia').replace(' 1 unexpected', ' 2 unexpected'), 'FUNCTIONAL_FAIL', inj=0)
	F('2b. A: FAIL inatteso di un altro test', 'A', serA.replace('SUMMARY', 'FAIL: vmx_cr_load: qualcosa\nSUMMARY').replace(' 1 unexpected', ' 2 unexpected'), 'FUNCTIONAL_FAIL', inj=0)
	F('2c. A: «viste» FAIL due volte', 'A', serA.replace('SUMMARY', "FAIL: B1 corsa: iniezioni viste dall'L1 (0)\nSUMMARY").replace(' 1 unexpected', ' 2 unexpected'), 'FUNCTIONAL_FAIL', inj=0)
	F('2d. A: XPASS inatteso', 'A', serA.replace('SUMMARY', 'XPASS: qualcosa\nSUMMARY').replace(' 1 unexpected', ' 2 unexpected'), 'FUNCTIONAL_FAIL', inj=0)
	F('2e. A: «viste» PASS senza race', 'A', base % dict(n=3, v='PASS', f=0), 'FUNCTIONAL_FAIL', inj=0)
	F('3. B: «viste» FAIL, race non attivata', 'B', base % dict(n=0, v='FAIL', f=1), 'FUNCTIONAL_INCONCLUSIVE', inj=0)
	F('3b. B: «viste» FAIL con iniezioni del kernel', 'B', base % dict(n=0, v='FAIL', f=1), 'FUNCTIONAL_FAIL', inj=5)
	F('3c. E: «viste» FAIL con iniezioni del kernel', 'E', base % dict(n=0, v='FAIL', f=1), 'FUNCTIONAL_FAIL', inj=150)
	F('4. riga attesa assente', 'B', serB.replace("PASS: B1 corsa: contenuto delle pagine intatto (0)\n", ''), 'FUNCTIONAL_INCONCLUSIVE')
	F('4b. seriale troncato (senza SUMMARY)', 'B', serB.split('SUMMARY')[0], 'FUNCTIONAL_INCONCLUSIVE')
	F('4c. seriale troncato prima di «fine»', 'B', 'B1RACE: pronto\n', 'FUNCTIONAL_INCONCLUSIVE')
	F('4d. asserzione ripetuta PASS/PASS', 'B', serB.replace('SUMMARY', 'PASS: B1 corsa: nessuna foglia vecchia conservata (0)\nSUMMARY'), 'FUNCTIONAL_INCONCLUSIVE')
	F('4e. fine e asserzione discordanti', 'B', serB.replace('voci senza W viste 4', 'voci senza W viste 9'), 'FUNCTIONAL_INCONCLUSIVE')
	F('4f. SUMMARY dice 1, nessuna riga FAIL', 'B', serB.replace(' 0 unexpected', ' 1 unexpected'), 'FUNCTIONAL_FAIL')
	F('4g. SUMMARY dice 0, una riga FAIL', 'A', serA.replace(' 1 unexpected', ' 0 unexpected'), 'FUNCTIONAL_INCONCLUSIVE', inj=0)
	F('B tutto PASS', 'B', serB, 'FUNCTIONAL_PASS')
	serB0 = serB.replace(', 0 unexpected failures', '')
	F('B formato reale: SUMMARY senza «unexpected»', 'B', serB0, 'FUNCTIONAL_PASS')
	F('B SUMMARY con skipped, senza «unexpected»', 'B', serB0.replace(' tests\n', ' tests, 3 skipped\n'), 'FUNCTIONAL_PASS')
	F('B SUMMARY senza «unexpected» ma una riga FAIL', 'B', serB0.replace('PASS: B1 corsa: contenuto', 'FAIL: B1 corsa: contenuto'), 'FUNCTIONAL_FAIL')
	F('A con SUMMARY senza «unexpected» (FAIL atteso non contato)', 'A', serA.replace(', 1 unexpected failures', ''), 'FUNCTIONAL_INCONCLUSIVE', inj=0)
	F('B con mismatch HPA', 'B', serB, 'FUNCTIONAL_FAIL', mm=3)
	F('B foglia vecchia', 'B', serB.replace('PASS: B1 corsa: nessuna foglia vecchia conservata (0)', 'FAIL: B1 corsa: nessuna foglia vecchia conservata (2)').replace(' 0 unexpected', ' 1 unexpected'), 'FUNCTIONAL_FAIL')
	if reale:
		ser = open(reale).read()
		print('FUNCTIONAL su seriale REALE (%s):' % reale)
		F('A reale (race 0) 25/10', 'A', ser, 'FUNCTIONAL_PASS', inj=0)
		F('lo stesso letto come B, race non attivata', 'B', ser, 'FUNCTIONAL_INCONCLUSIVE', inj=0)
		F('lo stesso letto come B, kernel ha iniettato', 'B', ser, 'FUNCTIONAL_FAIL', inj=2)
	if realeB:
		ser = open(realeB).read()
		print('FUNCTIONAL su seriale REALE di una prova B (%s):' % realeB)
		F('B reale (SUMMARY senza «unexpected»)', 'B', ser, 'FUNCTIONAL_PASS', inj=1)
		F('lo stesso letto come A', 'A', ser, 'FUNCTIONAL_FAIL', inj=0)
	print('ERRATI: %d' % nf)
	return nf

if __name__ == '__main__':
	a = sys.argv[1:]
	if a and a[0] == '--autotest':
		sys.exit(1 if autotest(a[1] if len(a) > 1 else None, a[2] if len(a) > 2 else None) else 0)
	opz = {'--qemu-args': None, '--exec': 'qemu-system-x86_64', '--margin-ns': '20000', '--smp-lista': None, '--barriere': None}
	pos = []
	while a:
		x = a.pop(0)
		if x in opz:
			opz[x] = a.pop(0)
		else:
			pos.append(x)
	scen, ftr, ferr, fser, fpr, fdo = pos
	smp = None
	if opz['--qemu-args']:
		m = re.search(r'-smp\s+(\d+)', open(opz['--qemu-args']).read())
		smp = int(m.group(1)) if m else None
	leggi = lambda f: open(f, errors='replace').read()
	barr = None
	if opz['--barriere']:
		barr = {}
		try:
			for l in leggi(opz['--barriere']).splitlines():
				m = re.match(r'^BARRIERA_(\w+)=(.*)$', l)
				if m:
					barr[m.group(1).lower()] = m.group(2).strip()
		except OSError:
			pass
	try:
		ser = leggi(fser)
	except OSError:
		ser = ''
	f, p, out = verdetto(scen, leggi(ftr), leggi(ferr), ser, sysctl_file(leggi(fpr)), sysctl_file(leggi(fdo)),
	    opz['--exec'], int(opz['--margin-ns']), smp,
	    int(opz['--smp-lista']) if opz['--smp-lista'] else None, barr)
	print('\n'.join(out))
