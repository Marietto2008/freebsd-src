#!/usr/local/bin/python3
# replay-diag77.py -- Claude 26/10/2026, parere #77 §4: replay OFFLINE dei record
# REALI di diag77.out (corsa ept12_remap 15:51) con i predicati corretti.
# Regole:
#  - legge solo i record grezzi (EXIT, ENTRY, INSTALL, FAULT, REFLECT, WIPE,
#    INVEPT, SONDA RICAVATA, ALLARME); IGNORA le righe derivate da diag77
#    (FOGLIA DOPO, RIEPILOGO, L0_*), che vengono ricalcolate;
#  - non inventa eventi: cio' che diag77 non registrava resta sconosciuto, e se
#    un predicato ne ha bisogno il verdetto e' INCONCLUSIVE;
#  - il seriale di L1 e il disassemblato sono prove SUPPLEMENTARI, mai sostituti
#    di un record L0 mancante.
# Uso: replay-diag77.py <diag77.out> [--autotest]
import re, sys, hashlib

AM = 0x000ffffffffff000
R0, R1, W2 = 0x40fb5b, 0x40fca1, 0x40fcbf		# da vmxc-plain.elf (9b87c5f4...)
VMC = {0x40fb63: 0, 0x40fcab: 1, 0x40fcc5: 3}

PAT = [
 ('bind',    r'^SONDA RICAVATA (0x[0-9a-f]+) \(fase (\d), rip (0x[0-9a-f]+)\) contesto tid=(\d+) vcpu=(\d+) eptp=(0x[0-9a-f]+)'),
 ('exit48',  r'^\[(\d+)\] EXIT fase(\d) reason=48 gpa=(0x[0-9a-f]+) qual=(0x[0-9a-f]+) rip=(0x[0-9a-f]+) eptp=(0x[0-9a-f]+)'),
 ('exit18',  r'^\[(\d+)\] EXIT reason=18 rip=(0x[0-9a-f]+) eptp=(0x[0-9a-f]+)'),
 ('entry',   r'^\[(\d+)\] ENTRY rip=(0x[0-9a-f]+) eptp=(0x[0-9a-f]+) radice=(0x[0-9a-f]+) sonda=(0x[0-9a-f]+) PTE=(0x[0-9a-f]+|0) primo_assente=(\S+)'),
 ('inv',     r'^\[(\d+)\] INVEPT-fisico eptp=(0x[0-9a-f]+) radice=(0x[0-9a-f]+)'),
 ('install', r'^INSTALL-SONDA fase(\d) l2gpa=(0x[0-9a-f]+) hpa=(0x[0-9a-f]+) perm=(0x[0-9a-f]+)'),
 ('fault',   r'^FAULT fase(\d) rc=(-?\d+) l1gpa=(0x[0-9a-f]+|0)'),
 ('reflect', r'^REFLECT fase(\d) l2gpa=(0x[0-9a-f]+) qual=(0x[0-9a-f]+) esito=(-?\d+)'),
 ('wipe',    r'^-- WIPE slot=(\d+) \(n\.(\d+)\)'),
 ('alarm',   r'^ALLARME SONDA CAMBIATA nello stesso contesto: (0x[0-9a-f]+) -> (0x[0-9a-f]+) \(rip (0x[0-9a-f]+)\)'),
]
DERIVATE = ('FOGLIA DOPO', '== RIEPILOGO', '   stage', 'L0_', '== TRACCIA')

def h(x): return int(x, 16) if x.startswith('0x') else int(x)

def parse(lines):
	ev = []
	for n, l in enumerate(lines, 1):
		l = l.rstrip('\n')
		if not l or l.startswith(DERIVATE):
			continue
		for k, p in PAT:
			m = re.match(p, l)
			if m:
				ev.append((n, k, m.groups()))
				break
		else:
			ev.append((n, 'sconosciuto', (l,)))
	return ev

def dati(q, scrittura):
	"""accesso DATI della fase: bit7=1, bit8=1, bit2=0, e bit1 (scrittura) o bit0 (lettura)"""
	return (q >> 7) & 1 and (q >> 8) & 1 and not (q >> 2) & 1 and \
	    ((q >> 1) & 1 if scrittura else q & 1)

def replay(lines, supp_cr3=None, verbose=True):
	ev = parse(lines)
	note, incon_leaf, incon_s2 = [], [], []
	ign = [e for e in ev if e[1] == 'sconosciuto']
	if ign:
		incon_leaf.append('righe non riconosciute: %s' % [e[0] for e in ign])
		incon_s2.append('righe non riconosciute')
	# contesto: un solo legame, un solo EPTP su tutti i record che lo portano
	binds = [e for e in ev if e[1] == 'bind']
	if len(binds) != 1:
		incon_leaf.append('legame sonda/contesto assente o multiplo'); incon_s2.append('legame')
		return 'REPLAY_INCONCLUSIVE', 'REPLAY_INCONCLUSIVE', incon_leaf, note
	sonda = h(binds[0][2][0]); ctx_eptp = h(binds[0][2][5])
	eptps = {h(g[-1]) for n, k, g in ev if k in ('exit48', 'exit18')} | \
	    {h(g[1]) for n, k, g in ev if k in ('inv',)} | {h(g[2]) for n, k, g in ev if k == 'entry'}
	if eptps != {ctx_eptp}:
		incon_leaf.append('EPTP non unico: %s' % sorted(hex(x) for x in eptps)); incon_s2.append('EPTP')
	note.append('contesto: tid=%s vcpu=%s eptp=%#x, sonda=%#x' % (binds[0][2][3], binds[0][2][4], ctx_eptp, sonda))

	# eventi a GPA diversa dalla sonda (allarmi): classificazione
	for n, k, g in ev:
		if k == 'alarm':
			gpa = h(g[1]); rip = h(g[2])
			s = 'riga %d: evento a rip %#x su GPA %#x, qualificazione NON registrata' % (n, rip, gpa)
			if supp_cr3 is not None and gpa == supp_cr3:
				s += ' -> per prova SUPPLEMENTARE (seriale: guest_cr3=%#x) e\' la pagina PML4 del guest: page walk, non dato' % supp_cr3
			note.append(s)

	# ogni EXIT48 registrato: sulla sonda, accesso dati coerente con la fase
	for n, k, g in ev:
		if k == 'exit48':
			fase, gpa, q, rip = int(g[1]), h(g[2]), h(g[3]), h(g[4])
			atteso_rip = {0: R0, 1: R1, 2: W2}[fase]
			if (gpa & ~0xfff) != sonda or rip != atteso_rip or not dati(q, fase == 2):
				(incon_leaf if fase < 2 else incon_s2).append(
				    'riga %d: EXIT fase%d non attribuibile (gpa %#x rip %#x qual %#x)' % (n, fase, gpa, rip, q))

	def dopo(i, kinds):
		return [e for e in ev[i + 1:] if e[1] in kinds]
	idx = {id(e): i for i, e in enumerate(ev)}

	# ---- stage 0 ----
	s0 = [e for e in ev if e[1] == 'install' and e[2][0] == '0']
	s0_hpa = h(s0[0][2][2]) if s0 else None

	# ---- stage 1 (L0_LEAF) ----
	leaf = None
	e1 = [e for e in ev if e[1] == 'exit48' and e[2][1] == '1']
	if len(e1) != 1:
		incon_leaf.append('EXIT di stage1 registrati: %d (atteso 1)' % len(e1))
	else:
		i1 = idx[id(e1[0])]
		wipes_prima = [e for e in ev[:i1] if e[1] == 'wipe']
		# lo slow path di questa violation: record fino al primo ENTRY successivo
		seg = []
		for e in ev[i1 + 1:]:
			if e[1] == 'entry':
				nxt = e; break
			seg.append(e)
		else:
			nxt = None
		inst = [e for e in seg if e[1] == 'install']
		flt = [e for e in seg if e[1] == 'fault']
		refl = [e for e in seg if e[1] == 'reflect']
		if not flt:
			incon_leaf.append('esito dello slow path di stage1 non registrato')
		elif refl or int(flt[0][2][1]) != 0 or h(flt[0][2][2]) != sonda:
			leaf = 'REPLAY_FAIL'; note.append('stage1: riflessa o rc!=0 o l1gpa!=sonda')
		elif not inst or nxt is None:
			incon_leaf.append('installazione o ingresso successivo di stage1 non registrati')
		else:
			hpa = h(inst[0][2][2]); pte = h(nxt[2][5])
			ok = (pte & 7) and (pte & AM) == (hpa & AM)
			note.append('stage1: righe %d-%d: wipe prima=%d, rc=0, l1gpa=sonda, hpa=%#x (stage0 %s), PTE all\'ingresso [%s]=%#x -> %s' %
			    (e1[0][0], nxt[0], len(wipes_prima), hpa, hex(s0_hpa) if s0_hpa else '?', nxt[2][0], pte,
			     'coincide' if ok else 'NON coincide'))
			if s0_hpa is None:
				incon_leaf.append('installazione di stage0 non registrata')
			elif not wipes_prima or hpa == s0_hpa or not ok:
				leaf = 'REPLAY_FAIL'
	# installazioni sulla sonda senza violation della sonda subito prima: fuori fase
	for i, e in enumerate(ev):
		if e[1] == 'install':
			prev = [x for x in ev[:i] if x[1] in ('exit48', 'entry')]
			if not prev or prev[-1][1] != 'exit48':
				leaf = 'REPLAY_FAIL'; note.append('riga %d: installazione fuori fase' % e[0])
	if leaf is None:
		leaf = 'REPLAY_INCONCLUSIVE' if incon_leaf else 'REPLAY_PASS'

	# ---- stage 2 (L0_S2) ----
	s2 = None
	e2 = [e for e in ev if e[1] == 'exit48' and e[2][1] == '2']
	if len(e2) < 2:
		incon_s2.append('EXIT di scrittura registrati: %d (attesi 2: negata, poi ripresa)' % len(e2))
	else:
		ia, ib = idx[id(e2[0])], idx[id(e2[-1])]
		tra = ev[ia + 1:ib]
		flt_a = [e for e in tra if e[1] == 'fault'][:1]
		refl = [e for e in tra if e[1] == 'reflect']
		inst_tra = [e for e in tra if e[1] == 'install']
		wipe_tra = [e for e in tra if e[1] == 'wipe']
		seg_b = []
		for e in ev[ib + 1:]:
			if e[1] == 'entry':
				break
			seg_b.append(e)
		inst_b = [e for e in seg_b if e[1] == 'install']
		flt_b = [e for e in seg_b if e[1] == 'fault']
		vmc3 = [e for e in ev[ib + 1:] if e[1] == 'exit18' and h(e[2][1]) == 0x40fcc5]
		if inst_tra:
			s2 = 'REPLAY_FAIL'; note.append('stage2: installazione sulla sonda prima del ripristino (righe %s)' % [e[0] for e in inst_tra])
		elif not flt_a or not refl:
			incon_s2.append('esito o riflessione della scrittura negata non registrati')
		elif int(flt_a[0][2][1]) != 1 or not (h(refl[0][2][2]) & 2):
			s2 = 'REPLAY_FAIL'; note.append('stage2: rc!=1 o riflessione senza bit W')
		elif not wipe_tra:
			incon_s2.append('nessun wipe (ripristino di L1) fra negazione e ripresa')
		elif not inst_b or not flt_b or not vmc3:
			incon_s2.append('installazione/esito/VMCALL della ripresa non registrati')
		elif int(inst_b[0][2][3], 16) != 7 or int(flt_b[0][2][1]) != 0:
			s2 = 'REPLAY_FAIL'; note.append('stage2: ripresa senza RWX o rc!=0')
		else:
			note.append('stage2: righe %d-%d: scrittura negata rc=1, REFLECT qual %s (bit W), nessuna installazione prima del ripristino, wipe=%d; ripresa riga %d: rc=0, install perm %s, VMCALL 0x40fcc5 riga %d' %
			    (e2[0][0], refl[0][0], refl[0][2][2], len(wipe_tra), e2[-1][0], inst_b[0][2][3], vmc3[0][0]))
	if s2 is None:
		s2 = 'REPLAY_INCONCLUSIVE' if incon_s2 else 'REPLAY_PASS'
	return leaf, s2, incon_leaf + incon_s2, note

def autotest(lines, cr3):
	"""copie ALTERATE in memoria dei record reali: il replayer deve accorgersene"""
	def mut(f):
		return [f(l) for l in lines]
	def senza(pred):
		return [l for l in lines if not pred(l)]
	casi = [
	 ('originale', lines, 'REPLAY_PASS', 'REPLAY_PASS'),
	 ('foglia di stage1 diversa', mut(lambda l: l.replace('[19] ENTRY rip=0x40fca1 eptp=0x29215e01e radice=0x29215e000 sonda=0x10d2000 PTE=0xc5e14b077', '[19] ENTRY rip=0x40fca1 eptp=0x29215e01e radice=0x29215e000 sonda=0x10d2000 PTE=0x123000077')), 'REPLAY_FAIL', 'REPLAY_PASS'),
	 ('esito di stage1 mancante', senza(lambda l: l.startswith('FAULT fase1')), 'REPLAY_INCONCLUSIVE', 'REPLAY_PASS'),
	 ('stage1 riflessa', mut(lambda l: l.replace('FAULT fase1 rc=0', 'FAULT fase1 rc=1')), 'REPLAY_FAIL', 'REPLAY_PASS'),
	 ('stage1 attribuita a un page walk', mut(lambda l: l.replace('qual=0x781 rip=0x40fca1', 'qual=0x681 rip=0x40fca1')), 'REPLAY_INCONCLUSIVE', 'REPLAY_PASS'),
	 ('nessun wipe prima di stage1', senza(lambda l: l.startswith('-- WIPE slot=0 (n.1)')), 'REPLAY_FAIL', 'REPLAY_PASS'),
	 ('EPTP diverso in un record', mut(lambda l: l.replace('[24] ENTRY rip=0x40fcae eptp=0x29215e01e', '[24] ENTRY rip=0x40fcae eptp=0x29215f01e')), 'REPLAY_INCONCLUSIVE', 'REPLAY_INCONCLUSIVE'),
	 ('riflessione di stage2 mancante', senza(lambda l: l.startswith('REFLECT fase2')), 'REPLAY_PASS', 'REPLAY_INCONCLUSIVE'),
	 ('installazione prima del ripristino', mut(lambda l: l + 'INSTALL-SONDA fase2 l2gpa=0x10d2000 hpa=0xc5e14b000 perm=0x7\n' if l.startswith('REFLECT fase2') else l), 'REPLAY_PASS', 'REPLAY_FAIL'),	# S2: e' nello slow path della violation, non fuori fase per la foglia di stage1
	 ('ripresa senza RWX', mut(lambda l: l.replace('INSTALL-SONDA fase2 l2gpa=0x10d2000 hpa=0xc5e14b000 perm=0x7', 'INSTALL-SONDA fase2 l2gpa=0x10d2000 hpa=0xc5e14b000 perm=0x5')), 'REPLAY_PASS', 'REPLAY_FAIL'),
	]
	nf = 0
	for nome, ls, al, a2 in casi:
		# le righe aggiunte con '\n' vanno spezzate
		ls = ''.join(x if x.endswith('\n') else x + '\n' for x in ls).splitlines(True)
		l, s, _, _ = replay(ls, cr3, False)
		ok = (l, s) == (al, a2)
		nf += not ok
		print('  %-36s %-20s %-20s %s' % (nome, l, s, 'ok' if ok else 'ERRATO (atteso %s %s)' % (al, a2)))
	return nf

if __name__ == '__main__':
	f = sys.argv[1]
	data = open(f, 'rb').read()
	lines = data.decode().splitlines(True)
	# prova supplementare: guest_cr3 dal seriale di L1, se presente accanto
	cr3 = None
	import glob, os
	for s in glob.glob(os.path.join(os.path.dirname(f), 'kut-*.serial')):
		m = re.search(r'guest_cr3=(0x[0-9a-f]+)', open(s).read())
		if m:
			cr3 = h(m.group(1)) & ~0xfff
			print('seriale (supplementare): %s sha256 %s guest_cr3=%#x' % (os.path.basename(s), hashlib.sha256(open(s, 'rb').read()).hexdigest()[:16], cr3))
	print('traccia: %s sha256 %s (%d righe)' % (f, hashlib.sha256(data).hexdigest(), len(lines)))
	if '--autotest' in sys.argv:
		print('autocontrollo su copie alterate in memoria dei record reali:')
		sys.exit(1 if autotest(lines, cr3) else 0)
	leaf, s2, incon, note = replay(lines, cr3)
	for x in note:
		print('  - ' + x)
	for x in incon:
		print('  ! mancante: ' + x)
	print('L0_LEAF (replay) = %s' % leaf)
	print('L0_S2   (replay) = %s' % s2)
