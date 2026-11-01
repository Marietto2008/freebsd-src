#!/usr/local/bin/python3
# mock-b1race.py -- Claude 26/10/2026 notte, parere #83 §5: finti sysctl,
# dtrace e kut-run per provare run-b1race-27125.sh dall'inizio alla fine SENZA
# VM e senza toccare un solo sysctl reale. Stato in un file JSON.
# Uso: mock-b1race.py init STATO | sysctl STATO args... | kut STATO LOGS VMM
# Guasti (variabile MOCK_GUASTI, separati da virgola): failA (A con un FAIL
# inatteso), noserC (C senza seriale), overlapD (D con un'operazione di un
# altro thread sovrapposta), nodoE (E crea un nodo /dev/vmm nuovo),
# riprfail (il ripristino di vept_keep non attecchisce), nosmp (in A nessun
# QEMU visibile: -smp non campionabile), lingerB (in B QEMU sopravvive 4 s a
# kut-run), hangB (in B QEMU sopravvive 8 s: oltre BARR_TIMEOUT del test).
import importlib.util, json, os, sys, time

T = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('vb', os.path.join(T, 'verdetto-b1race.py'))
vb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vb)
G = set(filter(None, os.environ.get('MOCK_GUASTI', '').split(',')))

TUN = dict(vept_keep=0, vept_verify_hpa=0, vept_scan_retries=1, vept_test_race=0,
    nested_diag58=0, vept_scan_budget_us=2000)
ALTRI = ['vept_scan_bytes_read', 'vept_keep_retained_leaves', 'vept_leaves_zapped_keep0']

def carica(f): return json.load(open(f))
def salva(f, s): json.dump(s, open(f, 'w'))

def init(f):
	s = {'tun': dict(TUN), 'ctr': {}}
	for i, c in enumerate(vb.CTR):
		s['ctr'][vb.SYM[c]] = 5000 + 7 * i
	for i, n in enumerate(ALTRI):
		s['ctr'][n] = 900 + i
	salva(f, s)

def sysctl(f, a):
	s = carica(f)
	tutti = {('hw.vmm.vmx.' + k): v for k, v in list(s['tun'].items()) + list(s['ctr'].items())}
	tutti['kern.osrelease'] = '16.0-CURRENT (finto)'
	if a == ['hw.vmm.vmx']:
		for k in sorted(tutti):
			if k.startswith('hw.vmm.vmx.'):
				print('%s: %s' % (k, tutti[k]))
		return 0
	nflag = a and a[0] == '-n'
	if nflag:
		a = a[1:]
	rc = 0
	for x in a:
		if '=' in x:
			k, v = x.split('=', 1)
			n = k.replace('hw.vmm.vmx.', '')
			if n not in s['tun']:
				print('sysctl: unknown oid %s' % k, file=sys.stderr); rc = 1; continue
			if 'riprfail' in G and n == 'vept_keep' and int(v) == 0:
				continue			# il ripristino non attecchisce
			s['tun'][n] = int(v)
		elif x in tutti:
			print(tutti[x] if nflag else '%s: %s' % (x, tutti[x]))
		else:
			print('sysctl: unknown oid \'%s\'' % x, file=sys.stderr); rc = 1
	salva(f, s)
	return rc

def prova(s):
	X, R = s['tun']['vept_test_race'], s['tun']['vept_scan_retries']
	return {(0, 1): 'A', (1, 0): 'B', (1, 1): 'C', (2, 1): 'D', (2, 2): 'E'}[(X, R)]

def piano(f):
	"""Variabili di shell per mkut: Q (lancia il finto QEMU), V (secondi di
	vita), STACCA (1 = kut-run non lo aspetta)."""
	P = prova(carica(f))
	q, v, st = 1, 1, 0
	if 'nosmp' in G and P == 'A': q = 0
	if 'lingerB' in G and P == 'B': v, st = 4, 1
	if 'hangB' in G and P == 'B': v, st = 8, 1
	print('Q=%d V=%d STACCA=%d' % (q, v, st))

def kut(f, logs, vmm):
	s = carica(f)
	P = prova(s)
	g = vb.Gen()
	g.t = int(time.monotonic_ns())
	tipo = dict(B=dict(inj=1, racefb=1, full=1, fb=0x40), C=dict(inj=1, rd=1, ok1=1, a1ns=300),
	    D=dict(inj=2, rd=1, esaur=1, racefb=1, a1ns=300, full=1, fb=0x40),
	    E=dict(inj=3, rd=2, esaur=1, racefb=1, a1ns=300, a2ns=300, full=1, fb=0x40))
	for k in range(6):
		g.op()
		if P != 'A' and k == 2:
			g.op(**tipo[P])
	if 'overlapD' in G and P == 'D':
		t = g.t - 300
		g.op(tid=102, t0=t, dur=100)
	open(f + '.trace', 'w').write('\n'.join(g.l + ['CONTI begin=%d' % g.nb, 'CONTI end=%d' % g.ne]) + '\n')
	for c in vb.CTR:
		s['ctr'][vb.SYM[c]] += g.glob[c]
	s['ctr']['vept_scan_bytes_read'] += 4096
	salva(f, s)
	n = 0 if P == 'A' else 4
	ser = ("B1RACE: pronto\nB1RACE: fine, voci senza W viste %d, violation 0, estranee 0\n"
	    "PASS: B1 corsa: nessuna foglia vecchia conservata (0)\n"
	    "PASS: B1 corsa: nessuna EPT violation ingiustificata (0, 0)\n"
	    "%s: B1 corsa: iniezioni viste dall'L1 (%d)\n"
	    "PASS: B1 corsa: contenuto delle pagine intatto (0)\n") % (n, 'FAIL' if P == 'A' else 'PASS', n)
	nf = 1 if P == 'A' else 0
	if 'failA' in G and P == 'A':
		ser += 'FAIL: vmx_cr_load: finto guasto\n'; nf += 1
	ser += 'SUMMARY: 102415 tests, %d unexpected failures\n' % nf
	if not ('noserC' in G and P == 'C'):
		open(os.path.join(logs, 'kut-%s-%s-b1_race.serial' % (time.strftime('%Y%m%d-%H%M%S'), P)), 'w').write(ser)
	if 'nodoE' in G and P == 'E':
		open(os.path.join(vmm, 'vm7'), 'w').close()
	print('b1_race %s (finto)' % ('FAIL' if nf > (1 if P == 'A' else 0) else 'PASS'))
	return 0

if __name__ == '__main__':
	m, f = sys.argv[1], sys.argv[2]
	if m == 'init': init(f)
	elif m == 'sysctl': sys.exit(sysctl(f, sys.argv[3:]))
	elif m == 'kut': sys.exit(kut(f, sys.argv[3], sys.argv[4]))
	elif m == 'piano': piano(f)
