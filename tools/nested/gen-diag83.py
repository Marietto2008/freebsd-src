#!/usr/local/bin/python3
# gen-diag83.py -- Claude 26/10/2026 notte, parere #83 §2: correlazione per
# operazione dei contatori B1 con prova di ESCLUSIVITA'. Rispetto a diag82.d:
#  - OPB/OPE per TUTTE le invocazioni di vmx_vept_invept (nessun filtro sul
#    processo), con pid, tid, cpu, timestamp di ingresso e di uscita,
#    profondita' (annidamento), puntatore del vCPU, tipo ed EPTP dell'INVEPT;
#  - NEST (ingresso mentre lo stesso thread e' gia' dentro), ORPH (ritorno
#    senza ingresso), KORPH (veptkeep fuori da ogni operazione);
#  - per l'operazione esterna: delta dei 14 contatori, numero di radici,
#    motivi, vcpuid dalla sonda veptkeep (e incoerenza fra radici);
#  - conteggi per aggregazione (sicuri fra CPU) stampati a END.
# Le sovrapposizioni fra intervalli (anche di thread diversi della stessa VM)
# e la CHIUSURA (somma dei delta per operazione = delta globale da sysctl) si
# controllano offline in verdetto-b1race.py. Le righe escono dai buffer per
# CPU fuori ordine: l'oracolo le ordina per timestamp.
# Genera dallo STESSO nucleo:
#   diag83.d     fbt:vmm-restore:vmx_vept_invept + vmm:vmx:nested:veptkeep
#   diag83sim.d  sim_invept/sim_keep di diag83sim.c (pid provider), collaudo
import sys

# (campo, simbolo del modulo) -- tutti scritti SOLO dentro vept_keep_invept,
# chiamata solo da vmx_vept_invept (verificato su 27125f004917)
CTR = [
	('inj', 'vept_test_race_injected'),
	('rd', 'vept_scan_retries_done'),
	('ok0', 'vept_scan_first_pass_ok'),
	('ok1', 'vept_scan_retry_1_success'),
	('ok2', 'vept_scan_retry_2_success'),
	('esaur', 'vept_scan_retry_exhausted'),
	('budget', 'vept_scan_retry_budget_fallback'),
	('nonrace', 'vept_scan_retry_nonrace_fallback'),
	('racefb', 'vept_keep_scan_race_fallbacks'),
	('a1ns', 'vept_t_attempt1_ns'),
	('a2ns', 'vept_t_attempt2_ns'),
	('partial', 'vept_keep_partial_invepts'),
	('full', 'vept_keep_full_fallbacks'),
	('mism', 'vept_keep_verify_mismatch'),
]

PROLOGO = r'''#pragma D option quiet
#pragma D option dynvarsize=16m
#pragma D option bufsize=4m
#pragma D option switchrate=20hz
/*
 * %(nome)s -- GENERATO da gen-diag83.py, non modificare a mano.
 * Solo lettura. self->d = profondita' nel thread; self->ts[d] = ingresso.
 */
BEGIN { printf("== TRACCIA PRONTA == %(nome)s\n"); }
'''

NUCLEO = r'''
%(entry)s
{
%(pre)s	self->d++;
	self->ts[self->d] = timestamp;
	@nb = count();
	printf("OPB tid=%%d pid=%%d cpu=%%d t0=%%d d=%%d vcpup=%%#lx type=%%d eptp=%%#lx exec=%%s\n",
	    tid, pid, cpu, timestamp, self->d, (uint64_t)arg0, (int)arg1, (uint64_t)arg2, execname);
}

%(entry)s
/ self->d > 1 /
{
	self->dirty = 1;
	@nn = count();
	printf("NEST tid=%%d pid=%%d cpu=%%d t=%%d d=%%d\n", tid, pid, cpu, timestamp, self->d);
}

%(entry)s
/ self->d == 1 /
{
	self->dirty = 0; self->nkeep = 0; self->fb = -1; self->vc = -1; self->vcbad = 0;
%(snap)s}

%(keep)s
/ self->d /
{
	self->vcbad = self->vcbad || (self->vc != -1 && self->vc != (int)%(vc)s);
	self->vc = (int)%(vc)s;
	self->nkeep++;
	self->fb = (int)(%(fb)s);
}

%(keep)s
/ !self->d /
{
	@nk = count();
	printf("KORPH tid=%%d pid=%%d cpu=%%d t=%%d vcpuid=%%d\n", tid, pid, cpu, timestamp, (int)%(vc)s);
}

%(ret)s
/ !self->d /
{
	@no = count();
	printf("ORPH tid=%%d pid=%%d cpu=%%d t1=%%d ret=%%d exec=%%s\n", tid, pid, cpu, timestamp, (int)arg1, execname);
}

%(ret)s
/ self->d == 1 /
{
	@ne = count();
	printf("OPE tid=%%d pid=%%d cpu=%%d t0=%%d t1=%%d d=1 dirty=%%d nkeep=%%d fb=%%#x vcpuid=%%d vcbad=%%d ret=%%d %(fmt)s exec=%%s\n",
	    tid, pid, cpu, self->ts[1], timestamp, self->dirty, self->nkeep, self->fb, self->vc, self->vcbad, (int)arg1,
%(delta)s,
	    execname);
	self->ts[1] = 0; self->d = 0; self->dirty = 0;
}

%(ret)s
/ self->d > 1 /
{
	@ne = count();
	printf("OPE tid=%%d pid=%%d cpu=%%d t0=%%d t1=%%d d=%%d interna=1 ret=%%d exec=%%s\n",
	    tid, pid, cpu, self->ts[self->d], timestamp, self->d, (int)arg1, execname);
	self->ts[self->d] = 0; self->d--;
}

END
{
	printa("CONTI begin=%%@d\n", @nb); printa("CONTI end=%%@d\n", @ne);
	printa("CONTI nest=%%@d\n", @nn); printa("CONTI orph=%%@d\n", @no);
	printa("CONTI korph=%%@d\n", @nk);
	printf("== TRACCIA CHIUSA ==\n");
}
'''

def genera(nome, sim):
	if sim:
		entry, ret, keep = 'pid$target::sim_invept:entry', 'pid$target::sim_invept:return', 'pid$target::sim_keep:entry'
		vc, fb = 'arg0', 'arg1'
		pre = '\tself->cp = arg3;\n'
		rd = lambda i, s: '*(uint64_t *)copyin(self->cp + %d, 8)' % (8 * i)
	else:
		entry, ret, keep = 'fbt:vmm-restore:vmx_vept_invept:entry', 'fbt:vmm-restore:vmx_vept_invept:return', 'vmm:vmx:nested:veptkeep'
		vc, fb = 'arg0', 'arg5 & 0xffff'
		pre = ''
		rd = lambda i, s: '*(uint64_t *)&`%s' % s
	snap = ''.join('\tself->s_%s = %s;\n' % (c, rd(i, s)) for i, (c, s) in enumerate(CTR))
	fmt = ' '.join('%s=%%d' % c for c, _ in CTR)
	delta = ',\n'.join('\t    %s - self->s_%s' % (rd(i, s), c) for i, (c, s) in enumerate(CTR))
	return (PROLOGO % dict(nome=nome)) + (NUCLEO % dict(entry=entry, ret=ret, keep=keep, vc=vc, fb=fb,
	    pre=pre, snap=snap, fmt=fmt, delta=delta))

if __name__ == '__main__':
	out = sys.argv[1] if len(sys.argv) > 1 else '.'
	for nome, sim in (('diag83.d', False), ('diag83sim.d', True)):
		open('%s/%s' % (out, nome), 'w').write(genera(nome, sim))
		print('%s/%s' % (out, nome))
