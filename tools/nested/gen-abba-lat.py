#!/usr/local/bin/python3
# gen-abba-lat.py -- Claude 27/10/2026, parere #85 §3.2.4: latenza del gestore
# INVEPT dell'L1 (vmx_vept_invept, slow path dopo critical_exit: il thread del
# vCPU PUO' essere prelazionato) separando:
#   tempo reale   = timestamp  all'uscita - all'ingresso
#   servizio      = vtimestamp all'uscita - all'ingresso (tempo su CPU del
#                   thread; gli interrupt serviti nel frattempo RESTANO qui)
#   fuori CPU     = reale - servizio (prelazione/attesa dell'host), con il
#                   numero di off-cpu del thread dentro l'operazione
# Aggregazioni (sicure fra CPU, nessuna riga per evento): llquantize 1 us ..
# 100 ms, 100 passi per decade (risoluzione ~2%); massimi; conteggi oltre 2 e
# 16 ms per reale e servizio. Solo il processo $1 (bhyve della VM). Stampa a END.
# Genera dallo STESSO nucleo:
#   abba-invept-lat.d     fbt:vmm-restore:vmx_vept_invept + sched (kernel)
#   abba-invept-latsim.d  sim_invept di abba-invept-latsim.c (pid provider)
import sys

NUCLEO = r'''#pragma D option quiet
#pragma D option dynvarsize=8m
#pragma D option bufsize=4m
#pragma D option aggsize=8m
/*
 * %(nome)s -- GENERATO da gen-abba-lat.py, non modificare a mano. Solo lettura.
 * Uso: dtrace -s %(nome)s <pid>
 */
self uint64_t t;
self uint64_t v;
self uint64_t toff;
self uint64_t offt;
self int off;

BEGIN { printf("== LATENZA PRONTA == pid=%%d\n", %(pidv)s); }

%(entry)s
/ pid == %(pidv)s && self->t /
{
	@annid = count();		/* rientro (PRIMA della clausola che imposta self->t) */
}

%(entry)s
/ pid == %(pidv)s && !self->t /
{
	self->t = timestamp; self->v = vtimestamp; self->off = 0; self->offt = 0;
}

sched:::off-cpu
/ self->t /
{
	self->off++; self->toff = timestamp;
}

sched:::on-cpu
/ self->toff /
{
	self->offt += timestamp - self->toff; self->toff = 0;
}

%(ret)s
/ self->t /
{
	this->w = timestamp - self->t;
	this->s = vtimestamp - self->v;
	@n = count();
	@reale = llquantize(this->w, 10, 3, 8, 100);
	@servizio = llquantize(this->s, 10, 3, 8, 100);
	@reale_max = max(this->w);
	@servizio_max = max(this->s);
	@reale_somma = sum(this->w);
	@servizio_somma = sum(this->s);
	@reale_2ms = sum(this->w > 2000000 ? 1 : 0);
	@reale_16ms = sum(this->w > 16000000 ? 1 : 0);
	@servizio_2ms = sum(this->s > 2000000 ? 1 : 0);
	@servizio_16ms = sum(this->s > 16000000 ? 1 : 0);
	@con_offcpu = sum(self->off > 0 ? 1 : 0);
	@offcpu_somma = sum(self->offt);
	@offcpu_max = max(self->offt);
	self->t = 0; self->v = 0; self->off = 0; self->offt = 0; self->toff = 0;
}

END
{
	printa("CONTA n=%%@d\n", @n);
	printa("CONTA annidate=%%@d\n", @annid);
	printa("CONTA reale_max=%%@d\n", @reale_max);
	printa("CONTA servizio_max=%%@d\n", @servizio_max);
	printa("CONTA reale_somma=%%@d\n", @reale_somma);
	printa("CONTA servizio_somma=%%@d\n", @servizio_somma);
	printa("CONTA reale_2ms=%%@d\n", @reale_2ms);
	printa("CONTA reale_16ms=%%@d\n", @reale_16ms);
	printa("CONTA servizio_2ms=%%@d\n", @servizio_2ms);
	printa("CONTA servizio_16ms=%%@d\n", @servizio_16ms);
	printa("CONTA con_offcpu=%%@d\n", @con_offcpu);
	printa("CONTA offcpu_somma=%%@d\n", @offcpu_somma);
	printa("CONTA offcpu_max=%%@d\n", @offcpu_max);
	printf("== ISTOGRAMMA reale ==\n"); printa(@reale);
	printf("== ISTOGRAMMA servizio ==\n"); printa(@servizio);
	printf("== LATENZA CHIUSA ==\n");
}
'''

def genera(nome, sim):
	if sim:
		e, r = 'pid$target::sim_invept:entry', 'pid$target::sim_invept:return'
	else:
		e, r = 'fbt:vmm-restore:vmx_vept_invept:entry', 'fbt:vmm-restore:vmx_vept_invept:return'
	return NUCLEO % dict(nome=nome, entry=e, ret=r, pidv='$target' if sim else '$1')

if __name__ == '__main__':
	out = sys.argv[1] if len(sys.argv) > 1 else '.'
	for nome, sim in (('abba-invept-lat.d', False), ('abba-invept-latsim.d', True)):
		open('%s/%s' % (out, nome), 'w').write(genera(nome, sim))
		print('%s/%s' % (out, nome))
