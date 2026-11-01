#pragma D option quiet
#pragma D option dynvarsize=8m
#pragma D option bufsize=4m
#pragma D option aggsize=8m
/*
 * abba-invept-latsim.d -- GENERATO da gen-abba-lat.py, non modificare a mano. Solo lettura.
 * Uso: dtrace -s abba-invept-latsim.d <pid>
 */
self uint64_t t;
self uint64_t v;
self uint64_t toff;
self uint64_t offt;
self int off;

BEGIN { printf("== LATENZA PRONTA == pid=%d\n", $target); }

pid$target::sim_invept:entry
/ pid == $target && self->t /
{
	@annid = count();		/* rientro (PRIMA della clausola che imposta self->t) */
}

pid$target::sim_invept:entry
/ pid == $target && !self->t /
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

pid$target::sim_invept:return
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
	printa("CONTA n=%@d\n", @n);
	printa("CONTA annidate=%@d\n", @annid);
	printa("CONTA reale_max=%@d\n", @reale_max);
	printa("CONTA servizio_max=%@d\n", @servizio_max);
	printa("CONTA reale_somma=%@d\n", @reale_somma);
	printa("CONTA servizio_somma=%@d\n", @servizio_somma);
	printa("CONTA reale_2ms=%@d\n", @reale_2ms);
	printa("CONTA reale_16ms=%@d\n", @reale_16ms);
	printa("CONTA servizio_2ms=%@d\n", @servizio_2ms);
	printa("CONTA servizio_16ms=%@d\n", @servizio_16ms);
	printa("CONTA con_offcpu=%@d\n", @con_offcpu);
	printa("CONTA offcpu_somma=%@d\n", @offcpu_somma);
	printa("CONTA offcpu_max=%@d\n", @offcpu_max);
	printf("== ISTOGRAMMA reale ==\n"); printa(@reale);
	printf("== ISTOGRAMMA servizio ==\n"); printa(@servizio);
	printf("== LATENZA CHIUSA ==\n");
}
