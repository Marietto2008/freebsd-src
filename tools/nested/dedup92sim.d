#pragma D option quiet
#pragma D option dynvarsize=8m
#pragma D option bufsize=4m
#pragma D option aggsize=8m
#pragma D option switchrate=10hz
/*
 * dedup92sim.d -- GENERATO da gen-dedup92.py, non modificare a mano. Solo lettura.
 * Parere #92 livello 1: record R (radice) e O (operazione) del gestore INVEPT del
 * processo indicato, G0/G1 (contatori globali), aggregazioni come abba-invept-lat.d.
 * Uso: dtrace -s dedup92sim.d -c dedup92sim
 */
self uint64_t t;
self uint64_t v;
self uint64_t toff;
self uint64_t offt;
self int off;
self uint64_t np;
self uint64_t kp;
self uint64_t ep;
self int ty;
self int vc;
self int nk;
self int nw;
self int vcm;
self uint64_t wt;
self uint64_t wv;
self uint64_t we;
self uint64_t wve;
self uint64_t bh1;
self uint64_t ah1;
self uint64_t bh2;
self uint64_t ah2;
self uint64_t bhr;
self uint64_t ahr;
self uint64_t bhn;
self uint64_t ahn;

self int lt;
self int lw;
self int lk;
self int lvc;

pid$target::sim_inizio:entry
{
	printf("G0 t=%d ops_s=%d ops_a=%d rm=%d rk=%d rf=%d part=%d full=%d race=%d rd=%d ok0=%d ok1=%d ok2=%d esaur=%d budget=%d nonrace=%d bytes=%d tscan=%d tpart=%d tfull=%d tver=%d\n", timestamp,
	    *(uint64_t *)copyin(arg0 + 0, 8),
	    *(uint64_t *)copyin(arg0 + 8, 8),
	    *(uint64_t *)copyin(arg0 + 16, 8),
	    *(uint64_t *)copyin(arg0 + 24, 8),
	    *(uint64_t *)copyin(arg0 + 32, 8),
	    *(uint64_t *)copyin(arg0 + 40, 8),
	    *(uint64_t *)copyin(arg0 + 48, 8),
	    *(uint64_t *)copyin(arg0 + 56, 8),
	    *(uint64_t *)copyin(arg0 + 64, 8),
	    *(uint64_t *)copyin(arg0 + 72, 8),
	    *(uint64_t *)copyin(arg0 + 80, 8),
	    *(uint64_t *)copyin(arg0 + 88, 8),
	    *(uint64_t *)copyin(arg0 + 96, 8),
	    *(uint64_t *)copyin(arg0 + 104, 8),
	    *(uint64_t *)copyin(arg0 + 112, 8),
	    *(uint64_t *)copyin(arg0 + 120, 8),
	    *(uint64_t *)copyin(arg0 + 128, 8),
	    *(uint64_t *)copyin(arg0 + 136, 8),
	    *(uint64_t *)copyin(arg0 + 144, 8),
	    *(uint64_t *)copyin(arg0 + 152, 8));
}

BEGIN { printf("== LATENZA PRONTA == pid=%d\n", $target); }

pid$target::sim_invept:entry
/ pid == $target && self->t /
{
	@annid = count();		/* rientro (PRIMA della clausola che imposta self->t) */
	printf("NEST tid=%d cpu=%d t=%d\n", tid, cpu, timestamp);
}

pid$target::sim_invept:entry
/ pid == $target && !self->t /
{
	@nb = count();			/* ingressi: nb - no = operazioni aperte alla fine */
	self->t = timestamp; self->v = vtimestamp; self->off = 0; self->offt = 0;
	self->ty = (int)arg1; self->ep = arg2; self->kp = arg3;
	self->vc = *(int *)copyin(arg0 + 0x2c0, 4);
	self->np = *(uint64_t *)copyin(arg0 + 0x2b8, 8);
	self->bh1 = *(uint64_t *)copyin(self->np + 0x5980, 8); self->ah1 = self->bh1;
	self->bh2 = *(uint64_t *)copyin(self->np + 0x5988, 8); self->ah2 = self->bh2;
	self->bhr = *(uint64_t *)copyin(self->np + 0x5990, 8); self->ahr = self->bhr;
	self->bhn = *(uint64_t *)copyin(self->np + 0x5998, 8); self->ahn = self->bhn;
	self->nk = 0; self->nw = 0; self->wt = 0; self->wv = 0; self->vcm = 0;
	/* invept2 dell'operazione PRECEDENTE di questo thread mai arrivata: errore certo
	 * (solo l'ultima operazione di ogni thread puo' perderla legittimamente, a END) */
	@inv2miss = sum(self->lt);
	self->lt = 0;
}

pid$target::sim_keep:entry
/ pid == $target && self->t /
{
	this->ch1 = *(uint64_t *)copyin(self->np + 0x5980, 8);
	this->ch2 = *(uint64_t *)copyin(self->np + 0x5988, 8);
	this->chr = *(uint64_t *)copyin(self->np + 0x5990, 8);
	this->chn = *(uint64_t *)copyin(self->np + 0x5998, 8);
	self->nk++;
	self->vcm += (int)arg0 != self->vc ? 1 : 0;
	@nr = count();
	printf("R tid=%d t0=%d k=%d vc=%d e=%x live=%d inv=%d nr=%d nc=%d fb=%x ntr=%d ns=%d t=%d vt=%d h1=%d h2=%d hr=%d hn=%d\n",
	    tid, self->t, self->nk, (int)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
	    (uint64_t)arg4 & 0xffffffff, (uint64_t)arg4 >> 32, (uint64_t)arg5 & 0xffff,
	    ((uint64_t)arg5 >> 16) & 0xffff, (uint64_t)arg5 >> 32, timestamp, vtimestamp,
	    this->ch1 - self->ah1,
	    this->ch2 - self->ah2,
	    this->chr - self->ahr,
	    this->chn - self->ahn);
	self->ah1 = this->ch1;
	self->ah2 = this->ch2;
	self->ahr = this->chr;
	self->ahn = this->chn;
}

pid$target::sim_keep:entry
/ pid == $target && !self->t /
{
	@korph = count();
	printf("KORPH tid=%d t=%d vc=%d e=%x fb=%x ntr=%d\n", tid, timestamp, (int)arg0, (uint64_t)arg1,
	    (uint64_t)arg5 & 0xffff, ((uint64_t)arg5 >> 16) & 0xffff);
}

pid$target::sim_keep:entry
/ pid != $target /
{
	@kaltri = count();
}

pid$target::sim_root_wipe:entry
/ self->t /
{
	self->we = timestamp; self->wve = vtimestamp;
}

pid$target::sim_root_wipe:return
/ self->t && self->we /
{
	self->wt += timestamp - self->we; self->wv += vtimestamp - self->wve; self->nw++;
	self->we = 0; self->wve = 0;
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

/* ritorno senza ingresso (operazione entrata PRIMA dell'inizio della traccia, o
 * rientro): PRIMA della clausola principale, che azzera self->t (parere #93 §4) */
pid$target::sim_invept:return
/ pid == $target && !self->t /
{
	@orph = count();
	printf("ORPH tid=%d t=%d w=%d\n", tid, timestamp, (int)arg1);
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
	this->ch1 = *(uint64_t *)copyin(self->np + 0x5980, 8);
	this->ch2 = *(uint64_t *)copyin(self->np + 0x5988, 8);
	this->chr = *(uint64_t *)copyin(self->np + 0x5990, 8);
	this->chn = *(uint64_t *)copyin(self->np + 0x5998, 8);
	this->kept = *(int *)copyin(self->kp, 4);
	@no = count();
	@wkmis = sum(self->nk != (int)arg1 + this->kept ? 1 : 0);
	@vcmis = sum(self->vcm);
	printf("O tid=%d pid=%d cpu=%d vc=%d ty=%d e=%x t0=%d t1=%d v0=%d sv=%d off=%d offt=%d nk=%d w=%d kept=%d nw=%d wt=%d wv=%d h1=%d h2=%d hr=%d hn=%d rh1=%d rh2=%d rhr=%d rhn=%d vcm=%d\n",
	    tid, pid, cpu, self->vc, self->ty, self->ep, self->t, timestamp, self->v, this->s, self->off,
	    self->offt, self->nk, (int)arg1, this->kept, self->nw, self->wt, self->wv,
	    this->ch1 - self->bh1,
	    this->ch2 - self->bh2,
	    this->chr - self->bhr,
	    this->chn - self->bhn,
	    this->ch1 - self->ah1,
	    this->ch2 - self->ah2,
	    this->chr - self->ahr,
	    this->chn - self->ahn,
	    self->vcm);
	self->lt = 1; self->lw = (int)arg1; self->lk = this->kept; self->lvc = self->vc;
	self->t = 0; self->v = 0; self->off = 0; self->offt = 0; self->toff = 0;
	self->np = 0; self->kp = 0; self->ep = 0; self->ty = 0; self->vc = 0;
	self->nk = 0; self->nw = 0; self->vcm = 0; self->wt = 0; self->wv = 0;
	self->ah1 = 0; self->bh1 = 0;
	self->ah2 = 0; self->bh2 = 0;
	self->ahr = 0; self->bhr = 0;
	self->ahn = 0; self->bhn = 0;
}

/* l'orfana PRIMA: la clausola che consuma self->lt la azzera, e le clausole
 * della stessa sonda si valutano in ordine */
pid$target::sim_invept2:entry
/ pid == $target && !self->lt /
{
	@inv2orph = count();
}

pid$target::sim_invept2:entry
/ pid == $target && self->lt /
{
	@inv2 = count();
	@inv2mis = sum(((int)arg0 != self->lvc || (int)((uint64_t)arg5 & 0xffff) != self->lw ||
	    (int)((uint64_t)arg5 >> 16) != self->lk) ? 1 : 0);
	self->lt = 0; self->lw = 0; self->lk = 0; self->lvc = 0;
}

pid$target::sim_fine:entry
{
	printf("G1 t=%d ops_s=%d ops_a=%d rm=%d rk=%d rf=%d part=%d full=%d race=%d rd=%d ok0=%d ok1=%d ok2=%d esaur=%d budget=%d nonrace=%d bytes=%d tscan=%d tpart=%d tfull=%d tver=%d\n", timestamp,
	    *(uint64_t *)copyin(arg0 + 0, 8),
	    *(uint64_t *)copyin(arg0 + 8, 8),
	    *(uint64_t *)copyin(arg0 + 16, 8),
	    *(uint64_t *)copyin(arg0 + 24, 8),
	    *(uint64_t *)copyin(arg0 + 32, 8),
	    *(uint64_t *)copyin(arg0 + 40, 8),
	    *(uint64_t *)copyin(arg0 + 48, 8),
	    *(uint64_t *)copyin(arg0 + 56, 8),
	    *(uint64_t *)copyin(arg0 + 64, 8),
	    *(uint64_t *)copyin(arg0 + 72, 8),
	    *(uint64_t *)copyin(arg0 + 80, 8),
	    *(uint64_t *)copyin(arg0 + 88, 8),
	    *(uint64_t *)copyin(arg0 + 96, 8),
	    *(uint64_t *)copyin(arg0 + 104, 8),
	    *(uint64_t *)copyin(arg0 + 112, 8),
	    *(uint64_t *)copyin(arg0 + 120, 8),
	    *(uint64_t *)copyin(arg0 + 128, 8),
	    *(uint64_t *)copyin(arg0 + 136, 8),
	    *(uint64_t *)copyin(arg0 + 144, 8),
	    *(uint64_t *)copyin(arg0 + 152, 8));
}

/* parere #94 + dtrace.c:7459: fuori da ACTIVE (WARMUP dopo BEGIN, DRAINING prima di END)
 * le sonde si scartano, quindi G0/G1 lasciano due fessure senza record. GT si legge
 * MENTRE la traccia e' attiva: la chiusura usa il primo e l'ultimo GT */
pid$target::sim_tick:entry
{
	this->tb = timestamp;	/* prima clausola: tempo PRIMA delle 20 letture */
	this->g0 = *(uint64_t *)copyin(arg0 + 0, 8);
	this->g1 = *(uint64_t *)copyin(arg0 + 8, 8);
	this->g2 = *(uint64_t *)copyin(arg0 + 16, 8);
	this->g3 = *(uint64_t *)copyin(arg0 + 24, 8);
	this->g4 = *(uint64_t *)copyin(arg0 + 32, 8);
	this->g5 = *(uint64_t *)copyin(arg0 + 40, 8);
	this->g6 = *(uint64_t *)copyin(arg0 + 48, 8);
	this->g7 = *(uint64_t *)copyin(arg0 + 56, 8);
	this->g8 = *(uint64_t *)copyin(arg0 + 64, 8);
	this->g9 = *(uint64_t *)copyin(arg0 + 72, 8);
	this->g10 = *(uint64_t *)copyin(arg0 + 80, 8);
	this->g11 = *(uint64_t *)copyin(arg0 + 88, 8);
	this->g12 = *(uint64_t *)copyin(arg0 + 96, 8);
	this->g13 = *(uint64_t *)copyin(arg0 + 104, 8);
	this->g14 = *(uint64_t *)copyin(arg0 + 112, 8);
	this->g15 = *(uint64_t *)copyin(arg0 + 120, 8);
	this->g16 = *(uint64_t *)copyin(arg0 + 128, 8);
	this->g17 = *(uint64_t *)copyin(arg0 + 136, 8);
	this->g18 = *(uint64_t *)copyin(arg0 + 144, 8);
	this->g19 = *(uint64_t *)copyin(arg0 + 152, 8);
}

/* parere #95 §2: le 20 letture non sono atomiche. Il timestamp si ricalcola a ogni
 * clausola (dtrace.c:7442), quindi qui e' il tempo DOPO le letture: [tb, ta] e' l'intervallo
 * di lettura, e l'analisi tratta come di bordo le operazioni che lo attraversano */
pid$target::sim_tick:entry
{
	printf("GT t=%d ta=%d ops_s=%d ops_a=%d rm=%d rk=%d rf=%d part=%d full=%d race=%d rd=%d ok0=%d ok1=%d ok2=%d esaur=%d budget=%d nonrace=%d bytes=%d tscan=%d tpart=%d tfull=%d tver=%d\n", this->tb, timestamp,
	    this->g0,
	    this->g1,
	    this->g2,
	    this->g3,
	    this->g4,
	    this->g5,
	    this->g6,
	    this->g7,
	    this->g8,
	    this->g9,
	    this->g10,
	    this->g11,
	    this->g12,
	    this->g13,
	    this->g14,
	    this->g15,
	    this->g16,
	    this->g17,
	    this->g18,
	    this->g19);
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
	printa("CONTI nb=%@d\n", @nb);
	printa("CONTI no=%@d\n", @no);
	printa("CONTI orph=%@d\n", @orph);
	printa("CONTI nr=%@d\n", @nr);
	printa("CONTI korph=%@d\n", @korph);
	printa("CONTI kaltri=%@d\n", @kaltri);
	printa("CONTI wkmis=%@d\n", @wkmis);
	printa("CONTI vcmis=%@d\n", @vcmis);
	printa("CONTI inv2=%@d\n", @inv2);
	printa("CONTI inv2mis=%@d\n", @inv2mis);
	printa("CONTI inv2orph=%@d\n", @inv2orph);
	printa("CONTI inv2miss=%@d\n", @inv2miss);
	printf("== ISTOGRAMMA reale ==\n"); printa(@reale);
	printf("== ISTOGRAMMA servizio ==\n"); printa(@servizio);
	printf("== LATENZA CHIUSA ==\n");
}
