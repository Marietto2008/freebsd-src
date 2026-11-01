#!/usr/local/bin/python3
# gen-dedup92.py -- Claude 27/10/2026, parere #92 §4 (LIVELLO 1, leggero): un record
# per RADICE esaminata (R) e uno per OPERAZIONE (O) del gestore INVEPT dell'L1, piu'
# le aggregazioni di latenza IDENTICHE ad abba-invept-lat.d (stessi nomi CONTA e
# istogrammi: confronto diretto con il braccio A gia' registrato). NESSUNA sonda su
# vm_gpa_hold (#92 §5: livello 2, condizionale). Solo lettura, nessuna scrittura nel
# kernel.
#
# Sonde (frequenza = operazioni, non letture di pagine), verificate sul modulo
# installato 27125f004917 (sha256 149fa57e..., build-id d30f6a7f...):
#   fbt:vmm-restore:vmx_vept_invept:entry/return  delimita l'operazione (unico
#       chiamante: nested_invept, vmx_nested.c:4220). arg0 = struct vmx_vcpu *,
#       arg1 = tipo, arg2 = eptp del descrittore, arg3 = int *kept; al ritorno
#       arg1 = radici svuotate.
#   vmm:vmx:nested:veptkeep  una per radice colpita con vept_keep (vmx_vept.c:1476
#       conservata, :1493 svuotata): arg0 vcpuid, arg1 eptp12 della radice, arg2
#       foglie vive prima, arg3 foglie invalidate (= arg2 se svuotata), arg4 =
#       nr | nc << 32 (nr = 0 se svuotata; nc = voci cambiate dell'ULTIMO tentativo,
#       parziale se svuotata), arg5 = fb (16 bit) | ntr << 16 (16 bit, saturato) |
#       ns << 32 (da t0 della radice: scansione + azzeramento + verifica se
#       conservata; SOLO scansione se svuotata, lo svuotamento viene dopo).
#   vmm:vmx:nested:invept2  dopo il ritorno, stesso thread: arg0 vcpuid, arg3 tipo,
#       arg4 eptp, arg5 = svuotate | conservate << 16 -> controllo di coerenza.
#   fbt:vmm-restore:vept_root_wipe:entry/return  chiamata vera (non incorporata)
#       dentro vmx_vept_invept: costo dello svuotamento, fuori da ns.
#   sched:::off-cpu/on-cpu  come abba-invept-lat.d.
# Letture di memoria (il modulo NON ha CTF: offset dal DWARF della stessa build,
# vmm-restore.ko.debug con build-id d30f6a7f..., e confermati nel disassemblato):
#   vmx_vcpu.nested = +0x2b8, vmx_vcpu.vcpuid = +0x2c0,
#   vmx_nested.st_vept = +0x58e8, uint64_t, indici VST_H_SCAN1 19, VST_H_SCAN2 20,
#   VST_H_SCAN2_REUSE 21, VST_H_NULL 22 -> +0x5980/+0x5988/+0x5990/+0x5998
#   ("incq 0x5980(%rcx)" e "incq 0x5988(%rcx)" in vmx_vept_invept). Contatori PER
#   vCPU letti dal SUO thread (nessun'altra CPU li scrive; il flush e' all'inizio di
#   vmx_nested_exit, fuori dall'operazione): letture di pagine EPT12 per radice SENZA
#   sonde su vm_gpa_hold; tentativi = ceil(h1 / ntr).
#   Contatori globali del modulo a inizio (G0) e fine (G1) della traccia: chiusura.
# Buffer come abba-invept-lat.d (bufsize 4m PER CPU, x2 per la commutazione: ~128 MB sui 16
# thread dell'host); flusso atteso ~250 KB/s in tutto, svuotato a 10 Hz.
# Genera dallo STESSO nucleo:
#   dedup92.d     kernel (uso: dtrace -s dedup92.d <pid del bhyve>)
#   dedup92sim.d  dedup92sim.c (pid provider), collaudo con DTrace vero
import sys

# contatori globali (campo, simbolo): letti in G0/G1
G = [
	('ops_s', 'vept_invept_single'), ('ops_a', 'vept_invept_all'),
	('rm', 'vept_invept_roots_matched'), ('rk', 'vept_invept_roots_kept'),
	('rf', 'vept_invept_roots_fallback'), ('part', 'vept_keep_partial_invepts'),
	('full', 'vept_keep_full_fallbacks'), ('race', 'vept_keep_scan_race_fallbacks'),
	('rd', 'vept_scan_retries_done'), ('ok0', 'vept_scan_first_pass_ok'),
	('ok1', 'vept_scan_retry_1_success'), ('ok2', 'vept_scan_retry_2_success'),
	('esaur', 'vept_scan_retry_exhausted'), ('budget', 'vept_scan_retry_budget_fallback'),
	('nonrace', 'vept_scan_retry_nonrace_fallback'), ('bytes', 'vept_scan_bytes_read'),
	('tscan', 'vept_t_scan_ns'), ('tpart', 'vept_t_partial_ns'),
	('tfull', 'vept_t_full_ns'), ('tver', 'vept_t_verify_ns'),
]
OFF_NESTED, OFF_VCPUID, OFF_ST = 0x2b8, 0x2c0, 0x58e8
VST = {'h1': 19, 'h2': 20, 'hr': 21, 'hn': 22}
H = ['h1', 'h2', 'hr', 'hn']

TESTA = r'''#pragma D option quiet
#pragma D option dynvarsize=8m
#pragma D option bufsize=4m
#pragma D option aggsize=8m
#pragma D option switchrate=10hz
/*
 * %(nome)s -- GENERATO da gen-dedup92.py, non modificare a mano. Solo lettura.
 * Parere #92 livello 1: record R (radice) e O (operazione) del gestore INVEPT del
 * processo indicato, G0/G1 (contatori globali), aggregazioni come abba-invept-lat.d.
 * Uso: %(uso)s
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
%(selfh)s
self int lt;
self int lw;
self int lk;
self int lvc;
'''

NUCLEO = r'''
%(g0probe)s
{
	printf("G0 t=%%d %(gfmt)s\n", timestamp,
%(g0args)s);
}

BEGIN { printf("== LATENZA PRONTA == pid=%%d\n", %(pidv)s); }

%(entry)s
/ pid == %(pidv)s && self->t /
{
	@annid = count();		/* rientro (PRIMA della clausola che imposta self->t) */
	printf("NEST tid=%%d cpu=%%d t=%%d\n", tid, cpu, timestamp);
}

%(entry)s
/ pid == %(pidv)s && !self->t /
{
	@nb = count();			/* ingressi: nb - no = operazioni aperte alla fine */
	self->t = timestamp; self->v = vtimestamp; self->off = 0; self->offt = 0;
	self->ty = (int)arg1; self->ep = arg2; self->kp = arg3;
	self->vc = %(vcpuid)s;
	self->np = %(nested)s;
%(hentry)s	self->nk = 0; self->nw = 0; self->wt = 0; self->wv = 0; self->vcm = 0;
	/* invept2 dell'operazione PRECEDENTE di questo thread mai arrivata: errore certo
	 * (solo l'ultima operazione di ogni thread puo' perderla legittimamente, a END) */
	@inv2miss = sum(self->lt);
	self->lt = 0;
}

%(keep)s
/ pid == %(pidv)s && self->t /
{
%(hthis)s	self->nk++;
	self->vcm += (int)arg0 != self->vc ? 1 : 0;
	@nr = count();
	printf("R tid=%%d t0=%%d k=%%d vc=%%d e=%%x live=%%d inv=%%d nr=%%d nc=%%d fb=%%x ntr=%%d ns=%%d t=%%d vt=%%d %(hfmt)s\n",
	    tid, self->t, self->nk, (int)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
	    (uint64_t)arg4 & 0xffffffff, (uint64_t)arg4 >> 32, (uint64_t)arg5 & 0xffff,
	    ((uint64_t)arg5 >> 16) & 0xffff, (uint64_t)arg5 >> 32, timestamp, vtimestamp,
%(hrargs)s);
%(hmark)s}

%(keep)s
/ pid == %(pidv)s && !self->t /
{
	@korph = count();
	printf("KORPH tid=%%d t=%%d vc=%%d e=%%x fb=%%x ntr=%%d\n", tid, timestamp, (int)arg0, (uint64_t)arg1,
	    (uint64_t)arg5 & 0xffff, ((uint64_t)arg5 >> 16) & 0xffff);
}

%(keep)s
/ pid != %(pidv)s /
{
	@kaltri = count();
}

%(wipe_e)s
/ self->t /
{
	self->we = timestamp; self->wve = vtimestamp;
}

%(wipe_r)s
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
%(ret)s
/ pid == %(pidv)s && !self->t /
{
	@orph = count();
	printf("ORPH tid=%%d t=%%d w=%%d\n", tid, timestamp, (int)arg1);
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
%(hthis)s	this->kept = %(kept)s;
	@no = count();
	@wkmis = sum(self->nk != (int)arg1 + this->kept ? 1 : 0);
	@vcmis = sum(self->vcm);
	printf("O tid=%%d pid=%%d cpu=%%d vc=%%d ty=%%d e=%%x t0=%%d t1=%%d v0=%%d sv=%%d off=%%d offt=%%d nk=%%d w=%%d kept=%%d nw=%%d wt=%%d wv=%%d %(hfmt)s %(rfmt)s vcm=%%d\n",
	    tid, pid, cpu, self->vc, self->ty, self->ep, self->t, timestamp, self->v, this->s, self->off,
	    self->offt, self->nk, (int)arg1, this->kept, self->nw, self->wt, self->wv,
%(htot)s,
%(hres)s,
	    self->vcm);
	self->lt = 1; self->lw = (int)arg1; self->lk = this->kept; self->lvc = self->vc;
	self->t = 0; self->v = 0; self->off = 0; self->offt = 0; self->toff = 0;
	self->np = 0; self->kp = 0; self->ep = 0; self->ty = 0; self->vc = 0;
	self->nk = 0; self->nw = 0; self->vcm = 0; self->wt = 0; self->wv = 0;
%(hzero)s}

/* l'orfana PRIMA: la clausola che consuma self->lt la azzera, e le clausole
 * della stessa sonda si valutano in ordine */
%(inv2)s
/ pid == %(pidv)s && !self->lt /
{
	@inv2orph = count();
}

%(inv2)s
/ pid == %(pidv)s && self->lt /
{
	@inv2 = count();
	@inv2mis = sum(((int)arg0 != self->lvc || (int)((uint64_t)arg5 & 0xffff) != self->lw ||
	    (int)((uint64_t)arg5 >> 16) != self->lk) ? 1 : 0);
	self->lt = 0; self->lw = 0; self->lk = 0; self->lvc = 0;
}

%(g1probe)s
{
	printf("G1 t=%%d %(gfmt)s\n", timestamp,
%(g1args)s);
}

/* parere #94 + dtrace.c:7459: fuori da ACTIVE (WARMUP dopo BEGIN, DRAINING prima di END)
 * le sonde si scartano, quindi G0/G1 lasciano due fessure senza record. GT si legge
 * MENTRE la traccia e' attiva: la chiusura usa il primo e l'ultimo GT */
%(gtprobe)s
{
	this->tb = timestamp;	/* prima clausola: tempo PRIMA delle 20 letture */
%(gtthis)s}

/* parere #95 §2: le 20 letture non sono atomiche. Il timestamp si ricalcola a ogni
 * clausola (dtrace.c:7442), quindi qui e' il tempo DOPO le letture: [tb, ta] e' l'intervallo
 * di lettura, e l'analisi tratta come di bordo le operazioni che lo attraversano */
%(gtprobe)s
{
	printf("GT t=%%d ta=%%d %(gfmt)s\n", this->tb, timestamp,
%(gtthisargs)s);
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
	printa("CONTI nb=%%@d\n", @nb);
	printa("CONTI no=%%@d\n", @no);
	printa("CONTI orph=%%@d\n", @orph);
	printa("CONTI nr=%%@d\n", @nr);
	printa("CONTI korph=%%@d\n", @korph);
	printa("CONTI kaltri=%%@d\n", @kaltri);
	printa("CONTI wkmis=%%@d\n", @wkmis);
	printa("CONTI vcmis=%%@d\n", @vcmis);
	printa("CONTI inv2=%%@d\n", @inv2);
	printa("CONTI inv2mis=%%@d\n", @inv2mis);
	printa("CONTI inv2orph=%%@d\n", @inv2orph);
	printa("CONTI inv2miss=%%@d\n", @inv2miss);
	printf("== ISTOGRAMMA reale ==\n"); printa(@reale);
	printf("== ISTOGRAMMA servizio ==\n"); printa(@servizio);
	printf("== LATENZA CHIUSA ==\n");
}
'''

# LIVELLO 2 (parere #95 §4.2-4.4): finestra BREVE, un processo dtrace per finestra (fuori
# dalle finestre vm_gpa_hold non e' nemmeno abilitata). Oltre al nucleo del livello 1:
#   H  tid t0 k p gpa   una riga per vm_gpa_hold della SCANSIONE dentro vmx_vept_invept dello
#                       stesso thread: p=1 passata 1, p=2 passata 2, k = radice (self->nk + 1).
#      Siti (27125f004917, objdump -dr): ritorno a vmx_vept_invept+0xcb8 (seguito da incq
#      0x5980 = VST_H_SCAN1) e +0x10eb (incq 0x5988 = VST_H_SCAN2). Gli altri 3 siti
#      (+0x335 vept_obs_scan, +0xfe2 iniezione di race, +0x1b0d verifica HPA) sono esclusi.
#      arg1 di vm_gpa_hold = GPA (vmm_mem.c:514). Un sito sbagliato si vede: le righe H per
#      radice non tornano con h1/h2 dei contatori per vCPU -> finestra INCOMPLETA.
#   FINESTRA inizio/fine  e uscita da sola dopo $2 ms (kernel) / $1 ms (simulatore).
L2 = r"""
/* -------- livello 2: finestra di %(ms)s ms (parere #96 §3) --------
 * BEGIN gira in WARMUP: segna solo la RICHIESTA. La finestra vera parte al primo tick-1ms
 * (le sonde profile scattano solo in ACTIVE, dtrace.c:7459) e finisce all'ultimo, quello che
 * chiama exit(): [ATTIVA inizio, ATTIVA fine] e' l'intervallo con le sonde certamente attive. */
BEGIN { printf("FINESTRA richiesta=%%d ms=%%d\n", timestamp, %(ms)s); }

profile:::tick-1ms
/ !attiva /
{
	attiva = timestamp;
	fine = timestamp + %(ms)s * 1000000;
	printf("ATTIVA inizio=%%d\n", timestamp);
}

profile:::tick-1ms
/ attiva && fine && timestamp >= fine /
{
	printf("ATTIVA fine=%%d\n", timestamp);
	fine = 0;
	exit(0);
}

/* azzeramento del segno della riga I: PRIMA della clausola di ritorno principale */
%(ret)s
/ self->ilog /
{
	self->ilog = 0;
}

%(hold)s
/ self->t && %(sito1)s /
{
	@nh1 = count();
	printf("H tid=%%d t0=%%d k=%%d p=1 gpa=%%x\n", tid, self->t, self->nk + 1, (uint64_t)arg1);
}

%(hold)s
/ self->t && %(sito2)s /
{
	@nh2 = count();
	printf("H tid=%%d t0=%%d k=%%d p=2 gpa=%%x\n", tid, self->t, self->nk + 1, (uint64_t)arg1);
}

END
{
	printa("CONTI nh1=%%@d\n", @nh1);
	printa("CONTI nh2=%%@d\n", @nh2);
}
"""

def genera(nome, sim, l2=False):
	if sim:
		r8 = lambda a: '*(uint64_t *)copyin(%s, 8)' % a
		r4 = lambda a: '*(int *)copyin(%s, 4)' % a
		pidv = '$target'
		p = dict(entry='pid$target::sim_invept:entry', ret='pid$target::sim_invept:return',
		    keep='pid$target::sim_keep:entry', inv2='pid$target::sim_invept2:entry',
		    wipe_e='pid$target::sim_root_wipe:entry', wipe_r='pid$target::sim_root_wipe:return',
		    g0probe='pid$target::sim_inizio:entry', g1probe='pid$target::sim_fine:entry',
		    gtprobe='pid$target::sim_tick:entry',
		    uso='dtrace -s %s -c dedup92sim' % nome)
		gv = lambda i, s: r8('arg0 + %d' % (8 * i))
	else:
		r8 = lambda a: '*(uint64_t *)(%s)' % a
		r4 = lambda a: '*(int *)(%s)' % a
		pidv = '$1'
		p = dict(entry='fbt:vmm-restore:vmx_vept_invept:entry', ret='fbt:vmm-restore:vmx_vept_invept:return',
		    keep='vmm:vmx:nested:veptkeep', inv2='vmm:vmx:nested:invept2',
		    wipe_e='fbt:vmm-restore:vept_root_wipe:entry', wipe_r='fbt:vmm-restore:vept_root_wipe:return',
		    g0probe='BEGIN', g1probe='END', gtprobe='profile:::tick-10hz',
		    uso='dtrace -s %s <pid del bhyve>' % nome)
		gv = lambda i, s: '*(uint64_t *)&`%s' % s
	st = lambda h: r8('self->np + %#x' % (OFF_ST + 8 * VST[h]))
	p.update(nome=nome, pidv=pidv,
	    vcpuid=r4('arg0 + %#x' % OFF_VCPUID), nested=r8('arg0 + %#x' % OFF_NESTED),
	    kept=r4('self->kp'),
	    selfh=''.join('self uint64_t b%s;\nself uint64_t a%s;\n' % (h, h) for h in H),
	    hentry=''.join('\tself->b%s = %s; self->a%s = self->b%s;\n' % (h, st(h), h, h) for h in H),
	    hthis=''.join('\tthis->c%s = %s;\n' % (h, st(h)) for h in H),
	    hfmt=' '.join('%s=%%d' % h for h in H),
	    rfmt=' '.join('r%s=%%d' % h for h in H),
	    hrargs=',\n'.join('\t    this->c%s - self->a%s' % (h, h) for h in H),
	    hmark=''.join('\tself->a%s = this->c%s;\n' % (h, h) for h in H),
	    htot=',\n'.join('\t    this->c%s - self->b%s' % (h, h) for h in H),
	    hres=',\n'.join('\t    this->c%s - self->a%s' % (h, h) for h in H),
	    hzero=''.join('\tself->a%s = 0; self->b%s = 0;\n' % (h, h) for h in H),
	    gfmt=' '.join('%s=%%d' % c for c, _ in G),
	    g0args=',\n'.join('\t    ' + gv(i, s) for i, (c, s) in enumerate(G)),
	    g1args=',\n'.join('\t    ' + gv(i, s) for i, (c, s) in enumerate(G)),
	    gtthis=''.join('\tthis->g%d = %s;\n' % (i, gv(i, s)) for i, (c, s) in enumerate(G)),
	    gtthisargs=',\n'.join('\t    this->g%d' % i for i, (c, s) in enumerate(G)))
	testo = (TESTA % p) + (NUCLEO % p)
	if l2:
		if sim:
			q = dict(ms='$1', hold='pid$target::sim_hold:entry', sito1='arg2 == 1', sito2='arg2 == 2',
			    entry=p['entry'], pidv=p['pidv'], ret=p['ret'])
		else:
			q = dict(ms='$2', hold='fbt:vmm-restore:vm_gpa_hold:entry', entry=p['entry'], pidv=p['pidv'], ret=p['ret'],
			    sito1='caller == (uintptr_t)&`vmx_vept_invept + 0xcb8',
			    sito2='caller == (uintptr_t)&`vmx_vept_invept + 0x10eb')
		testo = testo.replace('#pragma D option switchrate=10hz', '#pragma D option switchrate=50hz')
		testo = testo.replace(' * Uso: ', ' * LIVELLO 2: finestra breve con le GPA lette dalla scansione.\n * Uso: ')
		# il blocco L2 va PRIMA del nucleo: la clausola I precede l'ingresso principale e
		# l'END del livello 2 precede quello che stampa il marcatore di chiusura
		i = testo.index('\n%s\n{' % p['g0probe'])
		testo = testo[:i] + '\n' + (L2 % q) + testo[i:]
		# riga I DOPO l'ingresso principale: stampa lo STESSO self->t della riga O (aggancio
		# esatto, nessuna tolleranza); una sola per operazione, nessuna per un rientro
		testo += (r"""
/* livello 2: ingresso di ogni operazione; I senza O = aperta alla fine (censura dei gruppi) */
%(entry)s
/ pid == %(pidv)s && self->t && !self->ilog /
{
	self->ilog = 1;
	printf("I tid=%%d t0=%%d\n", tid, self->t);
}
""" % q)
	return testo

if __name__ == '__main__':
	out = sys.argv[1] if len(sys.argv) > 1 else '.'
	for nome, sim, l2 in (('dedup92.d', False, False), ('dedup92sim.d', True, False),
	    ('dedup95l2.d', False, True), ('dedup95l2sim.d', True, True)):
		open('%s/%s' % (out, nome), 'w').write(genera(nome, sim, l2))
		print('%s/%s' % (out, nome))
