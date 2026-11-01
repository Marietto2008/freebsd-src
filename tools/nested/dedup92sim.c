/*
 * dedup92sim.c -- Claude 27/10/2026, parere #92 §4/§7: collaudo OFFLINE di
 * dedup92.d (gen-dedup92.py) con DTrace VERO (pid provider) e 8 thread veri.
 * Al posto del modulo:
 *   sim_invept(vcpup, tipo, eptp, int *kept, op)  = vmx_vept_invept
 *   sim_keep(vcpuid, eptp12, live, inval, nr|nc<<32, fb|ntr<<16|ns<<32) = veptkeep
 *   sim_invept2(vcpuid, rip, vmcs12, tipo, eptp, svuotate|conservate<<16) = invept2
 *   sim_root_wipe(n, i)                           = vept_root_wipe
 *   sim_inizio(g) / sim_fine(g)                   = BEGIN/END per i contatori G
 * Il vCPU finto ha la STESSA disposizione del modulo: nested a +0x2b8, vcpuid a
 * +0x2c0, st_vept a +0x58e8 (h1 indice 19, h2 20, riuso 21, falliti 22).
 * Scenari (argv[1]):
 *   pulito   gruppi noti (raffica a 8, due EPTP insieme, catena 0/3/7 ms, stesso
 *            vCPU due volte, riuso dell'EPTP lontano nel tempo, ALL_CONTEXT a 3
 *            radici, ritentativo, sonno, nc diversi, FULL nel gruppo): valori
 *            ESATTI attesi in test-dedup92.sh;
 *   bordo    2 vCPU in operazioni lunghe e continue (per dtrace -p fermato a meta'):
 *            ritorno orfano all'inizio, operazione aperta alla fine;
 *   lungo    pulito + 1,5 s di coda (livello 2: la finestra chiude col suo timer);
 *   gt       primo e ultimo GT a meta' di operazioni, con 8 thread che incrementano insieme;
 *   1..8     UN difetto su una raffica regolare di 8 operazioni: 1 rientro,
 *            2 veptkeep orfana, 3 vcpuid incoerente, 4 invept2 incoerente,
 *            5 operazione NASCOSTA (contatori senza sonde), 6 ritorno incoerente,
 *            7 flush dei contatori dentro l'operazione, 8 invept2 mancante.
 * cc -O0 -Wall -Wextra -Werror -pthread -o dedup92sim dedup92sim.c
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NI __attribute__((noinline))
typedef unsigned long long u64;

#define NVC	8
#define OFF_NESTED	0x2b8
#define OFF_VCPUID	0x2c0
#define OFF_ST		0x58e8
#define NESTED_SZ	0x5a00
enum { H1 = 19, H2 = 20, HR = 21, HN = 22 };
/* stesso ordine di G in gen-dedup92.py */
enum { OPS_S, OPS_A, RM, RK, RF, PART, FULL, RACE, RD, OK0, OK1, OK2, ESAUR,
    BUDGET, NONRACE, BYTES, TSCAN, TPART, TFULL, TVER, NG };
static volatile u64 g[NG];
static volatile u64 pozzo;

struct radice {
	u64 eptp12, live, inval, gbase;	/* gbase: prima GPA delle tabelle (0 = disgiunte per vCPU) */
	int fb, ntr, nc, nr, h1, h2, a, spin_us;
};
struct op {
	int usato, delay_us, type, nroots, sleep_us;
	u64 eptp;
	struct radice r[3];
	/* difetti */
	int nested, vc_falso, wk_falso, nascosta, ritorno_falso, flush, no_inv2;
};
struct vc {
	unsigned char *vcpu, *nested;
	int id;
	struct op op[2];
};
static struct vc V[NVC];
static pthread_barrier_t b_in, b_out;
static volatile int fine_passi;
static u64 t_passo;

static u64
ora(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec);
}

static void
gira(u64 ns)
{
	u64 t0 = ora();

	while (ora() - t0 < ns)
		;
}

static u64 *
st(unsigned char *nested, int i)
{
	return ((u64 *)(nested + OFF_ST + 8 * i));
}

NI void sim_inizio(volatile u64 *gg) { pozzo += gg[0]; }
NI void sim_tick(volatile u64 *gg) { pozzo += gg[0]; }	/* = profile:::tick-10hz */
static volatile int tick_basta;

/* fotografia dei contatori MENTRE la traccia e' attiva, ogni 500 us */
static void *
ticker(void *arg)
{
	(void)arg;
	while (!tick_basta) {
		sim_tick(g);
		usleep(500);
	}
	sim_tick(g);
	return (NULL);
}
NI void sim_fine(volatile u64 *gg) { pozzo += gg[0]; }
NI void sim_keep(int vcpuid, u64 eptp12, u64 live, u64 inval, u64 nrnc, u64 a5)
{ pozzo += vcpuid + eptp12 + live + inval + nrnc + a5; }
NI void sim_invept2(int vcpuid, u64 rip, u64 vmcs12, int type, u64 eptp, u64 wk)
{ pozzo += vcpuid + rip + vmcs12 + type + eptp + wk; }
NI void sim_root_wipe(void *n, int i) { pozzo += (u64)n + i; gira(50000); }
/* = vm_gpa_hold della scansione: site 1 passata 1, 2 passata 2, 3 verifica (da escludere) */
NI void sim_hold(void *vcpup, u64 gpa, int site) { pozzo += (u64)vcpup + gpa + site; }

/* le letture di una radice, coerenti con h1 = ntr x a e h2: passata 1 legge TUTTE le ntr
 * tabelle a ogni tentativo, passata 2 le prime h2 (ciclicamente); piu' una lettura di
 * verifica (sito 3) che il livello 2 deve ignorare */
static void
letture(unsigned char *vcpup, int vcpuid, const struct radice *r)
{
	u64 base = r->gbase ? r->gbase : ((u64)(vcpuid + 1) << 36) | (r->eptp12 & ~0xfffull);
	int i;

	if (r->ntr <= 0)
		return;
	for (i = 0; i < r->h1; i++)
		sim_hold(vcpup, base + (u64)(i % r->ntr) * 0x1000, 1);
	for (i = 0; i < r->h2; i++)
		sim_hold(vcpup, base + (u64)(i % r->ntr) * 0x1000, 2);
	if (r->fb == 0)
		sim_hold(vcpup, 0xdead000, 3);
}

static void
conta(const struct radice *r)
{
	__atomic_add_fetch(&g[RM], 1, __ATOMIC_SEQ_CST);
	__atomic_add_fetch(&g[BYTES], (u64)(r->h1 + r->h2) * 4096, __ATOMIC_SEQ_CST);
	if (r->a > 1)
		__atomic_add_fetch(&g[RD], (u64)(r->a - 1), __ATOMIC_SEQ_CST);
	if (r->fb == 0) {
		__atomic_add_fetch(&g[RK], 1, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&g[PART], 1, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&g[r->a == 1 ? OK0 : r->a == 2 ? OK1 : OK2], 1, __ATOMIC_SEQ_CST);
	} else {
		__atomic_add_fetch(&g[RF], 1, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&g[FULL], 1, __ATOMIC_SEQ_CST);
		if (r->fb & 0x40)
			__atomic_add_fetch(&g[RACE], 1, __ATOMIC_SEQ_CST);
		if (r->fb == 0x40 && r->a > 1)
			__atomic_add_fetch(&g[ESAUR], 1, __ATOMIC_SEQ_CST);
		if (r->fb == 0x40 && r->a <= 1)		/* retries = 1 */
			__atomic_add_fetch(&g[BUDGET], 1, __ATOMIC_SEQ_CST);
		if (r->fb != 0x40 && r->fb != 0x400 && !(r->fb & 0x384) && r->a > 1)
			__atomic_add_fetch(&g[NONRACE], 1, __ATOMIC_SEQ_CST);
	}
}

/* operazione non tracciata: i contatori crescono, le sonde non scattano */
NI int
sim_nascosta(struct vc *v, const struct op *o)
{
	int k;

	__atomic_add_fetch(&g[o->type == 1 ? OPS_S : OPS_A], 1, __ATOMIC_SEQ_CST);
	for (k = 0; k < o->nroots; k++) {
		*st(v->nested, H1) += o->r[k].h1;
		*st(v->nested, H2) += o->r[k].h2;
		conta(&o->r[k]);
	}
	return (0);
}

NI int
sim_invept(unsigned char *vcpup, u64 type, u64 eptp, int *kept, const struct op *o)
{
	unsigned char *n = *(unsigned char **)(vcpup + OFF_NESTED);
	int vcpuid = *(int *)(vcpup + OFF_VCPUID), k, wiped = 0;
	const struct radice *r;
	u64 t0;

	*kept = 0;
	__atomic_add_fetch(&g[type == 1 ? OPS_S : OPS_A], 1, __ATOMIC_SEQ_CST);
	if (o->nested) {
		struct op vuota = { .type = (int)type };
		int k2;

		sim_invept(vcpup, type, eptp, &k2, &vuota);
	}
	if (o->sleep_us)
		usleep((useconds_t)o->sleep_us);
	for (k = 0; k < o->nroots; k++) {
		r = &o->r[k];
		t0 = ora();
		gira((u64)r->spin_us * 1000);
		letture(vcpup, vcpuid, r);
		*st(n, H1) += r->h1;
		*st(n, H2) += r->h2;
		if (o->flush)
			*st(n, H1) = 0;		/* come un flush dentro l'operazione */
		conta(r);
		sim_keep(o->vc_falso ? o->vc_falso : vcpuid, r->eptp12, r->live,
		    r->fb ? r->live : r->inval, (u64)r->nr | (u64)r->nc << 32,
		    (u64)r->fb | (u64)r->ntr << 16 | (ora() - t0) << 32);
		if (r->fb) {
			sim_root_wipe(n, k);
			wiped++;
		} else
			(*kept)++;
	}
	return (wiped + (o->ritorno_falso ? 1 : 0));
}

static void
esegui(struct vc *v, const struct op *o)
{
	int w, kept;
	u64 wk;

	/* con segno: prima di t_passo la differenza e' negativa (senza segno
	 * sarebbe enorme e l'attesa finirebbe subito) */
	while ((long long)(ora() - t_passo) < (long long)o->delay_us * 1000)
		;
	if (o->nascosta) {
		sim_nascosta(v, o);
		return;
	}
	w = sim_invept(v->vcpu, (u64)o->type, o->eptp, &kept, o);
	wk = (u64)w | (u64)(kept + (o->wk_falso ? 1 : 0)) << 16;
	if (!o->no_inv2)
		sim_invept2(v->id, 0xfffff80000001000ull, 0x1000ull * (v->id + 1), o->type, o->eptp, wk);
}

static void *
corpo(void *arg)
{
	struct vc *v = arg;

	for (;;) {
		pthread_barrier_wait(&b_in);
		if (fine_passi)
			break;
		if (v->op[0].usato)
			esegui(v, &v->op[0]);
		if (v->op[1].usato)
			esegui(v, &v->op[1]);
		pthread_barrier_wait(&b_out);
	}
	return (NULL);
}

static void
passo(void)
{
	t_passo = ora() + 2000000;	/* tutti i thread partono dopo la barriera */
	pthread_barrier_wait(&b_in);
	pthread_barrier_wait(&b_out);
	for (int i = 0; i < NVC; i++)
		memset(V[i].op, 0, sizeof(V[i].op));
	usleep(30000);			/* 30 ms fra i passi: nessuna finestra li unisce */
}

static struct radice
rad(u64 e, int fb, int ntr, int nc, int a, int h2, int spin_us)
{
	struct radice r = { .eptp12 = e, .live = 1000, .fb = fb, .ntr = ntr, .nc = nc,
	    .a = a, .h1 = ntr * a, .h2 = h2, .spin_us = spin_us };

	if (fb == 0) {
		r.nr = nc;
		r.inval = (u64)nc * 8;
	}
	return (r);
}

static struct op
op1(u64 e, int delay_us, struct radice r)
{
	struct op o = { .usato = 1, .delay_us = delay_us, .type = 1, .eptp = e, .nroots = 1 };

	o.r[0] = r;
	return (o);
}

#define E(x)	((u64)(x) << 12)

static void
pulito(void)
{
	int i;

	/* S1: raffica a 8 sulla stessa base, due EPTP12 COMPLETI (attributi 0x5e / 0x1e):
	 * chiave primaria 2 gruppi da 4, chiave secondaria (base) 1 gruppo da 8 */
	for (i = 0; i < NVC; i++) {
		V[i].op[0] = op1(E(0x101) | (i & 1 ? 0x1e : 0x5e), 0, rad(E(0x101) | (i & 1 ? 0x1e : 0x5e), 0, 4, 0, 1, 4, 200));
		/* livello 2: il VP i legge le tabelle i..i+3 di una regione COMUNE */
		V[i].op[0].r[0].gbase = 0xf000000000ull + (u64)i * 0x1000;	/* nessun vCPU usa 0xf0... */
	}
	passo();
	/* S2: due EPTP insieme, 4 + 4, nc=1 ntr=3 */
	for (i = 0; i < NVC; i++)
		V[i].op[0] = op1(E(i < 4 ? 0x102 : 0x103) | 0x5e, 0, rad(E(i < 4 ? 0x102 : 0x103) | 0x5e, 0, 3, 1, 1, 3, 150));
	passo();
	/* S3: catena 0 / 3 / 7 ms sulla stessa EPTP: a 5 ms {0,3} + {7}, a 1 ms tre singoli */
	V[0].op[0] = op1(E(0x104) | 0x5e, 0, rad(E(0x104) | 0x5e, 0, 2, 0, 1, 2, 100));
	V[1].op[0] = op1(E(0x104) | 0x5e, 3000, rad(E(0x104) | 0x5e, 0, 2, 0, 1, 2, 100));
	V[2].op[0] = op1(E(0x104) | 0x5e, 7000, rad(E(0x104) | 0x5e, 0, 2, 0, 1, 2, 100));
	passo();
	/* S4: vCPU 5 due volte (0 e subito dopo), vCPU 6 a 0,3 ms: {5a,6} + {5b} */
	V[5].op[0] = op1(E(0x105) | 0x5e, 0, rad(E(0x105) | 0x5e, 0, 2, 0, 1, 2, 100));
	V[5].op[1] = op1(E(0x105) | 0x5e, 0, rad(E(0x105) | 0x5e, 0, 2, 0, 1, 2, 100));
	V[6].op[0] = op1(E(0x105) | 0x5e, 300, rad(E(0x105) | 0x5e, 0, 2, 0, 1, 2, 100));
	passo();
	/* S5: riuso di E(0x101) lontano da S1: gruppo a parte */
	V[0].op[0] = op1(E(0x101) | 0x5e, 0, rad(E(0x101) | 0x5e, 0, 4, 0, 1, 4, 200));
	V[1].op[0] = op1(E(0x101) | 0x5e, 0, rad(E(0x101) | 0x5e, 0, 4, 0, 1, 4, 200));
	passo();
	/* S6: ALL_CONTEXT, 3 radici: race esaurita (svuotata), parziale nc=2, parziale nc=0 */
	V[3].op[0] = (struct op){ .usato = 1, .type = 2, .eptp = 0, .nroots = 3 };
	V[3].op[0].r[0] = rad(E(0x106) | 0x5e, 0x40, 3, 1, 2, 3, 100);
	V[3].op[0].r[1] = rad(E(0x107) | 0x5e, 0, 2, 2, 1, 2, 100);
	V[3].op[0].r[2] = rad(E(0x108) | 0x5e, 0, 1, 0, 1, 1, 100);
	passo();
	/* S7: ritentativo riuscito: ntr=5, 2 tentativi, h2 = 2 + 5 */
	V[2].op[0] = op1(E(0x109) | 0x5e, 0, rad(E(0x109) | 0x5e, 0, 5, 1, 2, 7, 100));
	passo();
	/* S8: sonno di 20 ms dentro l'operazione */
	V[4].op[0] = op1(E(0x10a) | 0x5e, 0, rad(E(0x10a) | 0x5e, 0, 2, 0, 1, 2, 100));
	V[4].op[0].sleep_us = 20000;
	passo();
	/* S9: stessa EPTP insieme, nc diversi (0 e 3): gruppo SENZA COUNTERS_MATCH */
	V[0].op[0] = op1(E(0x10b) | 0x5e, 0, rad(E(0x10b) | 0x5e, 0, 3, 0, 1, 3, 100));
	V[1].op[0] = op1(E(0x10b) | 0x5e, 0, rad(E(0x10b) | 0x5e, 0, 3, 3, 1, 3, 100));
	passo();
	/* S10: FULL (tetto, prima della scansione) e PARZIALE nello stesso gruppo */
	V[2].op[0] = op1(E(0x10c) | 0x5e, 0, rad(E(0x10c) | 0x5e, 0x04, 0, 0, 0, 0, 20));
	V[3].op[0] = op1(E(0x10c) | 0x5e, 0, rad(E(0x10c) | 0x5e, 0, 2, 0, 1, 2, 100));
	passo();
}

/* bordo: 2 vCPU in operazioni da 300 ms (sonno dentro) per ~4 s; dtrace si attacca
 * (-p) e si ferma a meta' di un'operazione: ritorno orfano all'inizio, operazione
 * aperta alla fine */
static void *
bordo_corpo(void *arg)
{
	struct vc *v = arg;
	struct op o = op1(E(0x300 + v->id) | 0x5e, 0, rad(E(0x300 + v->id) | 0x5e, 0, 5, 0, 1, 5, 10));
	int k;
	u64 t0 = ora();

	o.sleep_us = 300000;
	t_passo = 0;
	while (ora() - t0 < 4000000000ull) {
		sim_invept(v->vcpu, 1, o.eptp, &k, &o);
		sim_invept2(v->id, 0, 0, 1, o.eptp, (u64)k << 16);
	}
	return (NULL);
}

/* gt (parere #95 §2): il PRIMO e l'ULTIMO GT cadono a meta' di operazioni, mentre 8 thread
 * incrementano insieme: ogni operazione incrementa ops all'ingresso e le radici dopo 20 ms
 * (due contatori distinti in tempi diversi). Il ticker parte a meta' della prima ondata e si
 * ferma a meta' della seconda. */
static pthread_t tt_gt;

static void
gt_ondata(int ferma)
{
	int i;

	for (i = 0; i < NVC; i++) {
		V[i].op[0] = op1(E(0x400 + i) | 0x5e, 0, rad(E(0x400 + i) | 0x5e, 0, 5, 1, 1, 5, 50));
		V[i].op[0].sleep_us = 20000;
	}
	t_passo = ora() + 2000000;
	pthread_barrier_wait(&b_in);
	usleep(12000);			/* ~10 ms dentro le operazioni */
	if (ferma) {
		tick_basta = 1;
		pthread_join(tt_gt, NULL);
	} else
		pthread_create(&tt_gt, NULL, ticker, NULL);
	pthread_barrier_wait(&b_out);
	for (i = 0; i < NVC; i++)
		memset(V[i].op, 0, sizeof(V[i].op));
	usleep(30000);
}

/* UN difetto per corsa (1..8), sulle 8 operazioni regolari di una raffica */
static void
difetti(int d)
{
	int i;

	for (i = 0; i < NVC; i++)
		V[i].op[0] = op1(E(0x200 + i) | 0x5e, 0, rad(E(0x200 + i) | 0x5e, 0, 2, 0, 1, 2, 100));
	switch (d) {
	case 1: V[0].op[0].nested = 1; break;		/* rientro */
	case 3: V[2].op[0].vc_falso = 9; break;		/* vcpuid sonda != struttura */
	case 4: V[3].op[0].wk_falso = 1; break;		/* invept2 incoerente */
	case 5: V[4].op[0].nascosta = 1; break;		/* operazione persa dalla traccia */
	case 6: V[5].op[0].ritorno_falso = 1; break;	/* radici != svuotate + conservate */
	case 7: V[6].op[0].flush = 1; break;		/* flush dentro l'operazione */
	case 8: V[7].op[0].no_inv2 = 1;		/* invept2 mancante, poi un'altra */
		V[7].op[1] = op1(E(0x2f7) | 0x5e, 0, rad(E(0x2f7) | 0x5e, 0, 2, 0, 1, 2, 100));
		break;
	}
	passo();
	if (d == 2) {					/* veptkeep fuori da ogni operazione */
		sim_keep(1, E(0x2ff) | 0x5e, 1, 0, 0, (u64)1 << 16);
		usleep(30000);
	}
}

int
main(int argc, char **argv)
{
	pthread_t th[NVC], tt;
	int i;

	if (argc != 2 || (strcmp(argv[1], "pulito") && strcmp(argv[1], "lungo") && strcmp(argv[1], "bordo") && strcmp(argv[1], "gt") &&
	    (atoi(argv[1]) < 1 || atoi(argv[1]) > 8))) {
		fprintf(stderr, "uso: dedup92sim pulito|lungo|bordo|gt|1..8 (un difetto)\n");
		return (2);
	}
	pthread_barrier_init(&b_in, NULL, NVC + 1);
	pthread_barrier_init(&b_out, NULL, NVC + 1);
	for (i = 0; i < NVC; i++) {
		V[i].vcpu = calloc(1, 0x300);
		V[i].nested = calloc(1, NESTED_SZ);
		V[i].id = i;
		/* pagine gia' presenti: copyin di DTrace non le porta in memoria (nel
		 * kernel la struttura e' memoria del kernel, sempre presente) */
		memset(V[i].vcpu, 0xff, 0x300);
		memset(V[i].vcpu, 0, 0x300);
		memset(V[i].nested, 0xff, NESTED_SZ);
		memset(V[i].nested, 0, NESTED_SZ);
		*st(V[i].nested, H1) = 1000;	/* contatori gia' avviati: il flush */
		*st(V[i].nested, H2) = 1000;	/* dentro l'operazione da' un delta < 0 */
		*(unsigned char **)(V[i].vcpu + OFF_NESTED) = V[i].nested;
		*(int *)(V[i].vcpu + OFF_VCPUID) = i;
		if (strcmp(argv[1], "bordo"))
			pthread_create(&th[i], NULL, corpo, &V[i]);
	}
	if (strcmp(argv[1], "gt"))
		pthread_create(&tt, NULL, ticker, NULL);
	if (!strcmp(argv[1], "bordo")) {
		pthread_create(&th[0], NULL, bordo_corpo, &V[0]);
		pthread_create(&th[1], NULL, bordo_corpo, &V[1]);
		pthread_join(th[0], NULL);
		pthread_join(th[1], NULL);
		tick_basta = 1;
		pthread_join(tt, NULL);
		return (0);
	}
	usleep(200000);			/* DTrace attaccato ai thread */
	sim_inizio(g);
	if (!strcmp(argv[1], "gt")) {
		gt_ondata(0);
		gt_ondata(1);
		sim_fine(g);
	} else {
		if (!strcmp(argv[1], "pulito"))
			pulito();
		else if (!strcmp(argv[1], "lungo")) {
			pulito();		/* livello 2: la finestra chiude col SUO timer */
			usleep(1500000);
		} else
			difetti(atoi(argv[1]));
		sim_fine(g);
		usleep(2000);
		tick_basta = 1;
		pthread_join(tt, NULL);
	}
	fine_passi = 1;
	pthread_barrier_wait(&b_in);
	for (i = 0; i < NVC; i++)
		pthread_join(th[i], NULL);
	return (0);
}
