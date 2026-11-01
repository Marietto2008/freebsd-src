/*
 * diag83sim.c -- Claude 26/10/2026 notte, parere #83 §2: collaudo OFFLINE di
 * diag83 (gen-diag83.py) con DTrace vero (pid provider) e thread veri. Le
 * funzioni sim_invept/sim_keep stanno al posto di vmx_vept_invept/veptkeep;
 * i contatori sono un vettore in memoria utente (stesso ordine di CTR in
 * gen-diag83.py). Scrive i contatori prima/dopo nel formato del runner
 * (sysctl senza prefisso). Nessuna VM.
 * Uso: diag83sim <scenario> <file prima> <file dopo>
 * cc -O0 -Wall -Wextra -Werror -pthread -o diag83sim diag83sim.c
 */
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NI __attribute__((noinline))
typedef unsigned long long u64;

enum { INJ, RD, OK0, OK1, OK2, ESAUR, BUDGET, NONRACE, RACEFB, A1NS, A2NS,
    PARTIAL, FULL, MISM, NCTR };
static const char *nomi[NCTR] = {
	"vept_test_race_injected", "vept_scan_retries_done",
	"vept_scan_first_pass_ok", "vept_scan_retry_1_success",
	"vept_scan_retry_2_success", "vept_scan_retry_exhausted",
	"vept_scan_retry_budget_fallback", "vept_scan_retry_nonrace_fallback",
	"vept_keep_scan_race_fallbacks", "vept_t_attempt1_ns", "vept_t_attempt2_ns",
	"vept_keep_partial_invepts", "vept_keep_full_fallbacks",
	"vept_keep_verify_mismatch",
};
static volatile u64 ctr[NCTR];
static volatile u64 pozzo;
static jmp_buf salto;

/* un'operazione: incrementi, radici, attesa (us), annidata, uscita a salto */
struct op {
	u64 d[NCTR];
	int nkeep, fb, vcpuid, sleep_us, nested, jump;
};

NI void sim_keep(int vcpuid, int fb) { pozzo += vcpuid + fb; }

NI int
sim_invept(void *vcpup, int type, u64 eptp, volatile u64 *c, const struct op *o)
{
	int i, k;

	for (i = 0; i < NCTR; i++)
		__atomic_add_fetch(&c[i], o->d[i], __ATOMIC_SEQ_CST);
	if (o->sleep_us)
		usleep(o->sleep_us);
	if (o->nested) {
		struct op in = { .nkeep = 0 };
		sim_invept(vcpup, type, eptp, c, &in);
	}
	for (k = 0; k < o->nkeep; k++)
		sim_keep(k == 1 && o->vcpuid < 0 ? 7 : (o->vcpuid < 0 ? 0 : o->vcpuid), o->fb);
	if (o->jump)
		longjmp(salto, 1);
	return (o->d[FULL] != 0);
}

static void
fai(int vcpuid, const struct op *o)
{
	sim_invept((void *)(0xfffff80001000000ull + (u64)vcpuid * 0x1000), 1,
	    0x29215e01eull, ctr, o);
}

/* operazioni tipo */
static struct op PLAIN = { .d = { [OK0] = 1, [PARTIAL] = 1 }, .nkeep = 1 };
static struct op OPB_ = { .d = { [INJ] = 1, [RACEFB] = 1, [FULL] = 1 }, .nkeep = 1, .fb = 0x40 };
static struct op OPE_ = { .d = { [INJ] = 3, [RD] = 2, [ESAUR] = 1, [RACEFB] = 1,
    [A1NS] = 300, [A2NS] = 300, [FULL] = 1 }, .nkeep = 1, .fb = 0x40 };

struct targ { int vcpuid; struct op o; int ritardo_us; };
static void *
filo(void *a)
{
	struct targ *t = a;

	if (t->ritardo_us)
		usleep(t->ritardo_us);
	t->o.vcpuid = t->vcpuid;
	fai(t->vcpuid, &t->o);
	return (NULL);
}

static void
scrivi(const char *f)
{
	FILE *fp = fopen(f, "w");
	int i;

	if (fp == NULL) { perror(f); exit(1); }
	for (i = 0; i < NCTR; i++)
		fprintf(fp, "%s: %llu\n", nomi[i], (u64)ctr[i]);
	fclose(fp);
}

int
main(int argc, char **argv)
{
	int s, i;
	pthread_t t1, t2;
	struct targ a, b;

	if (argc != 4) { fprintf(stderr, "uso: diag83sim N prima dopo\n"); return (2); }
	s = atoi(argv[1]);
	for (i = 0; i < NCTR; i++)
		ctr[i] = 1000 + i;		/* valori iniziali non nulli */
	scrivi(argv[2]);
	switch (s) {
	case 1:		/* B sequenziale, un thread */
		fai(0, &PLAIN); fai(0, &PLAIN); fai(0, &OPB_); fai(0, &PLAIN);
		break;
	case 2:		/* B sovrapposta da un'operazione di un ALTRO thread */
		fai(0, &PLAIN);
		a = (struct targ){ 0, OPB_, 0 }; a.o.sleep_us = 200000;
		b = (struct targ){ 1, PLAIN, 50000 };
		pthread_create(&t1, NULL, filo, &a); pthread_create(&t2, NULL, filo, &b);
		pthread_join(t1, NULL); pthread_join(t2, NULL);
		break;
	case 3:		/* due thread NON sovrapposti */
		a = (struct targ){ 0, OPB_, 0 };
		pthread_create(&t1, NULL, filo, &a); pthread_join(t1, NULL);
		usleep(50000);
		b = (struct targ){ 1, PLAIN, 0 };
		pthread_create(&t2, NULL, filo, &b); pthread_join(t2, NULL);
		break;
	case 4:		/* chiamata annidata dentro B */
		fai(0, &PLAIN);
		a.o = OPB_; a.o.nested = 1; fai(0, &a.o);
		break;
	case 5:		/* ingresso senza ritorno (uscita a salto) dopo B */
		fai(0, &OPB_); usleep(20000);
		a.o = PLAIN; a.o.jump = 1;
		if (setjmp(salto) == 0)
			fai(0, &a.o);
		break;
	case 6:		/* contatore cambiato FUORI da ogni operazione */
		fai(0, &OPB_);
		__atomic_add_fetch(&ctr[INJ], 1, __ATOMIC_SEQ_CST);
		fai(0, &PLAIN);
		break;
	case 7:		/* E sequenziale: tre tentativi */
		fai(0, &PLAIN); fai(0, &OPE_); fai(0, &PLAIN);
		break;
	case 8:		/* B con due radici di vCPU diversi (vcpuid -1 = 0 poi 7) */
		a.o = OPB_; a.o.nkeep = 2; a.o.vcpuid = -1; fai(0, &a.o);
		break;
	case 9:		/* A sequenziale */
		fai(0, &PLAIN); fai(0, &PLAIN); fai(0, &PLAIN);
		break;
	case 10:	/* sovrapposizione anche da un thread che fa solo PLAIN, B esclusiva prima */
		fai(0, &OPB_); usleep(20000);
		a = (struct targ){ 0, PLAIN, 0 }; a.o.sleep_us = 100000;
		b = (struct targ){ 1, PLAIN, 20000 };
		pthread_create(&t1, NULL, filo, &a); pthread_create(&t2, NULL, filo, &b);
		pthread_join(t1, NULL); pthread_join(t2, NULL);
		break;
	default:
		return (2);
	}
	usleep(100000);
	scrivi(argv[3]);
	return (0);
}
