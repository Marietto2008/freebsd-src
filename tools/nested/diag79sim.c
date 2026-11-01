/*
 * diag79sim.c -- Claude 26/10/2026, parere #80 §4.5: collaudo OFFLINE della
 * macchina a stati di diag79 (gen-diag79.py). Le funzioni sim_* sono gli
 * eventi; diag79sim.d le osserva col pid provider e applica lo STESSO nucleo di
 * diag79.d. Nessuna VM. Uso: diag79sim <scenario>
 * cc -O0 -Wall -Wextra -Werror -o diag79sim diag79sim.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NI __attribute__((noinline))
typedef unsigned long long u64;
static volatile u64 pozzo;

NI void sim_ctx(u64 eptp, int cpu) { pozzo += eptp + cpu; }
NI void sim_exit(int ok, u64 tid, unsigned rsn, u64 rip, u64 gpa, u64 qual) { pozzo += ok + tid + rsn + rip + gpa + qual; }
NI void sim_entry(int ok, u64 tid, u64 pte, int ass) { pozzo += ok + tid + pte + ass; }
NI void sim_inv(int ok, u64 tid) { pozzo += ok + tid; }
NI void sim_wipe(int ok, u64 tid) { pozzo += ok + tid; }
NI void sim_keep(int ok, u64 tid, u64 inval, int fb) { pozzo += ok + tid + inval + fb; }
NI void sim_fault_ret(int ok, u64 tid, int rc, u64 l1gpa) { pozzo += ok + tid + rc + l1gpa; }
NI void sim_install(int ok, u64 tid, u64 l2gpa, u64 hpa, int perm) { pozzo += ok + tid + l2gpa + hpa + perm; }
NI void sim_reflect(int ok, u64 tid, u64 l2gpa, u64 qual, int rc) { pozzo += ok + tid + l2gpa + qual + rc; }

#define T	100101ull
#define T2	100102ull
#define P	0x10d2000ull
#define R0	0x40fb5bull
#define R1	0x40fca1ull
#define W2	0x40fcbfull
#define H1	0xcc490b000ull
#define H2	0xc5e14b000ull
#define EPTP	0x29215e01eull
#define QR	0x781ull
#define QW	0x182ull
#define QWALK	0x081ull
#define QFETCH	0x184ull

enum { PARZ, FALLBACK, KEEP0 };
struct opz {
	int path;		/* PARZ, FALLBACK, KEEP0 */
	int no_inval_s1;	/* nessuna invalidazione prima di stage1 */
	int old_leaf;		/* foglia vecchia ancora presente dopo l'invalidazione */
	int no_invept;		/* nessun INVEPT fisico dopo l'invalidazione di stage1 */
	int late_invept;	/* INVEPT dopo l'ingresso */
	int wrong_hpa;		/* stage1 installa la pagina vecchia */
	int bad_install;	/* stage2: installazione scrivibile prima del ripristino */
	int eptp_change, cpu_change, probe_change, missing_fault, other_ctx;
	int s2_granted;		/* stage2: scrittura concessa senza riflessione */
	int s1_reflect;		/* stage1 riflessa da L0 */
	int walk_s1;		/* page walk/fetch allo stesso RIP anche a stage1 */
};

static void
invalida(const struct opz *o, int stage, int salta_inv)
{
	int ass = o->path == PARZ ? 1 : 4;

	if (o->path == PARZ)
		sim_keep(1, T, 1, 0);
	else if (o->path == FALLBACK) {
		sim_keep(1, T, 90000, 0x40);
		sim_wipe(1, T);
	} else
		sim_wipe(1, T);
	if (o->late_invept && stage == 1) {
		sim_entry(1, T, 0, ass);
		sim_inv(1, T);
		return;
	}
	if (!salta_inv)
		sim_inv(1, T);
	if (o->old_leaf && stage == 1)
		sim_entry(1, T, H1 | 0x77, 0);
	else
		sim_entry(1, T, 0, ass);
}

static void
scenario(const struct opz *o)
{
	u64 g1 = o->probe_change ? P + 0x1000 : P;

	if (o->other_ctx)
		sim_exit(0, 999, 48, R0, 0x3fed1000, QR);
	/* stage0 */
	sim_entry(1, T, 0, 4);
	sim_exit(1, T, 48, R0, P, QR);
	sim_fault_ret(1, T, 0, P - 0x1000);
	sim_install(1, T, P, H1, 7);
	sim_entry(1, T, H1 | 0x77, 0);
	sim_exit(1, T, 18, 0x40fb63, P, 0);
	if (o->other_ctx)
		sim_exit(1, T2, 48, R1, 0x5000, QR);
	/* stage1: remap + INVEPT di L1 */
	if (!o->no_inval_s1)
		invalida(o, 1, o->no_invept);
	else
		sim_entry(1, T, 0, 1);
	if (o->cpu_change)
		sim_ctx(EPTP, 7);
	if (o->walk_s1) {
		sim_exit(1, T, 48, R1, 0x10c1000, QWALK);
		sim_fault_ret(1, T, 0, 0x10c1000);
		sim_entry(1, T, 0, 1);
	}
	if (o->eptp_change)
		sim_ctx(EPTP + 0x1000, 6);
	sim_exit(1, T, 48, R1, g1, QR);
	if (o->s1_reflect) {
		sim_fault_ret(1, T, 1, 0);
		sim_reflect(1, T, g1, QR, 1);
		return;
	}
	if (!o->missing_fault)
		sim_fault_ret(1, T, 0, g1);
	sim_install(1, T, g1, o->wrong_hpa ? H1 : H2, 7);
	sim_entry(1, T, (o->wrong_hpa ? H1 : H2) | 0x77, 0);
	sim_exit(1, T, 18, 0x40fcab, g1, 0);
	/* stage2: revoca di W + INVEPT di L1 */
	invalida(o, 2, 0);
	sim_exit(1, T, 48, W2, P, QW);
	if (o->s2_granted) {
		sim_fault_ret(1, T, 0, P);
		sim_install(1, T, P, H2, 7);
		sim_entry(1, T, H2 | 0x77, 0);
		sim_exit(1, T, 18, 0x40fcc5, P, 0);
		return;
	}
	sim_fault_ret(1, T, 1, 0);
	sim_reflect(1, T, P, QW, 1);	/* qualificazione HARDWARE */
	if (o->bad_install)
		sim_install(1, T, P, H2, 7);
	/* ripristino di RWX + INVEPT di L1; L2 riparte sulla scrittura: prima
	 * page walk e fetch allo stesso RIP, come nella corsa reale */
	invalida(o, 3, 0);
	sim_exit(1, T, 48, W2, 0x10c1000, QWALK);
	sim_fault_ret(1, T, 0, 0x10c1000);
	sim_entry(1, T, 0, 1);
	sim_exit(1, T, 48, W2, 0x40f000, QFETCH);
	sim_fault_ret(1, T, 0, 0x40f000);
	sim_entry(1, T, 0, 1);
	sim_exit(1, T, 48, W2, P, QW);
	sim_fault_ret(1, T, 0, P);
	sim_install(1, T, P, H2, 7);
	sim_entry(1, T, H2 | 0x77, 0);
	sim_exit(1, T, 18, 0x40fcc5, P, 0);
}

int
main(int argc, char **argv)
{
	struct opz o;
	int s = argc > 1 ? atoi(argv[1]) : 0;

	memset(&o, 0, sizeof(o));
	switch (s) {
	case 1: break;					/* parziale corretto */
	case 2: o.path = FALLBACK; break;		/* fallback completo corretto */
	case 3: o.path = KEEP0; break;			/* vept_keep=0 */
	case 4: o.no_inval_s1 = 1; break;		/* nessuna invalidazione prima di stage1 */
	case 5: o.old_leaf = 1; break;			/* foglia vecchia rimasta */
	case 6: o.no_invept = 1; break;			/* INVEPT fisico assente */
	case 7: o.late_invept = 1; break;		/* INVEPT tardivo */
	case 8: o.wrong_hpa = 1; break;			/* HPA errata a stage1 */
	case 9: o.bad_install = 1; break;		/* installazione indebita in revoca */
	case 10: o.walk_s1 = 1; break;			/* page walk allo stesso RIP anche a stage1 */
	case 11: o.eptp_change = 1; break;		/* EPTP02 cambiato */
	case 12: o.cpu_change = 1; break;		/* CPU cambiata */
	case 13: o.probe_change = 1; break;		/* sonda cambiata */
	case 14: o.missing_fault = 1; break;		/* dato mancante */
	case 15:					/* nessuna sonda osservata */
		sim_entry(1, T, 0, 4);
		sim_exit(1, T, 48, 0x400000, 0x5000, QR);
		sim_exit(1, T, 18, 0x40fb63, 0, 0);
		return (0);
	case 16: o.other_ctx = 1; break;		/* altri contesti ignorati */
	case 17: o.s2_granted = 1; break;		/* scrittura concessa senza riflessione */
	case 18: o.s1_reflect = 1; break;		/* stage1 riflessa da L0 */
	default:
		fprintf(stderr, "scenario 1..18\n");
		return (2);
	}
	scenario(&o);
	return (0);
}
