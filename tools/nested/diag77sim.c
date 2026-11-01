/*
 * diag77sim.c -- Claude 26/10/2026, parere #76 §3: collaudo OFFLINE della
 * macchina a stati di diag77 (generata da gen-diag77.py). Le funzioni sim_*
 * sono gli "eventi"; diag77sim.d le osserva col pid provider e applica lo
 * STESSO nucleo di diag77.d. Nessuna VM. Uso: diag77sim <scenario>
 * cc -O0 -Wall -Wextra -Werror -o diag77sim diag77sim.c
 */
#include <stdio.h>
#include <stdlib.h>

#define NI __attribute__((noinline))
static volatile unsigned long long pozzo;

/* (ok, tid, ...) : ok = 1 se l'evento viene dal processo QEMU */
NI void sim_exit(int ok, unsigned long long tid, unsigned rsn, unsigned long long rip,
    unsigned long long gpa, unsigned long long qual) { pozzo += ok + tid + rsn + rip + gpa + qual; }
NI void sim_entry(int ok, unsigned long long tid, unsigned long long pte) { pozzo += ok + tid + pte; }
NI void sim_inv(int ok, unsigned long long tid) { pozzo += ok + tid; }
NI void sim_wipe(int ok, unsigned long long tid) { pozzo += ok + tid; }
NI void sim_fault_entry(int ok, unsigned long long tid, unsigned long long l2gpa) { pozzo += ok + tid + l2gpa; }
NI void sim_fault_ret(int ok, unsigned long long tid, int rc, unsigned long long l1gpa) { pozzo += ok + tid + rc + l1gpa; }
NI void sim_install(int ok, unsigned long long tid, unsigned long long l2gpa,
    unsigned long long hpa, int perm) { pozzo += ok + tid + l2gpa + hpa + perm; }
NI void sim_reflect(int ok, unsigned long long tid, unsigned long long l2gpa,
    unsigned long long qual, int rc) { pozzo += ok + tid + l2gpa + qual + rc; }

#define T	100101ull		/* thread del vCPU di QEMU */
#define T2	100102ull		/* altro thread di QEMU */
#define P	0x10d2000ull		/* sonda */
#define R0	0x40fb5bull		/* lettura stage0 */
#define R1	0x40fca1ull		/* lettura stage1 */
#define W2	0x40fcbfull		/* scrittura stage2 */
#define H1	0xfd7c97000ull		/* data_page1 */
#define H2	0xfd7c96000ull		/* data_page2 */
#define QR	0x781ull		/* lettura, perm 0 */
#define QW	0x182ull		/* scrittura, perm 0 (dall'hardware) */
#define QWL1	0x1aaull		/* scrittura, perm R-X riportati a L1 */

static void
stage0(void)
{
	sim_entry(1, T, 0);
	sim_exit(1, T, 48, R0, P, QR);
	sim_fault_entry(1, T, P);
	sim_fault_ret(1, T, 0, P - 0x1000);
	sim_install(1, T, P, H1, 7);
	sim_entry(1, T, H1 | 0x77);
	sim_exit(1, T, 18, 0x40fb63, P, 0);
}

/* stage1: gpa letta, rc e l1gpa del walk, hpa installata (0 = nessuna), riflessa, PTE vista */
static void
stage1(int wipe, unsigned long long gpa, int rc, unsigned long long l1, unsigned long long hpa,
    int refl, unsigned long long pte)
{
	if (wipe) {
		sim_wipe(1, T);
		sim_inv(1, T);
	}
	sim_entry(1, T, 0);
	sim_exit(1, T, 48, R1, gpa, QR);
	sim_fault_entry(1, T, gpa);
	sim_fault_ret(1, T, rc, l1);
	if (refl)
		sim_reflect(1, T, gpa, QR, 1);
	if (hpa)
		sim_install(1, T, gpa, hpa, 7);
	sim_entry(1, T, pte);
	sim_exit(1, T, 18, 0x40fcab, gpa, 0);
}

/* stage2: riflessa (come deve) oppure scrittura concessa da L0 */
static void
stage2(int refl)
{
	sim_wipe(1, T);
	sim_inv(1, T);
	sim_entry(1, T, 0);
	sim_exit(1, T, 48, W2, P, QW);
	sim_fault_entry(1, T, P);
	if (refl) {
		sim_fault_ret(1, T, 1, 0);
		sim_reflect(1, T, P, QWL1, 1);
		sim_wipe(1, T);		/* L1 ripristina RWX + INVEPT */
		sim_inv(1, T);
		sim_entry(1, T, 0);
		sim_exit(1, T, 48, W2, P, QW);
		sim_fault_entry(1, T, P);
	}
	sim_fault_ret(1, T, 0, P);
	sim_install(1, T, P, H2, 7);
	sim_entry(1, T, H2 | 0x77);
	sim_exit(1, T, 18, 0x40fcc5, P, 0);
}

int
main(int argc, char **argv)
{
	int s = argc > 1 ? atoi(argv[1]) : 0;

	switch (s) {
	case 1:		/* corsa corretta */
		stage0(); stage1(1, P, 0, P, H2, 0, H2 | 0x77); stage2(1); break;
	case 2:		/* nessuna violation ai RIP attesi */
		sim_entry(1, T, 0); sim_exit(1, T, 48, 0x400000, 0x5000, QR);
		sim_exit(1, T, 18, 0x40fb63, 0, 0); break;
	case 3:		/* due contesti: un altro processo e un altro thread QEMU */
		sim_exit(0, 999, 48, R0, 0x3fed1000, QR);
		stage0();
		sim_exit(1, T2, 48, R1, 0x5000, QR);
		stage1(1, P, 0, P, H2, 0, H2 | 0x77); stage2(1); break;
	case 4:		/* sonda cambiata nello stesso contesto */
		stage0(); stage1(1, P + 0x1000, 0, P + 0x1000, H2, 0, H2 | 0x77); stage2(1); break;
	case 5:		/* installazione di stage1 non osservata */
		stage0(); stage1(1, P, 0, P, 0, 0, 0); stage2(1); break;
	case 6:		/* stage1 riflessa (L0 nega una GPA che EPT12 mappa) */
		stage0(); stage1(1, P, 1, 0, 0, 1, 0); break;
	case 7:		/* foglia nuova = foglia vecchia */
		stage0(); stage1(1, P, 0, P, H1, 0, H1 | 0x77); stage2(1); break;
	case 8:		/* la PTE letta non e' la foglia installata */
		stage0(); stage1(1, P, 0, P, H2, 0, 0x123000 | 0x77); stage2(1); break;
	case 9:		/* scrittura di stage2 concessa senza riflessione */
		stage0(); stage1(1, P, 0, P, H2, 0, H2 | 0x77); stage2(0); break;
	case 10:	/* nessun wipe prima di stage1 */
		stage0(); stage1(0, P, 0, P, H2, 0, H2 | 0x77); stage2(1); break;
	default:
		fprintf(stderr, "scenario 1..10\n");
		return (2);
	}
	return (0);
}
