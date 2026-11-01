/*
 * e12_oracle_test.c -- Claude 26/10/2026, parere #75 §5.6: regressione
 * negativa OFFLINE dell'oracolo di ept12_remap_sentinel (nessuna VM).
 * cc -std=c11 -Wall -Wextra -Werror -I<kut>/x86 -o e12_oracle_test e12_oracle_test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include "e12_oracle.h"

#define M1	0x12345678u	/* MAGIC_VAL_1, pagina vecchia */
#define M2	0x87654321u	/* MAGIC_VAL_2, pagina nuova */
#define RIP0	0x40fb63ull	/* VMCALL di stage0 (valori indicativi) */
#define VMC1	0x40fc90ull	/* VMCALL di stage1 */

static int nfail;

static void
caso(const char *nome, enum e12_verdict atteso, int skip, unsigned long long r1,
    unsigned int mark, unsigned int seen)
{
	enum e12_verdict v = e12_sentinel_verdict(skip, RIP0, r1, VMC1, mark,
	    seen, M1, M2);

	printf("%-58s -> %s %s\n", nome, e12_verdict_str(v),
	    v == atteso ? "(ok)" : "(ERRATO)");
	if (v != atteso)
		nfail++;
}

int
main(void)
{
	/* il caso giusto */
	caso("corsa corretta", E12_PASS, 1, VMC1, E12_S1_MARK, M2);
	/* il vecchio difetto: niente skip, L2 rifa' il VMCALL di stage0 */
	caso("DIFETTO VECCHIO: skip assente, guardie intatte", E12_F_NOSKIP,
	    0, RIP0, E12_GUARD, E12_GUARD);
	caso("DIFETTO VECCHIO senza guardia (seen = MAGIC_1 di stage0)",
	    E12_F_NOSKIP, 0, RIP0, E12_GUARD, M1);
	caso("skip dichiarato ma VMCALL ripetuto", E12_F_RIP_SAME, 1, RIP0,
	    E12_GUARD, E12_GUARD);
	caso("VMCALL di stage1 a un indirizzo sbagliato", E12_F_RIP_WRONG, 1,
	    VMC1 + 3, E12_S1_MARK, M2);
	caso("marcatore di L2 assente", E12_F_NOMARK, 1, VMC1, E12_GUARD, M2);
	caso("marcatore presente, valore = guardia", E12_F_NOREAD, 1, VMC1,
	    E12_S1_MARK, E12_GUARD);
	caso("stantio", E12_F_STALE, 1, VMC1, E12_S1_MARK, M1);
	caso("valore inatteso", E12_F_VALUE, 1, VMC1, E12_S1_MARK, 0);

	/* esaustivo su un dominio piccolo: PASS se e solo se tutto osservato */
	{
		unsigned long long rips[] = { RIP0, VMC1, VMC1 + 3, 0 };
		unsigned int marks[] = { E12_S1_MARK, E12_GUARD, 0, M2 };
		unsigned int seens[] = { M2, M1, E12_GUARD, 0, E12_S1_MARK };
		int n = 0, npass = 0;

		for (int s = 0; s < 2; s++)
		for (unsigned i = 0; i < sizeof(rips) / sizeof(rips[0]); i++)
		for (unsigned j = 0; j < sizeof(marks) / sizeof(marks[0]); j++)
		for (unsigned k = 0; k < sizeof(seens) / sizeof(seens[0]); k++) {
			enum e12_verdict v = e12_sentinel_verdict(s, RIP0,
			    rips[i], VMC1, marks[j], seens[k], M1, M2);
			int tutto = s && rips[i] == VMC1 &&
			    marks[j] == E12_S1_MARK && seens[k] == M2;

			n++;
			if (v == E12_PASS)
				npass++;
			if ((v == E12_PASS) != tutto) {
				printf("ESAUSTIVO ERRATO: s=%d rip=%#llx mark=%#x seen=%#x\n",
				    s, rips[i], marks[j], seens[k]);
				nfail++;
			}
		}
		printf("esaustivo: %d combinazioni, %d PASS (atteso 1)\n", n, npass);
		if (npass != 1)
			nfail++;
	}
	/* parere #76: stage 2 (violation di scrittura con EPT12 R-X) */
	{
		const unsigned long long P = 0x10d2000, W = 0x40fcb0;
		struct { const char *n; unsigned long long gpa, rip, qual; int att; } c[] = {
			{ "s2: violation conforme (W, perm R-X)", P, W, 0x2a | 0x180, 1 },
			{ "s2: GPA di un'altra pagina", P + 0x1000, W, 0x2a, 0 },
			{ "s2: RIP non della scrittura", P, W + 2, 0x2a, 0 },
			{ "s2: lettura invece di scrittura", P, W, 0x29, 0 },
			{ "s2: perm riportati RWX (W non revocato)", P, W, 0x3a, 0 },
			{ "s2: perm riportati 0 (non-present)", P, W, 0x02, 0 },
		};
		for (unsigned i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
			int r = e12_s2_fault_check(c[i].gpa, P, c[i].rip, W, c[i].qual);
			printf("%-58s -> %d %s\n", c[i].n, r, r == c[i].att ? "(ok)" : "(ERRATO)");
			if (r != c[i].att)
				nfail++;
		}
	}
	/* stage 3: esaustivo, PASS se e solo se tutto osservato */
	{
		const unsigned long long V3 = 0x40fcb6;
		unsigned long long rips[] = { V3, V3 + 3, RIP0, 0 };
		unsigned int vals[] = { 0xffffffffu, M2, M1, 0 };
		int n = 0, npass = 0;

		for (int s = 0; s < 2; s++)
		for (unsigned i = 0; i < 4; i++)
		for (unsigned j = 0; j < 4; j++) {
			enum e12_s3_verdict v = e12_s3_verdict(s, rips[i], V3,
			    vals[j], 0xffffffffu);
			int tutto = s && rips[i] == V3 && vals[j] == 0xffffffffu;

			n++;
			if (v == E12_S3_PASS)
				npass++;
			if ((v == E12_S3_PASS) != tutto)
				nfail++;
		}
		printf("stage3 esaustivo: %d combinazioni, %d PASS (atteso 1); "
		    "scrittura riuscita senza violation -> %s\n", n, npass,
		    e12_s3_str(e12_s3_verdict(0, V3, V3, 0xffffffffu, 0xffffffffu)));
		if (npass != 1)
			nfail++;
	}
	printf("%s\n", nfail ? "ORACOLO ERRATO" : "ORACOLO OK");
	return (nfail ? EXIT_FAILURE : EXIT_SUCCESS);
}
