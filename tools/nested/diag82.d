#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * diag82.d -- Claude 26/10/2026 notte, parere #82 §2.1: correlazione PER
 * OPERAZIONE dei tentativi di scansione B1 (vept_keep=1) durante b1_race.
 * vept_keep_invept e vept_test_race_inject sono inlinate nel modulo installato
 * (nessun simbolo): l'operazione si delimita con fbt su vmx_vept_invept (una
 * chiamata = un INVEPT di L1), e i tentativi si contano leggendo i contatori
 * del modulo (static u_long, senza CTF: letti per indirizzo) all'ingresso e
 * all'uscita. Il delta di vept_t_attempt2_ns > 0 prova che il TERZO tentativo
 * e' stato eseguito. veptkeep (SDT) da' i motivi finali per radice.
 * Valido solo con UNA VM in esecuzione (i contatori sono globali): il runner
 * lo verifica. Solo lettura.
 */
uint64_t nop;

BEGIN { printf("== TRACCIA PRONTA ==\n"); }

fbt:vmm-restore:vmx_vept_invept:entry
/ execname == "qemu-system-x86_64" /
{
	self->in = 1; self->t0 = timestamp; self->nkeep = 0; self->fb = -1;
	self->inj = *(uint64_t *)&`vept_test_race_injected;
	self->rd  = *(uint64_t *)&`vept_scan_retries_done;
	self->ok0 = *(uint64_t *)&`vept_scan_first_pass_ok;
	self->ok1 = *(uint64_t *)&`vept_scan_retry_1_success;
	self->ok2 = *(uint64_t *)&`vept_scan_retry_2_success;
	self->ex  = *(uint64_t *)&`vept_scan_retry_exhausted;
	self->bud = *(uint64_t *)&`vept_scan_retry_budget_fallback;
	self->nr  = *(uint64_t *)&`vept_scan_retry_nonrace_fallback;
	self->rfb = *(uint64_t *)&`vept_keep_scan_race_fallbacks;
	self->a1  = *(uint64_t *)&`vept_t_attempt1_ns;
	self->a2  = *(uint64_t *)&`vept_t_attempt2_ns;
	self->pa  = *(uint64_t *)&`vept_keep_partial_invepts;
	self->fu  = *(uint64_t *)&`vept_keep_full_fallbacks;
}

vmm:vmx:nested:veptkeep
/ self->in /
{
	self->nkeep++;
	self->fb = (int)(arg5 & 0xffff);
}

fbt:vmm-restore:vmx_vept_invept:return
/ self->in /
{
	nop++;
	printf("OP %d inj=%d tent=%d ok0=%d ok1=%d ok2=%d esaur=%d budget=%d nonrace=%d racefb=%d a1ns=%d a2ns=%d partial=%d full=%d fb=%#x nkeep=%d svuotate=%d ns=%d\n",
	    nop,
	    *(uint64_t *)&`vept_test_race_injected - self->inj,
	    1 + (*(uint64_t *)&`vept_scan_retries_done - self->rd),
	    *(uint64_t *)&`vept_scan_first_pass_ok - self->ok0,
	    *(uint64_t *)&`vept_scan_retry_1_success - self->ok1,
	    *(uint64_t *)&`vept_scan_retry_2_success - self->ok2,
	    *(uint64_t *)&`vept_scan_retry_exhausted - self->ex,
	    *(uint64_t *)&`vept_scan_retry_budget_fallback - self->bud,
	    *(uint64_t *)&`vept_scan_retry_nonrace_fallback - self->nr,
	    *(uint64_t *)&`vept_keep_scan_race_fallbacks - self->rfb,
	    *(uint64_t *)&`vept_t_attempt1_ns - self->a1,
	    *(uint64_t *)&`vept_t_attempt2_ns - self->a2,
	    *(uint64_t *)&`vept_keep_partial_invepts - self->pa,
	    *(uint64_t *)&`vept_keep_full_fallbacks - self->fu,
	    self->fb, self->nkeep, (int)arg1, timestamp - self->t0);
	self->in = 0;
}

END { printf("== TRACCIA CHIUSA == operazioni=%d\n", nop); }
