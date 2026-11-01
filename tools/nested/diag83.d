#pragma D option quiet
#pragma D option dynvarsize=16m
#pragma D option bufsize=4m
#pragma D option switchrate=20hz
/*
 * diag83.d -- GENERATO da gen-diag83.py, non modificare a mano.
 * Solo lettura. self->d = profondita' nel thread; self->ts[d] = ingresso.
 */
BEGIN { printf("== TRACCIA PRONTA == diag83.d\n"); }

fbt:vmm-restore:vmx_vept_invept:entry
{
	self->d++;
	self->ts[self->d] = timestamp;
	@nb = count();
	printf("OPB tid=%d pid=%d cpu=%d t0=%d d=%d vcpup=%#lx type=%d eptp=%#lx exec=%s\n",
	    tid, pid, cpu, timestamp, self->d, (uint64_t)arg0, (int)arg1, (uint64_t)arg2, execname);
}

fbt:vmm-restore:vmx_vept_invept:entry
/ self->d > 1 /
{
	self->dirty = 1;
	@nn = count();
	printf("NEST tid=%d pid=%d cpu=%d t=%d d=%d\n", tid, pid, cpu, timestamp, self->d);
}

fbt:vmm-restore:vmx_vept_invept:entry
/ self->d == 1 /
{
	self->dirty = 0; self->nkeep = 0; self->fb = -1; self->vc = -1; self->vcbad = 0;
	self->s_inj = *(uint64_t *)&`vept_test_race_injected;
	self->s_rd = *(uint64_t *)&`vept_scan_retries_done;
	self->s_ok0 = *(uint64_t *)&`vept_scan_first_pass_ok;
	self->s_ok1 = *(uint64_t *)&`vept_scan_retry_1_success;
	self->s_ok2 = *(uint64_t *)&`vept_scan_retry_2_success;
	self->s_esaur = *(uint64_t *)&`vept_scan_retry_exhausted;
	self->s_budget = *(uint64_t *)&`vept_scan_retry_budget_fallback;
	self->s_nonrace = *(uint64_t *)&`vept_scan_retry_nonrace_fallback;
	self->s_racefb = *(uint64_t *)&`vept_keep_scan_race_fallbacks;
	self->s_a1ns = *(uint64_t *)&`vept_t_attempt1_ns;
	self->s_a2ns = *(uint64_t *)&`vept_t_attempt2_ns;
	self->s_partial = *(uint64_t *)&`vept_keep_partial_invepts;
	self->s_full = *(uint64_t *)&`vept_keep_full_fallbacks;
	self->s_mism = *(uint64_t *)&`vept_keep_verify_mismatch;
}

vmm:vmx:nested:veptkeep
/ self->d /
{
	self->vcbad = self->vcbad || (self->vc != -1 && self->vc != (int)arg0);
	self->vc = (int)arg0;
	self->nkeep++;
	self->fb = (int)(arg5 & 0xffff);
}

vmm:vmx:nested:veptkeep
/ !self->d /
{
	@nk = count();
	printf("KORPH tid=%d pid=%d cpu=%d t=%d vcpuid=%d\n", tid, pid, cpu, timestamp, (int)arg0);
}

fbt:vmm-restore:vmx_vept_invept:return
/ !self->d /
{
	@no = count();
	printf("ORPH tid=%d pid=%d cpu=%d t1=%d ret=%d exec=%s\n", tid, pid, cpu, timestamp, (int)arg1, execname);
}

fbt:vmm-restore:vmx_vept_invept:return
/ self->d == 1 /
{
	@ne = count();
	printf("OPE tid=%d pid=%d cpu=%d t0=%d t1=%d d=1 dirty=%d nkeep=%d fb=%#x vcpuid=%d vcbad=%d ret=%d inj=%d rd=%d ok0=%d ok1=%d ok2=%d esaur=%d budget=%d nonrace=%d racefb=%d a1ns=%d a2ns=%d partial=%d full=%d mism=%d exec=%s\n",
	    tid, pid, cpu, self->ts[1], timestamp, self->dirty, self->nkeep, self->fb, self->vc, self->vcbad, (int)arg1,
	    *(uint64_t *)&`vept_test_race_injected - self->s_inj,
	    *(uint64_t *)&`vept_scan_retries_done - self->s_rd,
	    *(uint64_t *)&`vept_scan_first_pass_ok - self->s_ok0,
	    *(uint64_t *)&`vept_scan_retry_1_success - self->s_ok1,
	    *(uint64_t *)&`vept_scan_retry_2_success - self->s_ok2,
	    *(uint64_t *)&`vept_scan_retry_exhausted - self->s_esaur,
	    *(uint64_t *)&`vept_scan_retry_budget_fallback - self->s_budget,
	    *(uint64_t *)&`vept_scan_retry_nonrace_fallback - self->s_nonrace,
	    *(uint64_t *)&`vept_keep_scan_race_fallbacks - self->s_racefb,
	    *(uint64_t *)&`vept_t_attempt1_ns - self->s_a1ns,
	    *(uint64_t *)&`vept_t_attempt2_ns - self->s_a2ns,
	    *(uint64_t *)&`vept_keep_partial_invepts - self->s_partial,
	    *(uint64_t *)&`vept_keep_full_fallbacks - self->s_full,
	    *(uint64_t *)&`vept_keep_verify_mismatch - self->s_mism,
	    execname);
	self->ts[1] = 0; self->d = 0; self->dirty = 0;
}

fbt:vmm-restore:vmx_vept_invept:return
/ self->d > 1 /
{
	@ne = count();
	printf("OPE tid=%d pid=%d cpu=%d t0=%d t1=%d d=%d interna=1 ret=%d exec=%s\n",
	    tid, pid, cpu, self->ts[self->d], timestamp, self->d, (int)arg1, execname);
	self->ts[self->d] = 0; self->d--;
}

END
{
	printa("CONTI begin=%@d\n", @nb); printa("CONTI end=%@d\n", @ne);
	printa("CONTI nest=%@d\n", @nn); printa("CONTI orph=%@d\n", @no);
	printa("CONTI korph=%@d\n", @nk);
	printf("== TRACCIA CHIUSA ==\n");
}
