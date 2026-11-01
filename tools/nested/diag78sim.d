#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * diag78sim.d -- GENERATO da gen-diag78.py, non modificare a mano.
 * Parere #76 §3: sonda UNKNOWN finche' non e' osservata una EPT violation a un
 * RIP di lettura atteso; contesto legato (processo QEMU, thread, vCPU, EPTP02);
 * cambio di sonda nello stesso contesto = ALLARME e audit INCONCLUSIVO; eventi
 * di altri contesti ignorati e contati; verdetti espliciti a END.
 * Le variabili globali sono legate al contesto da ctx_tid: il percorso di un
 * vCPU (vm_run -> vmx_run -> slow path vmx_nested_exit) gira tutto nel thread
 * del vCPU di QEMU, anche se migra di CPU; self-> porta la fase dalla uscita al
 * suo slow path nello stesso thread.
 */
inline uint64_t AM = 0x000ffffffffff000;
uint64_t sonda; uint64_t ctx_tid; uint64_t ctx_vcpu; uint64_t ctx_eptp;
int changed; int other_ctx; int fuori_fase; int wipes; int wipes_at_s1;
uint64_t s0_hpa; int s1_seen; int s1_done; int s1_rc; uint64_t s1_l1gpa;
uint64_t s1_hpa; int s1_reflect; int s1_leaf_checked; int s1_leaf_ok;
int s2_seen; int s2_reflect; uint64_t s2_rqual; int s2_inst_perm;

BEGIN
{
	printf("== TRACCIA PRONTA == sonda=UNKNOWN rip_lettura1=%#lx rip_lettura0=%#lx rip_scrittura2=%#lx\n",
	    (uint64_t)$1, (uint64_t)$2, (uint64_t)$3);
	s1_rc = -1; s2_inst_perm = -1;
}

pid$target::sim_exit:entry
{
	this->ok = (int)arg0; this->tid = arg1; this->vcpu = 0; this->seq = 0;
	this->rsn = (uint32_t)arg2; this->rip = arg3; this->gpa = arg4; this->qual = arg5;
	this->eptp = 0x29215e01e;
	this->fase = -1; this->mio = 0; this->pg = (uint64_t)0;
}
pid$target::sim_entry:entry
{
	this->ok = (int)arg0; this->tid = arg1; this->vcpu = 0; this->seq = 0;
	this->rip = 0; this->eptp = 0x29215e01e;
	this->l4 = sonda == 0 ? 0 : 7; this->l3 = this->l4; this->l2 = this->l4;
	this->l1 = sonda == 0 ? 0 : arg2;
}
pid$target::sim_inv:entry { this->ok = (int)arg0; this->tid = arg1; this->seq = 0; this->eptp = 0x29215e01e; }
pid$target::sim_wipe:entry { this->ok = (int)arg0; this->tid = arg1; this->slot = 0; }
pid$target::sim_fault_entry:entry { this->ok = (int)arg0; this->tid = arg1; this->l2gpa = arg2; }
pid$target::sim_fault_ret:entry { this->ok = (int)arg0; this->tid = arg1; this->rc = (int)arg2; this->l1gpa = arg3; }
pid$target::sim_install:entry { this->ok = (int)arg0; this->tid = arg1; this->l2gpa = arg2; this->hpa = arg3; this->perm = (int)arg4; }
pid$target::sim_reflect:entry { this->ok = (int)arg0; this->tid = arg1; this->l2gpa = arg2; this->qual = arg3; this->rc = (int)arg4; }

/* uscite: violation a un RIP di lettura/scrittura atteso -> lega o controlla */
pid$target::sim_exit:entry
/ this->rsn == 48 && ((uint64_t)$2 != 0 && this->rip == (uint64_t)$2 ||
    (uint64_t)$1 != 0 && this->rip == (uint64_t)$1 ||
    (uint64_t)$3 != 0 && this->rip == (uint64_t)$3) /
{
	this->pg = this->gpa & ~0xfffUL;
	this->fase = this->rip == (uint64_t)$2 ? 0 : this->rip == (uint64_t)$1 ? 1 : 2;
	this->mio = this->ok && (ctx_tid == 0 || this->tid == ctx_tid);
	/* solo l'accesso DATI dell'istruzione: bit 8 (traduzione di un lineare)
	 * e nessun fetch (bit 2). Fetch e page walk allo stesso RIP no. */
	this->dati = (this->qual & 0x100) != 0 && (this->qual & 0x4) == 0;
	this->fase = this->dati ? this->fase : -1;
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && this->mio && ctx_tid == 0 && this->pg != 0 /
{
	ctx_tid = this->tid; ctx_vcpu = this->vcpu; ctx_eptp = this->eptp; sonda = this->pg;
	printf("SONDA RICAVATA %#lx (fase %d, rip %#lx) contesto tid=%d vcpu=%d eptp=%#lx\n",
	    sonda, this->fase, this->rip, this->tid, this->vcpu, this->eptp);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg != sonda && changed == 0 /
{
	changed = 1;
	printf("ALLARME SONDA CAMBIATA nello stesso contesto: %#lx -> %#lx (rip %#lx): audit INCONCLUSIVO\n",
	    sonda, this->pg, this->rip);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && !this->mio /
{
	other_ctx++;
	printf("ALTRO CONTESTO ignorato: ok=%d tid=%d gpa=%#lx rip=%#lx\n", this->ok, this->tid, this->gpa, this->rip);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg == sonda /
{
	self->fase = this->fase + 1;	/* 1,2,3 = fase 0,1,2 in corso; 0 = nessuna */
	s1_seen = this->fase == 1 ? 1 : s1_seen;
	wipes_at_s1 = this->fase == 1 ? wipes : wipes_at_s1;
	s2_seen = this->fase == 2 ? 1 : s2_seen;
	printf("[%u] EXIT fase%d reason=48 gpa=%#lx qual=%#lx rip=%#lx eptp=%#lx\n",
	    this->seq, this->fase, this->gpa, this->qual, this->rip, this->eptp);
}
pid$target::sim_exit:entry
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) && this->rsn == 18 /
{
	printf("[%u] EXIT reason=18 rip=%#lx eptp=%#lx\n", this->seq, this->rip, this->eptp);
}

/* ingresso: fine della fase; walk della sonda (quando nota) */
pid$target::sim_entry:entry
/ this->ok && this->tid == ctx_tid && sonda != 0 /
{
	this->ass = !(this->l4 & 7) ? "PML4E" : !(this->l3 & 7) ? "PDPTE" :
	    (this->l3 & 0x80) ? "nessuno(PDPTE PS)" : !(this->l2 & 7) ? "PDE" :
	    (this->l2 & 0x80) ? "nessuno(PDE PS)" : !(this->l1 & 7) ? "PTE" : "nessuno";
	printf("[%u] ENTRY rip=%#lx eptp=%#lx radice=%#lx sonda=%#lx PTE=%#lx primo_assente=%s\n",
	    this->seq, this->rip, this->eptp, this->eptp & AM, sonda, this->l1, this->ass);
}
pid$target::sim_entry:entry
/ this->ok && this->tid == ctx_tid && sonda != 0 && s1_hpa != 0 && s1_leaf_checked == 0 /
{
	s1_leaf_checked = 1;
	s1_leaf_ok = (this->l1 & 7) != 0 && (this->l1 & AM) == (s1_hpa & AM);
	printf("FOGLIA DOPO STAGE1: PTE=%#lx atteso hpa=%#lx -> %s\n", this->l1, s1_hpa,
	    s1_leaf_ok ? "coincide" : "NON coincide");
}
pid$target::sim_entry:entry
/ this->ok && this->tid == ctx_tid /
{
	self->fase = 0;
}

pid$target::sim_inv:entry
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) /
{
	printf("[%u] INVEPT-fisico eptp=%#lx radice=%#lx\n", this->seq, this->eptp, this->eptp & AM);
}
pid$target::sim_wipe:entry
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) /
{
	wipes++;
	printf("-- WIPE slot=%d (n.%d)\n", this->slot, wipes);
}

/* slow path della violation della sonda: esito di vmx_vept_fault */
pid$target::sim_fault_ret:entry
/ this->ok && this->tid == ctx_tid && self->fase == 2 /
{
	s1_done = 1; s1_rc = this->rc; s1_l1gpa = this->l1gpa;
	printf("FAULT fase1 rc=%d l1gpa=%#lx\n", this->rc, this->l1gpa);
}
pid$target::sim_fault_ret:entry
/ this->ok && this->tid == ctx_tid && (self->fase == 1 || self->fase == 3) /
{
	printf("FAULT fase%d rc=%d l1gpa=%#lx\n", self->fase - 1, this->rc, this->l1gpa);
}

pid$target::sim_install:entry
/ this->ok && this->tid == ctx_tid && sonda != 0 && (this->l2gpa & ~0xfffUL) == sonda /
{
	printf("INSTALL-SONDA fase%d l2gpa=%#lx hpa=%#lx perm=%#x\n", (int)self->fase - 1,
	    this->l2gpa, this->hpa, this->perm);
	s0_hpa = self->fase == 1 ? this->hpa : s0_hpa;
	s1_hpa = self->fase == 2 ? this->hpa : s1_hpa;
	s2_inst_perm = self->fase == 3 ? this->perm : s2_inst_perm;
	fuori_fase += self->fase == 0 ? 1 : 0;
}

pid$target::sim_reflect:entry
/ this->ok && this->tid == ctx_tid /
{
	printf("REFLECT fase%d l2gpa=%#lx qual=%#lx esito=%d\n", (int)self->fase - 1,
	    this->l2gpa, this->qual, this->rc);
	s1_reflect = self->fase == 2 ? 1 : s1_reflect;
	s2_reflect = self->fase == 3 ? 1 : s2_reflect;
	s2_rqual = self->fase == 3 ? this->qual : s2_rqual;
}

END
{
	printf("== RIEPILOGO == contesto=%s sonda=%#lx altri_contesti=%d wipe=%d (prima di stage1: %d)\n",
	    ctx_tid == 0 ? "NON LEGATO" : "legato", sonda, other_ctx, wipes, wipes_at_s1);
	printf("   stage0 hpa=%#lx | stage1: violation=%d slowpath=%d rc=%d l1gpa=%#lx hpa=%#lx riflessa=%d foglia=%s | install fuori fase=%d\n",
	    s0_hpa, s1_seen, s1_done, s1_rc, s1_l1gpa, s1_hpa, s1_reflect,
	    s1_leaf_checked ? (s1_leaf_ok ? "coincide" : "NON coincide") : "non letta", fuori_fase);
	this->leaf =
	    changed ? "L0_LEAF_INCONCLUSIVE" :
	    ctx_tid == 0 || !s1_seen ? "L0_LEAF_NOT_OBSERVED" :
	    /* una prova POSITIVA di errore vince sulla mancata osservazione */
	    s1_reflect || (s1_done && (s1_rc != 0 || s1_l1gpa != sonda)) ? "L0_LEAF_FAIL" :
	    !s1_done || s1_hpa == 0 || !s1_leaf_checked ? "L0_LEAF_NOT_OBSERVED" :
	    s1_hpa == s0_hpa || !s1_leaf_ok || wipes_at_s1 == 0 || fuori_fase != 0 ?
	    "L0_LEAF_FAIL" : "L0_LEAF_PASS";
	printf("%s\n", this->leaf);
	this->s2 =
	    (uint64_t)$3 == 0 ? "L0_S2_NA" :
	    changed ? "L0_S2_INCONCLUSIVE" :
	    !s2_seen ? "L0_S2_NOT_OBSERVED" :
	    /* veptrefl: qualificazione HARDWARE (bit 5:3 = 0); i permessi R-X
	     * riportati a L1 li controlla l'oracolo di L1 (e12_s2_fault_check) */
	    s2_reflect && (s2_rqual & 2) && s2_inst_perm == 7 ?
	    "L0_S2_PASS" : "L0_S2_FAIL";
	printf("   stage2: violation=%d riflessa=%d qual=%#lx perm dopo ripristino=%d\n",
	    s2_seen, s2_reflect, s2_rqual, s2_inst_perm);
	printf("%s\n== TRACCIA CHIUSA ==\n", this->s2);
}
