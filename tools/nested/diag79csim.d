#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * diag79csim.d -- GENERATO da gen-diag79c.py, non modificare a mano.
 * Variabili globali legate al contesto da ctx_tid (thread del vCPU di QEMU: il
 * percorso vm_run -> vmx_run -> slow path gira tutto in quel thread); self->
 * porta la fase dall'uscita al suo slow path nello stesso thread.
 */
inline uint64_t AM = 0x000ffffffffff000;
uint64_t sonda; uint64_t ctx_tid; uint64_t ctx_eptp; int ctx_cpu;
int changed; int eptp_changed; int eptp_bad_exit; int eptp_bad_entry; int eptp_bad_inv; int cpu_changed; int other_ctx; int fuori_fase;
int inv_pending; int order_bad; int inv_total; int inv_kind; int inv_first_entry;
uint64_t inv_pte_after; int inv_ass_after; int inv_since_s0; int inv_since_s1;
int s1_inv_kind; int s1_inv_ass; int s1_inv_n; uint64_t s1_inv_pte;
int s2_inv_kind; int s2_inv_ass; int s2_inv_n; uint64_t s2_inv_pte;
uint64_t s0_hpa; int s1_seen; int s1_done; int s1_rc; uint64_t s1_l1gpa;
uint64_t s1_hpa; int s1_reflect; int s1_leaf_checked; int s1_leaf_ok;
int s2_seen; int s2_reflect; uint64_t s2_rqual; int s2_inst_perm; int s2_bad_install;
int s2_restore_seen;

BEGIN
{
	printf("== TRACCIA PRONTA == sonda=UNKNOWN rip_lettura1=%#lx rip_lettura0=%#lx rip_scrittura2=%#lx modalita=%d\n",
	    (uint64_t)$1, (uint64_t)$2, (uint64_t)$3, (int)$4);
	s1_rc = -1; s2_inst_perm = -1; ctx_cpu = -1;
}

uint64_t sim_eptp; int sim_cpu; int sim_l2;
BEGIN { sim_eptp = 0x29215e01e; sim_cpu = 6; sim_l2 = 1; }
pid$target::sim_mode:entry { sim_l2 = (int)arg0; }
pid$target::sim_ctx:entry { sim_eptp = arg0; sim_cpu = (int)arg1; }
pid$target::sim_exit:entry
{
	this->ok = (int)arg0; this->tid = arg1; this->cpu = sim_cpu; this->seq = 0;
	this->rsn = (uint32_t)arg2; this->rip = arg3; this->gpa = arg4; this->qual = arg5;
	this->eptp = sim_eptp; this->l2 = sim_l2;
	this->fase = -1; this->mio = 0; this->pg = (uint64_t)0;
}
pid$target::sim_entry:entry
{
	/* sim_entry(ok, tid, pte, primo_assente 0..4) */
	this->ok = (int)arg0; this->tid = arg1; this->cpu = sim_cpu; this->seq = 0;
	this->rip = 0; this->eptp = sim_eptp;
	this->l4 = sonda == 0 || arg3 >= 4 ? 0 : 7;
	this->l3 = sonda == 0 || arg3 >= 3 ? 0 : 7;
	this->l2 = sonda == 0 || arg3 >= 2 ? 0 : 7;
	this->l1 = sonda == 0 || arg3 >= 1 ? 0 : arg2;
}
pid$target::sim_inv:entry { this->ok = (int)arg0; this->tid = arg1; this->cpu = sim_cpu; this->seq = 0; this->eptp = sim_eptp; }
pid$target::sim_wipe:entry { this->ok = (int)arg0; this->tid = arg1; this->cpu = sim_cpu; this->slot = 0; }
pid$target::sim_keep:entry { this->ok = (int)arg0; this->tid = arg1; this->cpu = sim_cpu; this->inval = arg2; this->fb = (int)arg3; this->eptp12 = 0x10cb01e; }
pid$target::sim_fault_ret:entry { this->ok = (int)arg0; this->tid = arg1; this->rc = (int)arg2; this->l1gpa = arg3; }
pid$target::sim_install:entry { this->ok = (int)arg0; this->tid = arg1; this->l2gpa = arg2; this->hpa = arg3; this->perm = (int)arg4; }
pid$target::sim_reflect:entry { this->ok = (int)arg0; this->tid = arg1; this->l2gpa = arg2; this->qual = arg3; this->rc = (int)arg4; }

/* ---------- uscite ---------- */
pid$target::sim_exit:entry
/ this->rsn == 48 && ((uint64_t)$2 != 0 && this->rip == (uint64_t)$2 ||
    (uint64_t)$1 != 0 && this->rip == (uint64_t)$1 ||
    (uint64_t)$3 != 0 && this->rip == (uint64_t)$3) /
{
	this->pg = this->gpa & ~0xfffUL;
	this->fase = this->rip == (uint64_t)$2 ? 0 : this->rip == (uint64_t)$1 ? 1 : 2;
	this->mio = this->ok && (ctx_tid == 0 || this->tid == ctx_tid);
	/* accesso DATI della fase: bit 7 e 8 (traduzione di un lineare), niente
	 * fetch (bit 2), lettura (bit 0) per le fasi 0-1, scrittura (bit 1) per la 2 */
	this->dati = (this->qual & 0x180) == 0x180 && (this->qual & 0x4) == 0 &&
	    (this->fase == 2 ? (this->qual & 0x2) != 0 : (this->qual & 0x1) != 0);
	this->fase = this->dati ? this->fase : -1;
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase == 0 && this->mio && ctx_tid == 0 && this->pg != 0 && this->l2 == 1 /
{
	/* la sonda si lega SOLO alla lettura di stage0: mai riappresa in 1-2 */
	ctx_tid = this->tid; ctx_eptp = this->eptp; ctx_cpu = this->cpu; sonda = this->pg;
	printf("SONDA RICAVATA %#lx (rip %#lx) contesto tid=%d cpu=%d eptp=%#lx\n",
	    sonda, this->rip, this->tid, this->cpu, this->eptp);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg != sonda && changed == 0 /
{
	changed = 1;
	printf("ALLARME SONDA CAMBIATA: %#lx -> %#lx (fase %d, rip %#lx)\n", sonda, this->pg, this->fase, this->rip);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && !this->mio /
{
	other_ctx++;
	printf("ALTRO CONTESTO ignorato: ok=%d tid=%d gpa=%#lx rip=%#lx\n", this->ok, this->tid, this->gpa, this->rip);
}
pid$target::sim_exit:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->l2 == 1 && this->eptp != ctx_eptp && eptp_bad_exit == 0 /
{
	eptp_changed = 1; eptp_bad_exit = 1;
	printf("ALLARME EPTP02 CAMBIATO (uscita da L2): %#lx -> %#lx\n", ctx_eptp, this->eptp);
}
pid$target::sim_exit:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->cpu != ctx_cpu && cpu_changed == 0 /
{
	cpu_changed = 1;
	printf("CPU CAMBIATA: %d -> %d (ordine degli eventi non garantito)\n", ctx_cpu, this->cpu);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg == sonda /
{
	self->fase = this->fase + 1;
	printf("[%u] EXIT fase%d reason=48 gpa=%#lx qual=%#lx rip=%#lx\n", this->seq, this->fase,
	    this->gpa, this->qual, this->rip);
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase == 1 && this->mio && this->tid == ctx_tid && this->pg == sonda && s1_seen == 0 /
{
	s1_seen = 1; s1_inv_kind = inv_kind; s1_inv_ass = inv_ass_after;
	s1_inv_pte = inv_pte_after; s1_inv_n = inv_since_s0;
}
pid$target::sim_exit:entry
/ this->rsn == 48 && this->fase == 2 && this->mio && this->tid == ctx_tid && this->pg == sonda && s2_seen == 0 /
{
	s2_seen = 1; s2_inv_kind = inv_kind; s2_inv_ass = inv_ass_after;
	s2_inv_pte = inv_pte_after; s2_inv_n = inv_since_s1;
}
pid$target::sim_exit:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->rsn == 18 && this->l2 == 1 /
{
	printf("[%u] EXIT reason=18 rip=%#lx\n", this->seq, this->rip);
}

/* ---------- invalidazioni (solo nel contesto legato) ---------- */
pid$target::sim_keep:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->fb == 0 /
{
	inv_kind = 1; inv_pending = 1; inv_first_entry = 1; inv_total++;
	inv_since_s0 += s0_hpa != 0 ? 1 : 0; inv_since_s1 += s1_hpa != 0 ? 1 : 0;
	s2_restore_seen = s2_reflect ? 1 : s2_restore_seen;
	printf("-- INVALIDAZIONE PARZIALE (veptkeep, radice conservata, foglie %d)\n", (int)this->inval);
}
pid$target::sim_keep:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->fb != 0 /
{
	inv_kind = 3;	/* fallback: deve seguire vept_root_wipe */
	printf("-- veptkeep: fallback motivi %#x (atteso svuotamento)\n", this->fb);
}
pid$target::sim_wipe:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid /
{
	/* il veptkeep di fallback non conta: lo svuotamento conta sempre, una volta */
	inv_total++;
	inv_since_s0 += s0_hpa != 0 ? 1 : 0;
	inv_since_s1 += s1_hpa != 0 ? 1 : 0;
	inv_kind = 2; inv_pending = 1; inv_first_entry = 1;
	s2_restore_seen = s2_reflect ? 1 : s2_restore_seen;
	printf("-- SVUOTAMENTO COMPLETO (vept_root_wipe slot %d)\n", this->slot);
}

/* ---------- INVEPT fisico ---------- */
pid$target::sim_inv:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->eptp == ctx_eptp /
{
	inv_pending = 0;
	printf("[%u] INVEPT-fisico eptp=%#lx cpu=%d\n", this->seq, this->eptp, this->cpu);
}
pid$target::sim_inv:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->eptp != ctx_eptp && eptp_bad_inv == 0 /
{
	eptp_changed = 1; eptp_bad_inv = 1;
	printf("ALLARME INVEPT su EPTP diverso: %#lx (contesto %#lx)\n", this->eptp, ctx_eptp);
}
pid$target::sim_inv:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->cpu != ctx_cpu && cpu_changed == 0 /
{
	cpu_changed = 1;
	printf("CPU CAMBIATA (INVEPT): %d -> %d\n", ctx_cpu, this->cpu);
}

/* ---------- ingressi in L2 ---------- */
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid /
{
	this->ass = !(this->l4 & 7) ? 4 : !(this->l3 & 7) ? 3 : (this->l3 & 0x80) ? 0 :
	    !(this->l2 & 7) ? 2 : (this->l2 & 0x80) ? 0 : !(this->l1 & 7) ? 1 : 0;
	this->pte = this->ass == 0 ? this->l1 : (uint64_t)0;
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->eptp != ctx_eptp && eptp_bad_entry == 0 /
{
	eptp_changed = 1; eptp_bad_entry = 1;
	printf("ALLARME EPTP02 CAMBIATO all'ingresso: %#lx -> %#lx\n", ctx_eptp, this->eptp);
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && this->cpu != ctx_cpu && cpu_changed == 0 /
{
	cpu_changed = 1;
	printf("CPU CAMBIATA (ingresso): %d -> %d\n", ctx_cpu, this->cpu);
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && inv_pending /
{
	order_bad++;
	printf("ORDINE VIOLATO: ingresso in L2 senza INVEPT fisico dopo l'invalidazione\n");
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && inv_first_entry /
{
	inv_first_entry = 0; inv_pte_after = this->pte; inv_ass_after = this->ass;
	printf("   primo ingresso dopo l'invalidazione: PTE sonda=%#lx primo_assente=%s\n", this->pte,
	    this->ass == 4 ? "PML4E" : this->ass == 3 ? "PDPTE" : this->ass == 2 ? "PDE" :
	    this->ass == 1 ? "PTE" : "nessuno");
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && s1_hpa != 0 && s1_leaf_checked == 0 /
{
	s1_leaf_checked = 1;
	s1_leaf_ok = this->ass == 0 && (this->pte & 7) != 0 && (this->pte & AM) == (s1_hpa & AM);
	printf("FOGLIA DOPO STAGE1: PTE=%#lx atteso hpa=%#lx -> %s\n", this->pte, s1_hpa,
	    s1_leaf_ok ? "coincide" : "NON coincide");
}
pid$target::sim_entry:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid /
{
	self->fase = 0;
}

/* ---------- slow path, installazioni, riflessioni ---------- */
pid$target::sim_fault_ret:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && self->fase == 2 /
{
	s1_done = 1; s1_rc = this->rc; s1_l1gpa = this->l1gpa;
	printf("FAULT fase1 rc=%d l1gpa=%#lx\n", this->rc, this->l1gpa);
}
pid$target::sim_install:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid && (this->l2gpa & ~0xfffUL) == sonda /
{
	printf("INSTALL-SONDA fase%d hpa=%#lx perm=%#x\n", (int)self->fase - 1, this->hpa, this->perm);
	s0_hpa = self->fase == 1 ? this->hpa : s0_hpa;
	s1_hpa = self->fase == 2 ? this->hpa : s1_hpa;
	s2_bad_install += self->fase == 3 && s2_reflect && !s2_restore_seen ? 1 : 0;
	s2_inst_perm = self->fase == 3 ? this->perm : s2_inst_perm;
	fuori_fase += self->fase == 0 ? 1 : 0;
}
pid$target::sim_reflect:entry
/ this->ok && ctx_tid != 0 && this->tid == ctx_tid /
{
	printf("REFLECT fase%d l2gpa=%#lx qual_hw=%#lx esito=%d\n", (int)self->fase - 1,
	    this->l2gpa, this->qual, this->rc);
	s1_reflect = self->fase == 2 ? 1 : s1_reflect;
	s2_reflect = self->fase == 3 ? 1 : s2_reflect;
	s2_rqual = self->fase == 3 ? this->qual : s2_rqual;
}

END
{
	this->ident = changed || eptp_changed;
	this->remap =
	    (int)$4 == 1 ? "NA" :
	    this->ident ? "INCONCLUSIVE" :
	    ctx_tid == 0 || !s1_seen ? "NOT_OBSERVED" :
	    s1_reflect || (s1_done && (s1_rc != 0 || s1_l1gpa != sonda)) ? "FAIL" :
	    s1_inv_n == 0 || (s1_inv_pte & 7) != 0 ? "FAIL" :
	    !s1_done || s1_hpa == 0 || !s1_leaf_checked ? "INCONCLUSIVE" :
	    s1_hpa == s0_hpa || !s1_leaf_ok || fuori_fase != 0 ? "FAIL" : "PASS";
	this->wrev =
	    (uint64_t)$3 == 0 ? "NA" :
	    this->ident ? "INCONCLUSIVE" :
	    !s2_seen ? "NOT_OBSERVED" :
	    s2_bad_install != 0 ? "FAIL" :
	    s2_inv_n == 0 || (s2_inv_pte & 7) != 0 ? "FAIL" :
	    !s2_reflect && s2_inst_perm >= 0 && !s2_restore_seen ? "FAIL" :
	    !s2_reflect ? "INCONCLUSIVE" :
	    (s2_rqual & 2) == 0 ? "FAIL" :
	    s2_inst_perm >= 0 && s2_inst_perm != 7 ? "FAIL" :
	    !s2_restore_seen || s2_inst_perm != 7 ? "INCONCLUSIVE" : "PASS";
	this->ord =
	    this->ident || cpu_changed ? "INCONCLUSIVE" :
	    inv_total == 0 ? "NOT_OBSERVED" :
	    order_bad != 0 ? "FAIL" : "PASS";
	this->p1 =
	    !s1_seen || s1_inv_n == 0 ? "UNKNOWN" :
	    s1_inv_kind == 1 && s1_inv_ass == 1 ? "PARTIAL" :
	    s1_inv_kind == 2 ? "FULL" : "UNKNOWN";
	this->p2 =
	    (uint64_t)$3 == 0 ? "NA" :
	    !s2_seen || s2_inv_n == 0 ? "UNKNOWN" :
	    s2_inv_kind == 1 && s2_inv_ass == 1 ? "PARTIAL" :
	    s2_inv_kind == 2 ? "FULL" : "UNKNOWN";
	printf("== RIEPILOGO == contesto=%s sonda=%#lx eptp=%#lx cpu=%d altri_contesti=%d invalidazioni=%d ordine_violato=%d\n",
	    ctx_tid == 0 ? "NON LEGATO" : "legato", sonda, ctx_eptp, ctx_cpu, other_ctx, inv_total, order_bad);
	printf("   stage1: violation=%d inval_prima=%d tipo=%d PTE_dopo=%#lx rc=%d l1gpa=%#lx hpa=%#lx (stage0 %#lx) riflessa=%d foglia=%s\n",
	    s1_seen, s1_inv_n, s1_inv_kind, s1_inv_pte, s1_rc, s1_l1gpa, s1_hpa, s0_hpa, s1_reflect,
	    s1_leaf_checked ? (s1_leaf_ok ? "coincide" : "NON coincide") : "non letta");
	printf("   stage2: violation=%d inval_prima=%d tipo=%d PTE_dopo=%#lx riflessa=%d qual_hw=%#lx install_indebite=%d ripristino=%d perm_finale=%d\n",
	    s2_seen, s2_inv_n, s2_inv_kind, s2_inv_pte, s2_reflect, s2_rqual, s2_bad_install, s2_restore_seen, s2_inst_perm);
	/* _np: lettura di stage1 su EPT12 non-present -> riflessa, nessuna foglia */
	this->np =
	    (int)$4 != 1 ? "NA" :
	    this->ident ? "INCONCLUSIVE" :
	    ctx_tid == 0 || !s1_seen ? "NOT_OBSERVED" :
	    s1_hpa != 0 ? "FAIL" :
	    s1_inv_n == 0 || (s1_inv_pte & 7) != 0 ? "FAIL" :
	    !s1_done ? "INCONCLUSIVE" :
	    s1_rc != 1 ? "FAIL" :
	    !s1_reflect ? "INCONCLUSIVE" : "PASS";
	printf("L0_NP=%s\n", this->np);
	printf("L0_REMAP=%s\nL0_W_REVOKE=%s\nL0_INVEPT_ORDER=%s\nL0_PATH_STAGE1=%s\nL0_PATH_STAGE2=%s\n== TRACCIA CHIUSA ==\n",
	    this->remap, this->wrev, this->ord, this->p1, this->p2);
}
