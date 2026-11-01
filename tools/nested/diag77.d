#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * diag77.d -- GENERATO da gen-diag77.py, non modificare a mano.
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

typedef struct d58_rec {
	uint32_t seq; uint16_t cpu; uint16_t vcpu;
	uint32_t reason; uint32_t in_l2;
	uint64_t eptp; uint64_t sec_ctls; uint64_t vpid;
	uint64_t gcr3; uint64_t gcr0; uint64_t gcr4; uint64_t gefer;
	uint64_t grip; uint64_t qual; uint64_t gpa; uint64_t gla;
	uint64_t ept02_leaf; uint64_t prim_ctls; uint64_t ept02_probe;
} d58_rec_t;
typedef struct d58_ent {
	uint32_t seq; uint16_t cpu; uint16_t vcpu;
	uint64_t prim_ctls; uint64_t sec_ctls; uint64_t eptp; uint64_t vpid;
	uint64_t grip; uint64_t ept02_probe;
} d58_ent_t;
typedef struct d58_inv {
	uint32_t seq; uint16_t cpu; uint16_t vcpu;
	uint64_t ep4ta; uint64_t type;
} d58_inv_t;
inline uint64_t DMAP = 0xfffff80000000000;

vmm:vmx:nested:diag58
{
	this->x = (d58_rec_t *)arg0;
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->vcpu = this->x->vcpu; this->seq = this->x->seq;
	this->rsn = this->x->reason; this->rip = this->x->grip;
	this->gpa = this->x->gpa; this->qual = this->x->qual; this->eptp = this->x->eptp;
	this->fase = -1; this->mio = 0; this->pg = (uint64_t)0;
}
vmm:vmx:nested:diag58ent
{
	this->e = (d58_ent_t *)arg0;
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->vcpu = this->e->vcpu; this->seq = this->e->seq;
	this->rip = this->e->grip; this->eptp = this->e->eptp;
	this->g = sonda;
	this->r = DMAP + (this->eptp & AM);
	this->l4 = sonda == 0 ? 0 : *(uint64_t *)(this->r + ((this->g >> 39) & 511) * 8);
	this->l3 = (this->l4 & 7) ? *(uint64_t *)(DMAP + (this->l4 & AM) + ((this->g >> 30) & 511) * 8) : 0;
	this->l2 = ((this->l3 & 7) && !(this->l3 & 0x80)) ? *(uint64_t *)(DMAP + (this->l3 & AM) + ((this->g >> 21) & 511) * 8) : 0;
	this->l1 = ((this->l2 & 7) && !(this->l2 & 0x80)) ? *(uint64_t *)(DMAP + (this->l2 & AM) + ((this->g >> 12) & 511) * 8) : 0;
}
vmm:vmx:nested:diag58inv
{
	this->i = (d58_inv_t *)arg0;
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->seq = this->i->seq; this->eptp = this->i->ep4ta;
}
fbt:vmm-restore:vept_root_wipe:entry
{
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->slot = (int)arg1;
}
fbt:vmm-restore:vmx_vept_fault:entry
{
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->l2gpa = arg1;
	self->l1p = (uint64_t *)arg3;
}
fbt:vmm-restore:vmx_vept_fault:return
{
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->rc = (int)arg1;
	this->l1gpa = self->l1p != NULL ? *self->l1p : 0;
	self->l1p = 0;
}
fbt:vmm-restore:vept_install:entry
{
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->l2gpa = arg2; this->hpa = arg3; this->perm = (int)arg4;
}
vmm:vmx:nested:veptrefl
{
	this->ok = execname == "qemu-system-x86_64";
	this->tid = (uint64_t)tid; this->l2gpa = arg2; this->qual = arg3; this->rc = (int)arg4;
}

/* uscite: violation a un RIP di lettura/scrittura atteso -> lega o controlla */
vmm:vmx:nested:diag58
/ this->rsn == 48 && ((uint64_t)$2 != 0 && this->rip == (uint64_t)$2 ||
    (uint64_t)$1 != 0 && this->rip == (uint64_t)$1 ||
    (uint64_t)$3 != 0 && this->rip == (uint64_t)$3) /
{
	this->pg = this->gpa & ~0xfffUL;
	this->fase = this->rip == (uint64_t)$2 ? 0 : this->rip == (uint64_t)$1 ? 1 : 2;
	this->mio = this->ok && (ctx_tid == 0 || this->tid == ctx_tid);
}
vmm:vmx:nested:diag58
/ this->rsn == 48 && this->fase >= 0 && this->mio && ctx_tid == 0 && this->pg != 0 /
{
	ctx_tid = this->tid; ctx_vcpu = this->vcpu; ctx_eptp = this->eptp; sonda = this->pg;
	printf("SONDA RICAVATA %#lx (fase %d, rip %#lx) contesto tid=%d vcpu=%d eptp=%#lx\n",
	    sonda, this->fase, this->rip, this->tid, this->vcpu, this->eptp);
}
vmm:vmx:nested:diag58
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg != sonda && changed == 0 /
{
	changed = 1;
	printf("ALLARME SONDA CAMBIATA nello stesso contesto: %#lx -> %#lx (rip %#lx): audit INCONCLUSIVO\n",
	    sonda, this->pg, this->rip);
}
vmm:vmx:nested:diag58
/ this->rsn == 48 && this->fase >= 0 && !this->mio /
{
	other_ctx++;
	printf("ALTRO CONTESTO ignorato: ok=%d tid=%d gpa=%#lx rip=%#lx\n", this->ok, this->tid, this->gpa, this->rip);
}
vmm:vmx:nested:diag58
/ this->rsn == 48 && this->fase >= 0 && this->mio && this->tid == ctx_tid && this->pg == sonda /
{
	self->fase = this->fase + 1;	/* 1,2,3 = fase 0,1,2 in corso; 0 = nessuna */
	s1_seen = this->fase == 1 ? 1 : s1_seen;
	wipes_at_s1 = this->fase == 1 ? wipes : wipes_at_s1;
	s2_seen = this->fase == 2 ? 1 : s2_seen;
	printf("[%u] EXIT fase%d reason=48 gpa=%#lx qual=%#lx rip=%#lx eptp=%#lx\n",
	    this->seq, this->fase, this->gpa, this->qual, this->rip, this->eptp);
}
vmm:vmx:nested:diag58
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) && this->rsn == 18 /
{
	printf("[%u] EXIT reason=18 rip=%#lx eptp=%#lx\n", this->seq, this->rip, this->eptp);
}

/* ingresso: fine della fase; walk della sonda (quando nota) */
vmm:vmx:nested:diag58ent
/ this->ok && this->tid == ctx_tid && sonda != 0 /
{
	this->ass = !(this->l4 & 7) ? "PML4E" : !(this->l3 & 7) ? "PDPTE" :
	    (this->l3 & 0x80) ? "nessuno(PDPTE PS)" : !(this->l2 & 7) ? "PDE" :
	    (this->l2 & 0x80) ? "nessuno(PDE PS)" : !(this->l1 & 7) ? "PTE" : "nessuno";
	printf("[%u] ENTRY rip=%#lx eptp=%#lx radice=%#lx sonda=%#lx PTE=%#lx primo_assente=%s\n",
	    this->seq, this->rip, this->eptp, this->eptp & AM, sonda, this->l1, this->ass);
}
vmm:vmx:nested:diag58ent
/ this->ok && this->tid == ctx_tid && sonda != 0 && s1_hpa != 0 && s1_leaf_checked == 0 /
{
	s1_leaf_checked = 1;
	s1_leaf_ok = (this->l1 & 7) != 0 && (this->l1 & AM) == (s1_hpa & AM);
	printf("FOGLIA DOPO STAGE1: PTE=%#lx atteso hpa=%#lx -> %s\n", this->l1, s1_hpa,
	    s1_leaf_ok ? "coincide" : "NON coincide");
}
vmm:vmx:nested:diag58ent
/ this->ok && this->tid == ctx_tid /
{
	self->fase = 0;
}

vmm:vmx:nested:diag58inv
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) /
{
	printf("[%u] INVEPT-fisico eptp=%#lx radice=%#lx\n", this->seq, this->eptp, this->eptp & AM);
}
fbt:vmm-restore:vept_root_wipe:entry
/ this->ok && (ctx_tid == 0 || this->tid == ctx_tid) /
{
	wipes++;
	printf("-- WIPE slot=%d (n.%d)\n", this->slot, wipes);
}

/* slow path della violation della sonda: esito di vmx_vept_fault */
fbt:vmm-restore:vmx_vept_fault:return
/ this->ok && this->tid == ctx_tid && self->fase == 2 /
{
	s1_done = 1; s1_rc = this->rc; s1_l1gpa = this->l1gpa;
	printf("FAULT fase1 rc=%d l1gpa=%#lx\n", this->rc, this->l1gpa);
}
fbt:vmm-restore:vmx_vept_fault:return
/ this->ok && this->tid == ctx_tid && (self->fase == 1 || self->fase == 3) /
{
	printf("FAULT fase%d rc=%d l1gpa=%#lx\n", self->fase - 1, this->rc, this->l1gpa);
}

fbt:vmm-restore:vept_install:entry
/ this->ok && this->tid == ctx_tid && sonda != 0 && (this->l2gpa & ~0xfffUL) == sonda /
{
	printf("INSTALL-SONDA fase%d l2gpa=%#lx hpa=%#lx perm=%#x\n", (int)self->fase - 1,
	    this->l2gpa, this->hpa, this->perm);
	s0_hpa = self->fase == 1 ? this->hpa : s0_hpa;
	s1_hpa = self->fase == 2 ? this->hpa : s1_hpa;
	s2_inst_perm = self->fase == 3 ? this->perm : s2_inst_perm;
	fuori_fase += self->fase == 0 ? 1 : 0;
}

vmm:vmx:nested:veptrefl
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
	    s2_reflect && (s2_rqual & 2) && ((s2_rqual >> 3) & 7) == 5 && s2_inst_perm == 7 ?
	    "L0_S2_PASS" : "L0_S2_FAIL";
	printf("   stage2: violation=%d riflessa=%d qual=%#lx perm dopo ripristino=%d\n",
	    s2_seen, s2_reflect, s2_rqual, s2_inst_perm);
	printf("%s\n== TRACCIA CHIUSA ==\n", this->s2);
}
