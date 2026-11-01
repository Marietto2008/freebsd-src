#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * Correzione dopo la corsa _sentinel (26/10): la GPA della sonda NON e' fissa
 * (alloc_page: 0x3fed1000 in alcune build, 0x10d2000 in vmxc-sent). Qui la si
 * ricava AL MOMENTO dalla EPT violation al RIP di lettura di stage0 ($3) o di
 * stage1 ($2); $1 e' solo il valore iniziale. Il resto come diag74.d.
 * Uso: dtrace -s diag76.d <GPA_iniziale> <RIP_lettura_stage1> <RIP_lettura_stage0>
 * Stampa: ogni VMCALL (reason 18), ogni EPT violation (48) sulla pagina della
 * sonda O con RIP della lettura di stage1, ogni wipe, ogni INVEPT fisico, e
 * all'ingresso il walk EPT02 della sonda col PRIMO livello assente (solo
 * quando cambia). EPTP intero e radice (EPTP & ~0xfff) separati.
 * Layout delle struct = vmx.c di 27125f004917. Solo lettura.
 */
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
inline uint64_t AM = 0x000ffffffffff000;

uint64_t lastsig; int have;
uint64_t sonda;

BEGIN { sonda = (uint64_t)$1 & ~0xfffUL;
	printf("== TRACCIA PRONTA == sonda_iniziale=%#lx rip_lettura1=%#lx rip_lettura0=%#lx\n", (uint64_t)$1, (uint64_t)$2, (uint64_t)$3); }

fbt:vmm-restore:vept_root_wipe:entry
{
	printf("-- WIPE slot=%d cpu%d\n", (int)arg1, cpu);
}

vmm:vmx:nested:diag58inv
{
	this->i = (d58_inv_t *)arg0;
	printf("[%u] INVEPT-fisico eptp=%#lx radice=%#lx tipo=%d cpu%d\n",
	    this->i->seq, (unsigned long)this->i->ep4ta,
	    (unsigned long)(this->i->ep4ta & AM), (int)this->i->type,
	    (int)this->i->cpu);
}

vmm:vmx:nested:diag58ent
{
	this->e = (d58_ent_t *)arg0;
	this->g = sonda;
	this->r = DMAP + (this->e->eptp & AM);
	this->l4 = *(uint64_t *)(this->r + ((this->g >> 39) & 511) * 8);
	this->l3 = (this->l4 & 7) ? *(uint64_t *)(DMAP + (this->l4 & AM) + ((this->g >> 30) & 511) * 8) : 0;
	this->l2 = ((this->l3 & 7) && !(this->l3 & 0x80)) ? *(uint64_t *)(DMAP + (this->l3 & AM) + ((this->g >> 21) & 511) * 8) : 0;
	this->l1 = ((this->l2 & 7) && !(this->l2 & 0x80)) ? *(uint64_t *)(DMAP + (this->l2 & AM) + ((this->g >> 12) & 511) * 8) : 0;
	this->abs =
	    !(this->l4 & 7) ? "PML4E" :
	    !(this->l3 & 7) ? "PDPTE" :
	    (this->l3 & 0x80) ? "nessuno(PDPTE PS=1)" :
	    !(this->l2 & 7) ? "PDE" :
	    (this->l2 & 0x80) ? "nessuno(PDE PS=1)" :
	    !(this->l1 & 7) ? "PTE" : "nessuno";
	this->sig = this->l1 ^ (this->l2 << 1) ^ (this->l3 << 2) ^ (this->l4 << 3) ^ this->e->eptp;
}
vmm:vmx:nested:diag58ent / have == 0 || this->sig != lastsig /
{
	printf("[%u] ENTRY cpu%d eptp=%#lx radice=%#lx rip=%#lx actsec=%d ept_on=%d | PML4E=%#lx PDPTE=%#lx PDE=%#lx PTE=%#lx primo_assente=%s\n",
	    this->e->seq, (int)this->e->cpu, (unsigned long)this->e->eptp,
	    (unsigned long)(this->e->eptp & AM), (unsigned long)this->e->grip,
	    (int)((this->e->prim_ctls >> 31) & 1), (int)((this->e->sec_ctls >> 1) & 1),
	    (unsigned long)this->l4, (unsigned long)this->l3,
	    (unsigned long)this->l2, (unsigned long)this->l1, this->abs);
	lastsig = this->sig; have = 1;
}

vmm:vmx:nested:diag58
{
	this->x = (d58_rec_t *)arg0;
	this->rsn = this->x->reason;
	this->gpa = this->x->gpa;
}
vmm:vmx:nested:diag58
/ this->rsn == 48 && (this->x->grip == (uint64_t)$2 || this->x->grip == (uint64_t)$3) &&
    (this->gpa & ~0xfffUL) != sonda /
{
	printf("SONDA RICAVATA: %#lx -> %#lx (rip %#lx)\n", (unsigned long)sonda,
	    (unsigned long)(this->gpa & ~0xfffUL), (unsigned long)this->x->grip);
	sonda = this->gpa & ~0xfffUL;
	have = 0;
}
vmm:vmx:nested:diag58
/ this->rsn == 18 || (this->rsn == 48 &&
    ((this->gpa & ~0xfffUL) == sonda || this->x->grip == (uint64_t)$2 || this->x->grip == (uint64_t)$3)) /
{
	printf("[%u] EXIT cpu%d in_l2=%d reason=%d gpa=%#lx qual=%#lx rip=%#lx eptp=%#lx foglia_sonda=%#lx\n",
	    this->x->seq, (int)this->x->cpu, (int)this->x->in_l2, this->rsn,
	    (unsigned long)this->gpa, (unsigned long)this->x->qual,
	    (unsigned long)this->x->grip, (unsigned long)this->x->eptp,
	    (unsigned long)this->x->ept02_probe);
}

/* L0 decide di riflettere a L1: esito 1=VEPT_VIOL 2=VEPT_MISCONF */
vmm:vmx:nested:veptrefl
{
	printf("REFLECT vcpu%d eptp12=%#lx l2gpa=%#lx qual=%#lx esito=%d host_rip=%#lx\n",
	    (int)arg0, (unsigned long)arg1, (unsigned long)arg2,
	    (unsigned long)arg3, (int)arg4, (unsigned long)arg5);
}

/* shadow coerente (parere #74 §4.5): NESSUNA foglia EPT02 per la sonda
 * dopo che l'EPT12 l'ha resa non-present */
fbt:vmm-restore:vept_install:entry / (arg2 & ~0xfffUL) == sonda /
{
	printf("INSTALL-SONDA l2gpa=%#lx hpa=%#lx perm=%#lx mt=%d\n",
	    (unsigned long)arg2, (unsigned long)arg3, (unsigned long)arg4, (int)arg5);
}

END { printf("== TRACCIA CHIUSA ==\n"); }
