#pragma D option quiet
#pragma D option dynvarsize=16m
/*
 * Parere #60 §8: consumo correlato, tutta la corsa, a basso volume.
 * EXIT stampato se: EPT violation (48) sulla sonda, oppure VMCALL (18).
 * ENTRY stampato quando la foglia EPT02 della sonda cambia valore.
 * GPA sonda = nested_diag58_gpa (impostare a 0x3fed1000). Layout = vmx.c.
 */
uint64_t lastleaf; int haveleaf;

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

vmm:vmx:nested:diag58ent
{
	this->e = (d58_ent_t *)arg0;
	this->p = this->e->ept02_probe;
}
vmm:vmx:nested:diag58ent /haveleaf == 0 || this->p != lastleaf/
{
	printf("[%u] ENTRY foglia_sonda=%#lx eptp=%#lx actsec=%d ept_on=%d rip=%#lx\n",
	    this->e->seq, (unsigned long)this->p, (unsigned long)this->e->eptp,
	    (int)((this->e->prim_ctls >> 31) & 1),
	    (int)((this->e->sec_ctls >> 1) & 1), (unsigned long)this->e->grip);
	lastleaf = this->p; haveleaf = 1;
}

vmm:vmx:nested:diag58
{
	this->r = (d58_rec_t *)arg0;
	this->rsn = this->r->reason;
	this->gpa = this->r->gpa;
}
vmm:vmx:nested:diag58
/ this->rsn == 18 || (this->rsn == 48 && (this->gpa & ~0xfffUL) == 0x3fed1000) /
{
	printf("[%u] EXIT reason=%d gpa=%#lx foglia_sonda=%#lx ept_leaf_exit=%#lx rip=%#lx\n",
	    this->r->seq, this->rsn, (unsigned long)this->gpa,
	    (unsigned long)this->r->ept02_probe, (unsigned long)this->r->ept02_leaf,
	    (unsigned long)this->r->grip);
}
