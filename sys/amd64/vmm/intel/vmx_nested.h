/*-
 * Copyright (C) 2021-2022 Intel Corporation.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Derivato da projectacrn/acrn-hypervisor (hypervisor/arch/x86/guest:
 * nested.h, vept.h). Intestazione e clausola 3 di ACRN conservate.
 *
 * Copyright (c) 2026 Marietto.
 *
 * Costanti per la virtualizzazione VMX annidata di vmm (piano nested v2,
 * task T1.1). Solo #define architetturali (Intel SDM vol. 3C) ed encoding
 * usati dalla cache VMCS12 presa da ACRN nested.h. Nessun tipo, nessuna
 * dipendenza: l'header si include dopo <machine/vmm.h> e "vmcs.h".
 */
#ifndef _VMX_NESTED_H_
#define	_VMX_NESTED_H_

/*
 * Indicatore "shadow VMCS": bit 31 della prima dword (VMCS revision ID)
 * della pagina VMCS02. Va impostato prima di usarla come shadow e sempre
 * preceduto da un VMCLEAR (SDM 25.11.3; ACRN nested.c:1051-1065).
 */
#define	VMX_VMCS_SHADOW_BIT		(1U << 31)

/*
 * Numeri delle MSR VMX esposte all'L1 non gia' presenti in specialreg.h
 * sotto altro nome. Guardati per evitare doppie definizioni.
 */
#ifndef IA32_VMX_MISC
#define	IA32_VMX_MISC			0x485
#endif
#ifndef IA32_VMX_VMCS_ENUM
#define	IA32_VMX_VMCS_ENUM		0x48A
#endif
#ifndef IA32_VMX_VMFUNC
#define	IA32_VMX_VMFUNC			0x491
#endif

/*
 * Codici di errore delle istruzioni VMX (SDM vol. 3C, "VM Instruction
 * Error Numbers"). Usati per VMfailValid().
 */
#define	VMXERR_VMCALL_IN_VMX_ROOT		1
#define	VMXERR_VMCLEAR_INVALID_ADDRESS		2
#define	VMXERR_VMCLEAR_VMXON_POINTER		3
#define	VMXERR_VMLAUNCH_NONCLEAR_VMCS		4
#define	VMXERR_VMRESUME_NONLAUNCHED_VMCS	5
#define	VMXERR_VMRESUME_AFTER_VMXOFF		6
#define	VMXERR_ENTRY_INVALID_CONTROL_FIELD	7
#define	VMXERR_ENTRY_INVALID_HOST_STATE		8
#define	VMXERR_VMPTRLD_INVALID_ADDRESS		9
#define	VMXERR_VMPTRLD_VMXON_POINTER		10
#define	VMXERR_VMPTRLD_INCORRECT_REVISION	11
#define	VMXERR_UNSUPPORTED_VMCS_COMPONENT	12
#define	VMXERR_VMWRITE_READ_ONLY_COMPONENT	13
#define	VMXERR_VMXON_IN_VMX_ROOT		15
#define	VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS	16
#define	VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE	17
#define	VMXERR_ENTRY_EXECUTIVE_VMCS_PTR		18
#define	VMXERR_VMCALL_NONCLEAR_VMCS		19
#define	VMXERR_VMCALL_INVALID_EXIT_FIELD	20
#define	VMXERR_VMCALL_INCORRECT_MSEG_REVISION	22
#define	VMXERR_VMXOFF_UNDER_DUAL_MONITOR	23
#define	VMXERR_VMCALL_INVALID_SMM_MONITOR	24
#define	VMXERR_ENTRY_INVALID_VM_CONTROL_SMM	25
#define	VMXERR_ENTRY_MOV_SS_BLOCKING		26
#define	VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID 28

/* Larghezza max della cache VMCS12 per vCPU (voci), §T1.3. */
#define	VMX_NESTED_MAX_VMCS12			4

/* Esito di un'istruzione VMX nel RFLAGS dell'L1 (SDM 31.2). */
#define	VMXR_SUCCEED	0	/* VMsucceed: tutti i flag a 0 */

/* GPA "nessun VMCS12" per le voci di cache e per current_vmcs12. */
#define	VMCS12_GPA_NONE		(~0ULL)
/* Numero di MSR VMX virtuali esposti all'L1: 0x480..0x491. */
#define	VMX_NESTED_NMSR		(0x491 - 0x480 + 1)

#ifdef _KERNEL
#include <sys/malloc.h>
#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>

MALLOC_DECLARE(M_VMX_NESTED);

/* Helper di vmx.c esposti per il nested (T1.7). */
uint64_t vmx_get_guest_reg(struct vmx_vcpu *vcpu, int ident);
void	vmx_set_guest_reg(struct vmx_vcpu *vcpu, int ident, uint64_t regval);
int	vmx_getdesc(void *vcpui, int reg, struct seg_desc *desc);
void	vmx_paging_info(struct vm_guest_paging *paging);
enum vm_cpu_mode vmx_cpu_mode(void);

/* Controlli/maschere richiesti dall'L0 (vmx.c), per comporre VMCS02 (T2.3). */
extern uint32_t pinbased_ctls, procbased_ctls, procbased_ctls2;
extern uint32_t exit_ctls, entry_ctls;
extern uint64_t cr0_ones_mask, cr0_zeros_mask, cr4_ones_mask, cr4_zeros_mask;
int	nested_compose_vmcs02(struct vmx_vcpu *vcpu);
int	nested_vmcs02_check(struct vmx_vcpu *vcpu);
bool	nested_l2_exit(struct vmx_vcpu *vcpu, struct vm_exit *vmexit);
/*
 * Shadow VMCS (pareri #43-#45), da vmx_run con interrupt spenti e il VMCS del
 * prossimo ingresso corrente. vmx_shvmcs_enter: true = errore, NON entrare
 * (fail-closed sincrono, parere #45 §3); il chiamante esce da vmx_run come
 * per una sospensione. nested_sh_entry_after_fault conta gli ingressi
 * avvenuti con un errore gia' registrato: deve restare 0.
 */
bool	vmx_shvmcs_enter(struct vmx_vcpu *vcpu);
void	vmx_shvmcs_run_end(struct vmx_vcpu *vcpu);
/* vpid_track (vmx.c): VPID01 e campi host del VMCS01 sulla CPU corrente,
 * dall'uscita L2->L1 dentro vmx_run */
void	vmx_vpid01_resume(struct vmx_vcpu *vcpu);
void	vmx_vpid_defer_request(struct vmx_vcpu *vcpu);
bool	vmx_vpid_is_unique(uint16_t vpid);
/*
 * Richieste d'invalidazione del VPID02 (parere #49 §6), semantica dei
 * contatori: vpid02_req = richieste ricevute; vpid02_req_coalesced = arrivate
 * con una gia' pendente (accorpate); vpid02_req_satisfied = richieste pendenti
 * consumate da un INVVPID(VPID02) eseguito sulla CPU d'ingresso in L2, qualunque
 * ne fosse la causa; vpid02_req_dropped = pendenti alla distruzione dello stato
 * nested. Invariante: req = coalesced + satisfied + dropped + pendenti ora (0 o
 * 1 per vCPU nested vivo).
 */
extern u_long vpid02_req, vpid02_req_coalesced, vpid02_req_satisfied,
    vpid02_req_dropped;
extern u_long vmcs02_host_write_compose;
extern u_long nested_sh_entry_after_fault;
/* esiti di vmx_vept_fault */
#define	VEPT_OK		0	/* shadow installata */
#define	VEPT_VIOL	1	/* EPT violation da riflettere all'L1 */
#define	VEPT_MISCONF	2	/* EPT misconfiguration da riflettere all'L1 */
#define	VEPT_MMIO	3	/* MMIO dell'L1: emulazione in L0 */
/* bit 3-6 di una voce EPT (memtype, IPAT), portati da ept12_translate in *perm */
#define	VEPT_PERM_ATTR	(EPT_PG_MEMORY_TYPE(7) | EPT_PG_IGNORE_PAT)
/*
 * Parere di Astra sul rapporto WSL2-FreeBSD 010 (§3-4): record E0/E1/E2 dello
 * stesso episodio "uscita MMIO LAPIC dell'L2 -> #PF chiesto dall'L1". Si
 * COPIA in memoria preallocata e si stampa dopo (sysctl), fuori dal percorso
 * critico. vept_diag_code: walk silenzioso del codice all'RIP dell'L2 con le
 * tabelle dell'L2 lette dalla memoria dell'L1 (vista di Hyper-V) e 16 byte
 * letti sia dalla pagina ombra EPT02 (vista della CPU) sia dall'L1.
 */
struct vept_diag_code {
	uint64_t	pte[4];		/* voci PML4..PT dell'L2 lette dall'L1 */
	uint64_t	l2gpa;		/* pagina finale del codice (L2-GPA) */
	uint64_t	l1gpa, perm;	/* EPT12 viva */
	uint64_t	shadow;		/* foglia EPT02 corrente */
	uint64_t	hpa_l1;		/* HPA della pagina dell'L1 (vm_gpa_hold) */
	int		r, fail_lvl, nbytes, ok_l1, ok_sh;
	uint8_t		b_l1[16], b_sh[16];
};
struct nested_pfrec {
	volatile int	done;
	int		vcpu;
	uint64_t	seq;		/* progressivo delle uscite E0 del vCPU */
	uint64_t	t0, rip0, cr3_0, gpa0, gla0, qual0, gpr0[16];
	struct vept_diag_code c0;
	uint64_t	t1, rip1, gpa1, gla1, qual1, reason1, gpr1[16];
	uint64_t	t2, cr2_2, rip2, cr3_2, gpr2[16];
	uint32_t	info2, err2;
	struct vept_diag_code c2;
	uint64_t	inv_seq, inv_tsc, inv_type, inv_eptp;
	int		inv_kept, inv_wiped;
};

int	vmx_vept_fault(struct vmx_vcpu *vcpu, uint64_t l2gpa, uint64_t qual,
	    uint64_t *l1gpa, uint64_t *perm);			/* slow path */
uint64_t vmx_vept_shadow_entry(struct vmx_vcpu *vcpu, uint64_t l2gpa);
void	vmx_vept_diag_keepstate(struct vmx_vcpu *vcpu, uint64_t eptp12,
	    uint64_t l2gpa);
int	vmx_vept_diag_code(struct vmx_vcpu *vcpu, uint64_t eptp12, uint64_t cr3,
	    uint64_t gla, struct vept_diag_code *o);
uint64_t vmx_vept_diag_walk(struct vmx_vcpu *vcpu, uint64_t eptp12, uint64_t cr3,
	    uint64_t gla, const char *tag);
int	vmx_vept_l1gpa(struct vmx_vcpu *vcpu, uint64_t gpa, int prot,
	    uint64_t *out);
int	vmx_vept_l1gpa_emul(struct vmx_vcpu *vcpu, uint64_t gpa, int prot,
	    uint64_t gla, int flags, uint64_t *out);	/* H2: dall'emulatore */
int	vmx_vept_ptp_write(struct vmx_vcpu *vcpu, uint64_t ptegpa,
	    uint64_t l1held, uint64_t gla, bool *denied); /* A/D dall'emulatore */
void	vmx_vept_flush(struct vmx_nested *n);
int	vmx_vept_invept(struct vmx_vcpu *vcpu, uint64_t type, uint64_t eptp,
	    int *kept);
void	vmx_vept_prepare(struct vmx_vcpu *vcpu);	/* puo' dormire */
uint64_t vmx_vept_eptp(struct vmx_vcpu *vcpu);	/* shadow EPTP per VMCS02 */
/*
 * Parere #39: indici di vmx_nested.st_vept[] (contatori per vCPU del percorso
 * EPT02 e degli hold EPT12). Gli hold "sito" sono le sole chiamate contate: i
 * rilasci contati devono pareggiare gli hold riusciti degli stessi siti.
 */
enum {
	VST_FAULT = 0,		/* vmx_vept_fault chiamate */
	VST_F_RAM,		/* foglia RAM installata */
	VST_F_MMIO,		/* foglia MMIO (BAR) installata */
	VST_F_VIOL_MISSING,	/* EPT12 non mappa: riflessa */
	VST_F_VIOL_PERM,	/* EPT12 mappa ma nega l'accesso: riflessa */
	VST_F_MISCONF,		/* EPT12 malformata: riflessa */
	VST_F_EMUL,		/* MMIO dell'L1: emulazione */
	VST_F_UNREAD,		/* tabella EPT12 illeggibile */
	VST_F_REINSTALL,	/* foglia gia' presente riscritta */
	VST_WALK,		/* ept12_translate chiamate (fault + emulazione) */
	VST_WALK_D1,		/* walk fermati dopo 1 livello */
	VST_WALK_D2,
	VST_WALK_D3,
	VST_WALK_D4,		/* walk fino al livello 0 (foglia 4K) */
	VST_H_WALK3,		/* hold del walk per livello (3 = PML4) */
	VST_H_WALK2,
	VST_H_WALK1,
	VST_H_WALK0,
	VST_H_L1PAGE,		/* hold della pagina dell'L1-GPA nel fault */
	VST_H_SCAN1,		/* hold della passata 1 di B1 */
	VST_H_SCAN2,		/* hold della passata 2 di B1 */
	VST_H_SCAN2_REUSE,	/* passata 2: riferimento della passata 1 riusato */
	VST_H_NULL,		/* hold (contati) falliti */
	VST_H_RELEASE,		/* rilasci (contati) */
	/*
	 * Parere #41 §6: tratti di vmx_run a interrupt disabilitati, in cicli TSC.
	 * USCITA: dal TSC letto subito dopo vmx_enter_guest all'enable_intr()
	 * successivo; INGRESSO: dal disable_intr() all'entry_tsc. L1/L2 = contesto
	 * dell'uscita / dell'ingresso. Classi: <1, 1-5, 5-20, >=20 us.
	 */
	VST_T_EXIT_L1, VST_T_EXIT_L1_N, VST_T_EXIT_L2, VST_T_EXIT_L2_N,
	VST_T_ENT_L1, VST_T_ENT_L1_N, VST_T_ENT_L2, VST_T_ENT_L2_N,
	VST_T_EXIT_B0, VST_T_EXIT_B1, VST_T_EXIT_B2, VST_T_EXIT_B3,
	VST_T_ENT_B0, VST_T_ENT_B1, VST_T_ENT_B2, VST_T_ENT_B3,
	VST_T_RDTSC, VST_T_RDTSC_N,	/* costo di due rdtsc di fila, 1 uscita su 256 */
	VST_N
};
void	vst_tratto(struct vmx_nested *n, int base, int bucket0, int imax,
	    uint64_t cicli);
void	vept_stats_flush(struct vmx_nested *n);	/* da nested_stats_flush */
/* B1 */
bool	vmx_vept_keep_enabled(void);		/* hw.vmm.vmx.vept_keep */
int	vmx_vept_ad_policy(void);		/* hw.vmm.vmx.nested_ept_ad && host A/D */
bool	vmx_nested_apicacc_policy(void);	/* hw.vmm.vmx.nested_apic_access && host */
void	vmx_vept_memgen_sync(struct vmx_vcpu *vcpu);	/* slow path */
int	vmx_vept_cur_slot(struct vmx_nested *n);	/* parere #53 §8: slot corrente o -1 */
bool	vmx_vept_memgen_stale(struct vmx_vcpu *vcpu);	/* non dorme */
void	vmx_vept_hw_flushed(struct vmx_vcpu *vcpu);	/* dopo l'INVEPT hw */
void	vmx_vept_enter_check(struct vmx_vcpu *vcpu);	/* prima dell'ingresso */
struct vmcs12_cache *nested_current_cache(struct vmx_nested *n);
uint64_t vmcs12_read_field(struct vmcs12_cache *c, uint32_t enc);
/* Secondari del VMCS12 come li vede la CPU: 0 se i primari non li attivano
 * (SDM: il campo e' allora ignorato e puo' contenere residui). */
uint32_t vmcs12_proc2(struct vmcs12_cache *c);
uint16_t vpid_alloc(int vcpuid);
void vpid_free(int vpid);

struct vmx_vcpu;

/*
 * Una voce della cache VMCS12->VMCS02 (per vCPU, MAI globale: §3). I campi
 * operativi li riempiono i task T1.7/T1.8/T2.*; qui c'e' solo il guscio.
 */
#define	VMCS12_NFIELDS	256	/* campi VMCS memorizzati per VMCS12 (T1.8) */
struct vmcs12_field {
	uint32_t	enc;
	uint64_t	val;
};

/*
 * Rappresentazione PERSISTENTE del VMCS12 nella sua regione di memoria
 * dell'L1 (parere #22 di Astra). La cache per-vCPU qui sotto e' solo
 * un'accelerazione: la copia di riferimento e' la regione indicata
 * dall'operando di VMPTRLD/VMCLEAR (GPA dell'L1, mai tradotto con l'EPT12).
 * VMCLEAR, lo sfratto dalla cache e VMXOFF vi scrivono i campi; VMPTRLD li
 * rilegge. Serve perche' Hyper-V migra i VMCS fra LP (VMCLEAR su uno,
 * VMPTRLD sull'altro, SDM 24.11.1): prima il contenuto si perdeva e il
 * VMLAUNCH della partizione di WSL2 dava VMfail 7 (7 campi su ~104).
 *
 * Il formato e' definito dall'implementazione (SDM 24.2): i primi 8 byte
 * (revision ID, abort indicator) sono architetturali e NON si toccano; poi
 * un'intestazione bhyve e le coppie (encoding, valore) serializzate a 12
 * byte, senza padding del compilatore. Un L1 che legga la pagina
 * direttamente non e' supportato, come sul ferro vero.
 */
#define	VMCS12_MEM_MAGIC	0x32316862U	/* "bh12" */
#define	VMCS12_MEM_VERSION	1
struct vmcs12_mem_field {
	uint32_t	enc;
	uint32_t	val_lo;
	uint32_t	val_hi;
} __packed;
struct vmcs12_mem {
	uint32_t	revision;	/* architetturale: lo scrive l'L1 */
	uint32_t	abort;		/* architetturale */
	uint32_t	magic;		/* VMCS12_MEM_MAGIC */
	uint16_t	version;	/* VMCS12_MEM_VERSION */
	uint16_t	launched;	/* launch state: 0 clear, 1 launched */
	uint32_t	nfields;	/* <= VMCS12_NFIELDS */
	uint32_t	digest;		/* FNV-1a 32 di fields[0..nfields) */
	struct vmcs12_mem_field fields[VMCS12_NFIELDS];
} __packed;
_Static_assert(sizeof(struct vmcs12_mem_field) == 12,
    "vmcs12_mem_field deve occupare 12 byte");
_Static_assert(sizeof(struct vmcs12_mem) <= PAGE_SIZE,
    "la rappresentazione del VMCS12 non sta in una pagina");

/*
 * Lista MSR del VMCS12 (SDM 24.7.2): fino a 512 voci da 16 byte = 8 KB,
 * allineata a 16, quindi su al massimo 3 pagine; una voce non scavalca mai
 * il confine di pagina.
 */
struct nested_msr_list {
	uint64_t	gpa;
	uint32_t	n;
	uint8_t		*pg[3];
	void		*ck[3];
};

struct vmcs12_cache {
	uint64_t	vmcs12_gpa;	/* GPA del VMCS12; VMCS12_GPA_NONE = libera */
	void		*vmcs02;	/* pagina VMCS02, allocata pigramente (T1.8) */
	int		ref_cnt;
	int		launched;	/* launch state di questo VMCS02 */
	int		host_cpu1;	/* vpid_track: CPU+1 dei campi host per-CPU
					 * scritti in questo VMCS02 (0 = nessuna) */
	bool		host_dirty;	/* host-state da ricomporre */
	bool		control_dirty;	/* controlli da ricomporre */
	struct vmcs12_field fields[VMCS12_NFIELDS];  /* store software (T1.8) */
	int		nfields;
	/*
	 * Bitmap I/O (A, B) e MSR dell'L1, mappate al VMLAUNCH/VMRESUME nello
	 * slow path: il percorso veloce (vmx_exit_process) gira in sezione
	 * critica e non puo' chiamare vm_gpa_hold, che puo' dormire.
	 */
	uint8_t		*bm_io_a, *bm_io_b, *bm_msr;
	void		*ck_io_a, *ck_io_b, *ck_msr;
	/* Liste MSR d'uscita dell'L1 (store, load), mappate come le bitmap:
	 * all'uscita da L2 si e' nel percorso veloce. */
	/* store/load all'uscita, load all'ingresso: mappate PRIMA del VMPTRLD
	 * (che fa critical_enter) e lette anche dal percorso veloce */
	struct nested_msr_list ml_st, ml_ld, ml_en;
	bool		ml_en_bad;	/* lista d'ingresso non mappabile */
	/*
	 * Shadow VMCS (pareri #43/#44): true finche' l'L1 puo' aver scritto in
	 * hardware i campi RW dello shadow dopo l'ultima copia di ritorno. In
	 * quello stato L0 non deve leggere ne' scrivere quei campi qui:
	 * vmcs12_read_field/vmcs12_write_field lo controllano (fail-closed).
	 */
	bool		sh_rw_owned;
	bool		sh_guard_hit;	/* la guardia e' scattata: si ferma la VM */
};

/*
 * Stato della virtualizzazione VMX annidata, per vCPU. Allocato quando la
 * capability passa 0->1 (vmx_nested_init), liberato a 1->0 e al cleanup del
 * vCPU (vmx_nested_free). Mai condiviso fra vCPU.
 */
/*
 * Cattura diagnostica di SOLA LETTURA (hw.vmm.vmx.diag_vec, spenta per
 * difetto). Quando l'ingresso hardware in L2 porta il vettore richiesto, i
 * campi qui sotto fotografano in UN SOLO istante -- immediatamente prima del
 * VMLAUNCH/VMRESUME, non alla composizione -- lo stato del VMCS caricato e lo
 * slot di messaggio SynIC che la root dovrebbe consumare. L'esito si legge al
 * VM-exit successivo (IDT_VECTORING_INFO). Nessun cambiamento funzionale.
 */
struct nested_diag {
	int		armed;		/* cattura fatta, attende l'uscita */
	uint32_t	entry_info;	/* VMCS_ENTRY_INTR_INFO */
	uint32_t	intblk;		/* GUEST_INTERRUPTIBILITY */
	uint32_t	activity;	/* GUEST_ACTIVITY */
	uint32_t	msgtype;	/* SIM slot: MessageType */
	uint32_t	msghdr;		/* PayloadSize | Flags<<8 (pending = bit 8) */
	uint32_t	ilen;		/* VMCS_ENTRY_INST_LENGTH all'ingresso hardware */
	uint64_t	rip;
	uint64_t	rsp;
	uint64_t	rflags;
	uint64_t	eptp;		/* VMCS_EPTP del VMCS02 */
	uint64_t	vmcs;		/* vmptrst: il VMCS DAVVERO caricato */
	uint64_t	eptp12;		/* EPTP12 corrente = etichetta del VTL */
	uint64_t	exp;		/* SIM slot: ExpirationTime */
	uint64_t	deliv;		/* SIM slot: DeliveryTime */
};

struct vmx_nested {
	bool		vmxon;		/* L1 in VMX operation (dopo VMXON) */
	bool		in_l2;		/* il vCPU sta eseguendo in L2 */
	bool		init_pending;	/* INIT latched per il bersaglio (§6.5.5) */
	uint64_t	vmxon_ptr;	/* GPA della regione VMXON */
	uint64_t	current_vmcs12;	/* GPA del VMCS12 corrente, _NONE se nessuno */
	struct vmcs12_cache cache[VMX_NESTED_MAX_VMCS12];
	uint64_t	vmx_msr[VMX_NESTED_NMSR];  /* MSR VMX 0x480..0x491 (T1.4) */
	uint64_t	feature_control;	/* IA32_FEATURE_CONTROL (T1.4) */
	char		*msr_bitmap;	/* pagina MSR bitmap fusa L0|L1 (T6.3) */
	/*
	 * Shadow VMCS hardware per le VMREAD/VMWRITE dell'L1 (pareri #43/#44),
	 * invisibile all'L1. sh_on si fissa alla creazione del vCPU nested.
	 * Proprieta' dei campi: RO (informazioni d'uscita, AR di CS/SS) sempre
	 * del VMCS12, lo shadow ne e' una copia; RW (INTERRUPTIBILITY, RFLAGS,
	 * RIP) dello shadow da quando l'L1 ci entra (cache->sh_rw_owned) fino
	 * alla copia di ritorno. sh_push: campi che L0 ha cambiato nel VMCS12 e
	 * che vanno ricopiati nello shadow prima del prossimo ingresso in L1
	 * (MAI una copia completa sopra RW non recuperati).
	 */
	bool		sh_on;
	bool		sh_live;	/* lo shadow rispecchia sh_cache */
	bool		sh_active;	/* referenziato da un ingresso in questo vmx_run */
	bool		sh_fault;	/* errore: la VM si ferma (fail-closed) */
	bool		sh_inject_vmx;	/* prova: la prossima copia fallisce */
	uint32_t	sh_push;	/* maschera dei campi da ricopiare */
	struct vmcs	*sh_vmcs;	/* pagina dello shadow VMCS */
	struct vmcs12_cache *sh_cache;	/* slot rispecchiato */
	int		evict_next;	/* prossimo slot da sfrattare (giro) */
	/*
	 * Immediate exit (parere #24 di Astra): VMX preemption timer a 0 nel
	 * VMCS02, armato da L0 quando rinvia un interrupt dell'L1 perche' l'L2
	 * ha un evento da consegnare. imm_ok: la CPU ha il timer nei controlli
	 * pin. imm_armed: il bit nel VMCS02 corrente e' di L0, non dell'L1.
	 */
	bool		imm_ok;
	bool		imm_armed;
	struct timeval	msrbm_warn_t;	/* ratelimit: bitmap L1 non mappabile */
	int		msrbm_warn_n;
	uint64_t	*vept_root;	/* radice shadow EPT (T2.7), NULL se assente */
	uint64_t	vept_eptp12;	/* EPTP12 che la shadow rispecchia */
	uint16_t	vpid2;		/* VPID distinto per L2 (T2.8) */
	/* audit VPID (parere #48): ultimo VPID12 entrato, e se l'uscita L2->L1
	 * avviene dentro vmx_run (sezione critica sulla CPU del prossimo
	 * ingresso) o nello slow path */
	uint16_t	last_vpid12;
	bool		last_vpid12_ok;
	bool		in_run;
	bool		vpid02_flush_pending;	/* INVVPID(VPID02) prima del prossimo ingresso in L2 */
	/* vpid_track (parere #48 §5): campi host e TLB separati da lastcpu.
	 * Le CPU sono memorizzate +1, 0 = nessuna. */
	bool		vpid_track;	/* fissato alla creazione del vCPU nested */
	bool		vpid02_off;	/* vpid_track con VPID02 non unico (VPID01,
					 * spazio di riserva, 0): VMCS02 SENZA VPID,
					 * l'hardware invalida a ogni ingresso/uscita */
	int		vmcs01_host_cpu1;	/* CPU dei campi host del VMCS01 */
	int		vpid02_lastcpu1;	/* CPU dove il TLB del VPID02 e' coerente */
	bool		restart_only;	/* uscita L2 gia' riflessa: lo slow path
					 * deve solo far ripartire vmx_run */
	bool		synth;		/* uscita L2->L1 SINTETICA (nessuna uscita
					 * hardware): i campi d'uscita per il
					 * VMCS12 vengono da synth_intr_info */
	uint32_t	synth_intr_info;
	uint64_t	synth_qual;	/* qualificazione dell'uscita sintetica */
	bool		ept_pending;	/* EPT violation di L2 da risolvere nello
					 * slow path (shadow EPT), restando in L2 */
	uint64_t	ept_gpa;	/* suo GPA di L2, catturato in uscita */
	uint64_t	ept_qual;	/* sua qualificazione (tipo d'accesso) */
	struct vm_exit	ept_emul;	/* paging dell'L2 per un'eventuale
					 * emulazione MMIO (vmexit_inst_emul,
					 * col VMCS02 ancora caricato) */
	bool		emu_viol;	/* sessione 1d: EPT violation trovata
					 * dall'EMULATORE (A/D in una tabella
					 * dell'L2 su una pagina senza W in
					 * EPT12), da riflettere all'L1 prima
					 * del prossimo ingresso in L2 */
	uint64_t	emu_viol_gpa;	/* GPA dell'L2 della voce di tabella */
	uint64_t	emu_viol_gla;	/* indirizzo lineare che si traduceva */
	/*
	 * WSL2-FreeBSD 003 (diagnostica, sysctl nested_diag_pf): #PF di fetch
	 * in modo supervisore dell'L2 intercettato da L0 nel VMCS02 quando il
	 * VMCS12 non intercetta i #PF. Nessun cambio di comportamento: si
	 * registra, si fa il walk nello slow path e si rientra in L2 per UN
	 * ingresso senza intercetto, cosi' il processore riesegue l'istruzione.
	 */
	bool		diag_pf_armed;	/* il VMCS02 intercetta per noi */
	bool		diag_pf_rearm;	/* riarmare alla prossima uscita da L2 */
	bool		diag_pf_pending; /* walk da fare nello slow path */
	uint32_t	diag_pf_ec;	/* codice d'errore del #PF */
	uint32_t	diag_pf_idtv;	/* IDT-vectoring info dell'uscita */
	uint32_t	diag_pf_ss_ar;	/* diritti di SS (CPL) */
	uint64_t	diag_pf_rip;
	uint64_t	diag_pf_qual;	/* indirizzo lineare del fault */
	uint64_t	diag_pf_cr0;
	uint64_t	diag_pf_cr3;
	uint64_t	diag_pf_cr4;
	uint64_t	diag_pf_efer;
	uint64_t	emu_viol_qual;	/* qualificazione per il VMCS12 */
	uint64_t	emu_viol_vmcs12; /* VMCS12 corrente alla produzione:
					  * la riflessione va a QUELLO (#110 §3) */
	uint32_t	emu_viol_reason; /* H2: EXIT_REASON_EPT_FAULT (48) o
					  * EXIT_REASON_EPT_MISCONFIG (49) */
	bool		slow_reflect;	/* riflessione chiamata dallo slow path:
					 * MSR del guest in guest_msrs[], NON nei
					 * registri hardware */
	uint64_t	l1_tsc_offset;	/* TSC offset del VMCS01 al VMLAUNCH */
	uint64_t	l2_exit_rip;	/* RIP dell'L2 all'ultima uscita (~0: nessuna
					 * dal VMLAUNCH/VMRESUME): se all'ingresso e'
					 * cambiato, L0 ha completato un'istruzione */
	uint64_t	exit_tsc;	/* TSC host all'ultima uscita da L2 */
	bool		preempt_on;	/* timer di preemption dell'L1 attivo */
	uint64_t	vapic_hpa;	/* pagina host della virtual-APIC dell'L1
					 * (TPR shadow nel VMCS02); 0 = nessuna */
	uint64_t	apicacc_hpa;	/* pagina host della APIC-access dell'L1
					 * ("virtualize APIC accesses" nel VMCS02);
					 * 0 = l'L1 non lo chiede o non e' RAM */
	uint64_t	preempt_deadline; /* sua scadenza, TSC host assoluto */
	int		preempt_rate;	/* IA32_VMX_MISC[4:0] */
	uint64_t	pdpte[4];	/* PDPTE dell'L2 letti dalla memoria di CR3 */
	bool		pdpte_mem;	/* ...da usare nel VMCS02 (PAE senza EPT12) */
	bool		pdpte_bad;	/* uno ha bit riservati: VM-entry fallito */
	bool		gs_bad;		/* stato guest non valido rilevato in
					 * software (campi che il VMCS02 non usa
					 * cosi' come sono: GUEST_PAT) */
	uint64_t	l1_efer;	/* EFER dell'L1 al VMLAUNCH */
	bool		launching;	/* VMLAUNCH in corso: se il primo ingresso
					 * fallisce il VMCS12 torna clear */
	bool		l1_tsc_dirty;	/* l1_tsc_offset cambiato (IA32_TSC in una
					 * lista d'ingresso): da riportare nel
					 * VMCS01 alla prossima uscita */
	int		msr_phase;	/* 1 lista d'ingresso (VMCS02 corrente),
					 * 2 lista load d'uscita (VMCS01) */
	uint64_t	l1_dr7;		/* DR7/DEBUGCTL dell'L1 al VMLAUNCH: */
	uint64_t	l1_debugctl;	/* li eredita l'L2 senza load debug */
	/*
	 * Campi d'uscita CATTURATI col VMCS01 corrente (in vmx_exit_process),
	 * perche' nel slow path (vm_run, vCPU FROZEN) il VMCS NON e' caricato e
	 * una vmcs_read grezza panica ("vmcs_read error 1"). Il gestore nested
	 * usa questi invece di rileggere; per lo stato guest usa l'API registri.
	 */
	uint64_t	exit_qual;	/* VMCS_EXIT_QUALIFICATION */
	uint64_t	exit_insn_info;	/* VMCS_EXIT_INSTRUCTION_INFO */
	uint64_t	exit_insn_length; /* VMCS_EXIT_INSTRUCTION_LENGTH */
	struct vm_guest_paging exit_paging; /* cr3/cpl/cpu_mode/paging_mode */
	/*
	 * Radici shadow per EPTP12 (in coda: gli offset sopra servono a
	 * DTrace). vept_root/vept_eptp12 sono la radice CORRENTE, una di
	 * queste. Hyper-V con la VBS alterna due EPT (VTL0/VTL1) ~1300 volte
	 * al secondo: con una radice sola ogni cambio la svuotava per intero
	 * (logs/win11-flush-191817.txt). Come il TLB, una radice resta valida
	 * finche' l'L1 non fa INVEPT.
	 */
#define	VEPT_NROOTS	4
	struct vept_slot {
		uint64_t	*root;		/* NULL: slot libero */
		uint64_t	eptp12;
		uint64_t	used;		/* ultimo uso (vept_tick), LRU */
	}		vept_slot[VEPT_NROOTS];
	uint64_t	vept_tick;
	/*
	 * Diagnostica, in coda per non spostare gli offset che DTrace usa.
	 * La SIM page si aggancia una volta, al WRMSR della SIMP, e si tiene
	 * (vm_gpa_hold_global): il percorso d'ingresso deve solo dereferenziare.
	 */
	void		*diag_simp_ck;	/* cookie della pagina tenuta */
	volatile uint8_t *diag_simp;	/* sua KVA, NULL se non agganciata */
	uint64_t	diag_simp_gpa;	/* suo GPA */
	struct nested_diag diag;
	/*
	 * Diagnostica della shadow EPT (fase C, parere #25 di Astra): per ogni
	 * radice, le tabelle EPT12 attraversate per costruirla con la loro
	 * PRIMA fotografia. Solo con hw.vmm.vmx.vept_diag; in coda per non
	 * spostare gli offset usati da DTrace.
	 */
	struct vept_obs	*vept_obs[VEPT_NROOTS];
	/*
	 * B1 (parere #28 di Astra): shadow EPT conservata all'INVEPT, con
	 * invalidazione per intervallo delle sole traduzioni che dipendono da
	 * voci EPT12 cambiate. vept_keep e' hw.vmm.vmx.vept_keep letto alla
	 * creazione del nested: spento, tutto come prima (31b286d).
	 */
	bool		vept_keep;
	bool		vept_ad;	/* fase A2: A/D attivi sulla radice CORRENTE (EPTP12 bit 6) */
	bool		vept_memgen_pending;	/* vmx_run: generazione cambiata */
	bool		vept_flush_pending;	/* shadow ridotta: INVEPT hw dovuto */
	struct vept_kslot {
		uint64_t	memgen;		/* generazione dei mapping di L0 */
		uint64_t	leaves;		/* foglie shadow vive */
		bool		nokeep;		/* foglia non wired o MMIO */
		bool		force_full;	/* il prossimo INVEPT svuota tutto */
		bool		wipe_now;	/* walk: svuotare prima di rientrare */
		/* verifica HPA (parere #31): reservoir di L2-GPA di foglie
		 * installate dall'ultimo svuotamento, niente puntatori */
#define	VEPT_VS_N	128
		uint64_t	vs_gpa[VEPT_VS_N];
		uint64_t	vs_n;		/* foglie viste dallo svuotamento */
		uint64_t	vs_rng;		/* xorshift64 */
		uint32_t	vs_start;	/* rotazione fra un INVEPT e l'altro */
	}		vept_ks[VEPT_NROOTS];
	/*
	 * Parere #30 §3: tempo di guest in L2 e in L1 e ingressi in L2, contati
	 * per vCPU nel percorso veloce (niente variabili condivise) e versati
	 * nei contatori globali hw.vmm.vmx.nested_* nello slow path.
	 */
	uint64_t	st_l2_entries;
	uint64_t	st_l2_tsc;
	uint64_t	st_l1_tsc;
	/*
	 * Parere #39 §5/§6.2/§7: contatori del percorso EPT02 e degli hold delle
	 * tabelle EPT12, per vCPU (stesso schema dei precedenti), versati nei
	 * globali hw.vmm.vmx.vst_* da vept_stats_flush.
	 */
	uint64_t	st_vept[64];
	uint64_t	st_vept_pk_peak;	/* massimo di riferimenti tenuti */
	uint64_t	st_tmax[4];	/* parere #41 §6: massimi dei tratti, cicli */
	/*
	 * Strumentazione INVEPT (parere #53 §8), SOLO diagnostica, in coda per
	 * non spostare gli offset DTrace precedenti. Classifica la causa di ogni
	 * INVEPT shadow a ogni ingresso in L2; non cambia il comportamento.
	 * vept_flush_cause: bit 1 = INVEPT di L1, bit 2 = voci EPT12 cambiate (B1).
	 * vept_invept_cpu1[i]: CPU+1 dell'ultimo INVEPT per lo slot i (0 = mai).
	 */
	uint8_t		vept_flush_cause;
	uint8_t		vept_invept_cpu1[VEPT_NROOTS];
	/*
	 * Parere #58 §4: gancio diagnostico SOLO lettura, in coda per non
	 * spostare gli offset DTrace precedenti. Progressivo per-vCPU degli
	 * eventi diag58 (exit L2 e INVEPT fisico). Non cambia il comportamento.
	 */
	uint32_t	diag58_seq;
	/*
	 * Parere Opus WSL2-FreeBSD 009 §1: ultimo INVEPT dell'L1 elaborato da
	 * QUESTO vCPU (progressivo, TSC, radici conservate/svuotate), letto
	 * dalla cattura nested_diag_pfinj. In coda: offset DTrace invariati.
	 */
	uint64_t	diag_invept_seq;
	uint64_t	diag_invept_tsc;
	int		diag_invept_kept;
	int		diag_invept_wiped;
	uint64_t	diag_invept_type;	/* parere di Astra 010 §4 */
	uint64_t	diag_invept_eptp;
	/* parere di Astra 010: episodio E0/E1 in corso su questo vCPU */
	struct nested_pfrec pfst;
	bool		pfrec_building;	/* E0 fatto, manca E1 (in questa uscita) */
	bool		pfrec_need_walk;	/* E1 scalari fatti, walk dopo il VMCLEAR */
	uint64_t	pfrec_eptp12;	/* EPTP12 per il walk differito */
	bool		pfrec_armed;	/* E0+E1 fatti, si attende l'ingresso */
	uint64_t	pfrec_seq;
};
void	nested_stats_flush(struct vmx_vcpu *vcpu);

int	vmx_nested_init(struct vmx_vcpu *vcpu);
int	vmx_nested_exit(void *vcpui);
void	nested_vmx_result(struct vmx_vcpu *vcpu, int errnum);
void	nested_vmfail_invalid(struct vmx_vcpu *vcpu);
/* Eventi dell'L1 da consegnare prima di rientrare in L2 (vmx_run). */
void	nested_preempt_refresh(struct vmx_vcpu *vcpu);
bool	nested_l1_intercepts_extint(struct vmx_vcpu *vcpu);
bool	nested_check_events(struct vmx_vcpu *vcpu, struct vm_exit *vmexit,
	    uint64_t rip);
/* Sonde d'arresto controllato (hw.vmm.vmx.nested_probe, vmx.c). */
extern int vmx_nested_probe;
void	nested_probe_dump(const char *tag);
int	vmx_nested_vmcs02_setup(struct vmcs12_cache *c);
void	vmx_nested_free(struct vmx_vcpu *vcpu);
/* Cattura diagnostica (hw.vmm.vmx.diag_vec); sola lettura, vedi nested_diag. */
void	nested_diag_pre_entry(struct vmx_vcpu *vcpu);
void	nested_diag_post_exit(struct vmx_vcpu *vcpu, struct vm_exit *vmexit);
/* true se il bit INT_WINDOW del VMCS02 e' soltanto di L0 (vedi vmx_nested.c) */
bool	nested_l0_owns_int_window(struct vmx_vcpu *vcpu);
/* cattura lo stato al #UD in L2 (hw.vmm.vmx.diag_ud); sola lettura */
void	nested_diag_ud_capture(struct vmx_vcpu *vcpu, struct vm_exit *vmexit);
void	nested_diag_efer_trace(struct vmx_vcpu *vcpu, struct vmcs12_cache *c);
/* richiesta d'invalidazione del VPID02 (semantica dei contatori sopra) */
static __inline void
nested_vpid02_request(struct vmx_nested *n)
{

	atomic_add_long(&vpid02_req, 1);
	if (n->vpid02_flush_pending)
		atomic_add_long(&vpid02_req_coalesced, 1);
	n->vpid02_flush_pending = true;
}
#endif /* _KERNEL */

#endif /* _VMX_NESTED_H_ */
