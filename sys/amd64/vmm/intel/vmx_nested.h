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
/* esiti di vmx_vept_fault */
#define	VEPT_OK		0	/* shadow installata */
#define	VEPT_VIOL	1	/* EPT violation da riflettere all'L1 */
#define	VEPT_MISCONF	2	/* EPT misconfiguration da riflettere all'L1 */
#define	VEPT_MMIO	3	/* MMIO dell'L1: emulazione in L0 */
int	vmx_vept_fault(struct vmx_vcpu *vcpu, uint64_t l2gpa, uint64_t qual,
	    uint64_t *l1gpa, uint64_t *perm);			/* slow path */
uint64_t vmx_vept_shadow_entry(struct vmx_vcpu *vcpu, uint64_t l2gpa);
int	vmx_vept_l1gpa(struct vmx_vcpu *vcpu, uint64_t gpa, int prot,
	    uint64_t *out);
void	vmx_vept_flush(struct vmx_nested *n);
void	vmx_vept_invept(struct vmx_nested *n);	/* svuota tutte, tiene le radici */
void	vmx_vept_prepare(struct vmx_vcpu *vcpu);	/* puo' dormire */
uint64_t vmx_vept_eptp(struct vmx_vcpu *vcpu);	/* shadow EPTP per VMCS02 */
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
	uint64_t	*vept_root;	/* radice shadow EPT (T2.7), NULL se assente */
	uint64_t	vept_eptp12;	/* EPTP12 che la shadow rispecchia */
	uint16_t	vpid2;		/* VPID distinto per L2 (T2.8) */
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
};

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
#endif /* _KERNEL */

#endif /* _VMX_NESTED_H_ */
