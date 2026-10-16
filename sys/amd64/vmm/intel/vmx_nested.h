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
int	vmx_vept_fault(struct vmx_vcpu *vcpu);	/* EPT violation in L2 (T2.7) */
void	vmx_vept_flush(struct vmx_nested *n);
uint64_t vmx_vept_eptp(struct vmx_vcpu *vcpu);	/* shadow EPTP per VMCS02 */
struct vmcs12_cache *nested_current_cache(struct vmx_nested *n);
uint64_t vmcs12_read_field(struct vmcs12_cache *c, uint32_t enc);
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

struct vmcs12_cache {
	uint64_t	vmcs12_gpa;	/* GPA del VMCS12; VMCS12_GPA_NONE = libera */
	void		*vmcs02;	/* pagina VMCS02, allocata pigramente (T1.8) */
	int		ref_cnt;
	int		launched;	/* launch state di questo VMCS02 */
	bool		host_dirty;	/* host-state da ricomporre */
	bool		control_dirty;	/* controlli da ricomporre */
	struct vmcs12_field fields[VMCS12_NFIELDS];  /* store software (T1.8) */
	int		nfields;
};

/*
 * Stato della virtualizzazione VMX annidata, per vCPU. Allocato quando la
 * capability passa 0->1 (vmx_nested_init), liberato a 1->0 e al cleanup del
 * vCPU (vmx_nested_free). Mai condiviso fra vCPU.
 */
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
};

int	vmx_nested_init(struct vmx_vcpu *vcpu);
int	vmx_nested_exit(void *vcpui);
void	nested_vmx_result(struct vmx_vcpu *vcpu, int errnum);
void	nested_vmfail_invalid(struct vmx_vcpu *vcpu);
int	vmx_nested_vmcs02_setup(struct vmcs12_cache *c);
void	vmx_nested_free(struct vmx_vcpu *vcpu);
#endif /* _KERNEL */

#endif /* _VMX_NESTED_H_ */
