/*-
 * Copyright (C) 2021-2022 Intel Corporation.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Derivato da projectacrn/acrn-hypervisor (hypervisor/arch/x86/guest:
 * nested.c). Intestazione e clausola 3 di ACRN conservate.
 *
 * Copyright (c) 2026 Marietto.
 *
 * VMX annidato per vmm (piano nested v2). T1.3: ciclo di vita dello stato
 * nested per vCPU (alloc su 0->1 della capability, free a 1->0 e al cleanup
 * del vCPU), piu' i contatori vmm_stat e le probe SDT che i task successivi
 * sparano. Nessuna logica di esecuzione annidata ancora: quella arriva da
 * T1.7 in poi.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <machine/clock.h>	/* tsc_freq: parere Opus 009 §1 */
#include <sys/sbuf.h>		/* parere di Astra 010: record E0/E1/E2 */
#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>
#include <machine/cpufunc.h>
#include <machine/psl.h>
#include <machine/specialreg.h>
#include <machine/md_var.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>
#include "vmx_cpufunc.h"
#include "vmx_controls.h"
#include "vmx.h"
#include "vmx_msr.h"
#include "vmx_nested.h"
#include "vmm_stat.h"
#include "vmm_host.h"
#include "io/vlapic.h"
#include <dev/vmm/vmm_mem.h>

MALLOC_DEFINE(M_VMX_NESTED, "vmx_nested", "Intel VMX nested virtualization");

uint32_t
vmcs12_proc2(struct vmcs12_cache *c)
{
	if ((vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_SECONDARY_CONTROLS) == 0)
		return (0);
	return ((uint32_t)vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS));
}

static void	nested_bitmaps_unmap(struct vmcs12_cache *c);
static void	nested_msr_list_unmap(struct nested_msr_list *l);
static int	nested_bitmaps_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c);
static void	nested_msr_list_exit(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c, bool store);
static uint32_t	nested_msr_list_entry(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c);
static void	nested_reflect_to_l1(struct vmx_vcpu *vcpu,
		    struct vm_exit *vmexit);
/* S0 e shadow VMCS (pareri #43/#44): definiti piu' sotto */
static struct sx nested_field_tab_sx;
static int	nested_fast_field_validate;
static int	nested_shadow_vmcs;
static int	nested_vpid_track;
static int	nested_vpid_test_off;
static u_long	vpid02_off_vcpus;
static int	nested_vpid_d4_arm;
static void	nested_diag_pf_arm(struct vmx_vcpu *vcpu);
static void	nested_diag_pfrec_entry(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c);
static void	nested_pfrec_cap_e0(struct vmx_vcpu *vcpu);
static void	nested_pfrec_cap_e1(struct vmx_vcpu *vcpu);
static void	nested_diag_pfinj_note(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c);	/* WSL2-FreeBSD 003 */
static u_long	nested_vpid_d4_injected;
static void	nested_field_tab_build(void);
static int	shv_global_init(void);
static int	shvmcs_pull(struct vmx_vcpu *vcpu);
static void	shvmcs_set_current(struct vmx_nested *n, struct vmcs12_cache *c);
static void	shvmcs_mark(struct vmx_nested *n, struct vmcs12_cache *c,
		    uint32_t enc);

/*
 * Probe SDT del nested. Non si sparano ancora (lo faranno T1.7+); definirle
 * qui le rende visibili da subito a dtrace: vmm:vmx:nested:*.
 */
SDT_PROVIDER_DECLARE(vmm);
SDT_PROBE_DEFINE1(vmm, vmx, nested, enter_l2, "struct vmx_vcpu *");
SDT_PROBE_DEFINE1(vmm, vmx, nested, reflect, "struct vmx_vcpu *");
SDT_PROBE_DEFINE2(vmm, vmx, nested, synth_exit, "struct vmx_vcpu *", "int");
SDT_PROBE_DEFINE1(vmm, vmx, nested, slowpath, "struct vmx_vcpu *");
SDT_PROBE_DEFINE2(vmm, vmx, nested, shadow_fill, "struct vmx_vcpu *", "uint64_t");
SDT_PROBE_DEFINE2(vmm, vmx, nested, vmfail, "struct vmx_vcpu *", "int");
SDT_PROBE_DEFINE1(vmm, vmx, nested, init_latched, "struct vmx_vcpu *");
/* decisione di nested_check_events: pin del VMCS12, interrupt dell'L1 in
 * attesa (0/1) e suo vettore */
SDT_PROBE_DEFINE4(vmm, vmx, nested, chkev, "struct vmx_vcpu *", "uint64_t",
    "int", "int");
/* fine composizione del VMCS02: entry intr info, pin, proc del VMCS12, e
 * (RFLAGS << 32 | interrompibilita') dell'L2 */
SDT_PROBE_DEFINE5(vmm, vmx, nested, compose, "struct vmx_vcpu *", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
/* EPT violation nel percorso veloce (VMCS02 caricato): eptp hardware, eptp
 * shadow da vept_root, gpa in fault, qualificazione. Per il ciclo infinito. */
SDT_PROBE_DEFINE5(vmm, vmx, nested, eptviol, "struct vmx_vcpu *", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
/*
 * Cattura diagnostica dell'ingresso che inietta hw.vmm.vmx.diag_vec. Le tre
 * sonde descrivono lo STESSO istante (lo stato e' fotografato prima
 * dell'ingresso hardware e sparato al VM-exit, dove le sonde sono lecite):
 *   diag_entry(vcpu, entry_info | intblk<<32, rip, msgtype | msghdr<<32,
 *              ExpirationTime, rflags)
 *   diag_exit (vcpu, exit_reason | idt_vectoring<<32, exit_intr_info,
 *              rip d'uscita, vmptrst, eptp12)
 *   diag_more (vcpu, DeliveryTime, activity | ENTRY_INST_LENGTH<<32,
 *              eptp del VMCS02, rsp, eptp12)
 * e diag_simp(vcpu, gpa della SIM page, valore scritto nella SIMP).
 */
SDT_PROBE_DEFINE6(vmm, vmx, nested, diag_entry, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(vmm, vmx, nested, diag_exit, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(vmm, vmx, nested, diag_more, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(vmm, vmx, nested, diag_simp, "int", "uint64_t", "uint64_t");
/*
 * EFER del VMCS02 a ogni ingresso in L2 (parere #19 di Astra). Per capire
 * dove si perde SCE: all'ingresso iniziale vs ricomposizioni successive, e se
 * la VM-entry MSR-load list del VMCS12 carica IA32_EFER.
 * efer(vcpuid, VMCS12.GUEST_IA32_EFER, VMCS02.GUEST_IA32_EFER dopo compose+lista,
 *      l1_efer, entry_ctls12, (lista_efer_presente<<32 | lista_efer_valore_basso))
 */
SDT_PROBE_DEFINE6(vmm, vmx, nested, efer, "int", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE4(vmm, vmx, nested, efer2, "int", "uint64_t", "uint64_t", "uint64_t");  /* vcpuid, eptp12, efer02, current_vmcs12 */
/*
 * Bitmap MSR del VMCS02 fusa (T6.3, parere #21 di Astra), a ogni compose.
 * msrbm(vcpuid, VMCS02.MSR_BITMAP riletto, efer, syse, flags):
 *   efer = byte c0000080..87 (EFER bit0, STAR 1, LSTAR 2, CSTAR 3, SFMASK 4)
 *          R01 | W01<<8 | R12<<16 | W12<<24 | R02<<32 | W02<<40
 *   syse = idem per il byte di 0x170..0x177 (SYSENTER_CS/ESP/EIP bit 4..6)
 *   flags = bit0 VMCS12 usa le bitmap MSR, bit1 bitmap dell'L1 mappata,
 *           bit2 VMCS02 ha PROCBASED_MSR_BITMAPS
 */
SDT_PROBE_DEFINE5(vmm, vmx, nested, msrbm, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t");
/*
 * Persistenza del VMCS12 (parere #22). vmcs12mem(vcpuid, gpa, op, nfields,
 * launched, digest): op 1 salvato da VMCLEAR, 2 salvato da sfratto, 3 salvato
 * da VMXOFF, 4 VMCLEAR di un VMCS12 non in cache (solo launch state), 5
 * VMCLEAR che inizializza il formato (pagina mai vista), 6 caricato da
 * VMPTRLD, 7 VMPTRLD senza formato (slot vuoto), 8 formato corrotto
 * (VMPTRLD rifiutato; su VMCLEAR si reinizializza), 9 regione non mappabile.
 */
SDT_PROBE_DEFINE6(vmm, vmx, nested, vmcs12mem, "int", "uint64_t", "int",
    "int", "int", "uint32_t");
/*
 * Immediate exit (parere #24). immexit(vcpuid, op, kind): op 1 armato (kind =
 * tipo del rinvio, 1 evento in ENTRY_INTR_INFO, 2 in exitintinfo), 2 uscita
 * del timer di L0 arrivata, 3 rinvio senza immediate exit perche' l'L1 usa il
 * suo timer, 4 CPU senza preemption timer.
 */
SDT_PROBE_DEFINE3(vmm, vmx, nested, immexit, "int", "int", "int");
/* INVEPT dell'L1 (parere #24): invept(vcpuid, tipo, eptp del descrittore,
 * radici shadow svuotate). */
SDT_PROBE_DEFINE4(vmm, vmx, nested, invept, "int", "int", "uint64_t", "int");
/* Parere #29 §4: invept2(vcpuid, RIP dell'L1, VMCS12 corrente, tipo, eptp del
 * descrittore, radici svuotate | conservate << 16). */
SDT_PROBE_DEFINE6(vmm, vmx, nested, invept2, "int", "uint64_t", "uint64_t",
    "int", "uint64_t", "uint64_t");
/*
 * Uscita INTR_WINDOW da L2 gestita da L0: chi possedeva il bit nel VMCS02.
 * owner 0 = solo L0 (nested_compose_vmcs02, T2.6): atteso. owner 1 = anche
 * il VMCS12 lo chiedeva: INVARIANTE VIOLATO, nested_l2_exit doveva riflettere.
 */
SDT_PROBE_DEFINE3(vmm, vmx, nested, winexit, "int", "int", "uint64_t");
/*
 * Rinvio dell'interrupt dell'L1 in nested_check_events: kind 1 = evento
 * dell'L2 ancora in VMCS02.ENTRY_INTR_INFO (composto dal VMCS12); kind 2 =
 * evento dell'L2 in exitintinfo (consegna interrotta da una EPT violation
 * sullo shadow, da reiniettare). info = l'evento che si protegge; vec =
 * l'interrupt dell'L1 rinviato, che NON viene accettato.
 */
SDT_PROBE_DEFINE4(vmm, vmx, nested, defer, "int", "int", "uint64_t", "int");
/*
 * Cattura diagnostica del #UD che uccide smss (parere #18 di Astra). Sola
 * lettura, gated da hw.vmm.vmx.diag_ud. Scatta all'uscita hardware da L2 col
 * VMCS02 ancora caricato, PRIMA di nested_l2_exit/riflessioni/save_idtvec,
 * quando l'uscita e' causata da #UD (exception exit, bitmap[6]=1) o avviene
 * durante la sua consegna (IDT_VECTORING = vettore 6). I campi bastano a
 * tradurre il RIP (CR3, con attenzione a PCID/LA57 lato script) e a decidere
 * istruzione-illegale vs consegna (VM_EXIT_INTR_INFO vs IDT_VECTORING, e le
 * exception bitmap di VMCS02 e VMCS12).
 */
SDT_PROBE_DEFINE6(vmm, vmx, nested, ud_a, "int", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(vmm, vmx, nested, ud_b, "int", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(vmm, vmx, nested, ud_c, "int", "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");


SYSCTL_DECL(_hw_vmm_vmx);		/* il nodo e' definito in vmx.c */

/*
 * Vettore da catturare all'ingresso in L2; 0 = diagnostica spenta (difetto).
 * Per il tick della root di Hyper-V: 0xd1 (SINT3 di STIMER0).
 */
static int nested_diag_vec = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, diag_vec, CTLFLAG_RWTUN, &nested_diag_vec, 0,
    "nested: vettore la cui iniezione in L2 va fotografata (0 = spenta)");
/* Offset dello slot di messaggio nella SIM page: SINTx sta a x * 256. */
static int nested_diag_slot = 0x300;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, diag_slot, CTLFLAG_RWTUN, &nested_diag_slot,
    0, "nested: offset dello slot SINT nella SIM page (SINT3 = 0x300)");
static int nested_diag_ud = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, diag_ud, CTLFLAG_RWTUN, &nested_diag_ud, 0,
    "nested: cattura lo stato al #UD in L2 (0 = spenta)");
static int nested_diag_efer = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, diag_efer, CTLFLAG_RWTUN, &nested_diag_efer, 0,
    "nested: traccia l'EFER del VMCS02 a ogni ingresso in L2 (0 = spenta)");

/* Contatori per vCPU (bhyvectl --get-stats). */
VMM_STAT_INTEL(VMX_NESTED_L2_ENTRIES, "ingressi in L2");
VMM_STAT_INTEL(VMX_NESTED_REFLECTIONS, "exit riflesse all'L1");
VMM_STAT_INTEL(VMX_NESTED_SYNTH_EXITS, "exit sintetiche verso l'L1");
VMM_STAT_INTEL(VMX_NESTED_SLOWPATH, "exit nested gestite nello slow path");

/*
 * Parere #30 §3: EPT violation dell'L2 risolte da L0 (shadow costruita) contro
 * quelle che Hyper-V vede davvero (riflesse all'L1), e tempo di guest in L2 e
 * in L1. Contatori leggeri per tutta la campagna; la sonda veptrefl per le
 * tracce brevi dettagliate.
 */
#define	NESTED_CTR(name, descr)						\
	static u_long name;						\
	SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, name, CTLFLAG_RD, &name, 0, descr)
NESTED_CTR(nested_ept02_faults_l0, "nested: EPT violation dell'L2 risolte da L0");
NESTED_CTR(nested_ept_mmio_emulated,
    "nested: EPT violation dell'L2 emulate come MMIO dell'L1");
NESTED_CTR(nested_ept12_viol_reflected,
    "nested: EPT violation riflesse all'L1 (Hyper-V le vede)");
/* #135 Fase C: VEPT_MMIO non emulabile (EPT12 concede, nessun backing in L0): fermato, MAI riflesso all'L1 */
NESTED_CTR(nested_vept_mmio_unemulable,
    "nested: accessi di L2 senza backing in L0 non emulabili (vCPU fermato, nessuna riflessione)");
SDT_PROBE_DEFINE5(vmm, vmx, nested, veptunemul, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t");
/* #160 R3: operando di un'istruzione VMX dell'L1 che L0 non sa completare: fermato, MAI saltato */
NESTED_CTR(nested_operand_fatal,
    "nested: istruzioni VMX dell'L1 con operando non accessibile da L0 (vCPU fermato, istruzione non eseguita)");
SDT_PROBE_DEFINE5(vmm, vmx, nested, opndfatal, "int", "int", "int", "uint64_t",
    "uint64_t");
NESTED_CTR(nested_ept12_viol_emul_reflected,
    "nested: EPT violation trovate dall'emulatore (A/D senza W) riflesse");
NESTED_CTR(nested_ept12_viol_emul_stale,
    "nested: violazioni dell'emulatore trovate fuori da L2 (deve essere 0)");
NESTED_CTR(nested_ept12_viol_emul_nocache,
    "nested: violazioni dell'emulatore senza il loro VMCS12 (deve essere 0)");
NESTED_CTR(nested_ept12_misconf_reflected,
    "nested: EPT misconfiguration riflesse all'L1");
/*
 * WSL2-FreeBSD 003 (Claude 04/11/2026): diagnostica del #PF di fetch in modo
 * supervisore che manda in panic il guest FreeBSD (lapic_et_start+0x327). Con
 * nested_diag_pf=1, e solo se il VMCS12 non intercetta i #PF (bit 14, maschera
 * e confronto a 0), il VMCS02 intercetta i #PF con codice I=1 U=0. All'uscita
 * si registrano lo stato e il walk (vista dell'L1 attraverso EPT12 contro EPT02
 * ombra) nello slow path, poi si rientra in L2 per UN ingresso senza
 * intercetto: il processore riesegue l'istruzione e, se il fault si ripete,
 * lo consegna all'L2 come senza diagnostica. Spento di default.
 */
static int nested_diag_pf = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_diag_pf, CTLFLAG_RWTUN,
    &nested_diag_pf, 0,
    "nested: intercetta in diagnostica i #PF di fetch supervisore dell'L2 (WSL2-FreeBSD 003)");
NESTED_CTR(nested_diag_pf_hits,
    "nested: #PF di fetch supervisore dell'L2 intercettati in diagnostica");
NESTED_CTR(nested_diag_pf_vectoring,
    "nested: di questi, durante la consegna di un altro evento (IDT-vectoring valido)");
NESTED_CTR(nested_diag_pf_l1_exits,
    "nested: uscite #PF dell'L2 chieste dal VMCS12 (riflesse all'L1)");
NESTED_CTR(nested_diag_pf_skipped,
    "nested: armamenti saltati perche' il VMCS12 intercetta gia' i #PF");
/*
 * diagpf2: con nested_diag_pfinj=1, a ogni ingresso in L2 in cui l'L1 chiede
 * nel VMCS12 di iniettare un #PF (vettore 14, eccezione hardware), si contano;
 * se il codice d'errore ha il bit I (fetch) si stampano i campi d'uscita che
 * l'L1 ha letto dall'uscita precedente e il walk di CR2 e dell'RIP dell'L2,
 * EPT12 viva contro EPT02 ombra. Costo sul percorso normale: una lettura del
 * VMCS12 software. Nessun effetto sull'ingresso. Spento di default.
 */
static int nested_diag_pfinj = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_diag_pfinj, CTLFLAG_RWTUN,
    &nested_diag_pfinj, 0,
    "nested: registra i #PF iniettati dall'L1 nell'L2 (WSL2-FreeBSD 003)");
NESTED_CTR(nested_diag_pfinj_all, "nested: #PF iniettati dall'L1 nell'L2");
NESTED_CTR(nested_diag_pfinj_fetch,
    "nested: di questi, con il bit I (fetch) nel codice d'errore");
/*
 * Parere di Astra sul rapporto 010: episodi "uscita MMIO LAPIC dell'L2 riflessa
 * -> ingresso successivo" sullo stesso vCPU, con tre punti E0/E1/E2 copiati in
 * memoria preallocata (prenotazione atomica) e stampati da un sysctl. Si
 * sorvegliano solo i RIP della pagina nested_diag_pfrec_rippage (0 = ogni RIP
 * del kernel dell'L2). Spento di base.
 */
static int nested_diag_pfrec = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_diag_pfrec, CTLFLAG_RWTUN,
    &nested_diag_pfrec, 0, "nested: record E0/E1/E2 degli episodi MMIO LAPIC");
static u_long nested_diag_pfrec_rippage = 0xffffffff8120b000UL;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_diag_pfrec_rippage, CTLFLAG_RWTUN,
    &nested_diag_pfrec_rippage, 0, "nested: pagina dei RIP sorvegliati (0 = kernel)");
NESTED_CTR(nested_diag_pfrec_e0, "nested: episodi E0 (uscita LAPIC sorvegliata)");
NESTED_CTR(nested_diag_pfrec_ok, "nested: episodi chiusi senza eccezione");
NESTED_CTR(nested_diag_pfrec_pf_fetch, "nested: episodi con #PF di fetch");
NESTED_CTR(nested_diag_pfrec_pf_data, "nested: episodi con #PF dati");
NESTED_CTR(nested_diag_pfrec_other, "nested: episodi con altro evento");
#define	NESTED_PFREC_MAX	8
static struct nested_pfrec nested_pfrecs[NESTED_PFREC_MAX];
static u_int nested_pfrec_n;

static void
nested_pfrec_code_sbuf(struct sbuf *sb, const char *tag,
    const struct vept_diag_code *o)
{
	int i;

	sbuf_printf(sb, "  %s: pte %#lx %#lx %#lx %#lx fail_lvl=%d | pagina "
	    "l2gpa=%#lx EPT12 r=%d l1gpa=%#lx perm=%#lx hpa_l1=%#lx ombra=%#lx%s\n",
	    tag, (u_long)o->pte[0], (u_long)o->pte[1], (u_long)o->pte[2],
	    (u_long)o->pte[3], o->fail_lvl, (u_long)o->l2gpa, o->r,
	    (u_long)o->l1gpa, (u_long)o->perm, (u_long)o->hpa_l1,
	    (u_long)o->shadow, ((o->shadow & 0x7) != 0 && o->ok_l1 &&
	    (o->shadow & 0x000ffffffffff000ULL) != o->hpa_l1) ? " <-- HPA DIVERSO" : "");
	sbuf_printf(sb, "  %s: byte L1  ", tag);
	for (i = 0; i < o->nbytes && o->ok_l1; i++)
		sbuf_printf(sb, "%02x ", o->b_l1[i]);
	sbuf_printf(sb, "%s\n  %s: byte EPT02", o->ok_l1 ? "" : "(non letti)",
	    tag);
	for (i = 0; i < o->nbytes && o->ok_sh; i++)
		sbuf_printf(sb, " %02x", o->b_sh[i]);
	sbuf_printf(sb, "%s%s\n", o->ok_sh ? "" : " (nessuna foglia)",
	    (o->ok_l1 && o->ok_sh && memcmp(o->b_l1, o->b_sh, o->nbytes) != 0) ?
	    "  <-- BYTE DIVERSI" : "");
}

static void
nested_pfrec_gpr_sbuf(struct sbuf *sb, const char *tag, const uint64_t *g)
{
	sbuf_printf(sb, "  %s: rdi=%#lx rsi=%#lx rdx=%#lx rcx=%#lx r8=%#lx "
	    "r9=%#lx rax=%#lx rbx=%#lx rbp=%#lx r10=%#lx r11=%#lx r12=%#lx "
	    "r13=%#lx r14=%#lx r15=%#lx cr2=%#lx\n", tag, (u_long)g[0],
	    (u_long)g[1], (u_long)g[2], (u_long)g[3], (u_long)g[4],
	    (u_long)g[5], (u_long)g[6], (u_long)g[7], (u_long)g[8],
	    (u_long)g[9], (u_long)g[10], (u_long)g[11], (u_long)g[12],
	    (u_long)g[13], (u_long)g[14], (u_long)g[15]);
}

static int
sysctl_nested_pfrec_dump(SYSCTL_HANDLER_ARGS)
{
	struct sbuf *sb;
	struct nested_pfrec *p;
	u_int i, n;
	int error;

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	n = atomic_load_int(&nested_pfrec_n);
	if (n > NESTED_PFREC_MAX)
		n = NESTED_PFREC_MAX;
	sbuf_printf(sb, "\n%u record (max %d)\n", n, NESTED_PFREC_MAX);
	for (i = 0; i < n; i++) {
		p = &nested_pfrecs[i];
		if (atomic_load_acq_int(&p->done) == 0)
			continue;
		sbuf_printf(sb, "== episodio %u vcpu%d seq %lu: E1-E0 %lu tsc, "
		    "E2-E0 %lu tsc\n", i, p->vcpu, (u_long)p->seq,
		    (u_long)(p->t1 - p->t0), (u_long)(p->t2 - p->t0));
		sbuf_printf(sb, " E0 uscita: rip=%#lx cr3=%#lx gpa=%#lx gla=%#lx "
		    "qual=%#lx\n", (u_long)p->rip0, (u_long)p->cr3_0,
		    (u_long)p->gpa0, (u_long)p->gla0, (u_long)p->qual0);
		nested_pfrec_gpr_sbuf(sb, "E0", p->gpr0);
		nested_pfrec_code_sbuf(sb, "E0", &p->c0);
		sbuf_printf(sb, " E1 all'L1: motivo=%#lx rip=%#lx gpa=%#lx "
		    "gla=%#lx qual=%#lx\n", (u_long)p->reason1, (u_long)p->rip1,
		    (u_long)p->gpa1, (u_long)p->gla1, (u_long)p->qual1);
		nested_pfrec_gpr_sbuf(sb, "E1", p->gpr1);
		sbuf_printf(sb, " E2 ingresso: info=%#x err=%#x%s cr2=%#lx "
		    "rip=%#lx cr3=%#lx\n", p->info2, p->err2,
		    (p->info2 & (1U << 11)) ? "" : " (codice d'errore NON valido)",
		    (u_long)p->cr2_2, (u_long)p->rip2, (u_long)p->cr3_2);
		nested_pfrec_gpr_sbuf(sb, "E2", p->gpr2);
		nested_pfrec_code_sbuf(sb, "E2", &p->c2);
		sbuf_printf(sb, " ultimo INVEPT dell'L1 su questo vCPU: #%lu tipo=%lu "
		    "eptp=%#lx %lu tsc prima di E0, radici conservate=%d "
		    "svuotate=%d\n", (u_long)p->inv_seq, (u_long)p->inv_type,
		    (u_long)p->inv_eptp, (u_long)(p->t0 - p->inv_tsc),
		    p->inv_kept, p->inv_wiped);
	}
	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}
SYSCTL_PROC(_hw_vmm_vmx, OID_AUTO, nested_diag_pfrec_dump,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_nested_pfrec_dump, "A",
    "nested: record E0/E1/E2 degli episodi MMIO LAPIC con eccezione");
NESTED_CTR(nested_ept12_misconf_emul_reflected,
    "nested: EPT misconfiguration trovate dall'emulatore riflesse (H2)");
NESTED_CTR(nested_l2_entries, "nested: ingressi in L2");
NESTED_CTR(nested_l2_tsc, "nested: cicli TSC di guest in L2");
NESTED_CTR(nested_l1_tsc, "nested: cicli TSC di guest in L1 (vCPU nested)");
NESTED_CTR(nested_invept_ns_sum, "nested: tempo nel gestore INVEPT (ns)");
static u_long nested_invept_ns_max;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_invept_ns_max, CTLFLAG_RW,
    &nested_invept_ns_max, 0, "nested: massimo del gestore INVEPT (ns)");
/* veptrefl(vcpuid, eptp12, l2gpa, qualificazione, esito, HOST_RIP del VMCS12) */
SDT_PROBE_DEFINE6(vmm, vmx, nested, veptrefl, "int", "uint64_t", "uint64_t",
    "uint64_t", "int", "uint64_t");

void
nested_stats_flush(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;

	if (n->st_l2_entries != 0)
		atomic_add_long(&nested_l2_entries, n->st_l2_entries);
	if (n->st_l2_tsc != 0)
		atomic_add_long(&nested_l2_tsc, n->st_l2_tsc);
	if (n->st_l1_tsc != 0)
		atomic_add_long(&nested_l1_tsc, n->st_l1_tsc);
	n->st_l2_entries = n->st_l2_tsc = n->st_l1_tsc = 0;
	vept_stats_flush(n);
}
VMM_STAT_INTEL(VMX_NESTED_VMFAIL, "VMfailValid restituiti all'L1");
VMM_STAT_INTEL(VMX_NESTED_VMFAIL_INVALID, "VMfailInvalid restituiti all'L1");
VMM_STAT_INTEL(VMX_NESTED_MSRBM_UNMAPPED,
    "bitmap MSR dell'L1 attiva ma non mappabile");
VMM_STAT_INTEL(VMX_NESTED_VMCS12_SAVED, "VMCS12 salvati in memoria");
VMM_STAT_INTEL(VMX_NESTED_VMCS12_LOADED, "VMCS12 caricati dalla memoria");
VMM_STAT_INTEL(VMX_NESTED_VMCS12_MEMERR,
    "VMCS12: regione corrotta o non mappabile");
VMM_STAT_INTEL(VMX_NESTED_IMMEXIT_ARMED, "immediate exit armate da L0");
VMM_STAT_INTEL(VMX_NESTED_IMMEXIT_FIRED, "immediate exit arrivate");
VMM_STAT_INTEL(VMX_NESTED_IMMEXIT_L1TIMER,
    "rinvii senza immediate exit (timer dell'L1 in uso)");
VMM_STAT_INTEL(VMX_NESTED_INVEPT_SINGLE, "INVEPT single-context dell'L1");
VMM_STAT_INTEL(VMX_NESTED_INVEPT_ALL, "INVEPT all-context dell'L1");
VMM_STAT_INTEL(VMX_NESTED_VEPT_WIPED, "radici shadow EPT svuotate da INVEPT");

/*
 * Alloca lo stato nested del vCPU. Idempotente: se gia' presente, no-op.
 * Chiamata dal passaggio 0->1 della capability VM_CAP_NESTED_VIRT, in
 * contesto di processo (ioctl), quindi M_WAITOK e' ammesso.
 */
/*
 * Calcola i valori delle MSR di capability VMX esposti all'L1 (D4=C, set A
 * misurato dall'host), con le esclusioni di §6.3 e i must-be-1 di D4.b.
 * Derivati dalle MSR dell'host; il set esatto lo conferma test_vmx_caps di
 * kvm-unit-tests sull'hardware (T1.4 "Fatto quando").  I bit potrebbero
 * essere rifiniti dopo quel test: vedi docs/nested/T1.4.md.
 */
static void
vmx_nested_init_msrs(struct vmx_nested *n)
{
	uint64_t basic, misc, proc2, eptcap;
	uint64_t *m = n->vmx_msr;

	/* IA32_VMX_BASIC: revisione dell'host, dimensione 4096, memtype WB,
	 * bit 54 (report INS/OUTS) e 55 (true controls). */
	basic = rdmsr(MSR_VMX_BASIC);
	m[0x480 - 0x480] = (basic & 0x7fffffffULL) | (4096ULL << 32) |
	    (6ULL << 50) | (1ULL << 54) | (1ULL << 55);

	/* pin-based (legacy e true): host + ext-int(0) e NMI(3) exiting
	 * must-be-1 nelle allowed-0 (D4.b). */
	/* Pin-based ESPOSTO GREZZO, come sul ferro nudo (0x7F00000016 sul 9900K:
	 * ext-int/NMI NON forzati, preemption timer presente). Hyper-V accetta
	 * questo; se forzo ext-int/NMI (allowed-0 bit 0,3) li rifiuta e scarta
	 * anche il preemption timer (evt 46: allowed 0x3F0000001E vs 0x7F0000001F).
	 * Il forzamento per la sicurezza di L0 NON serve qui: lo rimette la
	 * composizione del VMCS02 (nested_compose_vmcs02: pin |= EXTINT|NMI). */
	m[0x481 - 0x480] = rdmsr(MSR_VMX_PINBASED_CTLS);
	m[0x48d - 0x480] = rdmsr(MSR_VMX_TRUE_PINBASED_CTLS);

	/* proc-based primary, exit, entry: come l'host. */
	m[0x482 - 0x480] = rdmsr(MSR_VMX_PROCBASED_CTLS);
	m[0x48e - 0x480] = rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS);
	/*
	 * Exit/entry: niente "clear IA32_BNDCFGS" (exit bit 23) ne' "load
	 * IA32_BNDCFGS" (entry bit 16): lo stato MPX non e' commutato ne'
	 * verificato per l'L2 (come KVM senza MPX). Prima li esponevamo e
	 * l'L1 si vedeva accettare GUEST_BNDCFGS non validi
	 * (vmx_guest_state_area_test).
	 */
	m[0x483 - 0x480] = rdmsr(MSR_VMX_EXIT_CTLS) & ~((1ULL << 23) << 32);
	m[0x48f - 0x480] = rdmsr(MSR_VMX_TRUE_EXIT_CTLS) & ~((1ULL << 23) << 32);
	m[0x484 - 0x480] = rdmsr(MSR_VMX_ENTRY_CTLS) & ~((1ULL << 16) << 32);
	m[0x490 - 0x480] = rdmsr(MSR_VMX_TRUE_ENTRY_CTLS) & ~((1ULL << 16) << 32);

	/* MISC: host senza PT (14), SMBASE (15), VMXOFF-unblock-SMI (28).
	 * TENGO il rate del preemption timer (bit 0-4): se lo azzero, Hyper-V
	 * vede il timer annunciato ma con rate invalido e lo esclude dall'allowed
	 * del pin-based (evt 46 su 0x48D). bit 29 (VMWRITE-any) resta: F0=SI. */
	misc = rdmsr(IA32_VMX_MISC);
	m[0x485 - 0x480] = misc & ~((1ULL << 14) | (1ULL << 15) | (1ULL << 28));

	/* CR0/CR4 fixed e VMCS_ENUM: dall'host. */
	m[0x486 - 0x480] = rdmsr(MSR_VMX_CR0_FIXED0);
	m[0x487 - 0x480] = rdmsr(MSR_VMX_CR0_FIXED1);
	m[0x488 - 0x480] = rdmsr(MSR_VMX_CR4_FIXED0);
	m[0x489 - 0x480] = rdmsr(MSR_VMX_CR4_FIXED1);
	m[0x48a - 0x480] = rdmsr(IA32_VMX_VMCS_ENUM);

	/* proc-based2: host MENO le feature escluse (§6.3), togliendole dalle
	 * allowed-1 (dword alto). Restano EPT, VPID, unrestricted, RDTSCP,
	 * INVPCID, WBINVD, DESC_TABLE, RDRAND/RDSEED, PAUSE_LOOP. */
	proc2 = rdmsr(MSR_VMX_PROCBASED_CTLS2);
	{
		uint64_t exc =
		    (1ULL << 0)  | /* virtualize APIC accesses */
		    (1ULL << 4)  | /* virtualize x2APIC */
		    (1ULL << 8)  | /* APIC register virtualization */
		    (1ULL << 9)  | /* virtual-interrupt delivery */
		    (1ULL << 13) | /* VMFUNC */
		    (1ULL << 14) | /* VMCS shadowing (per l'L1) */
		    (1ULL << 15) | /* ENCLS exiting */
		    (1ULL << 17) | /* PML */
		    (1ULL << 18) | /* EPT-violation #VE */
		    (1ULL << 20) | /* XSAVES/XRSTORS */
		    (1ULL << 22) | /* mode-based execute control */
		    (1ULL << 23) | /* sub-page write permissions */
		    (1ULL << 24) | /* Intel PT uses guest phys */
		    (1ULL << 25) | /* TSC scaling */
		    (1ULL << 28);  /* ENCLV exiting */
		m[0x48b - 0x480] = proc2 & ~(exc << 32);
	}

	/* EPT/VPID cap: host senza EPT A/D (21) e page-walk a 5 livelli (7). */
	eptcap = rdmsr(MSR_VMX_EPT_VPID_CAP);
	m[0x48c - 0x480] = eptcap & ~((1ULL << 21) | (1ULL << 7));

	/* IA32_FEATURE_CONTROL: LOCK + VMX outside SMX (niente SMX). */
	n->feature_control = IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN;
}

int
vmx_nested_init(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n;
	int i;

	if (vcpu->nested != NULL)
		return (0);

	/* S0: la tabella solo se serve (parere #45 §4), qui si puo' dormire */
	if (nested_fast_field_validate != 0)
		nested_field_tab_build();
	n = malloc(sizeof(*n), M_VMX_NESTED, M_WAITOK | M_ZERO);
	n->current_vmcs12 = VMCS12_GPA_NONE;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++)
		n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
	vmx_nested_init_msrs(n);
	n->vpid2 = vpid_alloc(vcpu->vcpuid);	/* VPID distinto L2 (T2.8) */
	/*
	 * Bitmap MSR del VMCS02 (T6.3): una pagina per vCPU, allineata e
	 * quindi fisicamente contigua, allocata QUI dove si puo' dormire (non
	 * nel compose); la riempie nested_compose_msr_bitmap a ogni ingresso.
	 * Le pagine VMCS02 restano pigre (T1.8, al VMPTRLD del VMCS12).
	 */
	n->msr_bitmap = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX_NESTED,
	    M_WAITOK | M_ZERO);
	KASSERT((vtophys(n->msr_bitmap) & PAGE_MASK) == 0,
	    ("vmx_nested_init: bitmap MSR non allineata"));
	memset(n->msr_bitmap, 0xff, PAGE_SIZE);
	/* immediate exit: il VMCS02 puo' accendere il preemption timer? */
	n->imm_ok = ((rdmsr(MSR_VMX_TRUE_PINBASED_CTLS) >> 32) &
	    PINBASED_PREMPTION_TIMER) != 0;
	/* B1: la modalita' della shadow EPT resta quella della creazione */
	n->vept_keep = vmx_vept_keep_enabled();
	/*
	 * Tracciamento VPID (pareri #48 §5 e #49 §5): fissato qui, per la vita
	 * del vCPU. Se il VPID02 non e' unico (0, uguale al VPID01, dallo
	 * spazio di riserva condiviso fra le VM, o la prova lo chiede) l'L2 non
	 * ha un tag TLB suo: il VMCS02 si compone SENZA VPID e l'hardware
	 * invalida il contesto dell'L2 a ogni ingresso e uscita. Sicuro per
	 * costruzione, al prezzo di quei flush.
	 */
	n->vpid_track = nested_vpid_track != 0;
	if (n->vpid_track && (n->vpid2 == 0 || n->vpid2 == vcpu->state.vpid ||
	    !vmx_vpid_is_unique(n->vpid2) || nested_vpid_test_off != 0)) {
		n->vpid02_off = true;
		atomic_add_long(&vpid02_off_vcpus, 1);
	}
	/* shadow VMCS (pareri #43/#44): fissato qui, per la vita del vCPU */
	if (nested_shadow_vmcs != 0) {
		if (((rdmsr(MSR_VMX_PROCBASED_CTLS2) >> 32) &
		    PROCBASED2_VMCS_SHADOWING) == 0 ||
		    (rdmsr(IA32_VMX_MISC) & (1ULL << 29)) == 0) {
			printf("nested shadow VMCS: l'hardware non ha VMCS "
			    "shadowing o VMWRITE su ogni campo: resta spento\n");
		} else {
			int err;

			sx_xlock(&nested_field_tab_sx);
			shv_global_init();
			sx_xunlock(&nested_field_tab_sx);
			n->sh_vmcs = malloc_aligned(PAGE_SIZE, PAGE_SIZE,
			    M_VMX_NESTED, M_WAITOK | M_ZERO);
			n->sh_vmcs->identifier = vmx_revision() |
			    VMX_VMCS_SHADOW_BIT;
			critical_enter();
			err = vmclear(n->sh_vmcs);	/* SDM 25.11.3 */
			critical_exit();
			if (err == 0)
				n->sh_on = true;
			else {
				free(n->sh_vmcs, M_VMX_NESTED);
				n->sh_vmcs = NULL;
				printf("nested shadow VMCS: VMCLEAR iniziale "
				    "fallito: resta spento\n");
			}
		}
	}
	vcpu->nested = n;
	return (0);
}

/*
 * Libera lo stato nested. Idempotente. Chiamata a 1->0 della capability e
 * da vmx_vcpu_cleanup.
 */
void
vmx_nested_free(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n;
	int i;

	n = vcpu->nested;
	if (n == NULL)
		return;

	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		nested_bitmaps_unmap(&n->cache[i]);
		if (n->cache[i].vmcs02 != NULL)
			free(n->cache[i].vmcs02, M_VMX_NESTED);
	}
	vmx_vept_flush(n);
	if (n->vpid02_flush_pending)
		atomic_add_long(&vpid02_req_dropped, 1);
	if (n->vpid2 != 0)
		vpid_free(n->vpid2);
	if (n->msr_bitmap != NULL)
		free(n->msr_bitmap, M_VMX_NESTED);
	/* lo shadow non e' attivo da nessuna parte: vmx_run lo chiude sempre */
	if (n->sh_vmcs != NULL)
		free(n->sh_vmcs, M_VMX_NESTED);
	if (n->diag_simp_ck != NULL)
		vm_gpa_release(n->diag_simp_ck);
	free(n, M_VMX_NESTED);
	vcpu->nested = NULL;
}

/* --- Esito di un'istruzione VMX nel RFLAGS dell'L1 (SDM 31.2) --- */
static int vmcs12_write_field(struct vmcs12_cache *c, uint32_t enc,
    uint64_t val);	/* definito piu' sotto, usato da nested_vmx_result */

/*
 * Nota: questi girano nel slow path (vcpu FROZEN), dove il VMCS01 NON e'
 * caricato. Lo stato guest (RFLAGS, RIP) si tocca via l'API registri, che a
 * vcpu non-running carica il VMCS da sola; i campi d'uscita vengono dai valori
 * catturati in vmx_exit_process (vcpu->nested->exit_*).
 */
void
nested_vmx_result(struct vmx_vcpu *vcpu, int errnum)
{
	uint64_t rflags;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, &rflags);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	if (errnum != VMXR_SUCCEED && __predict_false(vmx_nested_probe == 7)) {
		/* sonda 7: traccia i VMfail dati all'L1 (non ferma nulla) */
		static int traced7;
		struct vmcs12_cache *cp = nested_current_cache(vcpu->nested);
		uint64_t rip = 0;

		vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &rip);
		/* solo i casi con un evento da iniettare (gli altri VMfail sono
		 * in gran parte quelli attesi dal test) */
		if (traced7 < 64 && cp != NULL &&
		    (vmcs12_read_field(cp, VMCS_ENTRY_INTR_INFO) &
		    VMCS_INTR_VALID)) {
			traced7++;
			printf("nested_probe VMFAIL#%d err=%d da=%p l1rip=%#lx "
			    "entryinfo12=%#lx pin=%#lx proc=%#lx proc2=%#lx "
			    "exit=%#lx entry=%#lx\n", traced7, errnum,
			    __builtin_return_address(0), (u_long)rip,
			    cp ? (u_long)vmcs12_read_field(cp, VMCS_ENTRY_INTR_INFO) : 0,
			    cp ? (u_long)vmcs12_read_field(cp, VMCS_PIN_BASED_CTLS) : 0,
			    cp ? (u_long)vmcs12_read_field(cp, VMCS_PRI_PROC_BASED_CTLS) : 0,
			    cp ? (u_long)vmcs12_proc2(cp) : 0,
			    cp ? (u_long)vmcs12_read_field(cp, VMCS_EXIT_CTLS) : 0,
			    cp ? (u_long)vmcs12_read_field(cp, VMCS_ENTRY_CTLS) : 0);
		}
	}
	if (errnum != VMXR_SUCCEED) {
		/* SDM VMfail: VMfailValid(errnum) se c'e' un VMCS corrente,
		 * altrimenti VMfailInvalid (non c'e' dove scrivere l'errore). */
		struct vmcs12_cache *c = nested_current_cache(vcpu->nested);
		/*
		 * Contatori: prima VMX_NESTED_VMFAIL era definito ma nessuno lo
		 * incrementava, e lo 0 di --get-stats non diceva nulla.
		 */
		if (c != NULL) {		/* L1 lo legge via VMREAD 0x4400 */
			rflags |= PSL_Z;
			vmcs12_write_field(c, VMCS_INSTRUCTION_ERROR, errnum);
			vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMFAIL, 1);
		} else {
			rflags |= PSL_C;
			vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMFAIL_INVALID, 1);
		}
	}
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, rflags);
}

/*
 * Sonda: stampa host-state, controlli e campi d'uscita del VMCS CORRENTE
 * (vmread grezzo: chiamarla solo con un VMCS caricato). Con
 * hw.vmm.vmx.nested_probe=1..3, vedi vmx.c.
 */
void
nested_probe_dump(const char *tag)
{
	static const struct { uint32_t enc; const char *nm; } f[] = {
		{ VMCS_HOST_CR0, "H_CR0" }, { VMCS_HOST_CR3, "H_CR3" },
		{ VMCS_HOST_CR4, "H_CR4" }, { VMCS_HOST_RSP, "H_RSP" },
		{ VMCS_HOST_RIP, "H_RIP" }, { VMCS_HOST_CS_SELECTOR, "H_CS" },
		{ VMCS_HOST_SS_SELECTOR, "H_SS" }, { VMCS_HOST_DS_SELECTOR, "H_DS" },
		{ VMCS_HOST_ES_SELECTOR, "H_ES" }, { VMCS_HOST_FS_SELECTOR, "H_FS" },
		{ VMCS_HOST_GS_SELECTOR, "H_GS" }, { VMCS_HOST_TR_SELECTOR, "H_TR" },
		{ VMCS_HOST_FS_BASE, "H_FSB" }, { VMCS_HOST_GS_BASE, "H_GSB" },
		{ VMCS_HOST_TR_BASE, "H_TRB" }, { VMCS_HOST_GDTR_BASE, "H_GDTRB" },
		{ VMCS_HOST_IDTR_BASE, "H_IDTRB" },
		{ VMCS_HOST_IA32_SYSENTER_CS, "H_SECS" },
		{ VMCS_HOST_IA32_SYSENTER_ESP, "H_SESP" },
		{ VMCS_HOST_IA32_SYSENTER_EIP, "H_SEIP" },
		{ VMCS_HOST_IA32_EFER, "H_EFER" }, { VMCS_HOST_IA32_PAT, "H_PAT" },
		{ VMCS_HOST_IA32_PERF_GLOBAL_CTRL, "H_PGC" },
		{ VMCS_PIN_BASED_CTLS, "PIN" }, { VMCS_PRI_PROC_BASED_CTLS, "PROC" },
		{ VMCS_SEC_PROC_BASED_CTLS, "PROC2" }, { VMCS_EXIT_CTLS, "EXIT" },
		{ VMCS_ENTRY_CTLS, "ENTRY" }, { VMCS_EPTP, "EPTP" },
		{ VMCS_VPID, "VPID" }, { VMCS_LINK_POINTER, "LINK" },
		{ VMCS_MSR_BITMAP, "MSRBM" },
		{ VMCS_EXIT_MSR_LOAD_COUNT, "XMLC" },
		{ VMCS_EXIT_MSR_STORE_COUNT, "XMSC" },
		{ VMCS_ENTRY_MSR_LOAD_COUNT, "NMLC" },
		{ VMCS_GUEST_RIP, "G_RIP" }, { VMCS_GUEST_RSP, "G_RSP" },
		{ VMCS_GUEST_RFLAGS, "G_RFL" }, { VMCS_GUEST_CR0, "G_CR0" },
		{ VMCS_GUEST_CR3, "G_CR3" }, { VMCS_GUEST_CR4, "G_CR4" },
		{ VMCS_GUEST_IA32_EFER, "G_EFER" },
		{ VMCS_GUEST_CS_SELECTOR, "G_CS" },
		{ VMCS_GUEST_CS_ACCESS_RIGHTS, "G_CSAR" },
		{ VMCS_GUEST_TR_ACCESS_RIGHTS, "G_TRAR" },
		{ VMCS_GUEST_ACTIVITY, "G_ACT" },
		{ VMCS_GUEST_INTERRUPTIBILITY, "G_INTR" },
		{ VMCS_ENTRY_INTR_INFO, "N_INTINFO" },
		{ VMCS_EXIT_REASON, "X_REASON" },
		{ VMCS_EXIT_QUALIFICATION, "X_QUAL" },
		{ VMCS_EXIT_INTR_INFO, "X_INTINFO" },
		{ VMCS_IDT_VECTORING_INFO, "X_IDTVEC" },
	};
	uint64_t v;
	int i;

	for (i = 0; i < (int)nitems(f); i++) {
		if (i % 6 == 0)
			printf("%snested_probe %s:", i ? "\n" : "", tag);
		if (vmread(f[i].enc, &v) == 0)
			printf(" %s=%#lx", f[i].nm, v);
		else
			printf(" %s=ERR", f[i].nm);
	}
	printf("\n");
}

void
nested_vmfail_invalid(struct vmx_vcpu *vcpu)
{
	uint64_t rflags;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, &rflags);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	rflags |= PSL_C;			/* VMfailInvalid */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, rflags);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMFAIL_INVALID, 1);
}

static void
nested_advance_rip(struct vmx_vcpu *vcpu)
{
	uint64_t rip;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &rip);
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    rip + vcpu->nested->exit_insn_length);
}

/* indirizzo canonico a 48 bit (LA57 non esposto all'L1) */
static bool
nested_canonical(uint64_t a)
{
	return ((int64_t)(a << 16) >> 16) == (int64_t)a;
}

/*
 * #160 R6: esito dell'accesso all'operando in memoria di un'istruzione VMX
 * dell'L1. Prima si traduceva il solo primo byte e si tenevano 8 byte contigui
 * da quel GPA: con l'operando a cavallo di pagina (offset 0xff9..0xfff, lecito
 * per l'SDM, che chiede l'allineamento al VALORE del puntatore, non al suo
 * indirizzo) _vm_gpa_hold va in panic, e la seconda pagina non era tradotta.
 * Ora l'accesso e' una copia: vm_copy_setup traduce TUTTE le pagine, poi le
 * tiene tutte, e solo dopo si copia un byte; vm_copy_teardown su ogni uscita.
 * Un esito "conteso" (P3) non esiste ancora: nessun cammino lo produce.
 */
enum nested_opnd {
	NOPND_OK,		/* operando copiato per intero */
	NOPND_INIETTATO,	/* #GP/#SS/#PF gia' iniettato all'L1: riparte */
	NOPND_HOST_FATALE,	/* L0 non completa l'accesso: nessun byte copiato */
	NOPND_CONTESO,		/* P3: walk conteso oltre il limite: nessun effetto, riparte servita */
};

/*
 * #160 R3: l'operando non si puo' completare per un errore di L0 (walk delle
 * tabelle dell'L1 su un GPA senza memoria, operando su un GPA senza backing,
 * vmread del descrittore di segmento fallito). Prima il gestore restituiva 0
 * senza nested_advance_rip: con nextrip gia' avanzato da vm_run l'istruzione
 * dell'L1 era SALTATA in silenzio (niente VMfail, niente eccezione). Ora, come
 * la Fase C (VEPT_MMIO non emulabile): latch fatale del vCPU (che registra il
 * nextrip avanzato), nextrip di nuovo sull'istruzione, uscita BOGUS di
 * lunghezza 0, ENOTRECOVERABLE fino a vm_run; K3 respinge ogni VM_RUN
 * successivo. Nessuna eccezione e nessun VMfail inventati.
 */
static int
nested_operand_latch(struct vmx_vcpu *vcpu, int err, int stadio, uint64_t gla,
    int valide)
{
	struct vm_exit *vme = vm_exitinfo(vcpu->vcpu);
	int error;

	error = vm_fatal_latch(vcpu->vcpu, err, stadio, vme->rip, 0, gla, NULL,
	    0, valide);
	vm_restart_instruction(vcpu->vcpu);	/* vCPU FROZEN: nextrip = RIP */
	vme->exitcode = VM_EXITCODE_BOGUS;
	vme->inst_length = 0;
	atomic_add_long(&nested_operand_fatal, 1);
	SDT_PROBE5(vmm, vmx, nested, opndfatal, vcpu->vcpuid, stadio, err,
	    vme->rip, (valide & VM_FATAL_V_GLA) ? gla : 0);
	return (error);
}

/*
 * #163 (09): limite dell'ULTIMO byte di un operando, con l'offset NON troncato
 * (SDM vol. 3A 253668-085US, ottobre 2024, 6.3 "Limit Checking" (5.3 nelle revisioni precedenti)). Expand-up: <= limite; dati expand-down: <= 0xffff o
 * 0xffffffff secondo il bit B. Il primo byte (e il limite inferiore di un
 * expand-down) lo controlla vie_calculate_gla, con lo stesso criterio di tipo.
 * Segmento piatto (base 0, limite 0xffffffff, dati expand-up o codice): per
 * l'SDM con limite effettivo FFFFFFFFH il controllo e' "implementation-
 * specific", e le CPU con VMX non lo fanno (KVM get_vmx_mem_address): niente
 * #GP, l'operando prosegue e l'indirizzo lineare si avvolge a 4 GB.
 */
static bool
nested_seg_last_ok(const struct seg_desc *d, uint64_t last)
{
	if (d->base == 0 && d->limit == 0xffffffff &&
	    ((SEG_DESC_TYPE(d->access) & 0x8) != 0 ||
	    (SEG_DESC_TYPE(d->access) & 0x4) == 0))	/* piatto */
		return (true);
	if ((SEG_DESC_TYPE(d->access) & 0xC) == 0x4)	/* dati expand-down */
		return (last <= (SEG_DESC_DEF32(d->access) ? 0xffffffffULL :
		    0xffffULL));
	return (last <= d->limit);
}

/*
 * Decodifica l'operando di memoria di un'istruzione VMX (SDM: campo
 * VM-exit instruction-information + exit qualification), lo valida per
 * 'len' byte (segmento, limite, canonicita' del primo e dell'ultimo byte) e
 * lo copia da/verso 'buf' (VM_PROT_WRITE: verso il guest). Stadio 10, K5:
 * niente piu' parametro 'add' (tutti i chiamanti passavano 0): un 'add' non
 * nullo sommato prima del troncamento riaprirebbe il difetto corretto da 09
 * (l'EA si tronca UNA volta). Il descrittore m128 di INVEPT/INVVPID e' un accesso unico di
 * 16 byte: tutti i controlli di segmento prima di ogni traduzione, tutte le
 * pagine tradotte e tenute prima di copiare un solo byte. Il formato dei bit
 * coincide con quello gia' usato da inout_str_* e con KVM/SDM: addrsize 9:7,
 * seg 17:15, index 21:18 (invalido se bit 22), base 26:23 (invalido se bit 27).
 */
static enum nested_opnd
nested_operand_copy(struct vmx_vcpu *vcpu, int prot, void *buf, size_t len)
{
	struct vm_copyinfo ci[4];		/* 2 pezzi al piu', 2 pagine ciascuno */
	struct vm_guest_paging paging;
	struct seg_desc desc;
	struct {
		uint64_t gla;
		size_t len;
	} pz[2];
	uint64_t qual, offset, ea, gla0, pga, gpa;
	uint32_t info;
	enum vm_reg_name seg;
	size_t fatto;
	int scaling, addrsize, fault, error, i, k, npg, npz;
	bool conteso;			/* P3: walk conteso oltre il limite */

	KASSERT(len == 4 || len == 8 || len == 16, ("%s: len %zu", __func__,
	    len));
	CTASSERT(nitems(ci) >= 2 * nitems(pz));
	bzero(ci, sizeof(ci));
	qual = vcpu->nested->exit_qual;		/* catturati col VMCS corrente */
	info = (uint32_t)vcpu->nested->exit_insn_info;

	scaling = info & 0x3;
	switch ((info >> 7) & 0x7) {
	case 0: addrsize = 2; break;
	case 1: addrsize = 4; break;
	default: addrsize = 8; break;
	}
	seg = vm_segment_name((info >> 15) & 0x7);

	offset = qual;				/* displacement */
	if (((info >> 27) & 0x1) == 0)		/* BaseReg valido */
		offset += vmx_get_guest_reg(vcpu, (info >> 23) & 0xf);
	if (((info >> 22) & 0x1) == 0)		/* IndexReg valido */
		offset += vmx_get_guest_reg(vcpu, (info >> 18) & 0xf) << scaling;

	error = vmx_getdesc(vcpu, seg, &desc);	/* sicuro: VMPTRLD a vcpu frozen */
	if (error != 0) {
		/* solo un vmread fallito (vmcs_getdesc): errore di L0, non dell'L1 */
		(void)nested_operand_latch(vcpu, error, VM_FATAL_NESTED_SEGDESC, 0, 0);
		return (NOPND_HOST_FATALE);
	}
	paging = vcpu->nested->exit_paging;	/* catturato col VMCS corrente */
	/*
	 * #163 (09): l'indirizzo effettivo si calcola UNA volta, troncato
	 * all'address size; i byte dell'operando stanno agli offset EA + i SENZA
	 * troncamento (SDM vol. 3A 253668-085US, ottobre 2024, 6.3 "Limit Checking" (5.3 nelle revisioni precedenti):
	 * "a quadword at an offset greater than
	 * (effective-limit - 7)" -> #GP, #SS via SS). Prima vie_calculate_gla era
	 * chiamata per meta' (EA + 8 ri-troncato: la seconda meta' di un m128 a
	 * 0xfff8 con indirizzamento a 16 bit finiva a base + 0) e controllava il
	 * limite con l'offset di ogni byte troncato, cioe' avvolto: un quadword a
	 * 0xfffc con limite 0xffff passava. Qui vie_calculate_gla controlla il
	 * PRIMO byte (segmento utilizzabile, tipo e permessi, limite, base) e ne
	 * da' l'indirizzo lineare; l'ultimo byte si confronta col limite qui. I
	 * byte sono a gla0 + i: a 32 bit fuori dal modo 64 bit (base + offset
	 * oltre 4 GB si avvolge), a 64 bit in modo 64 bit (la base di FS/GS si
	 * somma all'EA troncato, senza troncare la somma).
	 */
	ea = offset & (addrsize == 8 ? ~0ULL : addrsize == 4 ? 0xffffffffULL :
	    0xffffULL);
	if (vie_calculate_gla(paging.cpu_mode, seg, &desc, ea, 1, addrsize, prot,
	    &gla0) != 0)
		goto segfault;
	if (paging.cpu_mode != CPU_MODE_64BIT &&
	    !nested_seg_last_ok(&desc, ea + len - 1))
		goto segfault;
	/*
	 * In modo 64 bit vie_calculate_gla non rifiuta un indirizzo non
	 * canonico: lo farebbe vm_gla2gpa, ma sempre con #GP e solo per la
	 * pagina che traduce. Via SS l'SDM vuole #SS(0) (kvm-unit-tests
	 * invvpid_test_ss). Primo E ultimo byte: l'operando puo' finire oltre.
	 */
	if (paging.cpu_mode == CPU_MODE_64BIT && (!nested_canonical(gla0) ||
	    !nested_canonical(gla0 + len - 1)))
		goto segfault;
	/*
	 * #162 (08): l'accesso in PEZZI lineari contigui. Fuori dal modo 64 bit
	 * l'indirizzo lineare e' di 32 bit: un operando che passa 0xffffffff si
	 * spezza e il resto ricomincia da 0. Prima vm_copy_setup proseguiva oltre
	 * 4 GB: i walk a 32 bit e PAE traducono quell'indirizzo per indici
	 * mascherati, ma un #PF lo avrebbe messo tale e quale in CR2. Con due
	 * pezzi prima si traducono TUTTE le pagine, in ordine e senza tenerle,
	 * poi i vm_copy_setup che le tengono: un #PF del secondo pezzo precede un
	 * backing assente del primo, come in un accesso unico. Nessun byte si
	 * copia prima che tutto sia tenuto.
	 */
	if (paging.cpu_mode != CPU_MODE_64BIT && gla0 + len > (1ULL << 32)) {
		pz[0].gla = gla0;
		pz[0].len = (1ULL << 32) - gla0;
		pz[1].gla = 0;
		pz[1].len = len - pz[0].len;
		npz = 2;
	} else {
		pz[0].gla = gla0;
		pz[0].len = len;
		npz = 1;
	}
	for (k = 0; npz > 1 && k < npz; k++) {
		npg = (int)(((pz[k].gla & PAGE_MASK) + pz[k].len - 1) / PAGE_SIZE) + 1;
		for (i = 0; i < npg; i++) {
			pga = i == 0 ? pz[k].gla :
			    (pz[k].gla & ~(uint64_t)PAGE_MASK) + i * PAGE_SIZE;
			error = vm_gla2gpa_budget(vcpu->vcpu, &paging, pga, prot,
			    &gpa, &fault, &conteso);
			if (error == 0 && !fault && conteso)	/* P3 */
				return (NOPND_CONTESO);
			if (error != 0) {
				(void)nested_operand_latch(vcpu, error,
				    VM_FATAL_NESTED_OPERAND, pga, VM_FATAL_V_GLA);
				return (NOPND_HOST_FATALE);
			}
			if (fault)		/* #PF iniettato da vm_gla2gpa */
				return (NOPND_INIETTATO);
		}
	}
	for (k = 0; k < npz; k++) {
		error = vm_copy_setup_budget(vcpu->vcpu, &paging, pz[k].gla,
		    pz[k].len, prot, &ci[2 * k], 2, &fault, &conteso);
		if (error == 0 && !fault && conteso) {	/* P3: nulla copiato */
			vm_copy_teardown(ci, nitems(ci));	/* i pezzi gia' tenuti */
			return (NOPND_CONTESO);
		}
		if (error != 0) {
			vm_copy_teardown(ci, nitems(ci));	/* i pezzi gia' tenuti */
			(void)nested_operand_latch(vcpu, error,
			    VM_FATAL_NESTED_OPERAND, pz[k].gla, VM_FATAL_V_GLA);
			return (NOPND_HOST_FATALE);
		}
		if (fault) {			/* #PF iniettato da vm_gla2gpa */
			vm_copy_teardown(ci, nitems(ci));
			return (NOPND_INIETTATO);
		}
	}
	for (k = 0, fatto = 0; k < npz; fatto += pz[k].len, k++) {
		if (prot & VM_PROT_WRITE)
			vm_copyout((const char *)buf + fatto, &ci[2 * k],
			    pz[k].len);
		else
			vm_copyin(&ci[2 * k], (char *)buf + fatto, pz[k].len);
	}
	vm_copy_teardown(ci, nitems(ci));
	return (NOPND_OK);
segfault:
	/* SDM: riferimento via SS -> #SS(0), altrimenti #GP(0) */
	if (seg == VM_REG_GUEST_SS)
		vm_inject_ss(vcpu->vcpu, 0);
	else
		vm_inject_gp(vcpu->vcpu);
	return (NOPND_INIETTATO);
}

/* Legge gli 8 byte (puntatore VMCS/regione) all'operando. */
static enum nested_opnd
nested_read_operand_u64(struct vmx_vcpu *vcpu, uint64_t *out)
{
	return (nested_operand_copy(vcpu, VM_PROT_READ, out, sizeof(*out)));
}

/*
 * Esito NOPND_HOST_FATALE nel gestore: il latch e' gia' chiuso e l'uscita gia'
 * BOGUS (nested_operand_latch); il gestore restituisce l'errore del latch,
 * senza nested_advance_rip, VMfail o effetti dell'istruzione.
 */
static int
nested_operand_fatale(struct vmx_vcpu *vcpu)
{
	(void)vcpu;
	return (ENOTRECOVERABLE);
}

/*
 * P3 (stadio 11): esito NOPND_CONTESO nel gestore. La copia dell'operando non
 * ha avuto effetti (nessun byte copiato, nessuna pagina tenuta, nessuna
 * eccezione): l'istruzione riparte e l'uscita e' segnalata a vm_run, che la
 * serve invece di rientrare dal ciclo nested stretto.
 */
static int
nested_operand_conteso(struct vmx_vcpu *vcpu)
{
	vm_restart_instruction(vcpu->vcpu);
	vm_segnala_conteso(vcpu->vcpu);
	return (0);
}

/*
 * CR0/CR4 come li vede l'L1: i bit posseduti da L0 (maschera) vengono dal
 * read-shadow. Serve perche' bhyve forza bit come CR0.NE e CR4.VMXE nel
 * registro reale del guest. vm_get_register con VMCS_IDENT fa
 * VMPTRLD/VMCLEAR da se': sicuro anche nello slow path.
 */
static uint64_t
nested_guest_cr(struct vmx_vcpu *vcpu, int reg, uint32_t mask_enc,
    uint32_t shadow_enc)
{
	uint64_t v, m, s;

	vm_get_register(vcpu->vcpu, reg, &v);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(mask_enc), &m);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(shadow_enc), &s);
	return ((v & ~m) | (s & m));
}

static bool
nested_fixed_ok(uint64_t val, uint64_t fixed0, uint64_t fixed1)
{
	return ((val & fixed0) == fixed0 && (val & ~fixed1) == 0);
}

static int
nested_vmxon(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t ptr, cr0, cr4;
	uint32_t *p, rev;
	void *cookie;

	/*
	 * In VMX non-root VMXON esce SEMPRE verso L0, prima dei controlli
	 * dell'SDM: li rifacciamo qui, nell'ordine dell'SDM (come KVM
	 * handle_vmxon). Verificati da kvm-unit-tests test_vmxon.
	 */
	cr0 = nested_guest_cr(vcpu, VM_REG_GUEST_CR0, VMCS_CR0_MASK,
	    VMCS_CR0_SHADOW);
	cr4 = nested_guest_cr(vcpu, VM_REG_GUEST_CR4, VMCS_CR4_MASK,
	    VMCS_CR4_SHADOW);
	if ((cr4 & CR4_VMXE) == 0) {		/* precede la VM exit: #UD */
		vm_inject_ud(vcpu->vcpu);
		return (0);
	}
	if (n->exit_paging.cpl != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if (n->vmxon) {
		nested_vmx_result(vcpu, VMXERR_VMXON_IN_VMX_ROOT);
		goto done;
	}
	if (!nested_fixed_ok(cr0, n->vmx_msr[0x486 - 0x480],
	    n->vmx_msr[0x487 - 0x480]) ||
	    !nested_fixed_ok(cr4, n->vmx_msr[0x488 - 0x480],
	    n->vmx_msr[0x489 - 0x480])) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if ((n->feature_control & (IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN)) != (IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN)) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	switch (nested_read_operand_u64(vcpu, &ptr)) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	/* VMXON region: allineata a 4K, entro MAXPHYADDR, revisione giusta. */
	if ((ptr & PAGE_MASK) != 0 || (ptr >> cpu_maxphyaddr) != 0) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	p = vm_gpa_hold(vcpu->vcpu, ptr, sizeof(*p), VM_PROT_READ, &cookie);
	if (p == NULL) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	rev = *p;
	vm_gpa_release(cookie);
	if (rev != (uint32_t)(n->vmx_msr[0] & 0x7fffffff)) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	n->vmxon_ptr = ptr;
	n->vmxon = true;
	/*
	 * Nuovo ciclo VMX (parere #49 §4.1): il VPID02 e' lo stesso del ciclo
	 * precedente e puo' avere traduzioni di allora. Si dimentica l'identita'
	 * del VPID12 e, col tracciamento, si chiede l'invalidazione prima del
	 * primo ingresso in L2 (KVM fa lo stesso al primo uso, giugno 2026).
	 */
	n->last_vpid12_ok = false;
	if (n->vpid_track)
		nested_vpid02_request(n);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}

/* --- Persistenza del VMCS12 nella sua regione (parere #22) --- */
#define	VMCS12_OP_SAVE_VMCLEAR	1
#define	VMCS12_OP_SAVE_EVICT	2
#define	VMCS12_OP_SAVE_VMXOFF	3
#define	VMCS12_OP_CLEAR		4
#define	VMCS12_OP_INIT		5
#define	VMCS12_OP_LOAD		6
#define	VMCS12_OP_NOFORMAT	7
#define	VMCS12_OP_CORRUPT	8
#define	VMCS12_OP_UNMAPPED	9

static uint32_t
vmcs12_mem_digest(const struct vmcs12_mem_field *f, uint32_t n)
{
	const uint8_t *p = (const uint8_t *)f;
	uint32_t h = 2166136261U;
	size_t i;

	for (i = 0; i < n * sizeof(*f); i++)
		h = (h ^ p[i]) * 16777619U;
	return (h);
}

/* Il formato in memoria e' integro? (non controlla la revisione) */
static bool
vmcs12_mem_valid(const struct vmcs12_mem *m)
{
	uint32_t i, j, enc;

	if (m->magic != VMCS12_MEM_MAGIC || m->version != VMCS12_MEM_VERSION ||
	    m->launched > 1 || m->nfields > VMCS12_NFIELDS)
		return (false);
	for (i = 0; i < m->nfields; i++) {
		enc = m->fields[i].enc;
		if ((enc & 0xffff8000) != 0)
			return (false);
		for (j = 0; j < i; j++)
			if (m->fields[j].enc == enc)
				return (false);
	}
	return (vmcs12_mem_digest(m->fields, m->nfields) == m->digest);
}

/*
 * Scrive la cache c nella regione c->vmcs12_gpa con il launch state dato
 * (0 per VMCLEAR, quello corrente per sfratto e VMXOFF: lo sfratto di L0 NON
 * e' un VMCLEAR dell'L1). 0 se scritto; EFAULT se la regione non e'
 * mappabile, e allora il chiamante NON deve scartare lo slot (unica copia).
 * La cache e' gia' completa: VMWRITE dell'L1 e aggiornamenti impliciti
 * (uscite riflesse, VM_INSTRUCTION_ERROR, launch state) la scrivono tutti.
 */
static int
vmcs12_mem_save(struct vmx_vcpu *vcpu, struct vmcs12_cache *c, int launched,
    int op)
{
	struct vmcs12_mem *m;
	void *cookie;
	int i;

	m = vm_gpa_hold(vcpu->vcpu, c->vmcs12_gpa, PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (m == NULL) {
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_MEMERR, 1);
		SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid,
		    c->vmcs12_gpa, VMCS12_OP_UNMAPPED, c->nfields, launched, 0);
		return (EFAULT);
	}
	for (i = 0; i < c->nfields; i++) {
		m->fields[i].enc = c->fields[i].enc;
		m->fields[i].val_lo = (uint32_t)c->fields[i].val;
		m->fields[i].val_hi = (uint32_t)(c->fields[i].val >> 32);
	}
	m->nfields = c->nfields;
	m->digest = vmcs12_mem_digest(m->fields, m->nfields);
	m->launched = launched ? 1 : 0;
	m->version = VMCS12_MEM_VERSION;
	m->magic = VMCS12_MEM_MAGIC;
	SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid, c->vmcs12_gpa,
	    op, c->nfields, m->launched, m->digest);
	vm_gpa_release(cookie);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_SAVED, 1);
	return (0);
}

/*
 * VMCLEAR di un VMCS12 che non e' nella cache di questo vCPU. Formato valido:
 * conserva i campi, launch state = clear. Formato assente (VMCS appena
 * allocato: il primo VMCLEAR e' la sequenza raccomandata dall'SDM) o
 * corrotto: lo inizializza vuoto e clear.
 */
static int
vmcs12_mem_clear(struct vmx_vcpu *vcpu, uint64_t gpa)
{
	struct vmcs12_mem *m;
	void *cookie;
	int op;

	m = vm_gpa_hold(vcpu->vcpu, gpa, PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &cookie);
	if (m == NULL) {
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_MEMERR, 1);
		SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid, gpa,
		    VMCS12_OP_UNMAPPED, 0, 0, 0);
		return (EFAULT);
	}
	if (vmcs12_mem_valid(m))
		op = VMCS12_OP_CLEAR;
	else {
		op = (m->magic == VMCS12_MEM_MAGIC) ? VMCS12_OP_CORRUPT :
		    VMCS12_OP_INIT;
		if (op == VMCS12_OP_CORRUPT)
			vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_MEMERR, 1);
		m->nfields = 0;
		m->digest = vmcs12_mem_digest(m->fields, 0);
		m->version = VMCS12_MEM_VERSION;
		m->magic = VMCS12_MEM_MAGIC;
	}
	m->launched = 0;
	SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid, gpa, op,
	    m->nfields, 0, m->digest);
	vm_gpa_release(cookie);
	return (0);
}

/* Slot della cache per un VMCS12 appena caricato: niente dello occupante
 * precedente (campi, mappe, launch state) deve sopravvivere. */
static void
vmcs12_slot_reset(struct vmcs12_cache *c, uint64_t gpa)
{
	nested_bitmaps_unmap(c);
	c->vmcs12_gpa = gpa;
	c->nfields = 0;
	c->launched = 0;
	c->ml_en_bad = false;
	c->host_dirty = true;
	c->control_dirty = true;
	/* shadow VMCS: si arriva qui solo da VMPTRLD dopo la copia di ritorno */
	KASSERT(!c->sh_rw_owned, ("vmcs12_slot_reset: RW dello shadow non recuperati"));
	c->sh_guard_hit = false;
}

/*
 * VMPTRLD di un VMCS12 non in cache: carica la regione nello slot (gia'
 * azzerato da vmcs12_slot_reset). 0 caricato o formato assente (VMCS mai
 * passato da VMCLEAR: slot vuoto e clear, nessuno stato inventato); EINVAL
 * formato presente ma corrotto; EFAULT regione non mappabile.
 */
static int
vmcs12_mem_load(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmcs12_mem *m;
	void *cookie;
	uint32_t i;
	int op, error = 0;

	m = vm_gpa_hold(vcpu->vcpu, c->vmcs12_gpa, PAGE_SIZE, VM_PROT_READ,
	    &cookie);
	if (m == NULL) {
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_MEMERR, 1);
		SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid,
		    c->vmcs12_gpa, VMCS12_OP_UNMAPPED, 0, 0, 0);
		return (EFAULT);
	}
	if (m->magic != VMCS12_MEM_MAGIC)
		op = VMCS12_OP_NOFORMAT;
	else if (!vmcs12_mem_valid(m)) {
		op = VMCS12_OP_CORRUPT;
		error = EINVAL;
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_MEMERR, 1);
	} else {
		op = VMCS12_OP_LOAD;
		for (i = 0; i < m->nfields; i++) {
			c->fields[i].enc = m->fields[i].enc;
			c->fields[i].val = (uint64_t)m->fields[i].val_lo |
			    (uint64_t)m->fields[i].val_hi << 32;
		}
		c->nfields = m->nfields;
		c->launched = m->launched;
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VMCS12_LOADED, 1);
	}
	SDT_PROBE6(vmm, vmx, nested, vmcs12mem, vcpu->vcpuid, c->vmcs12_gpa,
	    op, m->nfields, m->launched, m->digest);
	vm_gpa_release(cookie);
	return (error);
}

static int
nested_vmxoff(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	int i;

	n->vmxon = false;
	n->current_vmcs12 = VMCS12_GPA_NONE;
	shvmcs_set_current(n, NULL);	/* RW gia' recuperati in vmx_nested_exit */
	/* i VMCS12 ancora nella cache vanno nella loro regione, col loro
	 * launch state (VMXOFF non e' un VMCLEAR); se una regione non e'
	 * scrivibile lo slot resta, unica copia */
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs12_gpa == VMCS12_GPA_NONE)
			continue;
		if (vmcs12_mem_save(vcpu, &n->cache[i], n->cache[i].launched,
		    VMCS12_OP_SAVE_VMXOFF) != 0)
			continue;
		nested_bitmaps_unmap(&n->cache[i]);
		n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
		n->cache[i].nfields = 0;
		n->cache[i].launched = 0;
	}
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

static int
nested_vmclear(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t vmcs12;
	int i;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	switch (nested_read_operand_u64(vcpu, &vmcs12)) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	if ((vmcs12 & PAGE_MASK) != 0 || (vmcs12 >> cpu_maxphyaddr) != 0) {
		nested_vmx_result(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		goto done;
	}
	if (vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);
		goto done;
	}
	if (vmcs12 == n->current_vmcs12) {
		n->current_vmcs12 = VMCS12_GPA_NONE;
		shvmcs_set_current(n, NULL);	/* RW gia' recuperati */
	}
	/*
	 * SDM 24.11.3: VMCLEAR scrive i dati del VMCS nella sua regione e ne
	 * porta il launch state a clear, SENZA cancellarne i campi; un VMPTRLD
	 * successivo, anche su un altro LP, li ritrova. Prima la cache si
	 * liberava e il contenuto andava perso (WSL2: VMfail 7).
	 */
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++)
		if (n->cache[i].vmcs12_gpa == vmcs12)
			break;
	if (i < VMX_NESTED_MAX_VMCS12) {
		n->cache[i].launched = 0;
		if (vmcs12_mem_save(vcpu, &n->cache[i], 0,
		    VMCS12_OP_SAVE_VMCLEAR) == 0) {
			nested_bitmaps_unmap(&n->cache[i]);
			n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
			n->cache[i].nfields = 0;
		}
		/* regione non scrivibile: lo slot (clear) resta, unica copia */
	} else
		(void)vmcs12_mem_clear(vcpu, vmcs12);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}

static int
nested_vmptrld(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t vmcs12;
	int i, slot;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	switch (nested_read_operand_u64(vcpu, &vmcs12)) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	if ((vmcs12 & PAGE_MASK) != 0 || (vmcs12 >> cpu_maxphyaddr) != 0) {
		nested_vmx_result(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		goto done;
	}
	if (vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);
		goto done;
	}
	/*
	 * Revisione del VMCS12 (primi 31 bit) = quella esposta in
	 * IA32_VMX_BASIC; il bit 31 (shadow-VMCS indicator) e' ammesso solo
	 * se l'L1 ha il VMCS shadowing, che NON gli esponiamo -> errore.
	 */
	{
		uint32_t *p, rev;
		void *cookie;

		p = vm_gpa_hold(vcpu->vcpu, vmcs12, sizeof(*p), VM_PROT_READ,
		    &cookie);
		if (p == NULL) {
			nested_vmx_result(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
			goto done;
		}
		rev = *p;
		vm_gpa_release(cookie);
		if (rev != (uint32_t)(n->vmx_msr[0] & 0x7fffffff)) {
			nested_vmx_result(vcpu,
			    VMXERR_VMPTRLD_INCORRECT_REVISION);
			goto done;
		}
	}
	slot = -1;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs12_gpa == vmcs12)
			break;
		if (slot < 0 && n->cache[i].vmcs12_gpa == VMCS12_GPA_NONE)
			slot = i;
	}
	if (i == VMX_NESTED_MAX_VMCS12) {	/* non in cache: caricalo */
		int j, k, error;

		if (slot < 0) {
			/*
			 * Sfratto a giro: la vittima va nella sua regione COL
			 * SUO launch state (lo sfratto di L0 non e' un VMCLEAR
			 * dell'L1). Se non si puo' scrivere non la si scarta:
			 * si prova la successiva.
			 */
			for (j = 0; j < VMX_NESTED_MAX_VMCS12; j++) {
				k = (n->evict_next + j) % VMX_NESTED_MAX_VMCS12;
				if (vmcs12_mem_save(vcpu, &n->cache[k],
				    n->cache[k].launched,
				    VMCS12_OP_SAVE_EVICT) == 0) {
					slot = k;
					break;
				}
			}
			if (slot < 0) {
				nested_vmx_result(vcpu,
				    VMXERR_VMPTRLD_INVALID_ADDRESS);
				goto done;
			}
			n->evict_next = (slot + 1) % VMX_NESTED_MAX_VMCS12;
		}
		vmcs12_slot_reset(&n->cache[slot], vmcs12);
		error = vmcs12_mem_load(vcpu, &n->cache[slot]);
		if (error != 0) {
			/*
			 * Formato bhyve presente ma corrotto: non lo si tratta
			 * come un VMCS nuovo. Regione non mappabile: gia'
			 * esclusa dal controllo di revisione qui sopra.
			 */
			vmcs12_slot_reset(&n->cache[slot], VMCS12_GPA_NONE);
			nested_vmx_result(vcpu, error == EINVAL ?
			    VMXERR_VMPTRLD_INCORRECT_REVISION :
			    VMXERR_VMPTRLD_INVALID_ADDRESS);
			goto done;
		}
	}
	n->current_vmcs12 = vmcs12;
	shvmcs_set_current(n, nested_current_cache(n));	/* tutto da copiare */
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}

static int
nested_vmptrst(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t cur;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	cur = n->current_vmcs12;		/* VMCS12_GPA_NONE se nessuno */
	switch (nested_operand_copy(vcpu, VM_PROT_WRITE, &cur, sizeof(cur))) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

/* --- store software dei campi VMCS12 (T1.8) --- */
struct vmcs12_cache *
nested_current_cache(struct vmx_nested *n)
{
	int i;

	if (n->current_vmcs12 == VMCS12_GPA_NONE)
		return (NULL);
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++)
		if (n->cache[i].vmcs12_gpa == n->current_vmcs12)
			return (&n->cache[i]);
	return (NULL);
}

static void	shv_guard(struct vmcs12_cache *c, uint32_t enc);

uint64_t
vmcs12_read_field(struct vmcs12_cache *c, uint32_t enc)
{
	int i;

	if (__predict_false(c->sh_rw_owned))	/* shadow VMCS, parere #44 §3 */
		shv_guard(c, enc);
	for (i = 0; i < c->nfields; i++)
		if (c->fields[i].enc == enc)
			return (c->fields[i].val);
	return (0);
}

static int
vmcs12_write_field(struct vmcs12_cache *c, uint32_t enc, uint64_t val)
{
	int i;

	if (__predict_false(c->sh_rw_owned))	/* shadow VMCS, parere #44 §3 */
		shv_guard(c, enc);
	for (i = 0; i < c->nfields; i++)
		if (c->fields[i].enc == enc) {
			c->fields[i].val = val;
			return (0);
		}
	if (c->nfields >= VMCS12_NFIELDS)
		return (-1);
	c->fields[c->nfields].enc = enc;
	c->fields[c->nfields].val = val;
	c->nfields++;
	return (0);
}

/*
 * Encoding VMCS dell'L1. All'L1 esponiamo la stessa CPU (VMCS_ENUM compreso):
 * un campo e' supportato se e solo se un VMREAD reale di quell'encoding
 * riesce (vm_get_register con VMCS_IDENT fa VMPTRLD/VMCLEAR da se').
 * Prima lo store accettava QUALUNQUE encoding (kvm-unit-tests: MAX_INDEX
 * 0x1ff invece di 0x17).
 */
static bool
nested_field_ok_hw(struct vmx_vcpu *vcpu, uint32_t field)
{
	uint64_t tmp;

	if ((field & 0xffff8000) != 0)		/* bit 31:15 riservati */
		return (false);
	return (vm_get_register(vcpu->vcpu, VMCS_IDENT(field), &tmp) == 0);
}

/*
 * S0 (pareri #43 §9 e #44 §6): la stessa risposta di nested_field_ok_hw senza
 * istruzioni VMX. Col vCPU FROZEN nessun VMCS e' caricato e vm_get_register fa
 * VMPTRLD + VMREAD + VMCLEAR di un VMCS vero per ogni VMREAD/VMWRITE dell'L1
 * (decine di migliaia al secondo con Hyper-V). Qui l'esito si calcola UNA volta,
 * con un VMREAD per encoding (bit 14:0) su un VMCS di prova, e poi e' un test di
 * bit. La semantica NON cambia: "campo valido" = "il VMREAD dell'hardware
 * dell'L0 riesce", come prima. Le altre due classi sono solo informazione:
 *  NFT_RO     tipo "informazioni d'uscita" (bit 11:10 = 1), sola lettura per
 *             l'SDM; la VMWRITE dell'L1 resta permessa come prima (MISC bit 29);
 *  NFT_NOFEAT esiste sull'hardware ma la funzione che lo usa NON e' esposta
 *             all'L1 (vmx_nested_init_msrs: shadowing, VID/APICv, PML, VMFUNC,
 *             #VE, XSAVES, ENCLS/ENCLV, sub-page, TSC scaling); oggi l'L1 puo'
 *             leggerlo e scriverlo, e lo si conta soltanto.
 * hw.vmm.vmx.nested_fast_field_validate: 0 = come prima (difetto), 1 = tabella,
 * 2 = tabella E metodo di prima a ogni accesso, con le discrepanze contate (la
 * risposta resta quella della tabella, la discrepanza non si nasconde).
 */
#define	NFT_HW		0x01
#define	NFT_RO		0x02
#define	NFT_NOFEAT	0x04
static uint8_t nested_field_tab[0x8000];
static int nested_field_tab_ok;		/* 1 = tabella costruita */
static struct sx nested_field_tab_sx;
SX_SYSINIT(nested_field_tab, &nested_field_tab_sx, "nested field tab");
static int nested_fast_field_validate = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_fast_field_validate, CTLFLAG_RWTUN,
    &nested_fast_field_validate, 0,
    "nested S0: validazione dell'encoding di VMREAD/VMWRITE dell'L1: 0 = "
    "VMPTRLD/VMREAD/VMCLEAR (come prima), 1 = tabella, 2 = tabella + confronto");
NESTED_CTR(nested_ffv_lookups, "nested S0: encoding validati con la tabella");
NESTED_CTR(nested_ffv_nofeat,
    "nested S0: accessi dell'L1 a campi di funzioni non esposte all'L1");
NESTED_CTR(nested_ffv_mismatch,
    "nested S0: tabella e metodo di prima in disaccordo (modalita' 2)");
static u_long nested_ffv_first_mismatch = ~0UL;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_ffv_first_mismatch, CTLFLAG_RD,
    &nested_ffv_first_mismatch, 0,
    "nested S0: primo encoding in disaccordo (~0 = nessuno)");
/* campi delle funzioni tolte all'L1 in vmx_nested_init_msrs (64 bit: anche HIGH) */
static const uint16_t nested_nofeat_enc[] = {
	0x0004,		/* EPTP index (#VE) */
	0x0810,		/* guest interrupt status (virtual-interrupt delivery) */
	0x0812,		/* PML index */
	0x200e,		/* PML address */
	0x2014,		/* APIC-access address (virtualize APIC accesses) */
	0x2018,		/* VM-function controls */
	0x201c, 0x201e, 0x2020, 0x2022,	/* EOI-exit bitmap (VID) */
	0x2024,		/* EPTP list (VMFUNC) */
	0x2026,		/* VMREAD bitmap (shadowing) */
	0x2028,		/* VMWRITE bitmap (shadowing) */
	0x202a,		/* #VE information address */
	0x202c,		/* XSS-exiting bitmap (XSAVES/XRSTORS) */
	0x202e,		/* ENCLS-exiting bitmap */
	0x2030,		/* sub-page-permission table pointer */
	0x2032,		/* TSC multiplier (TSC scaling) */
	0x2036,		/* ENCLV-exiting bitmap */
};

/* Riempie t[] (0x8000 voci) sulla CPU corrente; 0 se il VMCS di prova va. */
static int
nested_field_tab_fill(uint8_t *t)
{
	struct vmcs *v;
	uint64_t val;
	uint32_t e;
	u_int i;

	v = malloc_aligned(sizeof(*v), PAGE_SIZE, M_VMX_NESTED,
	    M_WAITOK | M_ZERO);
	v->identifier = vmx_revision();
	if (vmclear(v) != 0) {
		free(v, M_VMX_NESTED);
		return (EIO);
	}
	memset(t, 0, 0x8000);
	VMPTRLD(v);			/* critical_enter */
	for (e = 0; e < 0x8000; e++)
		if (vmread(e, &val) == 0)
			t[e] |= NFT_HW;
	VMCLEAR(v);			/* critical_exit */
	free(v, M_VMX_NESTED);
	for (e = 0; e < 0x8000; e++)
		if (((e >> 10) & 3) == 1)
			t[e] |= NFT_RO;
	for (i = 0; i < nitems(nested_nofeat_enc); i++) {
		e = nested_nofeat_enc[i];
		t[e] |= NFT_NOFEAT;
		if (((e >> 13) & 3) == 1)	/* 64 bit: anche l'accesso HIGH */
			t[e | 1] |= NFT_NOFEAT;
	}
	return (0);
}

/* Una volta, alla creazione del primo vCPU nested (si puo' dormire). */
static void
nested_field_tab_build(void)
{
	sx_xlock(&nested_field_tab_sx);
	if (!nested_field_tab_ok && nested_field_tab_fill(nested_field_tab) == 0)
		atomic_store_rel_int(&nested_field_tab_ok, 1);
	sx_xunlock(&nested_field_tab_sx);
}

static bool
nested_field_ok(struct vmx_vcpu *vcpu, uint32_t field)
{
	int mode = nested_fast_field_validate;
	bool ok;

	if (mode == 0)
		return (nested_field_ok_hw(vcpu, field));
	/*
	 * Acceso dopo la creazione del vCPU: la tabella si costruisce qui, la
	 * prima volta (percorso lento, fuori dalla sezione critica: si puo'
	 * dormire, VMX e' acceso). NON nel gestore del sysctl: col tunable al
	 * caricamento del modulo VMX non e' ancora acceso.
	 */
	if (atomic_load_acq_int(&nested_field_tab_ok) == 0)
		nested_field_tab_build();
	if (atomic_load_acq_int(&nested_field_tab_ok) == 0)
		return (nested_field_ok_hw(vcpu, field));
	ok = (field & 0xffff8000) == 0 &&
	    (nested_field_tab[field] & NFT_HW) != 0;
	atomic_add_long(&nested_ffv_lookups, 1);
	if (ok && (nested_field_tab[field] & NFT_NOFEAT) != 0)
		atomic_add_long(&nested_ffv_nofeat, 1);
	if (mode == 2 && ok != nested_field_ok_hw(vcpu, field)) {
		atomic_add_long(&nested_ffv_mismatch, 1);
		atomic_cmpset_long(&nested_ffv_first_mismatch, ~0UL, field);
	}
	return (ok);
}

/*
 * Autotest di S0 (parere #44 §6): scrivendo 1, la tabella si ricostruisce su
 * OGNI CPU e si confronta con quella in uso, encoding per encoding, per tutti
 * i 65536 valori di 16 bit (sopra 0x7fff entrambi i metodi dicono "non
 * valido" per il controllo dei bit 31:15). Esito: disaccordi totali (0 = ok) e
 * le tre classi contate, in nested_ffv_selftest e nel messaggio del kernel.
 */
static u_long nested_ffv_selftest = ~0UL;
static int
nested_ffv_selftest_sysctl(SYSCTL_HANDLER_ARGS)
{
	uint8_t *t;
	u_long bad = 0, hw = 0, ro = 0, nf = 0;
	int c, error, val = 0;
	uint32_t e;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL || val != 1)
		return (error);
	nested_field_tab_build();
	if (!nested_field_tab_ok)
		return (EIO);
	t = malloc(0x8000, M_VMX_NESTED, M_WAITOK);
	CPU_FOREACH(c) {
		thread_lock(curthread);
		sched_bind(curthread, c);
		thread_unlock(curthread);
		if (nested_field_tab_fill(t) != 0) {
			bad++;
			continue;
		}
		for (e = 0; e < 0x10000; e++) {
			bool a = (e & 0xffff8000) == 0 &&
			    (nested_field_tab[e & 0x7fff] & NFT_HW) != 0;
			bool b = e < 0x8000 && (t[e] & NFT_HW) != 0;
			if (a != b || (e < 0x8000 && t[e] != nested_field_tab[e]))
				bad++;
		}
	}
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
	free(t, M_VMX_NESTED);
	for (e = 0; e < 0x8000; e++) {
		hw += (nested_field_tab[e] & NFT_HW) != 0;
		ro += (nested_field_tab[e] & (NFT_HW | NFT_RO)) == (NFT_HW | NFT_RO);
		nf += (nested_field_tab[e] & (NFT_HW | NFT_NOFEAT)) ==
		    (NFT_HW | NFT_NOFEAT);
	}
	nested_ffv_selftest = bad;
	printf("nested S0: autotest su %d CPU: %lu disaccordi; encoding validi %lu, "
	    "di sola lettura %lu, di funzioni non esposte %lu\n", mp_ncpus, bad,
	    hw, ro, nf);
	return (0);
}
SYSCTL_PROC(_hw_vmm_vmx, OID_AUTO, nested_ffv_selftest_run,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    nested_ffv_selftest_sysctl, "I",
    "nested S0: scrivere 1 per l'autotest della tabella su tutte le CPU");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_ffv_selftest, CTLFLAG_RD,
    &nested_ffv_selftest, 0,
    "nested S0: disaccordi dell'ultimo autotest (~0 = mai eseguito)");

/*
 * ===== Shadow VMCS hardware (pareri #43 e #44 di Astra) =====
 * Le VMREAD/VMWRITE dell'L1 sui campi qui sotto non escono piu': l'hardware le
 * serve sullo shadow VMCS a cui punta il link pointer del VMCS01. Invisibile
 * all'L1 (MSR VMX, CPUID, VMPTRLD dell'L1 invariati; VMCS02 senza shadowing).
 * Il VMCS12 (cache + copia persistente) resta la rappresentazione canonica ai
 * confini di sincronizzazione. Regole di proprieta' (parere #44 §3):
 *  - campi RO (informazioni d'uscita, AR di CS/SS): la VMWRITE dell'L1 esce;
 *    li scrive solo L0, nel VMCS12; lo shadow ne e' una copia, aggiornata
 *    campo per campo (sh_push) prima del prossimo ingresso in L1;
 *  - campi RW (INTERRUPTIBILITY, RFLAGS, RIP): da quando l'L1 entra con lo
 *    shadow (cache->sh_rw_owned) il valore vero e' nello shadow; L0 lo
 *    riprende (shvmcs_pull) all'inizio di ogni gestore che consuma il VMCS12
 *    (VMPTRLD, VMCLEAR, VMLAUNCH/VMRESUME, VMXOFF) e solo dopo puo' leggerli o
 *    scriverli; la riflessione L2->L1 avviene col vCPU fuori dall'L1, dopo la
 *    copia di ritorno del VMRESUME;
 *  - la copia verso lo shadow e' SOLO dei campi in sh_push, e se un RW e' in
 *    sh_push mentre sh_rw_owned e' ancora vero e' un errore (il caso del
 *    parere #44 §3): fail-closed.
 * Fail-closed (parere #44 §7): ogni errore VMX o discrepanza registra campo e
 * motivo, scrive sul log del kernel e ferma la VM (VM_SUSPEND_POWEROFF); niente
 * ripiego automatico.
 * hw.vmm.vmx.nested_shadow_vmcs (tunable): letto alla creazione del vCPU nested.
 * hw.vmm.vmx.nested_shadow_verify: dopo ogni copia rilegge lo shadow e confronta.
 */
static int nested_shadow_vmcs = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_shadow_vmcs, CTLFLAG_RWTUN,
    &nested_shadow_vmcs, 0,
    "nested: shadow VMCS hardware per le VMREAD/VMWRITE dell'L1 (letto alla "
    "creazione del vCPU nested; 0 = spento)");
static int nested_shadow_verify = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_shadow_verify, CTLFLAG_RWTUN,
    &nested_shadow_verify, 0,
    "nested: shadow VMCS, rilettura e confronto dopo ogni copia (diagnostica)");
/*
 * Audit VPID (parere #48 §5.3), solo contatori: il comportamento non cambia.
 * vpid02_vpid12_change: ingressi in L2 con un VPID12 diverso dal precedente,
 * oggi SENZA invalidazione del VPID02 condiviso (difetto D1); vpid02_invvpid_*:
 * le due invalidazioni del VPID02 che esistono oggi, entrambe sulla sola CPU
 * corrente (D2); vpid01_slowpath_claim: uscite L2->L1 riflesse dallo slow path
 * su una CPU diversa da lastcpu, dove lastcpu = curcpu dichiara coerente un
 * VPID01 mai invalidato su quella CPU (D3).
 */
/*
 * D1 (parere #48): tutti i VPID12 dell'L1 condividono il VPID02, quindi un
 * VPID12 diverso dal precedente vuole un contesto TLB nuovo: con
 * nested_vpid12_flush=1 si chiede un INVVPID(VPID02), eseguito da vmx_run
 * sulla CPU del prossimo ingresso in L2 (anche al primo ingresso: il VPID02
 * non e' mai stato invalidato). Invalida soltanto di piu'. kvm-unit-tests
 * vmx_pf_vpid_test fallisce senza.
 */
static int nested_vpid12_flush = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_vpid12_flush, CTLFLAG_RWTUN,
    &nested_vpid12_flush, 0,
    "nested: invalida il VPID02 condiviso quando cambia il VPID12 (0 = spento)");
/*
 * Tracciamento VPID (parere #48 §5), letto alla creazione del vCPU nested.
 * Separa i tre significati di lastcpu: i campi host per-CPU hanno una CPU per
 * VMCS (host_cpu1 del VMCS01 e di ogni VMCS02); lastcpu resta SOLO del VPID01
 * (CPU dove il suo TLB e' coerente, NOCPU = invalidazione in attesa) e il
 * nested non lo scrive piu', salvo NOCPU dove l'SDM chiede un flush (VMCS12
 * senza VPID); il VPID02 ha la sua lastcpu e la sua richiesta pendente.
 * Effetto: niente INVVPID(VPID01) a ogni ingresso in L2 (falsa migrazione), e
 * il VPID02 invalidato sulle migrazioni vere, al cambio di VPID12 (D1), dopo un
 * INVVPID dell'L1 eseguito su un'altra CPU (D2) e per le richieste differite
 * (D4); dallo slow path non si dichiara piu' coerente il VPID01 (D3).
 * Con un VPID02 non unico (D5) il VMCS02 si compone senza VPID (vpid02_off,
 * parere #49 §5): vedi vmx_nested_init.
 */
/*
 * Prova del ripiego (parere #49 §5): con nested_vpid_test_off=1 i vCPU nested
 * creati da qui in poi si comportano come se l'allocatore avesse esaurito i
 * VPID (VPID02 non unico): VMCS02 senza VPID. Solo diagnostica.
 */
static int nested_vpid_test_off = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_vpid_test_off, CTLFLAG_RWTUN,
    &nested_vpid_test_off, 0,
    "nested, prova: vpid_track col VPID02 trattato come non unico (VMCS02 "
    "senza VPID)");
NESTED_CTR(vpid02_off_vcpus,
    "vpid_track: vCPU nested col VPID02 non unico, VMCS02 senza VPID");
/*
 * D4 (parere #51 §7), aggancio di prova, SPENTO per default: con
 * nested_vpid_d4_arm = N, una entrata su N nello slow path nested (vCPU in L2,
 * frozen) inietta una richiesta d'invalidazione differita del VPID02, come se
 * l'L1 avesse scritto CR3 col vCPU fermo. Con migratore.sh che sposta il thread
 * fra le CPU, la richiesta nasce su una CPU e deve essere soddisfatta sulla CPU
 * del prossimo ingresso in L2: se il meccanismo fosse rotto, i test di
 * contenuto (vmx_pf_vpid_test, vmx_vpid_ctx_test) vedrebbero traduzioni stantie.
 */
static int nested_vpid_d4_arm = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_vpid_d4_arm, CTLFLAG_RWTUN,
    &nested_vpid_d4_arm, 0,
    "nested, prova D4: 1 richiesta differita del VPID02 ogni N entrate nello "
    "slow path in L2 (0 = spento)");
NESTED_CTR(nested_vpid_d4_injected,
    "prova D4: richieste differite del VPID02 iniettate dall'aggancio");
static int nested_vpid_track = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_vpid_track, CTLFLAG_RWTUN,
    &nested_vpid_track, 0,
    "nested: VPID01/VPID02 e campi host tracciati separatamente (letto alla "
    "creazione del vCPU nested; 0 = spento)");
NESTED_CTR(vpid02_vpid12_change,
    "VPID: ingressi in L2 con VPID12 cambiato (VPID02 condiviso non invalidato)");
NESTED_CTR(vpid02_invvpid_l1insn,
    "VPID: INVVPID(VPID02) per un INVVPID dell'L1 (solo sulla CPU corrente)");
NESTED_CTR(vpid02_invvpid_novpid12,
    "VPID: INVVPID(VPID02) all'uscita da un VMCS12 senza VPID (CPU corrente)");
NESTED_CTR(vpid02_invvpid_novpid12_slow,
    "VPID: di cui con l'uscita riflessa dallo slow path");
NESTED_CTR(vpid01_slowpath_claim,
    "VPID: uscite L2->L1 dallo slow path con lastcpu != curcpu (VPID01 non invalidato)");
NESTED_CTR(nested_sh_push, "nested shadow: copie VMCS12 -> shadow");
NESTED_CTR(nested_sh_push_fields, "nested shadow: campi copiati verso lo shadow");
NESTED_CTR(nested_sh_push_tsc, "nested shadow: cicli TSC delle copie verso lo shadow");
NESTED_CTR(nested_sh_pull, "nested shadow: copie di ritorno shadow -> VMCS12");
NESTED_CTR(nested_sh_pull_tsc, "nested shadow: cicli TSC delle copie di ritorno");
NESTED_CTR(nested_sh_pull_changed,
    "nested shadow: campi RW trovati cambiati dall'L1 alla copia di ritorno");
NESTED_CTR(nested_sh_clear, "nested shadow: VMCLEAR dello shadow a fine vmx_run");
NESTED_CTR(nested_sh_ctl, "nested shadow: riscritture di controllo/bitmap/link nel VMCS01");
NESTED_CTR(nested_sh_verify, "nested shadow: confronti della modalita' di verifica");
NESTED_CTR(nested_sh_ar_norm,
    "nested shadow: AR di CS/SS normalizzati dall'hardware (solo bit riservati)");
NESTED_CTR(nested_sh_faults, "nested shadow: errori (VM fermata)");
/*
 * Iniezione d'errore a un colpo per la prova del fail-closed (parere #45 §3):
 * 1 = discrepanza su un RW alla prossima copia di ritorno, 2 = copia verso lo
 * shadow di un RW non recuperato, 3 = errore VMX alla prossima copia verso lo
 * shadow. Il motivo registrato porta il bit 0x80 (iniettato).
 */
static int nested_shadow_inject = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_shadow_inject, CTLFLAG_RW,
    &nested_shadow_inject, 0,
    "nested shadow: errore simulato a un colpo (1 RW, 2 sovrascrittura, 3 VMX)");
u_long nested_sh_entry_after_fault;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_sh_entry_after_fault, CTLFLAG_RD,
    &nested_sh_entry_after_fault, 0,
    "nested shadow: ingressi avvenuti dopo un errore registrato (deve essere 0)");
NESTED_CTR(nested_sh_blocked, "nested shadow: ingressi impediti da un errore");
static u_long nested_sh_first_fault = 0;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, nested_sh_first_fault, CTLFLAG_RD,
    &nested_sh_first_fault, 0,
    "nested shadow: primo errore, (motivo << 32) | encoding");

#define	SHV_RW		0x1
static const struct { uint32_t enc; uint32_t fl; } shv_fields[] = {
	{ VMCS_GUEST_INTERRUPTIBILITY, SHV_RW },
	{ VMCS_GUEST_RFLAGS, SHV_RW },
	{ VMCS_GUEST_RIP, SHV_RW },
	{ VMCS_GUEST_CS_ACCESS_RIGHTS, 0 },	/* RO: parere #44 §2.1 */
	{ VMCS_GUEST_SS_ACCESS_RIGHTS, 0 },
	{ VMCS_EXIT_REASON, 0 },
	{ VMCS_EXIT_QUALIFICATION, 0 },
	{ VMCS_EXIT_INSTRUCTION_LENGTH, 0 },
	{ VMCS_EXIT_INTR_INFO, 0 },
	{ VMCS_EXIT_INTR_ERRCODE, 0 },
	{ VMCS_IDT_VECTORING_INFO, 0 },
	{ VMCS_IDT_VECTORING_ERROR, 0 },
	{ VMCS_EXIT_INSTRUCTION_INFO, 0 },
	{ VMCS_GUEST_LINEAR_ADDRESS, 0 },
	{ VMCS_GUEST_PHYSICAL_ADDRESS, 0 },	/* 64 bit: anche HIGH nella bitmap */
};
#define	SHV_N		nitems(shv_fields)
#define	SHV_ALL		((1U << SHV_N) - 1)
CTASSERT(SHV_N <= 32);
static uint32_t shv_rw_mask;		/* bit dei campi RW in shv_fields */
static uint8_t *shv_rbm, *shv_wbm;	/* bitmap VMREAD/VMWRITE: 1 = esce */
/* motivi di errore (alti 32 bit di nested_sh_first_fault) */
#define	SHF_VMX		1	/* VMPTRLD/VMREAD/VMWRITE/VMCLEAR sullo shadow fallita */
#define	SHF_GUARD	2	/* L0 ha toccato un RW nel VMCS12 mentre era dello shadow */
#define	SHF_CLOBBER	3	/* copia verso lo shadow di un RW non recuperato */
#define	SHF_VERIFY	4	/* rilettura dello shadow diversa dal VMCS12 */
#define	SHF_INJECTED	0x80	/* errore simulato (nested_shadow_inject) */

static int
shv_idx(uint32_t enc)
{
	u_int i;

	for (i = 0; i < SHV_N; i++)
		if (shv_fields[i].enc == enc)
			return (i);
	return (-1);
}

/* Le bitmap si costruiscono una volta (sotto nested_field_tab_sx). */
static int
shv_global_init(void)
{
	uint32_t e;
	u_int i;

	sx_assert(&nested_field_tab_sx, SA_XLOCKED);
	if (shv_rbm != NULL)
		return (0);
	shv_rbm = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX_NESTED, M_WAITOK);
	shv_wbm = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX_NESTED, M_WAITOK);
	memset(shv_rbm, 0xff, PAGE_SIZE);
	memset(shv_wbm, 0xff, PAGE_SIZE);
	for (i = 0; i < SHV_N; i++) {
		e = shv_fields[i].enc;
		shv_rbm[e >> 3] &= ~(1 << (e & 7));
		if (((e >> 13) & 3) == 1)	/* 64 bit: anche l'accesso HIGH */
			shv_rbm[(e | 1) >> 3] &= ~(1 << ((e | 1) & 7));
		if (shv_fields[i].fl & SHV_RW) {
			shv_wbm[e >> 3] &= ~(1 << (e & 7));
			shv_rw_mask |= 1U << i;
		}
	}
	return (0);
}

/* Fail-closed: registra, avvisa, ferma la VM. */
static void
shv_fault(struct vmx_vcpu *vcpu, int why, uint32_t enc)
{
	struct vmx_nested *n = vcpu->nested;

	atomic_add_long(&nested_sh_faults, 1);
	atomic_cmpset_long(&nested_sh_first_fault, 0,
	    ((u_long)why << 32) | enc);
	if (!n->sh_fault)
		printf("nested shadow VMCS: vcpu%d errore %d sul campo %#x: "
		    "VM fermata (parere #44 §7)\n", vcpu->vcpuid, why, enc);
	n->sh_fault = true;
	vm_suspend(vcpu->vmx->vm, VM_SUSPEND_POWEROFF);
}

/*
 * Guardia di vmcs12_read_field/vmcs12_write_field: un RW dello slot rispecchiato
 * toccato da L0 senza copia di ritorno. Lo slot non conosce il suo vCPU: si
 * registra qui e lo shadow del vCPU si ferma al prossimo ingresso in L1.
 */
static void
shv_guard(struct vmcs12_cache *c, uint32_t enc)
{
	int i = shv_idx(enc);

	if (i < 0 || (shv_fields[i].fl & SHV_RW) == 0)
		return;
	atomic_add_long(&nested_sh_faults, 1);
	atomic_cmpset_long(&nested_sh_first_fault, 0,
	    ((u_long)SHF_GUARD << 32) | enc);
	c->sh_rw_owned = false;		/* una volta sola; la VM si ferma */
	c->sh_guard_hit = true;
}

/*
 * shadow -> VMCS12 dei campi RW. Slow path: vCPU FROZEN, nessun VMCS corrente
 * (vmx_run fa VMCLEAR del VMCS01 e dello shadow prima di tornare), su qualunque
 * CPU. Da chiamare all'inizio di ogni gestore che consuma il VMCS12.
 */
static int
shvmcs_pull(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = n->sh_cache;
	uint64_t v[SHV_N], t0;
	int err = 0;
	u_int i;

	if (!n->sh_on)
		return (0);
	if (n->sh_fault)
		return (EIO);
	if (!n->sh_live || c == NULL || !c->sh_rw_owned)
		return (0);
	if (nested_shadow_inject == 1 &&
	    atomic_cmpset_int(&nested_shadow_inject, 1, 0)) {
		shv_fault(vcpu, SHF_VERIFY | SHF_INJECTED, VMCS_GUEST_RIP);
		return (EIO);
	}
	t0 = rdtsc();
	critical_enter();
	err = vmptrld(n->sh_vmcs);
	for (i = 0; i < SHV_N && err == 0; i++)
		if ((shv_rw_mask & (1U << i)) != 0 || nested_shadow_verify)
			err = vmread(shv_fields[i].enc, &v[i]);
	err |= vmclear(n->sh_vmcs);
	critical_exit();
	if (err != 0) {
		shv_fault(vcpu, SHF_VMX, 0);
		return (EIO);
	}
	c->sh_rw_owned = false;
	for (i = 0; i < SHV_N; i++) {
		uint32_t e = shv_fields[i].enc;
		uint64_t old = vmcs12_read_field(c, e);

		if ((shv_rw_mask & (1U << i)) != 0) {
			if (v[i] != old) {
				atomic_add_long(&nested_sh_pull_changed, 1);
				vmcs12_write_field(c, e, v[i]);
			}
		} else if (nested_shadow_verify && (n->sh_push & (1U << i)) == 0) {
			/* RO non scritto da L0 dopo l'ultima copia: deve coincidere */
			atomic_add_long(&nested_sh_verify, 1);
			if (v[i] != old) {
				shv_fault(vcpu, SHF_VERIFY, e);
				return (EIO);
			}
		}
	}
	atomic_add_long(&nested_sh_pull, 1);
	atomic_add_long(&nested_sh_pull_tsc, rdtsc() - t0);
	return (0);
}

/* Il VMCS12 rispecchiato cambia (VMPTRLD) o sparisce (VMCLEAR, VMXOFF). */
static void
shvmcs_set_current(struct vmx_nested *n, struct vmcs12_cache *c)
{
	if (!n->sh_on)
		return;
	KASSERT(n->sh_cache == NULL || !n->sh_cache->sh_rw_owned,
	    ("shvmcs_set_current: RW non recuperati"));
	/* una guardia scattata sullo slot che lascia lo shadow non va persa */
	if (n->sh_cache != NULL && n->sh_cache->sh_guard_hit)
		n->sh_fault = true;
	n->sh_cache = c;
	n->sh_live = c != NULL;
	n->sh_push = c != NULL ? SHV_ALL : 0;	/* lo shadow e' tutto da riempire */
}

/* L0 ha scritto il campo enc del VMCS12 c: va ricopiato nello shadow. */
static void
shvmcs_mark(struct vmx_nested *n, struct vmcs12_cache *c, uint32_t enc)
{
	int i;

	if (!n->sh_on || !n->sh_live || c != n->sh_cache)
		return;
	if (enc == ~0U) {
		n->sh_push = SHV_ALL;
		return;
	}
	if ((i = shv_idx(enc)) >= 0)
		n->sh_push |= 1U << i;
}

/*
 * Prima di ogni ingresso in L1 (vmx_run, interrupt spenti, VMCS01 corrente,
 * PRIMA dei controlli di sospensione: un errore ferma la VM e il controllo
 * successivo esce senza entrare). Ricopia i campi marcati, poi rende il VMCS01
 * coerente con lo stato virtuale: shadowing e bitmap accesi fra VMXON e VMXOFF,
 * link pointer sullo shadow se c'e' un VMCS12 corrente, ~0 altrimenti. Rilegge
 * sempre i valori veri del VMCS01: bhyve riscrive i controlli secondari da
 * cap.proc_ctls2 in altri punti (x2APIC, capability).
 */
/*
 * Pulizia dopo un errore nella copia verso lo shadow: lo shadow non deve
 * restare attivo e il VMCS01 deve tornare corrente (errori ignorati: la VM si
 * ferma comunque).
 */
static void
shv_fault_cleanup(struct vmx_vcpu *vcpu)
{
	(void)vmclear(vcpu->nested->sh_vmcs);
	(void)vmptrld(vcpu->vmcs01);
}

bool
vmx_shvmcs_enter(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = n->sh_cache;
	uint64_t t0, link, want_link, proc2, rb;
	bool want_ctl;
	int err = 0, inj;
	u_int i, k = 0;

	/* fail-closed sincrono (parere #45 §3): con un errore registrato non si
	 * entra piu', ne' in L1 ne' in L2 */
	if (n->sh_fault || (c != NULL && c->sh_guard_hit)) {
		if (!n->sh_fault)
			shv_fault(vcpu, SHF_GUARD, 0);
		vm_suspend(vcpu->vmx->vm, VM_SUSPEND_POWEROFF);
		atomic_add_long(&nested_sh_blocked, 1);
		return (true);
	}
	if (n->in_l2)
		return (false);		/* in L2 lo shadow non e' in uso */
	inj = nested_shadow_inject;
	if ((inj == 2 || inj == 3) &&
	    atomic_cmpset_int(&nested_shadow_inject, inj, 0)) {
		if (inj == 2) {
			shv_fault(vcpu, SHF_CLOBBER | SHF_INJECTED, 0);
			atomic_add_long(&nested_sh_blocked, 1);
			return (true);
		}
		n->sh_push |= SHV_ALL & ~shv_rw_mask;	/* forza una copia... */
		n->sh_inject_vmx = true;		/* ...che fallisce */
	}
	if (n->sh_live && c != NULL && n->sh_push != 0) {
		if (c->sh_rw_owned && (n->sh_push & shv_rw_mask) != 0) {
			shv_fault(vcpu, SHF_CLOBBER, 0);	/* parere #44 §3 */
			atomic_add_long(&nested_sh_blocked, 1);
			return (true);
		}
		t0 = rdtsc();
		err = vmptrld(n->sh_vmcs);
		if (n->sh_inject_vmx) {
			n->sh_inject_vmx = false;
			err = EIO;
			inj = 3;	/* il motivo porta 0x80 anche se armata prima */
		}
		for (i = 0; i < SHV_N && err == 0; i++) {
			if ((n->sh_push & (1U << i)) == 0)
				continue;
			err = vmwrite(shv_fields[i].enc,
			    vmcs12_read_field(c, shv_fields[i].enc));
			k++;
			if (err == 0 && nested_shadow_verify) {
				uint64_t want = vmcs12_read_field(c,
				    shv_fields[i].enc);

				err = vmread(shv_fields[i].enc, &rb);
				atomic_add_long(&nested_sh_verify, 1);
				if (err == 0 && rb != want) {
					/* AR: l'hardware puo' scartare i bit
					 * riservati (parere #44 §2.1) */
					if ((i == 3 || i == 4) &&
					    ((rb ^ want) & ~0xfffe0f00ULL) == 0) {
						atomic_add_long(&nested_sh_ar_norm, 1);
						continue;
					}
					shv_fault_cleanup(vcpu);
					shv_fault(vcpu, SHF_VERIFY,
					    shv_fields[i].enc);
					atomic_add_long(&nested_sh_blocked, 1);
					return (true);
				}
			}
		}
		if (err == 0)
			err = vmclear(n->sh_vmcs);
		if (err == 0)
			err = vmptrld(vcpu->vmcs01);	/* torna corrente; resta launched */
		if (err != 0) {
			shv_fault_cleanup(vcpu);
			shv_fault(vcpu, SHF_VMX | (inj == 3 ? SHF_INJECTED : 0), 0);
			atomic_add_long(&nested_sh_blocked, 1);
			return (true);
		}
		n->sh_push = 0;
		atomic_add_long(&nested_sh_push, 1);
		atomic_add_long(&nested_sh_push_fields, k);
		atomic_add_long(&nested_sh_push_tsc, rdtsc() - t0);
	}
	want_ctl = n->vmxon;
	want_link = (want_ctl && n->sh_live) ? vtophys(n->sh_vmcs) : ~0UL;
	proc2 = vmcs_read(VMCS_SEC_PROC_BASED_CTLS);
	if (((proc2 & PROCBASED2_VMCS_SHADOWING) != 0) != want_ctl) {
		if (want_ctl) {
			vmcs_write(VMCS_VMREAD_BITMAP, vtophys(shv_rbm));
			vmcs_write(VMCS_VMWRITE_BITMAP, vtophys(shv_wbm));
			proc2 |= PROCBASED2_VMCS_SHADOWING;
		} else
			proc2 &= ~PROCBASED2_VMCS_SHADOWING;
		vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc2);
		atomic_add_long(&nested_sh_ctl, 1);
	}
	link = vmcs_read(VMCS_LINK_POINTER);
	if (link != want_link) {
		vmcs_write(VMCS_LINK_POINTER, want_link);
		atomic_add_long(&nested_sh_ctl, 1);
	}
	if (want_link != ~0UL) {
		n->sh_active = true;	/* VMCLEAR a fine vmx_run (parere #44 §5) */
		c->sh_rw_owned = true;	/* da qui i RW sono dello shadow */
	}
	return (false);
}

/*
 * Fine di vmx_run, ancora in sezione critica sulla CPU dell'ultimo ingresso:
 * lo shadow referenziato dal link pointer e' diventato attivo all'ingresso
 * (SDM 24.11.1) e va chiuso QUI, prima che il thread possa migrare.
 */
void
vmx_shvmcs_run_end(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;

	if (n->sh_fault && n->sh_vmcs != NULL) {
		(void)vmclear(n->sh_vmcs);	/* dopo un errore: mai attivo */
		n->sh_active = false;
		return;
	}
	if (!n->sh_active)
		return;
	n->sh_active = false;
	if (vmclear(n->sh_vmcs) != 0)
		shv_fault(vcpu, SHF_VMX, 1);
	atomic_add_long(&nested_sh_clear, 1);
}

/* Larghezza del campo (bit 14:13): 0=16, 1=64, 2=32, 3=naturale. */
#define	NESTED_FIELD_WIDTH(f)	(((f) >> 13) & 3)
/* Accesso HIGH (bit 0) di un campo a 64 bit = meta' alta dello stesso campo. */
#define	NESTED_FIELD_HIGH(f)	(NESTED_FIELD_WIDTH(f) == 1 && ((f) & 1) != 0)

static uint64_t
nested_field_mask(uint32_t field)
{
	switch (NESTED_FIELD_WIDTH(field)) {
	case 0:	return (0xffffULL);
	case 2:	return (0xffffffffULL);
	default: return (~0ULL);
	}
}

/*
 * VMREAD/VMWRITE dell'L1. Tutte le istruzioni escono (nessuno shadowing
 * hardware ancora: §6.2 e' un'ottimizzazione rimandata a T2) e si gestiscono
 * in software sullo store del VMCS12 corrente. Decode dell'operando: campo
 * in reg2 (bit 31:28), valore/dest in reg1 (bit 6:3) se registro (bit 10),
 * altrimenti operando di memoria (SDM/KVM).
 */
/*
 * Stadio 10, K3 (SDM vol. 3C, VMREAD/VMWRITE/INVEPT/INVVPID: fuori dal modo
 * 64 bit gli operandi registro sono di 32 bit e i bit 63:32 si ignorano; KVM
 * kvm_register_read): il registro operando come lo vede l'istruzione. Unico
 * punto per il campo di VMREAD/VMWRITE, il valore registro di VMWRITE e il tipo
 * di INVEPT/INVVPID. Le istruzioni VMX in compatibilita' danno #UD prima
 * dell'uscita: fuori dal modo 64 bit qui c'e' solo il modo protetto.
 */
static uint64_t
nested_reg_operando(struct vmx_vcpu *vcpu, int reg)
{
	uint64_t v;

	v = vmx_get_guest_reg(vcpu, reg);
	if (vcpu->nested->exit_paging.cpu_mode != CPU_MODE_64BIT)
		v &= 0xffffffffULL;
	return (v);
}

static int
nested_vmread(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t val, field64;
	uint32_t info, field;
	size_t len;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) { nested_vmfail_invalid(vcpu); goto done; }

	info = (uint32_t)vcpu->nested->exit_insn_info; /* catturato */
	field64 = nested_reg_operando(vcpu, (info >> 28) & 0xf);
	field = (uint32_t)field64;
	/*
	 * Stadio 10, K2 (SDM VMREAD/VMWRITE: in modo 64 bit un campo con i bit
	 * 63:32 non nulli non corrisponde a nessun componente -> VMfail(12)).
	 * Fuori dal modo 64 bit nested_reg_operando li ha gia' azzerati (K3).
	 */
	if ((field64 >> 32) != 0 || !nested_field_ok(vcpu, field)) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	if (NESTED_FIELD_HIGH(field))
		val = vmcs12_read_field(c, field & ~1U) >> 32;
	else
		val = vmcs12_read_field(c, field) & nested_field_mask(field);
	/*
	 * #160 R7: fuori dal modo 64 bit l'operando e' di 32 bit (SDM VMREAD):
	 * i bit alti del campo non si leggono, e in memoria si scrivono 4 byte,
	 * non 8 (prima: 4 byte oltre l'operando sovrascritti).
	 */
	len = vcpu->nested->exit_paging.cpu_mode == CPU_MODE_64BIT ? 8 : 4;
	if (len == 4)
		val &= 0xffffffffULL;

	if ((info >> 10) & 0x1) {
		vmx_set_guest_reg(vcpu, (info >> 3) & 0xf, val);
	} else {
		switch (nested_operand_copy(vcpu, VM_PROT_WRITE, &val, len)) {
		case NOPND_OK:
			break;
		case NOPND_INIETTATO:
			return (0);
		case NOPND_HOST_FATALE:
			return (nested_operand_fatale(vcpu));
		case NOPND_CONTESO:
			return (nested_operand_conteso(vcpu));
		}
	}
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}

static int
nested_vmwrite(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t val, field64;
	uint32_t info, field;
	size_t len;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) { nested_vmfail_invalid(vcpu); goto done; }

	info = (uint32_t)vcpu->nested->exit_insn_info; /* catturato */
	field64 = nested_reg_operando(vcpu, (info >> 28) & 0xf);
	field = (uint32_t)field64;

	/*
	 * #160 R7: fuori dal modo 64 bit la sorgente e' di 32 bit (SDM VMWRITE):
	 * si leggono 4 byte, e un campo piu' largo ha i bit alti azzerati.
	 */
	len = vcpu->nested->exit_paging.cpu_mode == CPU_MODE_64BIT ? 8 : 4;
	val = 0;
	if ((info >> 10) & 0x1) {
		val = nested_reg_operando(vcpu, (info >> 3) & 0xf);
	} else {
		switch (nested_operand_copy(vcpu, VM_PROT_READ, &val, len)) {
		case NOPND_OK:
			break;
		case NOPND_INIETTATO:
			return (0);
		case NOPND_HOST_FATALE:
			return (nested_operand_fatale(vcpu));
		case NOPND_CONTESO:
			return (nested_operand_conteso(vcpu));
		}
	}
	/*
	 * Stadio 10, K2 (SDM VMREAD/VMWRITE: in modo 64 bit un campo con i bit
	 * 63:32 non nulli non corrisponde a nessun componente -> VMfail(12)).
	 * Fuori dal modo 64 bit nested_reg_operando li ha gia' azzerati (K3).
	 */
	if ((field64 >> 32) != 0 || !nested_field_ok(vcpu, field)) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	if (NESTED_FIELD_HIGH(field)) {		/* scrive la meta' alta */
		field &= ~1U;
		val = (vmcs12_read_field(c, field) & 0xffffffffULL) |
		    (val << 32);
	} else
		val &= nested_field_mask(field);
	/* F0: VMWRITE su ogni campo (MISC bit 29) = SI -> niente rifiuto RO. */
	if (vmcs12_write_field(c, field, val) != 0) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	shvmcs_mark(n, c, field);	/* campo RO dello shadow: va ricopiato */
	c->control_dirty = true;
	c->host_dirty = true;
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}


/*
 * L1 -> L2: VMLAUNCH (is_resume=false) / VMRESUME (is_resume=true), §6.6.
 * Prepara e compone VMCS02, lo rende corrente e lascia che vm_run (dopo il
 * goto restart) ci entri. Su fallimento ripristina VMCS01 e riflette un
 * VMfail all'L1 (in bring-up, piu' sicuro di sospendere la VM). Ritorna
 * sempre 0: l'esito e' nel RFLAGS dell'L1 (fallimento) o nell'ingresso in L2.
 */
/*
 * Controlli SDM 26.2.1 (campi di controllo, VMfailValid 7) e 26.2.2-26.2.4
 * (stato host e dimensione dello spazio d'indirizzi, VMfailValid 8) sul
 * VMCS12, contro le capacita' VMX ESPOSTE all'L1 (n->vmx_msr). Prima erano
 * "rimandati": la composizione aggiunge di suo i bit obbligatori e nascondeva
 * gli errori dell'L1 (kvm-unit-tests vmx_controls_test,
 * vmx_host_state_area_test). Slow path: puo' leggere la memoria dell'L1
 * (VTPR della pagina virtual-APIC). 0 se tutto valido.
 */
static bool
nested_pa_ok(uint64_t pa, uint64_t align)
{
	return ((pa & (align - 1)) == 0 && (pa >> cpu_maxphyaddr) == 0);
}

/*
 * #162: EPTP valido per le capacita' EPT esposte all'L1 (la EPT/VPID cap
 * virtuale): tipo di memoria UC (bit 8) o WB (bit 14), page walk a 4 livelli
 * (il 5 non e' esposto), A/D solo col bit 21, bit 11:7 a zero, entro
 * MAXPHYADDR. Lo stesso controllo serve al VM entry (SDM 26.2.1.1) e a INVEPT
 * single-context ("un EPTP che farebbe fallire un VM entry" -> VMfail; KVM
 * nested_vmx_check_eptp). Prima era scritto solo nel controllo d'ingresso.
 */
static bool
nested_eptp_ok(uint64_t cap, uint64_t e)
{
	uint64_t mt = e & 7;

	return (((mt == 0 && (cap & (1ULL << 8))) ||
	    (mt == 6 && (cap & (1ULL << 14)))) &&
	    ((e >> 3) & 7) == 3 &&
	    ((e & (1ULL << 6)) == 0 || (cap & (1ULL << 21)) != 0) &&
	    (e & 0xf80) == 0 && (e >> cpu_maxphyaddr) == 0);
}

static bool
nested_ctl_ok(uint32_t val, uint64_t msr)
{
	return ((val & (uint32_t)msr) == (uint32_t)msr &&
	    (val & ~(uint32_t)(msr >> 32)) == 0);
}

static bool
nested_msr_area_ok(struct vmcs12_cache *c, uint32_t addr_f, uint32_t cnt_f)
{
	uint64_t a = vmcs12_read_field(c, addr_f);
	uint64_t n = vmcs12_read_field(c, cnt_f);

	if (n == 0)
		return (true);
	return ((a & 0xf) == 0 && ((a + n * 16 - 1) >> cpu_maxphyaddr) == 0);
}

static int
nested_check_vmentry(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t *m = n->vmx_msr;
	bool tru = (m[0] >> 55) & 1;
	uint32_t pin, proc, proc2, exitc, entryc, info;
	uint64_t misc = m[0x485 - 0x480], cap = m[0x48c - 0x480];
	uint64_t v, l1efer = 0;
	bool hostlm;
	int i;

	pin = (uint32_t)vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
	proc = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	proc2 = (proc & PROCBASED_SECONDARY_CONTROLS) ?
	    (uint32_t)vmcs12_proc2(c) : 0;
	exitc = (uint32_t)vmcs12_read_field(c, VMCS_EXIT_CTLS);
	entryc = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_CTLS);

	/* --- 26.2.1.1 controlli d'esecuzione --- */
	if (!nested_ctl_ok(pin, m[(tru ? 0x48d : 0x481) - 0x480]) ||
	    !nested_ctl_ok(proc, m[(tru ? 0x48e : 0x482) - 0x480]) ||
	    ((proc & PROCBASED_SECONDARY_CONTROLS) &&
	    !nested_ctl_ok(proc2, m[0x48b - 0x480])))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (vmcs12_read_field(c, VMCS_CR3_TARGET_COUNT) > ((misc >> 16) & 0x1ff))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc & PROCBASED_IO_BITMAPS) &&
	    (!nested_pa_ok(vmcs12_read_field(c, VMCS_IO_BITMAP_A), PAGE_SIZE) ||
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_IO_BITMAP_B), PAGE_SIZE)))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc & PROCBASED_MSR_BITMAPS) &&
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_MSR_BITMAP), PAGE_SIZE))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (proc & PROCBASED_USE_TPR_SHADOW) {
		uint64_t va = vmcs12_read_field(c, VMCS_VIRTUAL_APIC);
		uint32_t thr = (uint32_t)vmcs12_read_field(c, VMCS_TPR_THRESHOLD);

		if (!nested_pa_ok(va, PAGE_SIZE))
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if ((proc2 & PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY) == 0) {
			if ((thr & ~0xfU) != 0)
				return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
			if ((proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) == 0) {
				uint8_t *pg;
				void *ck;
				uint8_t vtpr;

				/* pagina non RAM: la CPU legge cio' che c'e';
				 * non e' un errore di formato -> niente VMfail */
				pg = vm_gpa_hold(vcpu->vcpu, va, PAGE_SIZE,
				    VM_PROT_READ, &ck);
				if (pg != NULL) {
					vtpr = pg[0x80];
					vm_gpa_release(ck);
					if ((thr & 0xf) > (uint32_t)(vtpr >> 4))
						return (
						    VMXERR_ENTRY_INVALID_CONTROL_FIELD);
				}
			}
		}
	} else if (proc2 & (PROCBASED2_VIRTUALIZE_X2APIC_MODE |
	    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_NMI_EXITING) == 0 && (pin & PINBASED_VIRTUAL_NMI))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_VIRTUAL_NMI) == 0 &&
	    (proc & PROCBASED_NMI_WINDOW_EXITING))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) &&
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_APIC_ACCESS), PAGE_SIZE))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) &&
	    (proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY) &&
	    (pin & PINBASED_EXTINT_EXITING) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_ENABLE_VPID) &&
	    (vmcs12_read_field(c, VMCS_VPID) & 0xffff) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_ENABLE_EPT) &&
	    !nested_eptp_ok(cap, vmcs12_read_field(c, VMCS_EPTP)))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_UNRESTRICTED_GUEST) &&
	    (proc2 & PROCBASED2_ENABLE_EPT) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.1.2 controlli d'uscita --- */
	if (!nested_ctl_ok(exitc, m[(tru ? 0x48f : 0x483) - 0x480]))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_PREMPTION_TIMER) == 0 &&
	    (exitc & VM_EXIT_SAVE_PREEMPTION_TIMER))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (!nested_msr_area_ok(c, VMCS_EXIT_MSR_STORE,
	    VMCS_EXIT_MSR_STORE_COUNT) ||
	    !nested_msr_area_ok(c, VMCS_EXIT_MSR_LOAD, VMCS_EXIT_MSR_LOAD_COUNT))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.1.3 controlli d'ingresso --- */
	if (!nested_ctl_ok(entryc, m[(tru ? 0x490 : 0x484) - 0x480]) ||
	    (entryc & (VM_ENTRY_INTO_SMM | VM_ENTRY_DEACTIVATE_DUAL_MONITOR)))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	info = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO);
	if (info & VMCS_INTR_VALID) {
		uint32_t type = (info >> 8) & 7, vec = info & 0xff;
		bool pe = (vmcs12_read_field(c, VMCS_GUEST_CR0) & CR0_PE) != 0;
		bool ec, want;

		if (type == 1 ||
		    (type == 7 && (vec != 0 ||
		    ((m[(tru ? 0x48e : 0x482) - 0x480] >> 32) &
		    PROCBASED_MTF) == 0)) ||
		    (type == 2 && vec != 2) || (type == 3 && vec > 31))
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		ec = (info & (1U << 11)) != 0;
		want = type == 3 && (pe ||
		    (proc2 & PROCBASED2_UNRESTRICTED_GUEST) == 0) &&
		    (vec == 8 || (vec >= 10 && vec <= 14) || vec == 17 ||
		    vec == 21);
		if (ec != want || (info & 0x7ffff000U) != 0)
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if (ec && (vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR) >>
		    16) != 0)
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if (type >= 4 && type <= 6) {
			v = vmcs12_read_field(c, VMCS_ENTRY_INST_LENGTH);
			if (v > 15 || (v == 0 && (misc & (1ULL << 30)) == 0))
				return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		}
	}
	if (!nested_msr_area_ok(c, VMCS_ENTRY_MSR_LOAD,
	    VMCS_ENTRY_MSR_LOAD_COUNT))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.2 stato host --- */
	if (!nested_fixed_ok(vmcs12_read_field(c, VMCS_HOST_CR0),
	    m[0x486 - 0x480], m[0x487 - 0x480]) ||
	    !nested_fixed_ok(vmcs12_read_field(c, VMCS_HOST_CR4),
	    m[0x488 - 0x480], m[0x489 - 0x480]) ||
	    (vmcs12_read_field(c, VMCS_HOST_CR3) >> cpu_maxphyaddr) != 0 ||
	    !nested_canonical(vmcs12_read_field(c,
	    VMCS_HOST_IA32_SYSENTER_ESP)) ||
	    !nested_canonical(vmcs12_read_field(c,
	    VMCS_HOST_IA32_SYSENTER_EIP)))
		return (VMXERR_ENTRY_INVALID_HOST_STATE);
	if (exitc & VM_EXIT_LOAD_PAT) {
		v = vmcs12_read_field(c, VMCS_HOST_IA32_PAT);
		for (i = 0; i < 8; i++) {
			uint8_t t = (v >> (i * 8)) & 0xff;

			if (t == 2 || t == 3 || t > 7)
				return (VMXERR_ENTRY_INVALID_HOST_STATE);
		}
	}
	hostlm = (exitc & VM_EXIT_HOST_LMA) != 0;
	if (exitc & VM_EXIT_LOAD_EFER) {
		v = vmcs12_read_field(c, VMCS_HOST_IA32_EFER);
		if ((v & ~(EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE)) != 0 ||
		    ((v & EFER_LMA) != 0) != hostlm ||
		    ((v & EFER_LME) != 0) != hostlm)
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	{
		static const uint32_t sel[] = {
			VMCS_HOST_ES_SELECTOR, VMCS_HOST_CS_SELECTOR,
			VMCS_HOST_SS_SELECTOR, VMCS_HOST_DS_SELECTOR,
			VMCS_HOST_FS_SELECTOR, VMCS_HOST_GS_SELECTOR,
			VMCS_HOST_TR_SELECTOR,
		};
		for (i = 0; i < (int)nitems(sel); i++)
			if (vmcs12_read_field(c, sel[i]) & 0x7)	/* RPL, TI */
				return (VMXERR_ENTRY_INVALID_HOST_STATE);
		if (vmcs12_read_field(c, VMCS_HOST_CS_SELECTOR) == 0 ||
		    vmcs12_read_field(c, VMCS_HOST_TR_SELECTOR) == 0 ||
		    (!hostlm && vmcs12_read_field(c, VMCS_HOST_SS_SELECTOR) == 0))
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	if (!nested_canonical(vmcs12_read_field(c, VMCS_HOST_FS_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_GS_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_GDTR_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_IDTR_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_TR_BASE)))
		return (VMXERR_ENTRY_INVALID_HOST_STATE);

	/* --- 26.2.4 dimensione dello spazio d'indirizzi --- */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_EFER, &l1efer);
	if (((l1efer & EFER_LMA) != 0) != hostlm)
		return (VMXERR_ENTRY_INVALID_HOST_STATE);
	if (hostlm) {
		if ((vmcs12_read_field(c, VMCS_HOST_CR4) & CR4_PAE) == 0 ||
		    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_RIP)))
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	} else {
		if ((entryc & VM_ENTRY_GUEST_LMA) ||
		    (vmcs12_read_field(c, VMCS_HOST_CR4) & CR4_PCIDE) ||
		    (vmcs12_read_field(c, VMCS_HOST_RIP) >> 32) != 0)
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	return (0);
}

/*
 * PAE senza EPT nel VMCS12: la CPU vera, al VM-entry, legge i 4 PDPTE dalla
 * memoria di CR3 e ne verifica i bit riservati (SDM 26.3.1.6). Il VMCS02 usa
 * sempre EPT (quella di L0), quindi la CPU li prenderebbe dai campi PDPTE del
 * VMCS: li si legge qui (slow path, PRIMA del VMPTRLD: vm_gpa_hold puo'
 * dormire) e la composizione li scrive. Prima si copiavano i campi PDPTE del
 * VMCS12, senza senso in questo caso (kvm-unit-tests vmx_pae_test, che poi si
 * bloccava). Riservati: bit 2:1, 8:5, da MAXPHYADDR a 62, e 63 senza EFER.NX.
 */
static void
nested_load_pdptes(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t cr0, cr4, efer, cr3, *p, rsvd;
	void *ck;
	int i;

	n->pdpte_mem = n->pdpte_bad = false;
	cr0 = vmcs12_read_field(c, VMCS_GUEST_CR0);
	cr4 = vmcs12_read_field(c, VMCS_GUEST_CR4);
	if ((vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_SECONDARY_CONTROLS) != 0 &&
	    (vmcs12_proc2(c) &
	    PROCBASED2_ENABLE_EPT) != 0)
		return;				/* con EPT12: dal VMCS12 */
	if ((cr0 & CR0_PG) == 0 || (cr4 & CR4_PAE) == 0 ||
	    (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_GUEST_LMA) != 0)
		return;				/* non e' paging PAE */
	efer = vmcs12_read_field(c, VMCS_GUEST_IA32_EFER);
	/*
	 * L'hardware verifica EFER PRIMA dei PDPTE: con load EFER e un EFER
	 * incoerente (LMA o LME accesi per un L2 non IA-32e) l'ingresso fallisce
	 * con qualificazione 0, non 2. Qui non si valutano i PDPTE: ci pensa
	 * l'hardware sul VMCS02 (vmx_guest_state_area_test, 'EFER_LMA/LME
	 * ... controls off').
	 */
	if ((vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_LOAD_EFER) &&
	    (efer & (EFER_LMA | EFER_LME)) != 0)
		return;
	cr3 = vmcs12_read_field(c, VMCS_GUEST_CR3) & 0xffffffe0UL;
	rsvd = 0x1e6ULL | (((1ULL << 63) - 1) & ~((1ULL << cpu_maxphyaddr) - 1));
	if ((efer & EFER_NXE) == 0)
		rsvd |= 1ULL << 63;
	p = vm_gpa_hold(vcpu->vcpu, cr3, 4 * sizeof(uint64_t), VM_PROT_READ,
	    &ck);
	if (p == NULL) {
		n->pdpte_bad = true;
		return;
	}
	for (i = 0; i < 4; i++) {
		n->pdpte[i] = p[i];
		if ((p[i] & 1) != 0 && (p[i] & rsvd) != 0)
			n->pdpte_bad = true;
	}
	vm_gpa_release(ck);
	n->pdpte_mem = true;
}

static int
nested_vmlaunch(struct vmx_vcpu *vcpu, bool is_resume)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	struct vmcs *vmcs02;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	int error;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) {
		nested_vmfail_invalid(vcpu);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* SDM 26.1: VMLAUNCH/VMRESUME nell'ombra di un MOV SS -> VMfail 26,
	 * prima del controllo sul launch state (vmentry_movss_shadow_test) */
	{
		uint64_t gi = 0;

		vm_get_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY), &gi);
		if (gi & VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING) {
			nested_vmx_result(vcpu, VMXERR_ENTRY_MOV_SS_BLOCKING);
			nested_advance_rip(vcpu);
			return (0);
		}
	}
	/* launch state: VMLAUNCH vuole clear, VMRESUME vuole launched */
	if (is_resume && !c->launched) {
		nested_vmx_result(vcpu, VMXERR_VMRESUME_NONLAUNCHED_VMCS);
		nested_advance_rip(vcpu);
		return (0);
	}
	if (!is_resume && c->launched) {
		nested_vmx_result(vcpu, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* controlli SDM su controlli e stato host del VMCS12 (VMfail 7 / 8);
	 * lo stato guest lo verifica l'hardware sul VMCS02 */
	if ((error = nested_check_vmentry(vcpu, c)) != 0) {
		nested_vmx_result(vcpu, error);
		nested_advance_rip(vcpu);
		return (0);
	}

	/* Bitmap I/O e MSR dell'L1: mappate qui (slow path, si puo' dormire),
	 * lette dal percorso veloce. Non mappabili -> controllo non valido. */
	if (nested_bitmaps_map(vcpu, c) != 0) {
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}

	/* DR7/DEBUGCTL dell'L1, letti ORA (VMCS01 ancora vcpu->vmcs; dopo il
	 * VMPTRLD del VMCS02 vm_get_register lo scaricherebbe): se l'L1 non
	 * chiede load debug controls, l'L2 li eredita (compose). */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_DR7, &n->l1_dr7);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(VMCS_GUEST_IA32_DEBUGCTL),
	    &n->l1_debugctl);
	/* TSC dell'L1 = TSC host + offset del VMCS01 (se usato): l'L2 vede
	 * quello dell'L1 + l'offset del VMCS12. Si legge ORA, come DR7. */
	{
		uint64_t p01 = 0, o01 = 0;

		vm_get_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_PRI_PROC_BASED_CTLS), &p01);
		if (p01 & PROCBASED_TSC_OFFSET)
			vm_get_register(vcpu->vcpu,
			    VMCS_IDENT(VMCS_TSC_OFFSET), &o01);
		n->l1_tsc_offset = o01;
	}

	/* host-state fisso del VMCS02 (lascia nessun VMCS corrente) */
	if ((error = vmx_nested_vmcs02_setup(c)) != 0) {
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	vmcs02 = (struct vmcs *)c->vmcs02;

	nested_load_pdptes(vcpu, c);		/* puo' dormire: prima del VMPTRLD */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_EFER, &n->l1_efer);
	/*
	 * Stato guest che l'hardware NON puo' verificare sul VMCS02 perche' la
	 * composizione non lo copia: il PAT dell'L2 e' virtuale (guest_msrs),
	 * il VMCS02 non lo carica mai. Con load PAT ogni byte di GUEST_PAT
	 * dev'essere un tipo valido (SDM 26.3.1.1; vmx_guest_state_area_test).
	 */
	n->gs_bad = false;
	if (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_LOAD_PAT) {
		uint64_t pat = vmcs12_read_field(c, VMCS_GUEST_IA32_PAT);
		int b;

		for (b = 0; b < 8; b++) {
			uint8_t t = (pat >> (b * 8)) & 0xff;

			if (t == 2 || t == 3 || t > 7)
				n->gs_bad = true;
		}
	}

	/* Pagina host della virtual-APIC dell'L1 (TPR shadow nel VMCS02, vedi
	 * nested_compose_vmcs02): QUI, prima del VMPTRLD, perche' vm_gpa_hold
	 * puo' dormire. 0 = non RAM o TPR shadow spento -> emulazione su CR8. */
	n->vapic_hpa = 0;
	if (vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_USE_TPR_SHADOW) {
		uint64_t va12 = vmcs12_read_field(c, VMCS_VIRTUAL_APIC);
		void *pg, *ck;

		pg = vm_gpa_hold(vcpu->vcpu, va12 & ~(uint64_t)PAGE_MASK,
		    PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE, &ck);
		if (pg != NULL) {
			n->vapic_hpa = DMAP_TO_PHYS((vm_offset_t)pg);
			vm_gpa_release(ck);
		}
	}

	/* Shadow EPT: radice preparata QUI, dove si puo' dormire. Da VMPTRLD
	 * in poi si e' in sezione critica (niente malloc ne' vm_gpa_hold). */
	if (vmcs12_proc2(c) &
	    PROCBASED2_ENABLE_EPT)
		vmx_vept_prepare(vcpu);
	/* diagpf2: #PF iniettato dall'L1 (qui si puo' dormire: vm_gpa_hold) */
	if (__predict_false(nested_diag_pfinj != 0))
		nested_diag_pfinj_note(vcpu, c);
	if (__predict_false(nested_diag_pfrec != 0))
		nested_diag_pfrec_entry(vcpu, c);

	VMPTRLD(vmcs02);
	nested_compose_vmcs02(vcpu);
	/* host-state PER-CPU + HOST_CR3 (dipendono dalla CPU d'ingresso) */
	vmwrite(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmwrite(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmwrite(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmwrite(VMCS_HOST_CR3, rcr3());
	if (n->vpid_track && c->host_cpu1 != curcpu + 1)
		atomic_add_long(&vmcs02_host_write_compose, 1);
	c->host_cpu1 = curcpu + 1;		/* vpid_track */

	/* controllo di sicurezza OBBLIGATORIO (unico chiamante, §3/§6.3) */
	error = nested_vmcs02_check(vcpu);
	if (error != 0) {
		VMCLEAR(vmcs02);
		VMPTRLD(vcpu->vmcs01);		/* torna corrente l'L1 */
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	/*
	 * Lista "carica all'ingresso" del VMCS12 (dopo lo stato guest, SDM
	 * 26.4). Prima le liste MSR erano azzerate e mai applicate. Un elemento
	 * non caricabile (es. FS_BASE, vietato) e' un VM-entry fallito: uscita
	 * verso l'L1 con motivo 34 + bit 31 e qualificazione = indice 1-based.
	 */
	{
		/* PDPTE non validi: stato guest non valido (33), qualificazione 2,
		 * PRIMA delle liste MSR (SDM: i controlli di stato vengono prima) */
		bool st = n->gs_bad || n->pdpte_bad;
		uint32_t fail = n->gs_bad ? 0 : n->pdpte_bad ? 2 :
		    nested_msr_list_entry(vcpu, c);
		uint32_t why = st ? EXIT_REASON_INVAL_VMCS :
		    EXIT_REASON_INVAL_MSR;

		if (st || fail != 0) {
			vcpu->vmcs = vmcs02;	/* la riflessione usa il corrente */
			n->in_l2 = true;
			vmexit->u.vmx.exit_reason = why | 0x80000000;
			n->synth = true;
			n->synth_intr_info = 0;
			n->synth_qual = fail;
			n->slow_reflect = true;
			nested_reflect_to_l1(vcpu, vmexit);
			n->synth = false;
			n->slow_reflect = false;
			n->synth_qual = 0;
			/* slow path: nessun VMCS lasciato attivo sulla CPU, e
			 * nextrip allineato all'host RIP dell'L1 (vm_run l'aveva
			 * gia' calcolato sul RIP del VMLAUNCH) */
			VMCLEAR(vcpu->vmcs01);
			vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP, vmexit->rip);
			return (0);
		}
	}

	if (__predict_false(vmx_nested_probe == 1)) {
		/* sonda 1: host-state VMCS02 contro VMCS01, poi VMfail (no L2) */
		nested_probe_dump("VMCS02");
		VMCLEAR(vmcs02);
		VMPTRLD(vcpu->vmcs01);
		nested_probe_dump("VMCS01");
		VMCLEAR(vcpu->vmcs01);
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* EFER del VMCS02 dopo compose + MSR-load list, VMCS02 ancora caricato
	 * (parere #19): per vedere dove si perde SCE */
	nested_diag_efer_trace(vcpu, c);
	VMCLEAR(vmcs02);			/* vmx_run lo ricarichera' */

	/*
	 * Commuta al VMCS02: vmx_run, dopo il goto restart di vm_run, fara'
	 * VMPTRLD(vcpu->vmcs) ed entrera' in L2. Il RIP dell'L2 e' nel
	 * GUEST_RIP di VMCS02 (copiato in compose).
	 */
	vcpu->vmcs = vmcs02;
	/*
	 * I campi host per-CPU (TR/GDTR/GS base) li scrive solo
	 * vmx_set_pcpu_defaults, e solo se lastcpu != curcpu: col vCPU sulla
	 * stessa CPU il VMCS02 restava con basi a 0 -> alla prima uscita da
	 * L2 l'host caricava GDT/TSS/GS nulli -> triple fault, reset
	 * istantaneo della macchina (kvm-unit-tests F2a). lastcpu vale per
	 * VMCS: NOCPU forza la riscrittura nel VMCS02 al prossimo vmx_run.
	 */
	if (!n->vpid_track) {
		if (vcpu->state.lastcpu != NOCPU)	/* non coprire una richiesta differita */
			vcpu->state.nocpu_why = VMX_NOCPU_NESTED_ENTRY;
		vcpu->state.lastcpu = NOCPU;
	} else if ((vmcs12_proc2(c) & PROCBASED2_ENABLE_VPID) == 0) {
		/*
		 * VMCS12 senza VPID: ingresso e uscita invalidano il contesto
		 * VPID 0 dell'L1, che nell'emulazione sono il VPID01 (prima che
		 * l'L1 torni a girare) e il VPID02 (prima di entrare in L2).
		 */
		if (vcpu->state.lastcpu != NOCPU)
			vcpu->state.nocpu_why = VMX_NOCPU_NESTED_ENTRY;
		vcpu->state.lastcpu = NOCPU;
		nested_vpid02_request(n);
	}
	/*
	 * Identita' del contesto TLB virtuale dell'L2 (D1, parere #49 §4.2):
	 * il VPID12 se il VMCS12 lo abilita, 0 altrimenti (con VPID abilitato
	 * il VPID12 non puo' essere 0: lo rifiutano i controlli d'ingresso).
	 * Un'identita' diversa dalla precedente vuole un contesto nuovo; anche
	 * A -> disabilitato -> A, perche' il tratto senza VPID ha usato lo
	 * stesso VPID02. Il VMCS12 in se' non conta: due VMCS12 con lo stesso
	 * VPID12 sono, per l'architettura, lo stesso contesto. L'identita' si
	 * aggiorna qui, dopo tutti i controlli software dell'ingresso; un
	 * ingresso che fallisce in hardware trova l'INVVPID gia' eseguito da
	 * vmx_run prima di entrare, quindi non lo perde (il caso corretto in
	 * KVM a luglio 2026).
	 */
	{
		uint16_t v12 = (vmcs12_proc2(c) & PROCBASED2_ENABLE_VPID) ?
		    (vmcs12_read_field(c, VMCS_VPID) & 0xffff) : 0;

		if (n->last_vpid12_ok && v12 != n->last_vpid12)
			atomic_add_long(&vpid02_vpid12_change, 1);
		if ((nested_vpid12_flush != 0 || n->vpid_track) &&
		    (!n->last_vpid12_ok || v12 != n->last_vpid12))
			nested_vpid02_request(n);
		n->last_vpid12 = v12;
		n->last_vpid12_ok = true;
	}
	n->in_l2 = true;
	/* launched solo se l'ingresso RIESCE (SDM): un VM-entry fallito lascia
	 * il VMCS clear. Si segna ora e si annulla nella riflessione se il
	 * primo ingresso fallisce (n->launching). */
	if (!is_resume)
		n->launching = true;
	c->launched = 1;			/* dopo VMLAUNCH il VMCS12 e' launched */
	/*
	 * vm_run ha GIA' calcolato nextrip = RIP dell'L1 + lunghezza del
	 * VMLAUNCH, prima di chiamare questo slow path, e vmx_run lo scrive
	 * nel GUEST_RIP del VMCS corrente: senza questo, l'L2 partiva
	 * dall'istruzione dell'L1 dopo il VMLAUNCH (kvm-unit-tests F2a:
	 * "VM-Fail on vmlaunch: unexpected flags 2", stampato DA L2).
	 * vm_set_register(RIP) scrive nel VMCS02 (ora vcpu->vmcs) e allinea
	 * nextrip al punto d'ingresso di L2.
	 */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    vmcs12_read_field(c, VMCS_GUEST_RIP));
	/*
	 * vmx_inject_interrupts azzera il blocco STI/MOV-SS se il RIP
	 * d'ingresso differisce da state.nextrip (l'ultima uscita, dell'L1):
	 * al VMLAUNCH/VMRESUME il RIP cambia SEMPRE, e cancellava il blocco
	 * chiesto dall'L1 nel VMCS12 (kvm-unit-tests vmx_intr_window_test,
	 * 'blocking by STI / MOV-SS'). Il riferimento diventa il RIP dell'L2.
	 */
	vcpu->state.nextrip = vmcs12_read_field(c, VMCS_GUEST_RIP);
	n->l2_exit_rip = ~0UL;		/* nessuna uscita da L2 ancora */
	/* Load PAT all'ingresso: il PAT virtuale del vCPU diventa quello
	 * dell'L2 (kvm-unit-tests 'control field PAT': l'L2 lo rilegge con
	 * RDMSR, che bhyve serve da guest_msrs). */
	if (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_LOAD_PAT)
		vcpu->guest_msrs[IDX_MSR_PAT] =
		    vmcs12_read_field(c, VMCS_GUEST_IA32_PAT);
	vmexit->inst_length = 0;
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_L2_ENTRIES, 1);
	return (0);
}


/* Attributi "host load" standard dei segmenti all'uscita verso l'L1 (SDM
 * "Loading Host State"): CS code R/A, dati RW/A, TR busy-TSS. */
#define	NESTED_AR_CODE	0x0000a09b	/* P,S,DPL0,exec/read,accessed,L/D,G */
#define	NESTED_AR_DATA	0x0000c093	/* P,S,DPL0,read/write,accessed,G */
#define	NESTED_AR_TR	0x0000008b	/* P,busy 32/64 TSS */

static void
nested_load_seg(uint32_t sel_enc, uint32_t base_enc, uint32_t lim_enc,
    uint32_t ar_enc, uint16_t sel, uint64_t base, uint32_t lim, uint32_t ar)
{
	vmwrite(sel_enc, sel);
	vmwrite(base_enc, base);
	vmwrite(lim_enc, lim);
	vmwrite(ar_enc, ar);
}

/*
 * L2 -> L1 (riflessione, §6.6). Il VMCS02 e' corrente. Salva le info d'uscita
 * e lo stato di L2 nello store VMCS12, poi carica lo stato host di VMCS12 nel
 * guest di VMCS01 (l'L1 riprende al suo "host RIP"). Al ritorno VMCS01 e'
 * corrente, in_l2=0. vmexit->rip = host RIP di VMCS12.
 * ⚠ Gli attributi di segmento e i dettagli di "Loading Host State" seguono
 * l'SDM a memoria: da validare su hardware (un AR errato fa triple-fault
 * l'L1 alla ripresa; lo rileva kut-f2a).
 */
static void
nested_reflect_to_l1(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	struct vmcs *vmcs02 = vcpu->vmcs;
	uint64_t efer, hrip, hrsp, hcr0, hcr3, hcr4;
	uint32_t i;
	/* stato di L2 da ricopiare in VMCS12 cosi' l'L1 lo rilegge con VMREAD */
	/*
	 * SDM 28.3: all'uscita si salva TUTTO lo stato guest. Prima solo 11
	 * campi: l'L1 rileggeva segmenti, GDTR/IDTR, SYSENTER, LDTR, PDPTE
	 * dell'L2 come li aveva scritti lui (kvm-unit-tests vmx_ldtr_test,
	 * vmx_mtf_pdpte_test); Hyper-V li usa per emulare la partizione root.
	 * PAT, EFER, DR7 e DEBUGCTL solo coi rispettivi save controls (piu'
	 * sotto).
	 */
	static const uint32_t l2state[] = {
		VMCS_GUEST_RIP, VMCS_GUEST_RSP, VMCS_GUEST_RFLAGS,
		VMCS_GUEST_CR0, VMCS_GUEST_CR3, VMCS_GUEST_CR4,
		VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_CS_SELECTOR,
		VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_DS_SELECTOR,
		VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_GS_SELECTOR,
		VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_TR_SELECTOR,
		VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_SS_LIMIT,
		VMCS_GUEST_DS_LIMIT, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT,
		VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_TR_LIMIT,
		VMCS_GUEST_GDTR_LIMIT, VMCS_GUEST_IDTR_LIMIT,
		VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_GUEST_CS_ACCESS_RIGHTS,
		VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_GUEST_DS_ACCESS_RIGHTS,
		VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_GUEST_GS_ACCESS_RIGHTS,
		VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_GUEST_TR_ACCESS_RIGHTS,
		VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE, VMCS_GUEST_SS_BASE,
		VMCS_GUEST_DS_BASE, VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE,
		VMCS_GUEST_LDTR_BASE, VMCS_GUEST_TR_BASE,
		VMCS_GUEST_GDTR_BASE, VMCS_GUEST_IDTR_BASE,
		VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
		VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_ESP,
		VMCS_GUEST_IA32_SYSENTER_EIP,
		VMCS_GUEST_PDPTE0, VMCS_GUEST_PDPTE1,
		VMCS_GUEST_PDPTE2, VMCS_GUEST_PDPTE3,
		VMCS_GUEST_INTERRUPTIBILITY, VMCS_GUEST_ACTIVITY,
	};

	if (c == NULL)
		return;
	/*
	 * Motivo d'uscita COMPLETO: vmx_run lo prende con vmcs_exit_reason(),
	 * che tiene solo i bit 15:0 e scarta il bit 31 (VM-entry fallito).
	 * L'L1 vedeva un VM-entry fallito del VMCS02 (motivo 33, CR3 con bit
	 * riservati) come un'uscita normale e saltava un'istruzione
	 * (kvm-unit-tests vmx_pse_test / vmx_pae_test). Le uscite sintetiche o
	 * dello slow path hanno gia' il motivo impostato da chi le genera.
	 */
	if (!vcpu->nested->synth && !vcpu->nested->slow_reflect)
		vmexit->u.vmx.exit_reason =
		    (uint32_t)vmcs_read(VMCS_EXIT_REASON);
	/*
	 * VM-entry fallito sul VMLAUNCH: il VMCS12 resta clear (SDM 26.7/26.8).
	 * Prima restava launched e ogni VMLAUNCH successivo rispondeva VMfail 4
	 * invece di valutare i controlli (kvm-unit-tests vmx_controls_test /
	 * vmx_host_state_area_test: 1411 + 537 fallimenti in gran parte a
	 * catena).
	 */
	if ((vmexit->u.vmx.exit_reason & 0x80000000) != 0 &&
	    vcpu->nested->launching)
		c->launched = 0;
	vcpu->nested->launching = false;
	if (__predict_false(vmx_nested_probe == 6)) {
		/* sonda 6: traccia le uscite riflesse all'L1 (non ferma nulla) */
		static int traced6;
		if (traced6 < 64) {
			traced6++;
			printf("nested_probe REFLECT#%d reason=%#x qual=%#lx "
			    "l2rip=%#lx l2cr3=%#lx synth=%d slow=%d\n", traced6,
			    vmexit->u.vmx.exit_reason,
			    (u_long)(vcpu->nested->synth ? vcpu->nested->synth_qual :
			    vmcs_read(VMCS_EXIT_QUALIFICATION)),
			    (u_long)vmcs_read(VMCS_GUEST_RIP),
			    (u_long)vmcs_read(VMCS_GUEST_CR3),
			    vcpu->nested->synth, vcpu->nested->slow_reflect);
		}
	}
	/* 1-2. info d'uscita + stato di L2 -> store VMCS12 */
	vmcs12_write_field(c, VMCS_EXIT_REASON,
	    vmexit->u.vmx.exit_reason);
	if (vcpu->nested->synth) {
		/* uscita sintetica: nessun dato hardware */
		vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
		    vcpu->nested->synth_qual);
		vmcs12_write_field(c, VMCS_EXIT_INTR_INFO,
		    vcpu->nested->synth_intr_info);
		vmcs12_write_field(c, VMCS_EXIT_INTR_ERRCODE, 0);
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_LENGTH, 0);
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_INFO, 0);
	} else {
		vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
		    vmcs_read(VMCS_EXIT_QUALIFICATION));
		vmcs12_write_field(c, VMCS_EXIT_INTR_INFO,
		    vmcs_read(VMCS_EXIT_INTR_INFO));
		vmcs12_write_field(c, VMCS_EXIT_INTR_ERRCODE,
		    vmcs_read(VMCS_EXIT_INTR_ERRCODE));
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_LENGTH,
		    vmcs_read(VMCS_EXIT_INSTRUCTION_LENGTH));
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_INFO,
		    vmcs_read(VMCS_EXIT_INSTRUCTION_INFO));
		/* EPT violation/misconfig: il GPA (e il lineare) che l'L1 deve
		 * conoscere per gestirla. */
		vmcs12_write_field(c, VMCS_GUEST_PHYSICAL_ADDRESS,
		    vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS));
		vmcs12_write_field(c, VMCS_GUEST_LINEAR_ADDRESS,
		    vmcs_read(VMCS_GUEST_LINEAR_ADDRESS));
	}
	/*
	 * SDM: ogni VM exit azzera il bit valid del VM-entry
	 * interruption-information. Senza, ogni VMRESUME successivo
	 * re-iniettava l'evento in L2 (kvm-unit-tests 'Inject an event to a
	 * halted guest': #GP in L2 a rip 0xa). L'IDT-vectoring info dice
	 * all'L1 se l'uscita ha interrotto la consegna di un evento.
	 */
	vmcs12_write_field(c, VMCS_ENTRY_INTR_INFO,
	    vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO) & ~VMCS_INTR_VALID);
	/*
	 * Evento per l'L2 NON ancora consegnato (come vmcs12_save_pending_event
	 * di KVM): va all'L1 nell'IDT-vectoring, che lo reinietta al prossimo
	 * VMRESUME. Due posti dove puo' stare:
	 *  - vcpu->exitintinfo / eccezione pendente: un'uscita dell'L2 gestita
	 *    in L0 durante la consegna (vmx_exit_save_idtvec, b4a46ea; es.
	 *    fault dello shadow EPT sullo stack della root mentre riceve il
	 *    clock) o un'eccezione decisa da L0 per l'L2;
	 *  - il VM-entry interruption-info del VMCS02, composto dal VMCS12 al
	 *    VMRESUME e non ancora entrato (uscita sintetica prima
	 *    dell'ingresso).
	 * Prima l'uscita sintetica scriveva IDT-vectoring 0: la root perdeva
	 * l'evento (il clock -> SYNTHETIC/CLOCK_WATCHDOG_TIMEOUT) e quello in
	 * exitintinfo veniva poi iniettato in HYPER-V da vmx_inject_interrupts,
	 * cioe' nel contesto sbagliato. Lo stesso per l'EPT violation riflessa
	 * dallo slow path: l'IDT-vectoring hardware arrivava all'L1, ma la
	 * copia in exitintinfo restava e finiva anche nell'L1.
	 */
	{
		uint64_t pend = 0, idt, idterr, ilen;
		uint32_t ent = vmcs_read(VMCS_ENTRY_INTR_INFO);
		bool have = vm_entry_intinfo(vcpu->vcpu, &pend) != 0;

		ilen = 0;
		if (!vcpu->nested->synth) {
			idt = vmcs_read(VMCS_IDT_VECTORING_INFO);
			idterr = vmcs_read(VMCS_IDT_VECTORING_ERROR);
			if ((idt & VMCS_IDT_VEC_VALID) == 0 && have) {
				idt = (uint32_t)pend;
				idterr = pend >> 32;
			}
		} else if (have) {
			idt = (uint32_t)pend;
			idterr = pend >> 32;
			ilen = vmcs_read(VMCS_EXIT_INSTRUCTION_LENGTH);
		} else if (ent & VMCS_INTR_VALID) {
			idt = ent;
			idterr = vmcs_read(VMCS_ENTRY_EXCEPTION_ERROR);
			ilen = vmcs_read(VMCS_ENTRY_INST_LENGTH);
		} else
			idt = idterr = 0;
		idt &= ~(1UL << 12);		/* bit indefinito */
		if ((idt & VMCS_IDT_VEC_ERRCODE_VALID) == 0)
			idterr = 0;
		/* evento software (int n, #BP/#OF, ICEBP): serve la lunghezza */
		if (vcpu->nested->synth && (idt & VMCS_IDT_VEC_VALID) != 0) {
			uint32_t t = idt & VMCS_INTR_T_MASK;

			if (t == VMCS_INTR_T_SWINTR || t == VMCS_INTR_T_PRIV_SWEXCEPTION ||
			    t == VMCS_INTR_T_SWEXCEPTION)
				vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_LENGTH,
				    ilen);
		}
		if (__predict_false((idt & VMCS_IDT_VEC_VALID) != 0 &&
		    vcpu->nested->synth))
			SDT_PROBE2(vmm, vmx, nested, synth_exit, vcpu, (int)idt);
		vmcs12_write_field(c, VMCS_IDT_VECTORING_INFO, idt);
		vmcs12_write_field(c, VMCS_IDT_VECTORING_ERROR, idterr);
		/* il VMCS02 non deve reiniettarlo da se' a un ingresso futuro */
		if (ent & VMCS_INTR_VALID)
			vmcs_write(VMCS_ENTRY_INTR_INFO, 0);
	}
	for (i = 0; i < nitems(l2state); i++)
		vmcs12_write_field(c, l2state[i], vmcs_read(l2state[i]));
	/*
	 * PAT: bhyve lo virtualizza in guest_msrs[IDX_MSR_PAT] (il PAT
	 * hardware resta quello dell'host, per l'L1 come per l'L2): e' "il PAT
	 * corrente del vCPU". Save PAT copia quello che l'L2 ha in uso.
	 */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PAT)
		vmcs12_write_field(c, VMCS_GUEST_IA32_PAT,
		    vcpu->guest_msrs[IDX_MSR_PAT]);
	/*
	 * Save EFER (SDM 28.3, parere #21 di Astra): il campo del VMCS12 si
	 * aggiorna SOLO se l'L1 lo chiede, come fa KVM. Prima si copiava
	 * sempre e un L1 senza save EFER si ritrovava sovrascritto il valore
	 * che aveva scritto lui (kvm-unit-tests EFER save matrix, SAVE=0). Il
	 * VMCS02 ha sempre VM_EXIT_SAVE_EFER (controlli dell'L0): il valore
	 * dell'L2 qui e' corretto in ogni caso.
	 */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_EFER)
		vmcs12_write_field(c, VMCS_GUEST_IA32_EFER,
		    vmcs_read(VMCS_GUEST_IA32_EFER));
	/* Save preemption timer: il residuo (salvato dal VMCS02) all'L1. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PREEMPTION_TIMER)
		vmcs12_write_field(c, VMCS_PREEMPTION_TIMER_VALUE,
		    vmcs_read(VMCS_PREEMPTION_TIMER_VALUE));
	/* Save debug controls: DR7/DEBUGCTL dell'L2 nel VMCS12, solo se chiesto. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_DEBUG_CONTROLS) {
		vmcs12_write_field(c, VMCS_GUEST_DR7,
		    vmcs_read(VMCS_GUEST_DR7));
		vmcs12_write_field(c, VMCS_GUEST_IA32_DEBUGCTL,
		    vmcs_read(VMCS_GUEST_IA32_DEBUGCTL));
	}
	/* [v2] IA-32e mode guest degli entry controls di VMCS12 = EFER.LMA di L2 */
	efer = vmcs_read(VMCS_GUEST_IA32_EFER);

	/* 3. se VMCS12 non usa VPID, flush del VPID02 (§6.6); col VMCS02 senza
	 * VPID (vpid02_off) lo fa gia' l'hardware all'uscita */
	if ((vmcs12_proc2(c) &
	    PROCBASED2_ENABLE_VPID) == 0 && !n->vpid02_off) {
		struct invvpid_desc d;
		bzero(&d, sizeof(d));
		d.vpid = n->vpid2;
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, d);
		atomic_add_long(&vpid02_invvpid_novpid12, 1);
		if (!n->in_run)
			atomic_add_long(&vpid02_invvpid_novpid12_slow, 1);
	}
	/* Lista "salva all'uscita": MSR dell'L2, col VMCS02 ancora corrente
	 * (EFER, SYSENTER...). Non su un VM-entry fallito (SDM 27.8). */
	if ((vmexit->u.vmx.exit_reason & 0x80000000) == 0)
		nested_msr_list_exit(vcpu, c, true);

	/* 4. commuta a VMCS01 */
	VMCLEAR(vmcs02);
	VMPTRLD(vcpu->vmcs01);
	vcpu->vmcs = vcpu->vmcs01;
	if (n->vpid_track) {
		/*
		 * Campi host del VMCS01 per QUESTA CPU, registrata. Il VPID01:
		 * dentro vmx_run si allinea qui (stessa CPU e stessa sezione
		 * critica del prossimo ingresso nell'L1); dallo slow path
		 * decide il prossimo vmx_run, sulla CPU vera (D3).
		 */
		vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
		vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
		vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
		n->vmcs01_host_cpu1 = curcpu + 1;
		if (n->in_run)
			vmx_vpid01_resume(vcpu);
	} else {
	/* Il VMCS01 riparte su QUESTA CPU, ma il vCPU puo' essere migrato
	 * mentre era in L2 (la riscrittura e' finita nel VMCS02): riscrivo i
	 * campi host per-CPU qui, ora che il VMCS01 e' corrente. */
	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	if (!n->in_run && vcpu->state.lastcpu != curcpu)
		atomic_add_long(&vpid01_slowpath_claim, 1);	/* audit VPID, D3 */
	vcpu->state.lastcpu = curcpu;
	}

	/* 6. Loading Host State: host di VMCS12 -> guest di VMCS01 */
	hcr0 = (vmcs12_read_field(c, VMCS_HOST_CR0) | cr0_ones_mask) &
	    ~cr0_zeros_mask;
	hcr4 = (vmcs12_read_field(c, VMCS_HOST_CR4) | cr4_ones_mask) &
	    ~cr4_zeros_mask;
	hcr3 = vmcs12_read_field(c, VMCS_HOST_CR3);
	hrip = vmcs12_read_field(c, VMCS_HOST_RIP);
	hrsp = vmcs12_read_field(c, VMCS_HOST_RSP);
	vmwrite(VMCS_GUEST_CR0, hcr0);
	vmwrite(VMCS_GUEST_CR3, hcr3);
	vmwrite(VMCS_GUEST_CR4, hcr4);
	vmwrite(VMCS_GUEST_RIP, hrip);
	vmwrite(VMCS_GUEST_RSP, hrsp);
	vmwrite(VMCS_GUEST_RFLAGS, 0x2);		/* bit 1 fisso */
	vmwrite(VMCS_GUEST_DR7, 0x400);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);
	vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
	vmwrite(VMCS_GUEST_ACTIVITY, 0);		/* active */
	vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
	/* SYSENTER */
	vmwrite(VMCS_GUEST_IA32_SYSENTER_CS,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_CS));
	vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_ESP));
	vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_EIP));
	/*
	 * EFER (SDM 28.5.1): HOST_EFER solo con "load IA32_EFER"; altrimenti
	 * resta quello dell'L1 (ancora nel VMCS01) con LMA = LME = host
	 * address-space size. Prima HOST_EFER si caricava sempre: con valori
	 * di prova senza load EFER l'L1 ripartiva con un EFER incoerente, il
	 * VM-entry nel VMCS01 falliva (motivo 33) e QEMU riprovava
	 * all'infinito (kvm-unit-tests vmx_host_state_area_test, 470 MB di
	 * seriale). Il controllo "IA-32e mode guest" del VMCS01 deve
	 * coincidere con EFER.LMA.
	 */
	{
		bool lm = (vmcs12_read_field(c, VMCS_EXIT_CTLS) &
		    VM_EXIT_HOST_LMA) != 0;
		uint32_t ent01;

		if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_LOAD_EFER)
			efer = vmcs12_read_field(c, VMCS_HOST_IA32_EFER);
		else {
			efer = vmcs_read(VMCS_GUEST_IA32_EFER);
			efer &= ~(EFER_LMA | EFER_LME);
			if (lm)
				efer |= EFER_LMA | EFER_LME;
		}
		vmwrite(VMCS_GUEST_IA32_EFER, efer);
		ent01 = (uint32_t)vmcs_read(VMCS_ENTRY_CTLS);
		if (lm)
			ent01 |= VM_ENTRY_GUEST_LMA;
		else
			ent01 &= ~VM_ENTRY_GUEST_LMA;
		vmwrite(VMCS_ENTRY_CTLS, ent01);
	}
	/* SDM "Loading Host State": all'uscita DR7 = 0x400, DEBUGCTL = 0. */
	vmwrite(VMCS_GUEST_DR7, 0x400);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);
	/* Load PAT all'uscita: il PAT virtuale dell'L1 diventa HOST_PAT. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_LOAD_PAT)
		vcpu->guest_msrs[IDX_MSR_PAT] =
		    vmcs12_read_field(c, VMCS_HOST_IA32_PAT);
	/* segmenti host: selettori da VMCS12, basi/limiti/attributi standard */
	nested_load_seg(VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_CS_BASE,
	    VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_CS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_CODE);
	nested_load_seg(VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_SS_BASE,
	    VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_SS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_DS_SELECTOR, VMCS_GUEST_DS_BASE,
	    VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_DS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_ES_BASE,
	    VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_ES_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_FS_BASE,
	    VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_FS_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_FS_BASE), 0xfffff, NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_GS_SELECTOR, VMCS_GUEST_GS_BASE,
	    VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_GS_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_GS_BASE), 0xfffff, NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_TR_BASE,
	    VMCS_GUEST_TR_LIMIT, VMCS_GUEST_TR_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_TR_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_TR_BASE), 0x67, NESTED_AR_TR);
	/* SDM 28.5.2: all'uscita LDTR = 0, inutilizzabile (prima restava
	 * quella dell'L2: kvm-unit-tests vmx_ldtr_test) */
	nested_load_seg(VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_LDTR_BASE,
	    VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0, 0, 0,
	    0x10000);
	vmwrite(VMCS_GUEST_GDTR_BASE, vmcs12_read_field(c, VMCS_HOST_GDTR_BASE));
	vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_IDTR_BASE, vmcs12_read_field(c, VMCS_HOST_IDTR_BASE));
	vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_FS_BASE, vmcs12_read_field(c, VMCS_HOST_FS_BASE));
	vmwrite(VMCS_GUEST_GS_BASE, vmcs12_read_field(c, VMCS_HOST_GS_BASE));

	/* TSC dell'L1 cambiato da una lista d'ingresso: nel VMCS01 ora */
	if (n->l1_tsc_dirty) {
		vmx_set_tsc_offset(vcpu, n->l1_tsc_offset);
		n->l1_tsc_dirty = false;
	}
	/* Lista "carica all'uscita": MSR dell'L1, dopo lo stato host (SDM). */
	n->msr_phase = 2;
	nested_msr_list_exit(vcpu, c, false);
	n->msr_phase = 0;

	n->in_l2 = false;
	n->emu_viol = false;		/* una violazione dell'emulatore non
					 * ancora consegnata decade con l'L2 */
	vmexit->rip = hrip;
	vmexit->inst_length = 0;
	vm_exit_intinfo(vcpu->vcpu, 0);
	if (__predict_false(vmx_nested_probe == 3)) {
		/* sonda 3: riflessione completata, VMCS01 pronto per l'L1 */
		nested_probe_dump("REFLECT-VMCS01");
		vm_suspend(vcpu->vmx->vm, VM_SUSPEND_POWEROFF);
	}
	/* shadow VMCS: uscita e stato di L2 nuovi nel VMCS12, tutti da ricopiare
	 * (i RW erano stati recuperati al VMLAUNCH/VMRESUME: niente perdite) */
	shvmcs_mark(n, c, ~0U);
	SDT_PROBE1(vmm, vmx, nested, reflect, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_REFLECTIONS, 1);
}

/*
 * Eventi dell'L1 mentre il vCPU e' in L2 (come vmx_check_nested_events di
 * KVM). Chiamata da vmx_run PRIMA di ogni ingresso in L2, col VMCS02
 * corrente. Se l'L1 ha un interrupt pendente e il suo VMCS12 chiede
 * l'uscita sugli interrupt esterni, l'hardware vero uscirebbe verso l'L1
 * con motivo EXTERNAL_INTERRUPT, qualunque sia l'IF di L2: si fa
 * un'uscita SINTETICA. Prima l'interrupt veniva iniettato in L2
 * (kvm-unit-tests 'interrupt': "intercepted interrupt while running
 * guest", poi exit reason 7 non richiesta). Con "acknowledge interrupt on
 * exit" il vettore e' accettato dall'APIC e va nelle info d'uscita;
 * senza, resta pendente e l'L1 lo prende riabilitando gli interrupt.
 * Ritorna true se l'uscita e' stata fatta: vmx_run deve uscire
 * (VM_EXITCODE_NESTED + restart_only, come dopo una riflessione).
 */
/*
 * Prima di ogni ingresso in L2 (vmx_run, interrupt spenti, VMCS02 corrente):
 * residuo del timer di preemption dell'L1 = scadenza assoluta - adesso.
 */
void
nested_preempt_refresh(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t now = rdtsc(), rem = 0;

	if (!n->preempt_on)
		return;
	if (n->preempt_deadline > now)
		rem = (n->preempt_deadline - now) >> n->preempt_rate;
	if (rem > 0xffffffffULL)
		rem = 0xffffffffULL;
	vmwrite(VMCS_PREEMPTION_TIMER_VALUE, rem);
}

/*
 * Immediate exit (parere #24 di Astra; come request_immediate_exit di KVM).
 * Quando nested_check_events RINVIA un interrupt dell'L1 perche' l'L2 ha un
 * evento da consegnare, senza altro l'interrupt aspettava la successiva uscita
 * naturale dell'L2: sotto carico di calcolo fino a secondi (fase A: 3,98 M
 * rinvii, coda fino a 4 s). Ora L0 accende nel VMCS02 il VMX preemption timer
 * a 0: SDM 22.6.4, l'uscita avviene dopo la consegna dell'evento iniettato e
 * prima della prima istruzione dell'L2. Se la consegna e' interrotta (EPT
 * violation sullo shadow) l'uscita ha quel motivo e l'evento finisce in
 * exitintinfo: il rinvio di tipo 2 lo protegge come prima (22dc5d5).
 *
 * Il timer e' una risorsa di L0: si arma solo se l'L1 NON usa il suo
 * (preempt_on); altrimenti serve un multiplexing delle due scadenze, non
 * fatto: si conta il caso (con Windows 11 + Hyper-V: mai, misurato). Il bit
 * si toglie alla chiamata successiva (prima dell'ingresso dopo), e l'uscita
 * 52 col bit di L0 non si riflette mai all'L1 (nested_l2_exit).
 */
static void
nested_immexit_arm(struct vmx_vcpu *vcpu, int kind)
{
	struct vmx_nested *n = vcpu->nested;

	if (!n->imm_ok) {
		SDT_PROBE3(vmm, vmx, nested, immexit, vcpu->vcpuid, 4, kind);
		return;
	}
	if (n->preempt_on) {
		vmm_stat_incr(vcpu->vcpu, VMX_NESTED_IMMEXIT_L1TIMER, 1);
		SDT_PROBE3(vmm, vmx, nested, immexit, vcpu->vcpuid, 3, kind);
		return;
	}
	vmwrite(VMCS_PIN_BASED_CTLS, vmcs_read(VMCS_PIN_BASED_CTLS) |
	    PINBASED_PREMPTION_TIMER);
	vmwrite(VMCS_PREEMPTION_TIMER_VALUE, 0);
	n->imm_armed = true;
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_IMMEXIT_ARMED, 1);
	SDT_PROBE3(vmm, vmx, nested, immexit, vcpu->vcpuid, 1, kind);
}

/* Toglie il timer di L0 dal VMCS02 corrente (l'L1 non lo usa: armato solo
 * con preempt_on falso). */
static void
nested_immexit_disarm(struct vmx_vcpu *vcpu)
{
	vmwrite(VMCS_PIN_BASED_CTLS, vmcs_read(VMCS_PIN_BASED_CTLS) &
	    ~PINBASED_PREMPTION_TIMER);
	vcpu->nested->imm_armed = false;
}

bool
nested_check_events(struct vmx_vcpu *vcpu, struct vm_exit *vmexit,
    uint64_t rip)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	struct vlapic *vl = vm_lapic(vcpu->vcpu);
	int vec;

	if (c == NULL || !n->in_l2)
		return (false);
	/* il timer di L0 vale per UN ingresso: lo si riarma se serve ancora */
	if (n->imm_armed)
		nested_immexit_disarm(vcpu);
	/*
	 * MTF pendente (SDM 26.5.2 / come nested_vmx_mtf_pending di KVM): se
	 * L0 ha completato un'istruzione dell'L2 per conto suo (I/O, MSR, CPUID
	 * emulati: il RIP e' avanzato dall'ultima uscita) e l'L1 ha il monitor
	 * trap flag, l'hardware non ha visto l'istruzione e non generera' la
	 * trappola: uscita MTF sintetica verso l'L1 (kvm-unit-tests
	 * vmx_mtf_test, 'MTF VM-exit after OUT'). Prima degli interrupt.
	 */
	if (n->l2_exit_rip != ~0UL && rip != n->l2_exit_rip &&
	    (vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) & PROCBASED_MTF)) {
		n->l2_exit_rip = ~0UL;
		n->synth_intr_info = 0;
		n->synth_qual = 0;
		vmexit->u.vmx.exit_reason = EXIT_REASON_MTF;
		n->synth = true;
		nested_reflect_to_l1(vcpu, vmexit);
		n->synth = false;
		/*
		 * Con RFLAGS.TF nell'L2 anche la trappola di passo singolo
		 * coincide con l'MTF: vince l'uscita MTF e la #DB resta pendente
		 * (BS, bit 14), come sulla CPU vera (vmx_mtf_test, 'pending debug
		 * exceptions field after MTF VM-exit').
		 */
		if (vmcs12_read_field(c, VMCS_GUEST_RFLAGS) & PSL_T)
			vmcs12_write_field(c, VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
			    vmcs12_read_field(c,
			    VMCS_GUEST_PENDING_DBG_EXCEPTIONS) | (1UL << 14));
		n->restart_only = true;
		vmexit->exitcode = VM_EXITCODE_NESTED;
		return (true);
	}
	{
		uint64_t pin12 = vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
		int pend;

		vec = -1;
		pend = vlapic_pending_intr(vl, &vec) ? 1 : 0;
		SDT_PROBE4(vmm, vmx, nested, chkev, vcpu, pin12, pend, vec);
		if ((pin12 & PINBASED_EXTINT_EXITING) == 0 || !pend)
			return (false);
	}

	/*
	 * RINVIO (come nested_run_pending di KVM): se il VMCS02 ha ancora un
	 * evento da consegnare all'L2 (ENTRY_INTR_INFO valido: l'iniezione
	 * composta dal VMCS12 al VMRESUME, non ancora entrata) NON si riflette
	 * l'interrupt dell'L1 adesso. Sulla CPU vera l'L1 non preempta l'L2 tra
	 * la VM-entry e la consegna dell'evento iniettato: si ritorna false, il
	 * VMRESUME consegna l'evento (vmx_inject_interrupts non inietta altro,
	 * stessa condizione in vmx.c), e l'interrupt dell'L1 -- che resta
	 * pendente nel vlapic -- si riflette alla prossima uscita naturale.
	 * Prima la riflessione immediata scavalcava il clock IPI (0xd2) che
	 * Hyper-V iniettava nel VP1 della root: senza EOI -> CLOCK_WATCHDOG sul
	 * processore 1. NB: si guarda SOLO ENTRY_INTR_INFO, non vm_get_intinfo:
	 * quest'ultimo (exitintinfo) lo consuma vmx_inject_interrupts, e
	 * rimandare lasciandolo pendente creava la doppia iniezione -> reset
	 * secco dell'host (beeabe4, revert fec9211).
	 */
	if ((vmcs_read(VMCS_ENTRY_INTR_INFO) & VMCS_INTR_VALID) != 0) {
		SDT_PROBE4(vmm, vmx, nested, defer, vcpu->vcpuid, 1,
		    vmcs_read(VMCS_ENTRY_INTR_INFO), vec);
		nested_immexit_arm(vcpu, 1);
		return (false);
	}
	/*
	 * Stesso rinvio quando l'evento dell'L2 sta in exitintinfo: la sua
	 * consegna e' stata interrotta da una EPT violation sullo shadow EPT
	 * (un terzo dei tick di Hyper-V segue questo percorso), l'uscita VM ha
	 * azzerato il valid di ENTRY_INTR_INFO e L0 lo deve reiniettare. Senza
	 * questo, l'uscita sintetica lo restituiva all'L1 nell'IDT-vectoring
	 * e Hyper-V non lo reiniettava piu': 2 corse su 6 dopo e8efe28, con
	 * synth_exit idt=0x800000d1 e nessun rinvio (parere #16 di Astra).
	 *
	 * Solo info1 (exitintinfo), non l'eccezione pendente: con in_l2 e' per
	 * forza un evento dell'L2, perche' lo salva vmx_exit_save_idtvec nei
	 * rami nested e ogni riflessione all'L1 lo consuma (vm_entry_intinfo in
	 * nested_reflect_to_l1) prima che l'L1 possa rifare VMRESUME. E solo con
	 * ENTRY_INTR_INFO NON valido (il caso sopra ha gia' restituito false):
	 * i due eventi non coesistono mai, e vmx_inject_interrupts ne inietta
	 * uno solo. beeabe4, che guardava anche questo, resettava l'host senza
	 * dump; non aveva la guardia in vmx_inject_interrupts (e8efe28) ne' la
	 * finestra INT_WINDOW corretta (6496bc2).
	 *
	 * Come sopra, si ritorna PRIMA di vlapic_intr_accepted: l'interrupt
	 * dell'L1 resta in IRR, non viene consumato.
	 */
	{
		uint64_t info1, info2;

		vm_get_intinfo(vcpu->vcpu, &info1, &info2);
		if ((info1 & VM_INTINFO_VALID) != 0) {
			SDT_PROBE4(vmm, vmx, nested, defer, vcpu->vcpuid, 2,
			    info1, vec);
			nested_immexit_arm(vcpu, 2);
			return (false);
		}
	}

	n->synth_intr_info = 0;
	n->synth_qual = 0;
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) &
	    VM_EXIT_ACKNOWLEDGE_INTERRUPT) {
		vlapic_intr_accepted(vl, vec);
		n->synth_intr_info = vec | VMCS_INTR_T_HWINTR | VMCS_INTR_VALID;
	}
	if (__predict_false(vmx_nested_probe == 5)) {
		/* sonda 5: traccia le uscite sintetiche (non ferma nulla) */
		static int traced;
		if (traced < 32) {
			traced++;
			printf("nested_probe EXTINT#%d vec=%d info=%#x "
			    "pin12=%#lx exit12=%#lx l2rip=%#lx entryinfo12=%#lx\n",
			    traced, vec, n->synth_intr_info,
			    vmcs12_read_field(c, VMCS_PIN_BASED_CTLS),
			    vmcs12_read_field(c, VMCS_EXIT_CTLS),
			    vmcs_read(VMCS_GUEST_RIP),
			    vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO));
		}
	}
	vmexit->u.vmx.exit_reason = EXIT_REASON_EXT_INTR;
	n->synth = true;
	nested_reflect_to_l1(vcpu, vmexit);
	n->synth = false;
	n->restart_only = true;
	vmexit->exitcode = VM_EXITCODE_NESTED;
	return (true);
}

/*
 * Bitmap I/O e MSR dell'L1. Il percorso veloce (vmx_exit_process, sotto il
 * critical_enter di vm_run) non puo' chiamare vm_gpa_hold, che puo' dormire:
 * lo faceva qui (panic "vm_gpa_hold: invalid vcpu state 2", kvm-unit-tests
 * 'control field PAT', RDMSR di L2). Come KVM, le pagine si mappano una volta
 * al VMLAUNCH/VMRESUME, nello slow path, e restano tenute finche' la voce del
 * VMCS12 esiste.
 */
static void
nested_bitmaps_unmap(struct vmcs12_cache *c)
{
	if (c->ck_io_a != NULL)
		vm_gpa_release(c->ck_io_a);
	if (c->ck_io_b != NULL)
		vm_gpa_release(c->ck_io_b);
	if (c->ck_msr != NULL)
		vm_gpa_release(c->ck_msr);
	nested_msr_list_unmap(&c->ml_st);
	nested_msr_list_unmap(&c->ml_ld);
	nested_msr_list_unmap(&c->ml_en);
	c->bm_io_a = c->bm_io_b = c->bm_msr = NULL;
	c->ck_io_a = c->ck_io_b = c->ck_msr = NULL;
}

/*
 * Mappa una lista MSR del VMCS12 (SDM 24.7.2): indirizzo allineato a 16, al
 * massimo 512 elementi, pagina per pagina (prima una sola pagina: le liste
 * da 512 voci di atomic_switch_max_msrs_test facevano fallire il VMLAUNCH).
 * 0 ok o lista vuota; -1 non valida.
 */
static int
nested_msr_list_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c,
    uint32_t addr_f, uint32_t cnt_f, int prot, struct nested_msr_list *l)
{
	uint64_t gpa = vmcs12_read_field(c, addr_f);
	uint64_t cnt = vmcs12_read_field(c, cnt_f);
	uint64_t first, last, pg;
	int i;

	bzero(l, sizeof(*l));
	if (cnt == 0)
		return (0);
	if ((gpa & 0xf) != 0 || cnt > 512)
		return (-1);
	first = trunc_page(gpa);
	last = trunc_page(gpa + cnt * sizeof(struct msr_entry) - 1);
	for (pg = first, i = 0; pg <= last; pg += PAGE_SIZE, i++) {
		l->pg[i] = vm_gpa_hold(vcpu->vcpu, pg, PAGE_SIZE, prot,
		    &l->ck[i]);
		if (l->pg[i] == NULL) {
			nested_msr_list_unmap(l);
			return (-1);
		}
	}
	l->gpa = gpa;
	l->n = (uint32_t)cnt;
	return (0);
}

static void
nested_msr_list_unmap(struct nested_msr_list *l)
{
	int i;

	for (i = 0; i < 3; i++)
		if (l->ck[i] != NULL)
			vm_gpa_release(l->ck[i]);
	bzero(l, sizeof(*l));
}

/* voce i della lista (gia' mappata) */
static struct msr_entry *
nested_msr_ent(struct nested_msr_list *l, uint32_t i)
{
	uint64_t off = (l->gpa & PAGE_MASK) + (uint64_t)i * sizeof(struct msr_entry);

	return ((struct msr_entry *)(l->pg[off >> PAGE_SHIFT] +
	    (off & PAGE_MASK)));
}

/*
 * Legge/scrive un MSR "come lo vede il vCPU" per le liste MSR del nested.
 * live = true dentro vmx_run (uscita da L2): LSTAR, CSTAR, STAR, SF_MASK e
 * KGSBASE del guest sono nei registri hardware (vmx_msr_guest_enter);
 * live = false nello slow path (ingresso): sono in guest_msrs[]. PAT e
 * TSC_AUX stanno sempre in guest_msrs[] (PAT e' virtuale; TSC_AUX e'
 * commutato solo attorno al VM-entry). EFER, SYSENTER e DEBUGCTL vivono
 * nel VMCS CORRENTE. 0 ok; EINVAL MSR non gestito (per le liste di
 * caricamento: non ammesso).
 */
static int
nested_msr_rw(struct vmx_vcpu *vcpu, uint32_t idx, uint64_t *val, bool wr,
    bool live)
{
	int g = -1;
	uint32_t f = 0;

	switch (idx) {
	case MSR_LSTAR:		g = IDX_MSR_LSTAR; break;
	case MSR_CSTAR:		g = IDX_MSR_CSTAR; break;
	case MSR_STAR:		g = IDX_MSR_STAR; break;
	case MSR_SF_MASK:	g = IDX_MSR_SF_MASK; break;
	case MSR_KGSBASE:	g = IDX_MSR_KGSBASE; break;
	case MSR_PAT:		g = IDX_MSR_PAT; live = false; break;
	case MSR_TSC_AUX:	g = IDX_MSR_TSC_AUX; live = false; break;
	case MSR_EFER:		f = VMCS_GUEST_IA32_EFER; break;
	case MSR_SYSENTER_CS_MSR: f = VMCS_GUEST_IA32_SYSENTER_CS; break;
	case MSR_SYSENTER_ESP_MSR: f = VMCS_GUEST_IA32_SYSENTER_ESP; break;
	case MSR_SYSENTER_EIP_MSR: f = VMCS_GUEST_IA32_SYSENTER_EIP; break;
	case MSR_DEBUGCTLMSR:	f = VMCS_GUEST_IA32_DEBUGCTL; break;
	case MSR_TSC:
		/*
		 * Le liste MSR lavorano nel tempo dell'L1 (SDM: il valore NON
		 * subisce l'offset del VMCS12): TSC host + offset dell'L0 per
		 * l'L1. Prima si usava l'offset del VMCS02 (L0 + L1->L2): il
		 * valore salvato era piu' alto dell'offset dell'L2
		 * (vmx_store_tsc_test, rdtsc_vmexit_diff_test,
		 * vmx_preemption_timer_expiry_test). In scrittura non ammesso.
		 */
		if (wr) {
			/*
			 * Scrivere IA32_TSC = WRMSR dell'L1: cambia l'offset che
			 * L0 da' all'L1 (come vmx_wrmsr). Nella lista d'ingresso
			 * il VMCS corrente e' il VMCS02: si ricalcola il suo
			 * offset e il VMCS01 si aggiorna all'uscita; nella lista
			 * load d'uscita il VMCS01 e' gia' corrente.
			 */
			struct vmx_nested *nn = vcpu->nested;
			struct vmcs12_cache *cc = nested_current_cache(nn);
			uint64_t off;

			nn->l1_tsc_offset = *val - rdtsc();
			if (nn->msr_phase == 2) {
				vmx_set_tsc_offset(vcpu, nn->l1_tsc_offset);
				nn->l1_tsc_dirty = false;
				return (0);
			}
			off = nn->l1_tsc_offset;
			if (cc != NULL && (vmcs12_read_field(cc,
			    VMCS_PRI_PROC_BASED_CTLS) & PROCBASED_TSC_OFFSET))
				off += vmcs12_read_field(cc, VMCS_TSC_OFFSET);
			vmwrite(VMCS_TSC_OFFSET, off);
			vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    vmcs_read(VMCS_PRI_PROC_BASED_CTLS) |
			    PROCBASED_TSC_OFFSET);
			nn->l1_tsc_dirty = true;
			return (0);
		}
		/* all'istante dell'uscita hardware (per una sintetica: ora) */
		*val = (vcpu->nested->synth ? rdtsc() : vcpu->nested->exit_tsc) +
		    vcpu->nested->l1_tsc_offset;
		return (0);
	default:
		return (EINVAL);	/* FS/GS_BASE, x2APIC, SMM...: vietati */
	}
	if (g >= 0) {
		if (live) {
			if (wr)
				wrmsr(idx, *val);
			else
				*val = rdmsr(idx);
		} else {
			if (wr)
				vcpu->guest_msrs[g] = *val;
			else
				*val = vcpu->guest_msrs[g];
		}
	} else {
		if (wr)
			vmwrite(f, idx == MSR_DEBUGCTLMSR ? (*val & 0x3) : *val);
		else
			*val = vmcs_read(f);
	}
	return (0);
}

/*
 * Lista "carica all'ingresso" del VMCS12 (slow path, VMCS02 corrente, dopo
 * lo stato guest come da SDM). 0 ok; altrimenti indice 1-based
 * dell'elemento non caricabile (VM-entry fallita, motivo 34).
 */
static uint32_t
nested_msr_list_entry(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct nested_msr_list *ml = &c->ml_en;	/* da nested_bitmaps_map */
	struct msr_entry *e;
	uint64_t v;
	uint32_t i, fail = 0;

	if (c->ml_en_bad)
		return (1);		/* lista non leggibile: prima voce */
	vcpu->nested->msr_phase = 1;
	for (i = 0; i < ml->n && fail == 0; i++) {
		e = nested_msr_ent(ml, i);
		v = e->val;
		if (e->reserved != 0 ||
		    nested_msr_rw(vcpu, e->index, &v, true, false) != 0)
			fail = i + 1;
	}
	vcpu->nested->msr_phase = 0;
	return (fail);
}

/*
 * Liste d'uscita (percorso veloce, pagine gia' mappate): store = salva gli
 * MSR dell'L2 (VMCS02 corrente, prima della commutazione); load = carica
 * quelli dell'L1 (VMCS01 corrente, dopo lo stato host). Un elemento non
 * gestito si salta: sull'hardware sarebbe un VMX abort.
 */
static void
nested_msr_list_exit(struct vmx_vcpu *vcpu, struct vmcs12_cache *c,
    bool store)
{
	struct nested_msr_list *ml = store ? &c->ml_st : &c->ml_ld;
	struct msr_entry *l;
	uint32_t i, n = ml->n;
	bool live = !vcpu->nested->slow_reflect;
	uint64_t v;

	for (i = 0; i < n; i++) {
		l = nested_msr_ent(ml, i);
		if (l->reserved != 0)
			continue;
		if (store) {
			if (nested_msr_rw(vcpu, l->index, &v, false, live) == 0)
				l->val = v;
		} else {
			v = l->val;
			(void)nested_msr_rw(vcpu, l->index, &v, true, live);
		}
	}
}

/* Slow path (vCPU FROZEN). 0 se ok; -1 se una bitmap richiesta dall'L1 non
 * e' mappabile (indirizzo non allineato o fuori dalla memoria del guest). */
static int
nested_bitmaps_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	uint32_t p12;
	uint64_t gpa;

	/*
	 * Il FORMATO degli indirizzi (allineamento, MAXPHYADDR) lo verifica
	 * nested_check_vmentry; qui una mappatura fallita (indirizzo valido ma
	 * non RAM) NON e' un VMfail: la CPU vera accetta l'indirizzo e legge
	 * quello che c'e' (kvm-unit-tests vmx_controls_test, 'vmlaunch
	 * succeeds'). Bitmap non mappata = percorso veloce conservativo
	 * (riflette all'L1); liste d'uscita non mappate = ignorate; lista
	 * d'ingresso non mappata = VM-entry fallito, motivo 34 (ml_en_bad).
	 */
	nested_bitmaps_unmap(c);
	c->ml_en_bad = false;
	p12 = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	if (p12 & PROCBASED_IO_BITMAPS) {
		gpa = vmcs12_read_field(c, VMCS_IO_BITMAP_A);
		c->bm_io_a = vm_gpa_hold(vcpu->vcpu, trunc_page(gpa), PAGE_SIZE,
		    VM_PROT_READ, &c->ck_io_a);
		gpa = vmcs12_read_field(c, VMCS_IO_BITMAP_B);
		c->bm_io_b = vm_gpa_hold(vcpu->vcpu, trunc_page(gpa), PAGE_SIZE,
		    VM_PROT_READ, &c->ck_io_b);
	}
	if (p12 & PROCBASED_MSR_BITMAPS) {
		gpa = vmcs12_read_field(c, VMCS_MSR_BITMAP);
		c->bm_msr = vm_gpa_hold(vcpu->vcpu, trunc_page(gpa), PAGE_SIZE,
		    VM_PROT_READ, &c->ck_msr);
	}
	(void)nested_msr_list_map(vcpu, c, VMCS_EXIT_MSR_STORE,
	    VMCS_EXIT_MSR_STORE_COUNT, VM_PROT_READ | VM_PROT_WRITE, &c->ml_st);
	(void)nested_msr_list_map(vcpu, c, VMCS_EXIT_MSR_LOAD,
	    VMCS_EXIT_MSR_LOAD_COUNT, VM_PROT_READ, &c->ml_ld);
	if (nested_msr_list_map(vcpu, c, VMCS_ENTRY_MSR_LOAD,
	    VMCS_ENTRY_MSR_LOAD_COUNT, VM_PROT_READ, &c->ml_en) != 0)
		c->ml_en_bad = true;
	return (0);
}

/* Percorso veloce: bit di una bitmap gia' mappata. true se impostato o se la
 * bitmap non e' mappata (conservativo: riflette all'L1). */
static bool
nested_bitmap_bit(const uint8_t *bm, uint32_t bit)
{
	if (bm == NULL)
		return (true);
	return ((bm[bit >> 3] >> (bit & 7)) & 1);
}

/*
 * Instradamento delle uscite mentre il vCPU e' in L2 (§6.4). Chiamata
 * all'inizio di vmx_exit_process. Ritorna true se l'uscita e' stata gestita
 * qui (riflessa all'L1): il chiamante deve restituire HANDLED senza toccare i
 * rami dell'L1. ext-int/NMI restano all'L0 (ritorna false: il flusso normale
 * li gestisce e si rientra in L2, con VMCS02 ancora corrente).
 */
/* RIP dell'L2 a questa uscita, per l'MTF pendente (nested_check_events) */
static void
n_exit_rip_record(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	vcpu->nested->l2_exit_rip = vmexit->rip;
}

/*
 * HV_X64_MSR_SIMP: bit 0 = abilitata, bit 12.. = GPA della pagina dei messaggi
 * SynIC. E' stato PRIVATO di ciascun VTL, quindi il GPA cambia col VTL: qui si
 * tiene l'ultimo visto, che e' quello del VTL in cui gira il tick.
 */
#define	HV_X64_MSR_SIMP		0x40000083

/*
 * Aggancia la SIM page quando l'L2 ne scrive il GPA, cosi' che il percorso
 * d'ingresso (interrupt disabilitati, nessuna sospensione possibile) debba solo
 * dereferenziare un indirizzo. vm_gpa_hold_global e non vm_gpa_hold: la
 * seconda pretende il vCPU FROZEN (KASSERT sotto INVARIANTS) e qui il vCPU e'
 * RUNNING. La pagina resta tenuta fino al prossimo cambio o alla distruzione.
 */
static void
nested_diag_snoop_simp(struct vmx_vcpu *vcpu, uint32_t msr, bool wr)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t val, gpa;
	void *kva, *ck;

	if (nested_diag_vec == 0 || !wr || msr != HV_X64_MSR_SIMP)
		return;
	val = ((vcpu->ctx.guest_rdx & 0xffffffff) << 32) |
	    (vcpu->ctx.guest_rax & 0xffffffff);
	if ((val & 1) == 0)
		return;			/* SIMP disabilitata: niente da leggere */
	gpa = val & ~(uint64_t)PAGE_MASK;
	if (gpa == n->diag_simp_gpa && n->diag_simp != NULL)
		return;			/* gia' agganciata */
	kva = vm_gpa_hold_global(vcpu->vmx->vm, gpa, PAGE_SIZE, VM_PROT_READ,
	    &ck);
	if (kva == NULL)
		return;
	if (n->diag_simp_ck != NULL)
		vm_gpa_release(n->diag_simp_ck);
	n->diag_simp_ck = ck;
	n->diag_simp = kva;
	n->diag_simp_gpa = gpa;
	SDT_PROBE3(vmm, vmx, nested, diag_simp, vcpu->vcpuid, gpa, val);
}

/*
 * Fotografia atomica immediatamente prima del VMLAUNCH/VMRESUME. Chiamata da
 * vmx_run con gli interrupt disabilitati: solo vmcs_read e letture di memoria,
 * nessuna sonda e nessuna printf. L'esito lo spara nested_diag_post_exit.
 */
void
nested_diag_pre_entry(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct nested_diag *d;
	volatile uint8_t *p;
	uint32_t ei;

	if (nested_diag_vec == 0 || n == NULL || !n->in_l2)
		return;
	ei = vmcs_read(VMCS_ENTRY_INTR_INFO);
	if ((ei & VMCS_INTR_VALID) == 0 ||
	    (ei & 0xff) != (uint32_t)nested_diag_vec)
		return;

	d = &n->diag;
	d->entry_info = ei;
	d->intblk = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	d->activity = vmcs_read(VMCS_GUEST_ACTIVITY);
	/* lunghezza con cui l'hardware consegna un evento SOFTWARE iniettato:
	 * l'indirizzo di ritorno spinto e' RIP + ilen */
	d->ilen = vmcs_read(VMCS_ENTRY_INST_LENGTH);
	d->rip = vmcs_read(VMCS_GUEST_RIP);
	d->rsp = vmcs_read(VMCS_GUEST_RSP);
	d->rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	d->eptp = vmcs_read(VMCS_EPTP);
	vmptrst(&d->vmcs);
	d->eptp12 = n->vept_eptp12;
	d->msgtype = d->msghdr = 0;
	d->exp = d->deliv = 0;
	p = n->diag_simp;
	if (p != NULL) {
		/*
		 * Intestazione del messaggio SynIC: MessageType a +0,
		 * PayloadSize a +4, MessageFlags a +5 (bit 0 = MessagePending).
		 * Payload del timer: TimerIndex +0x10, Expiration +0x18,
		 * Delivery +0x20.
		 */
		p += nested_diag_slot & (PAGE_SIZE - 1);
		d->msgtype = *(volatile uint32_t *)p;
		d->msghdr = p[4] | ((uint32_t)p[5] << 8);
		d->exp = *(volatile uint64_t *)(p + 0x18);
		d->deliv = *(volatile uint64_t *)(p + 0x20);
	}
	d->armed = 1;
}

/*
 * Al primo VM-exit dopo quell'ingresso, col VMCS02 ancora caricato: sparo la
 * fotografia e l'esito. IDT_VECTORING_INFO dice se l'evento e' stato
 * consegnato e poi interrotto dall'uscita; se l'iniezione non e' avvenuta
 * affatto, entry_info qui sotto lo dimostra.
 */
void
nested_diag_post_exit(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	struct vmx_nested *n = vcpu->nested;
	struct nested_diag *d;

	if (n == NULL || n->diag.armed == 0)
		return;
	d = &n->diag;
	d->armed = 0;

	SDT_PROBE6(vmm, vmx, nested, diag_entry, vcpu->vcpuid,
	    (uint64_t)d->entry_info | ((uint64_t)d->intblk << 32),
	    d->rip,
	    (uint64_t)d->msgtype | ((uint64_t)d->msghdr << 32),
	    d->exp, d->rflags);
	SDT_PROBE6(vmm, vmx, nested, diag_exit, vcpu->vcpuid,
	    (uint64_t)(vmexit->u.vmx.exit_reason & 0xffff) |
	    ((uint64_t)(uint32_t)vmcs_read(VMCS_IDT_VECTORING_INFO) << 32),
	    (uint64_t)(uint32_t)vmcs_read(VMCS_EXIT_INTR_INFO),
	    vmexit->rip, d->vmcs, d->eptp12);
	SDT_PROBE6(vmm, vmx, nested, diag_more, vcpu->vcpuid, d->deliv,
	    (uint64_t)d->activity | ((uint64_t)d->ilen << 32), d->eptp, d->rsp,
	    d->eptp12);
}

/*
 * Proprieta' del bit INT_WINDOW_EXITING nel VMCS02 (parere #15 di Astra). Il
 * bit vi arriva da due sorgenti: il VMCS12 (la finestra e' dell'L1, e la sua
 * uscita va riflessa) oppure L0 (nested_compose_vmcs02, blocco T2.6, per un
 * interrupt pendente dell'L1: la consuma L0). Restituisce true se l'L1 NON la
 * chiede, cioe' se il bit e' soltanto di L0. Una uscita 7 che arriva a L0 con
 * l'L1 che la chiedeva viola l'invariante: si conta con la sonda winexit.
 */
bool
nested_l0_owns_int_window(struct vmx_vcpu *vcpu)
{
	struct vmcs12_cache *c = nested_current_cache(vcpu->nested);
	uint64_t p12;
	bool l0;

	p12 = (c != NULL) ? vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) : 0;
	l0 = (p12 & PROCBASED_INT_WINDOW_EXITING) == 0;
	SDT_PROBE3(vmm, vmx, nested, winexit, vcpu->vcpuid, l0 ? 0 : 1, p12);
	return (l0);
}

void
nested_diag_ud_capture(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint32_t reason, intr, idtvec;
	uint64_t pend = 0, exc = 0, eb12;

	if (nested_diag_ud == 0 || n == NULL || !n->in_l2)
		return;
	reason = vmexit->u.vmx.exit_reason & 0xffff;
	intr = vmcs_read(VMCS_EXIT_INTR_INFO);
	idtvec = vmcs_read(VMCS_IDT_VECTORING_INFO);
	/* #UD che causa l'uscita (bitmap[6]=1), o gia' in consegna */
	if (!((reason == EXIT_REASON_EXCEPTION &&
	    (intr & 0x800007ff) == 0x80000306) ||
	    (idtvec & 0x800007ff) == 0x80000306))
		return;

	c = nested_current_cache(n);
	eb12 = (c != NULL) ? vmcs12_read_field(c, VMCS_EXCEPTION_BITMAP) : 0;
	vm_get_intinfo(vcpu->vcpu, &pend, &exc);
	SDT_PROBE6(vmm, vmx, nested, ud_a, vcpu->vcpuid,
	    vmcs_read(VMCS_GUEST_CR3), vmcs_read(VMCS_GUEST_RIP),
	    vmcs_read(VMCS_GUEST_RSP), vmcs_read(VMCS_GUEST_CR4),
	    vmcs_read(VMCS_GUEST_IA32_EFER));
	SDT_PROBE6(vmm, vmx, nested, ud_b, vcpu->vcpuid,
	    (uint64_t)reason | ((uint64_t)(vmcs_read(VMCS_GUEST_CS_SELECTOR) & 0xffff) << 16) |
	    ((uint64_t)(uint32_t)idtvec << 32),
	    (uint64_t)(uint32_t)intr,
	    vmcs_read(VMCS_EXIT_QUALIFICATION),
	    vmcs_read(VMCS_GUEST_LINEAR_ADDRESS),
	    vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS));
	SDT_PROBE6(vmm, vmx, nested, ud_c, vcpu->vcpuid,
	    vmcs_read(VMCS_EXCEPTION_BITMAP), eb12,
	    (uint64_t)(uint32_t)vmcs_read(VMCS_ENTRY_INTR_INFO),
	    pend, n->vept_eptp12);
}

/*
 * T6.3 (parere #21 di Astra): bitmap MSR del VMCS02 = OR della bitmap dell'L0
 * (VMCS01) e di quella dell'L1 (VMCS12), byte per byte su tutta la pagina: un
 * accesso passa senza uscita solo se lo lasciano passare ENTRAMBI. Prima il
 * VMCS02 usava la sola bitmap dell'L0, che lascia passare EFER, STAR, LSTAR,
 * CSTAR, SF_MASK, SYSENTER_* (e TSC/TSC_AUX in lettura): Hyper-V li intercetta
 * ma non riceveva le uscite, non vedeva la WRMSR EFER|SCE di Windows e
 * ricaricava il suo 0xd00 con LOAD_EFER -> SYSCALL con SCE=0 -> #UD in smss.
 *
 * Si ricalcola a ogni compose: la bitmap dell'L1 e' memoria ordinaria che
 * l'L1 puo' cambiare senza VMWRITE (l'hardware la legge a ogni RDMSR/WRMSR).
 * Limite noto: una modifica fatta da un altro LP dell'L1 mentre questo L2 gira
 * si vede solo al prossimo ingresso.
 *
 * L1 senza bitmap MSR: ogni RDMSR/WRMSR esce (SDM) -> tutto a 1. L1 con bitmap
 * attiva ma non mappabile (indirizzo valido, non RAM; non e' un VMfail, vedi
 * nested_bitmaps_map): tutto a 1 anche qui, coerente con l'instradamento in
 * nested_l2_exit che in quel caso riflette all'L1, ma CONTATO a parte
 * (VMX_NESTED_MSRBM_UNMAPPED) e segnalato, per non nasconderlo.
 * L'instradamento delle uscite (L1 intercetta -> riflette, altrimenti L0) non
 * cambia.
 */
static void
nested_compose_msr_bitmap(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	const uint64_t *b01 = (const uint64_t *)vcpu->vmx->msr_bitmap;
	const uint64_t *b12;
	uint64_t *b02 = (uint64_t *)n->msr_bitmap;
	uint32_t p12;
	int i, flags = 0;

	p12 = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	if (p12 & PROCBASED_MSR_BITMAPS) {
		flags |= 1;
		if (c->bm_msr == NULL) {
			vmm_stat_incr(vcpu->vcpu, VMX_NESTED_MSRBM_UNMAPPED, 1);
			if (ppsratecheck(&n->msrbm_warn_t, &n->msrbm_warn_n, 1))
				printf("vmx_nested: vcpu %d: bitmap MSR "
				    "dell'L1 (gpa %#lx) non mappabile, si "
				    "intercetta tutto\n", vcpu->vcpuid,
				    vmcs12_read_field(c, VMCS_MSR_BITMAP));
		} else
			flags |= 2;
	}
	if (flags == 3) {
		b12 = (const uint64_t *)c->bm_msr;
		for (i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++)
			b02[i] = b01[i] | b12[i];
	} else
		memset(b02, 0xff, PAGE_SIZE);
	vmwrite(VMCS_MSR_BITMAP, vtophys(n->msr_bitmap));

#define	MSRBM_PACK(o)							\
	((uint64_t)((const uint8_t *)b01)[1024 + (o)] |			\
	 (uint64_t)((const uint8_t *)b01)[3072 + (o)] << 8 |		\
	 (uint64_t)(flags == 3 ? c->bm_msr[1024 + (o)] : 0) << 16 |	\
	 (uint64_t)(flags == 3 ? c->bm_msr[3072 + (o)] : 0) << 24 |	\
	 (uint64_t)((const uint8_t *)b02)[1024 + (o)] << 32 |		\
	 (uint64_t)((const uint8_t *)b02)[3072 + (o)] << 40)
	/* SYSENTER 0x174..0x176: bassi, quindi offset -1024 dalla meta' alta */
	SDT_PROBE5(vmm, vmx, nested, msrbm, vcpu->vcpuid,
	    vmcs_read(VMCS_MSR_BITMAP), MSRBM_PACK(16), MSRBM_PACK(46 - 1024),
	    flags | ((vmcs_read(VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_MSR_BITMAPS) ? 4 : 0));
#undef	MSRBM_PACK
}

void
nested_diag_efer_trace(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct nested_msr_list *ml;
	struct msr_entry *e;
	uint64_t list_efer = 0;	/* bit63 presente, bit0..62 valore basso */
	uint32_t i;

	if (nested_diag_efer == 0 || c == NULL)
		return;
	/* la VM-entry MSR-load list del VMCS12 carica IA32_EFER? */
	ml = &c->ml_en;
	if (!c->ml_en_bad) {
		for (i = 0; i < ml->n; i++) {
			e = nested_msr_ent(ml, i);
			if (e->index == MSR_EFER) {
				list_efer = (1ULL << 63) | (e->val & 0x7fffffffffffffffULL);
				break;
			}
		}
	}
	SDT_PROBE6(vmm, vmx, nested, efer, vcpu->vcpuid,
	    vmcs12_read_field(c, VMCS_GUEST_IA32_EFER),
	    vmcs_read(VMCS_GUEST_IA32_EFER),		/* VMCS02 corrente */
	    vcpu->nested->l1_efer,
	    vmcs12_read_field(c, VMCS_ENTRY_CTLS),
	    list_efer);
	SDT_PROBE4(vmm, vmx, nested, efer2, vcpu->vcpuid,
	    vcpu->nested->vept_eptp12, vmcs_read(VMCS_GUEST_IA32_EFER),
	    vcpu->nested->current_vmcs12);
}

bool
nested_l2_exit(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	uint32_t reason = vmexit->u.vmx.exit_reason & 0xffff;

	n_exit_rip_record(vcpu, vmexit);
	/* WSL2-FreeBSD 003: l'ingresso senza intercetto e' passato, si riarma */
	if (__predict_false(vcpu->nested->diag_pf_rearm)) {
		vcpu->nested->diag_pf_rearm = false;
		nested_diag_pf_arm(vcpu);
	}
	/* un'uscita normale da L2 = l'ingresso e' riuscito: VMCS12 launched */
	if ((vmcs_read(VMCS_EXIT_REASON) & 0x80000000) == 0)
		vcpu->nested->launching = false;
	/*
	 * D4 (parere #51 §7): aggancio di prova, SPENTO per default. Qui il
	 * vCPU e' in L2 (n->in_l2 vero) e siamo in sezione critica: si
	 * registrano solo i flag (vmx_vpid_defer_request non esegue INVVPID).
	 * Una volta ogni N uscite da L2 si inietta una richiesta differita come
	 * se l'L1 avesse scritto CR3 col vCPU fermo; con migratore.sh la
	 * richiesta nasce su una CPU e sara' soddisfatta su quella del prossimo
	 * ingresso.
	 */
	if (__predict_false(nested_vpid_d4_arm != 0)) {
		static u_int d4_n;
		if ((++d4_n % (u_int)nested_vpid_d4_arm) == 0) {
			vmx_vpid_defer_request(vcpu);
			atomic_add_long(&nested_vpid_d4_injected, 1);
		}
	}

	switch (reason) {
	case EXIT_REASON_EXT_INTR:
		/* interrupt fisico per l'host: lo gestisce l'L0, si rientra in L2 */
		return (false);
	case EXIT_REASON_VMX_PREEMPT:
		/*
		 * Immediate exit di L0 (nested_immexit_arm): NON e' una scadenza
		 * del timer dell'L1 e non gli si riflette. L'evento dell'L2 e'
		 * consegnato; si resta in L2 e, prima del prossimo ingresso,
		 * nested_check_events consegna l'interrupt rinviato all'L1.
		 */
		if (vcpu->nested->imm_armed) {
			vmm_stat_incr(vcpu->vcpu, VMX_NESTED_IMMEXIT_FIRED, 1);
			SDT_PROBE3(vmm, vmx, nested, immexit, vcpu->vcpuid, 2,
			    0);
			vmexit->inst_length = 0;
			return (true);
		}
		break;			/* timer dell'L1 -> riflette */
	case EXIT_REASON_EXCEPTION: {
		uint32_t ii = (uint32_t)vmcs_read(VMCS_EXIT_INTR_INFO);
		struct vmx_nested *dn = vcpu->nested;

		/* NMI (intr_type NMI) all'L0; le altre eccezioni si riflettono
		 * se nella exception bitmap di VMCS12 (semplificato: riflette). */
		if ((ii & 0x700) == (2 << 8))	/* type 2 = NMI */
			return (false);
		if ((ii & 0xff) == IDT_PF && dn->diag_pf_armed) {
			/*
			 * WSL2-FreeBSD 003: #PF intercettato per noi (il VMCS12 non
			 * lo vuole). Si cattura lo stato col VMCS02 caricato, si
			 * toglie l'intercetto per UN ingresso e si rimanda il walk
			 * allo slow path; nessun evento iniettato: il processore
			 * riesegue l'istruzione (rip invariato).
			 */
			dn->diag_pf_ec = (uint32_t)vmcs_read(VMCS_EXIT_INTR_ERRCODE);
			dn->diag_pf_idtv = (uint32_t)vmcs_read(VMCS_IDT_VECTORING_INFO);
			dn->diag_pf_ss_ar =
			    (uint32_t)vmcs_read(VMCS_GUEST_SS_ACCESS_RIGHTS);
			dn->diag_pf_rip = vmcs_read(VMCS_GUEST_RIP);
			dn->diag_pf_qual = vmcs_read(VMCS_EXIT_QUALIFICATION);
			dn->diag_pf_cr0 = vmcs_read(VMCS_GUEST_CR0);
			dn->diag_pf_cr3 = vmcs_read(VMCS_GUEST_CR3);
			dn->diag_pf_cr4 = vmcs_read(VMCS_GUEST_CR4);
			dn->diag_pf_efer = vmcs_read(VMCS_GUEST_IA32_EFER);
			atomic_add_long(&nested_diag_pf_hits, 1);
			if (dn->diag_pf_idtv & VMCS_IDT_VEC_VALID)
				atomic_add_long(&nested_diag_pf_vectoring, 1);
			vmcs_write(VMCS_EXCEPTION_BITMAP,
			    (uint32_t)vmcs_read(VMCS_EXCEPTION_BITMAP) &
			    ~(1u << IDT_PF));
			vmcs_write(VMCS_PF_ERROR_MASK, 0);
			vmcs_write(VMCS_PF_ERROR_MATCH, 0);
			dn->diag_pf_armed = false;
			dn->diag_pf_rearm = true;
			dn->diag_pf_pending = true;
			vmexit->inst_length = 0;
			return (true);
		}
		if ((ii & 0xff) == IDT_PF)
			atomic_add_long(&nested_diag_pf_l1_exits, 1);
		break;			/* eccezione non-NMI -> riflette */
	}
	case EXIT_REASON_INOUT: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12;
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if (p12 & PROCBASED_IO_BITMAPS) {
			/*
			 * SDM: con le bitmap l'I/O "incondizionato" e' ignorato.
			 * Esce se UNA qualunque delle porte toccate (1, 2 o 4
			 * byte) ha il bit, o se l'accesso sfora oltre 0xffff.
			 */
			uint64_t q = vmcs_read(VMCS_EXIT_QUALIFICATION);
			uint32_t port = (q >> 16) & 0xffff, size = (q & 7) + 1;
			uint32_t p;
			bool hit = false;

			if (port + size - 1 > 0xffff)
				break;			/* wrap -> riflette */
			for (p = port; p < port + size && !hit; p++)
				hit = nested_bitmap_bit(p < 0x8000 ?
				    cc->bm_io_a : cc->bm_io_b, p & 0x7fff);
			if (hit)
				break;			/* L1 intercetta -> riflette */
			return (false);		/* L0 gestisce con i reg. di L2 */
		}
		if (p12 & PROCBASED_IO_EXITING) break;	/* uncond -> riflette */
		return (false);			/* L0 gestisce con i registri di L2 */
	}
	case EXIT_REASON_INTR_WINDOW:
	case EXIT_REASON_NMI_WINDOW: {
		/*
		 * L0 apre queste finestre per iniettare eventi in L2: all'L1
		 * solo se il SUO VMCS12 le chiede. Prima si riflettevano
		 * sempre (kvm-unit-tests 'interrupt': "Unknown exit reason
		 * 0x7" nell'L1). Altrimenti la gestisce il flusso normale
		 * (chiude la finestra, inietta, si rientra in L2).
		 */
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t flag = (reason == EXIT_REASON_INTR_WINDOW) ?
		    PROCBASED_INT_WINDOW_EXITING : PROCBASED_NMI_WINDOW_EXITING;

		if (cc != NULL && (vmcs12_read_field(cc,
		    VMCS_PRI_PROC_BASED_CTLS) & flag))
			break;			/* L1 la chiede -> riflette */
		return (false);
	}
	case EXIT_REASON_CR_ACCESS: {
		/*
		 * CR8 (TPR): L0 forza le uscite su CR8 nel VMCS02; si riflette
		 * all'L1 solo se il SUO VMCS12 le chiede, altrimenti L0 emula
		 * sul TPR del vCPU, che e' cio' che l'L2 vedrebbe sul ferro.
		 * Gli altri CR (0, 3, 4): riflessi come prima.
		 */
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint64_t q = vmcs_read(VMCS_EXIT_QUALIFICATION);
		uint32_t cr = q & 0xf, type = (q >> 4) & 3, p12;

		if (cc == NULL || cr != 8 || type > 1)
			break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if (p12 & (type == 0 ? PROCBASED_CR8_LOAD_EXITING :
		    PROCBASED_CR8_STORE_EXITING))
			break;			/* L1 intercetta -> riflette */
		/* con il TPR shadow dell'L1 CR8 e' del VTPR (hardware, vedi
		 * nested_compose_vmcs02): mai sul TPR vero dell'L1 */
		if (p12 & PROCBASED_USE_TPR_SHADOW)
			break;
		return (false);			/* L0 emula sul TPR */
	}
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12, msr, base, bit;
		bool wr = (reason == EXIT_REASON_WRMSR);
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if ((p12 & PROCBASED_MSR_BITMAPS) == 0) break; /* tutte -> riflette */
		/*
		 * RCX dell'L2. NON vmx_get_guest_reg(vcpu, VM_REG_GUEST_RCX):
		 * quella vuole il numero hardware del registro (codifica delle
		 * istruzioni VMX: 0 RAX, 1 RCX, 2 RDX) e VM_REG_GUEST_RCX vale 2,
		 * cioe' RDX. Si decideva sull'MSR "RDX": Windows 11 + Hyper-V,
		 * RDMSR/WRMSR di HV_X64_MSR_HYPERCALL (0x40000001) con RDX=0 presi
		 * per l'MSR 0, non intercettato -> gestiti da L0 invece che
		 * riflessi: il loader leggeva 0, attivava la pagina hypercall al
		 * GPA 0, il kernel la chiamava, Hyper-V vedeva la root eseguire al
		 * GPA 0 -> triple fault -> reset (OUT 0xCF9).
		 */
		msr = (uint32_t)vcpu->ctx.guest_rcx;
		nested_diag_snoop_simp(vcpu, msr, wr);
		if (msr < 0x2000) { base = wr ? 2048 : 0; bit = msr; }
		else if (msr >= 0xc0000000 && msr < 0xc0002000)
			{ base = wr ? 3072 : 1024; bit = msr - 0xc0000000; }
		else break;			/* fuori range -> riflette */
		if (nested_bitmap_bit(cc->bm_msr == NULL ? NULL :
		    cc->bm_msr + base, bit))
			break;			/* L1 intercetta -> riflette */
		return (false);			/* L0 gestisce con i registri di L2 */
	}
	case EXIT_REASON_MWAIT:
	case EXIT_REASON_MONITOR: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12, flag;
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		flag = (reason == EXIT_REASON_MWAIT) ? PROCBASED_MWAIT_EXITING :
		    PROCBASED_MONITOR_EXITING;
		if (p12 & flag) break;		/* L1 intercetta -> riflette */
		vm_inject_ud(vcpu->vcpu);	/* non intercettato -> #UD in L2 */
		return (false);
	}
	case EXIT_REASON_EPT_FAULT:
	case EXIT_REASON_EPT_MISCONFIG: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		if (cc != NULL && (vmcs12_proc2(cc) & PROCBASED2_ENABLE_EPT)) {
			if (reason == EXIT_REASON_EPT_MISCONFIG)
				break;		/* -> riflette all'L1 */
			/*
			 * Violation con shadow EPT: si risolve nello SLOW PATH.
			 * Qui (dentro vmx_run, sotto critical_enter) non si puo'
			 * dormire, e vmx_vept_fault ne ha bisogno (vm_gpa_hold
			 * sulle tabelle dell'L1, malloc). Si cattura il GPA, si
			 * esce da vmx_run RESTANDO in L2 (vmx.c vede ept_pending)
			 * e si riesegue l'istruzione (inst_length 0).
			 */
			vcpu->nested->ept_gpa =
			    vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS);
			vcpu->nested->ept_qual = vmcs_read(VMCS_EXIT_QUALIFICATION);
			SDT_PROBE5(vmm, vmx, nested, eptviol, vcpu,
			    vmcs_read(VMCS_EPTP), vmx_vept_eptp(vcpu),
			    vcpu->nested->ept_gpa, vcpu->nested->ept_qual);
			vcpu->nested->ept_pending = true;
			vmexit->inst_length = 0;
			return (true);
		}
		/* VMCS12 senza EPT: L2-GPA == L1-GPA, gestione L0 normale */
		return (false);
	}
	default:
		break;
	}
	/* ogni break qui sopra significa: rifletti all'L1 */
	nested_reflect_to_l1(vcpu, vmexit);
	return (true);
}

static int
nested_invvpid(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct invvpid_desc d;
	uint32_t info = (uint32_t)n->exit_insn_info;
	uint64_t type, cap = n->vmx_msr[0x48c - 0x480], q[2];

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	/*
	 * Emulazione completa (prima: flush e VMsucceed qualunque operando;
	 * kvm-unit-tests invvpid_test, 897 fallimenti). Descrittore di 16
	 * byte in memoria: VPID nei bit 15:0, bit 63:16 riservati, poi
	 * l'indirizzo lineare. Tipo nel registro (bit 31:28 di insn_info).
	 */
	type = nested_reg_operando(vcpu, (info >> 28) & 0xf);
	/*
	 * #160: SDM INVVPID, il tipo non annunciato (bit 40 + tipo dell'EPT/VPID
	 * cap) da' VMfail PRIMA di leggere il descrittore; poi il descrittore
	 * m128 si legge in un accesso solo (prima: due meta' da 8, la seconda
	 * tradotta dopo aver letto la prima, e il tipo controllato dopo).
	 */
	if (type > 3 || (cap & (1ULL << (40 + type))) == 0) {
		nested_vmx_result(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		nested_advance_rip(vcpu);
		return (0);
	}
	switch (nested_operand_copy(vcpu, VM_PROT_READ, q, sizeof(q))) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	if ((q[0] >> 16) != 0 ||				/* riservati */
	    (type != 2 && (q[0] & 0xffff) == 0) ||		/* VPID 0 */
	    (type == 0 && !nested_canonical(q[1]))) {		/* indirizzo */
		nested_vmx_result(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* tutti i VPID dell'L1 condividono il VPID02 dell'L2: qualunque tipo
	 * e' soddisfatto (per eccesso) da un flush single-context di vpid2 */
	bzero(&d, sizeof(d));
	d.vpid = n->vpid2;
	if (!n->vpid02_off) {	/* senza VPID nel VMCS02 non c'e' nulla da invalidare */
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, d);
		atomic_add_long(&vpid02_invvpid_l1insn, 1);
	}
	/* vpid_track (D2): questa e' la CPU dello slow path, non per forza quella
	 * del prossimo ingresso in L2 */
	if (n->vpid_track)
		nested_vpid02_request(n);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

/*
 * INVEPT dell'L1 (prima non instradata: finiva in userland). All-context
 * svuota tutta la shadow EPT; single-context solo le radici con la stessa
 * base EPT12 dell'EPTP del descrittore (vmx_vept_invept, parere #24). Il TLB
 * dell'EPTP shadow lo invalida vmx_run al prossimo ingresso in L2. Tipo non
 * annunciato nell'EPT cap esposto all'L1 (bit 25 single, 26 all) -> VMfail 28.
 * Il descrittore (m128) ha l'EPTP nei primi 8 byte.
 */
static int
nested_invept(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint32_t info = (uint32_t)n->exit_insn_info;
	uint64_t type, eptp = 0, cap = n->vmx_msr[0x48c - 0x480], rip, desc[2];
	sbintime_t t0;
	u_long ns;
	int wiped, kept;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	type = nested_reg_operando(vcpu, (info >> 28) & 0xf);
	if (!((type == 1 && (cap & (1ULL << 25))) ||
	    (type == 2 && (cap & (1ULL << 26))))) {
		nested_vmx_result(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		nested_advance_rip(vcpu);
		return (0);
	}
	/*
	 * #160: SDM INVEPT, per OGNI tipo annunciato il descrittore m128 si legge
	 * (un #PF e' possibile anche con all-context); l'EPTP sono i primi 8
	 * byte e conta solo per single-context.
	 */
	switch (nested_operand_copy(vcpu, VM_PROT_READ, desc, sizeof(desc))) {
	case NOPND_OK:
		break;
	case NOPND_INIETTATO:
		return (0);
	case NOPND_HOST_FATALE:
		return (nested_operand_fatale(vcpu));
	case NOPND_CONTESO:
		return (nested_operand_conteso(vcpu));
	}
	if (type == 1) {
		eptp = desc[0];
		/* #162: EPTP che farebbe fallire un VM entry -> VMfail 28, nessuna
		 * invalidazione (SDM INVEPT, single-context) */
		if (!nested_eptp_ok(cap, eptp)) {
			nested_vmx_result(vcpu,
			    VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
			nested_advance_rip(vcpu);
			return (0);
		}
	}
	t0 = sbinuptime();
	wiped = vmx_vept_invept(vcpu, type, eptp, &kept);
	n->diag_invept_seq++;		/* parere Opus 009 §1 */
	n->diag_invept_tsc = rdtsc();
	n->diag_invept_kept = kept;
	n->diag_invept_wiped = wiped;
	n->diag_invept_type = type;	/* parere di Astra 010 §4 */
	n->diag_invept_eptp = eptp;
	ns = (u_long)sbttons(sbinuptime() - t0);
	atomic_add_long(&nested_invept_ns_sum, ns);
	if (ns > nested_invept_ns_max)
		nested_invept_ns_max = ns;		/* indicativo: senza CAS */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &rip);
	SDT_PROBE6(vmm, vmx, nested, invept2, vcpu->vcpuid, rip,
	    n->current_vmcs12, (int)type, eptp,
	    (uint64_t)wiped | (uint64_t)kept << 16);
	vmm_stat_incr(vcpu->vcpu, type == 1 ? VMX_NESTED_INVEPT_SINGLE :
	    VMX_NESTED_INVEPT_ALL, 1);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_VEPT_WIPED, wiped);
	SDT_PROBE4(vmm, vmx, nested, invept, vcpu->vcpuid, (int)type, eptp,
	    wiped);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

/*
 * EPT violation di L2 con shadow EPT, nello slow path (vedi nested_l2_exit).
 *  - VEPT_OK: shadow installata, si riparte in L2 sulla stessa istruzione;
 *  - VEPT_MMIO: l'L2 tocca un dispositivo emulato dell'L1 -> emulazione
 *    normale di bhyve sul GPA dell'L1 (vm_run: VM_EXITCODE_INST_EMUL);
 *  - VEPT_VIOL / VEPT_MISCONF: riflessa all'L1 (motivo 48 o 49). Per la
 *    violation i bit 5:3 della qualificazione sono i permessi dell'EPT
 *    dell'L1, non quelli della shadow. Il VMCS02 conserva i campi d'uscita
 *    anche dopo VMCLEAR/VMPTRLD.
 */
/* true se l'L1 intercetta gli interrupt esterni dell'L2 (pin del VMCS12) */
bool
nested_l1_intercepts_extint(struct vmx_vcpu *vcpu)
{
	struct vmcs12_cache *c = nested_current_cache(vcpu->nested);

	return (c != NULL && (vmcs12_read_field(c, VMCS_PIN_BASED_CTLS) &
	    PINBASED_EXTINT_EXITING) != 0);
}

/*
 * Sonda 9 (SOLO slow path, prime 8 volte): EPT violation di L2 che sta per
 * essere riflessa all'L1. Rifa' in software il percorso delle tabelle delle
 * pagine dell'L2 per il GLA del fault, leggendole attraverso l'EPT12 (il
 * riferimento), e per ogni pagina di tabella confronta la pagina host attesa
 * con quella a cui punta lo shadow EPT (quella che legge l'hardware).
 * Windows 11 + Hyper-V: fault in fetch con GPA 0 su un RIP del kernel.
 */
static void
nested_probe_walk(struct vmx_vcpu *vcpu, int r, uint64_t l1gpa, uint64_t perm)
{
	struct vmx_nested *n = vcpu->nested;
	struct vm_guest_paging *pg = &n->ept_emul.u.inst_emul.paging;
	uint64_t gla = n->ept_emul.u.inst_emul.gla, tgpa, l1, pte, swgpa = 0;
	uint64_t exp, sh, *p;
	void *ck;
	int lvl, fault = 0, err;
	static int count;

	if (count >= 8)
		return;
	count++;
	err = vm_gla2gpa_nofault(vcpu->vcpu, pg, gla, VM_PROT_EXECUTE, &swgpa,
	    &fault);
	printf("nested_probe EPT-RIFL#%d r=%d l2gpa=%#lx qual=%#lx gla=%#lx "
	    "cr3=%#lx mode=%d/%d l1gpa=%#lx perm=%#lx | sw gpa=%#lx err=%d "
	    "fault=%d\n", count, r, (u_long)n->ept_gpa, (u_long)n->ept_qual,
	    (u_long)gla, (u_long)pg->cr3, pg->cpu_mode, pg->paging_mode,
	    (u_long)l1gpa, (u_long)perm, (u_long)swgpa, err, fault);
	if (pg->paging_mode != PAGING_MODE_64)
		return;
	tgpa = pg->cr3 & 0x000ffffffffff000ULL;
	for (lvl = 3; lvl >= 0; lvl--) {
		if (vmx_vept_l1gpa(vcpu, tgpa, VM_PROT_READ, &l1) != 0) {
			printf("nested_probe   L%d tabella l2gpa=%#lx: l'EPT12 "
			    "non la mappa\n", lvl + 1, (u_long)tgpa);
			return;
		}
		p = vm_gpa_hold(vcpu->vcpu, l1 & ~(uint64_t)PAGE_MASK,
		    PAGE_SIZE, VM_PROT_READ, &ck);
		if (p == NULL) {
			printf("nested_probe   L%d tabella l1gpa=%#lx non RAM\n",
			    lvl + 1, (u_long)l1);
			return;
		}
		exp = DMAP_TO_PHYS((vm_offset_t)p);
		pte = p[(gla >> (12 + 9 * lvl)) & 0x1ff];
		vm_gpa_release(ck);
		sh = vmx_vept_shadow_entry(vcpu, tgpa);
		printf("nested_probe   L%d tabella l2gpa=%#lx l1gpa=%#lx host "
		    "atteso=%#lx shadow=%#lx%s pte=%#lx\n", lvl + 1,
		    (u_long)tgpa, (u_long)l1, (u_long)exp, (u_long)sh,
		    (sh != 0 && (sh & 0x000ffffffffff000ULL) != exp) ?
		    " <-- DIVERSO" : "", (u_long)pte);
		if ((pte & 1) == 0 || (lvl > 0 && (pte & 0x80) != 0))
			return;
		tgpa = pte & 0x000ffffffffff000ULL;
	}
}

/*
 * Sessione 1d (parere di Astra sul caso H): EPT violation trovata
 * dall'EMULATORE di L0 (vmx_vept_ptp_write: A/D in una tabella dell'L2 su una
 * pagina che EPT12 non concede in scrittura), consegnata qui da vmx_run prima
 * di rientrare in L2. L'istruzione dell'L2 non ha scritto nulla ed e' gia'
 * ripartita (rip invariato nel VMCS02). Si riflette con il ramo SINTETICO di
 * nested_reflect_to_l1: quello hardware copierebbe GPA e indirizzo lineare
 * dall'ultima uscita del VMCS02, che per un movsq da MMIO e' il fault sulla
 * SORGENTE; qui GPA e lineare sono quelli della voce di tabella e del walk.
 */
static int
nested_ept_emul_reflect(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	struct vmcs12_cache *c;
	uint64_t gpa = n->emu_viol_gpa, gla = n->emu_viol_gla;

	/*
	 * Chi chiama ha gia' verificato in_l2 (emu_viol => in_l2: nasce solo in
	 * L2 e decade in nested_reflect_to_l1). GPA e lineare sono copiati qui,
	 * la qualifica passa in synth_qual PRIMA della riflessione:
	 * nested_reflect_to_l1 azzera emu_viol ma non ne tocca i dati.
	 *
	 * Parere #110 §3: il VMCS12 va verificato PRIMA di consumare la causa.
	 * Con c == NULL nested_reflect_to_l1 esce senza riflettere, e il resto di
	 * questa funzione darebbe all'L1 un RIP mai preparato. Irraggiungibile:
	 * il VMCS12 corrente e le cache cambiano solo emulando VMXON/VMXOFF/
	 * VMCLEAR/VMPTRLD dell'L1, mai fra la produzione (in L2, con c != NULL,
	 * vmx_vept_ptp_write) e questo punto. Se capitasse: nessuna riflessione
	 * parziale; la VM si spegne (come per un errore dello shadow VMCS),
	 * l'host resta intatto, nessun panic.
	 */
	c = nested_current_cache(n);
	if (c == NULL || n->current_vmcs12 != n->emu_viol_vmcs12) {
		n->emu_viol = false;
		atomic_add_long(&nested_ept12_viol_emul_nocache, 1);
		vm_suspend(vcpu->vmx->vm, VM_SUSPEND_POWEROFF);
		return (0);
	}
	n->emu_viol = false;		/* consumata: UNA sola riflessione */
	VMPTRLD(vcpu->vmcs);			/* il VMCS02 */
	/* H2: anche una misconfiguration (motivo 49, qualificazione 0) */
	vmexit->u.vmx.exit_reason = n->emu_viol_reason;
	n->synth = true;
	n->synth_qual = n->emu_viol_qual;
	n->synth_intr_info = 0;
	n->slow_reflect = true;
	nested_reflect_to_l1(vcpu, vmexit);
	n->slow_reflect = false;
	n->synth = false;
	n->synth_qual = 0;
	c = nested_current_cache(n);	/* invariato dalla riflessione */
	if (c != NULL) {
		/* dopo la riflessione, prima del prossimo ingresso in L1: la copia
		 * verso lo shadow VMCS avviene all'ingresso e legge il VMCS12 in
		 * quel momento; i due campi si segnano anche qui (parere #109 §2.D),
		 * senza contare sul segno globale di nested_reflect_to_l1 */
		vmcs12_write_field(c, VMCS_GUEST_PHYSICAL_ADDRESS, gpa);
		shvmcs_mark(n, c, VMCS_GUEST_PHYSICAL_ADDRESS);
		/* la misconfiguration non riporta l'indirizzo lineare (SDM) */
		if (n->emu_viol_reason == EXIT_REASON_EPT_FAULT) {
			vmcs12_write_field(c, VMCS_GUEST_LINEAR_ADDRESS, gla);
			shvmcs_mark(n, c, VMCS_GUEST_LINEAR_ADDRESS);
		}
	}
	VMCLEAR(vcpu->vmcs01);			/* niente VMCS attivo nello slow path */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP, vmexit->rip);
	/* #110 §3: conta la riflessione COSTRUITA, non il tentativo */
	atomic_add_long(n->emu_viol_reason == EXIT_REASON_EPT_FAULT ?
	    &nested_ept12_viol_emul_reflected :
	    &nested_ept12_misconf_emul_reflected, 1);
	return (0);
}

/*
 * WSL2-FreeBSD 003: arma l'intercetto diagnostico nel VMCS02 CORRENTE. Solo se il
 * VMCS12 non vuole nessun #PF (bit 14 a 0 con maschera e confronto a 0: allora
 * nessun #PF esce verso l'L1), cosi' l'intercetto non toglie nulla all'L1.
 */
static void
nested_diag_pf_arm(struct vmx_vcpu *vcpu)
{
	struct vmcs12_cache *c = nested_current_cache(vcpu->nested);

	vcpu->nested->diag_pf_armed = false;
	if (nested_diag_pf == 0 || c == NULL)
		return;
	if ((vmcs12_read_field(c, VMCS_EXCEPTION_BITMAP) & (1u << IDT_PF)) != 0 ||
	    vmcs12_read_field(c, VMCS_PF_ERROR_MASK) != 0 ||
	    vmcs12_read_field(c, VMCS_PF_ERROR_MATCH) != 0) {
		atomic_add_long(&nested_diag_pf_skipped, 1);
		return;
	}
	vmcs_write(VMCS_EXCEPTION_BITMAP,
	    (uint32_t)vmcs_read(VMCS_EXCEPTION_BITMAP) | (1u << IDT_PF));
	vmcs_write(VMCS_PF_ERROR_MASK, PGEX_I | PGEX_U);
	vmcs_write(VMCS_PF_ERROR_MATCH, PGEX_I);
	vcpu->nested->diag_pf_armed = true;
}

/*
 * WSL2-FreeBSD 003: slow path (nessun VMCS attivo, fuori dalla sezione critica
 * del percorso d'uscita). Stato catturato all'uscita e walk delle tabelle
 * dell'L2 per l'indirizzo del fault: per ogni livello la pagina host ATTESA
 * (tabella dell'L2 tradotta con EPT12, la vista dell'L1) contro quella a cui
 * punta l'EPT02 OMBRA (quella che ha letto il processore). Prime 32 volte.
 */
/* parere di Astra 010: copia i 16 registri del contesto (rdi..r15, cr2) */
static void
nested_pfrec_gpr(struct vmx_vcpu *vcpu, uint64_t *g)
{
	struct vmxctx *x = &vcpu->ctx;

	g[0] = x->guest_rdi; g[1] = x->guest_rsi; g[2] = x->guest_rdx;
	g[3] = x->guest_rcx; g[4] = x->guest_r8; g[5] = x->guest_r9;
	g[6] = x->guest_rax; g[7] = x->guest_rbx; g[8] = x->guest_rbp;
	g[9] = x->guest_r10; g[10] = x->guest_r11; g[11] = x->guest_r12;
	g[12] = x->guest_r13; g[13] = x->guest_r14; g[14] = x->guest_r15;
	g[15] = x->guest_cr2;
}

/*
 * Parere di Astra 010 §4: E0 (stato dell'L2 all'uscita MMIO sul LAPIC; il
 * VMCS02 e' caricato, la riflessione ha letto lo stato guest senza cambiarlo)
 * ed E1 (lo stesso stato appena consegnato all'L1 nel VMCS12). Riempie il
 * record in corso del vCPU e lo arma per l'ingresso successivo.
 */
static void
nested_pfrec_cap_e0(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct nested_pfrec *p = &n->pfst;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t rip;

	rip = vmcs_read(VMCS_GUEST_RIP);	/* RIP dell'L2 (VMCS02, prima della riflessione) */
	n->pfrec_building = false;
	if (nested_diag_pfrec_rippage != 0 &&
	    (rip & ~(uint64_t)PAGE_MASK) != nested_diag_pfrec_rippage)
		return;
	memset(p, 0, sizeof(*p));
	p->vcpu = vcpu->vcpuid;
	p->seq = ++n->pfrec_seq;
	p->t0 = rdtsc();
	p->rip0 = rip;
	p->cr3_0 = vmcs_read(VMCS_GUEST_CR3);
	p->gpa0 = n->ept_gpa;
	p->gla0 = vmcs_read(VMCS_GUEST_LINEAR_ADDRESS);
	p->qual0 = n->ept_qual;
	nested_pfrec_gpr(vcpu, p->gpr0);
	/* eptp12 conservato nel record per il walk in E1 (vm_gpa_hold puo' dormire) */
	p->c0.l2gpa = c != NULL ? vmcs12_read_field(c, VMCS_EPTP) : 0;
	n->pfrec_building = true;
}

static void
nested_pfrec_cap_e1(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct nested_pfrec *p = &n->pfst;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t eptp12 = p->c0.l2gpa;	/* salvato in E0 */

	n->pfrec_building = false;
	p->t1 = rdtsc();
	if (c != NULL) {
		p->rip1 = vmcs12_read_field(c, VMCS_GUEST_RIP);
		p->gpa1 = vmcs12_read_field(c, VMCS_GUEST_PHYSICAL_ADDRESS);
		p->gla1 = vmcs12_read_field(c, VMCS_GUEST_LINEAR_ADDRESS);
		p->qual1 = vmcs12_read_field(c, VMCS_EXIT_QUALIFICATION);
		p->reason1 = vmcs12_read_field(c, VMCS_EXIT_REASON);
	}
	memcpy(p->gpr1, p->gpr0, sizeof(p->gpr1));	/* i GPR non cambiano */
	/* walk del codice all'RIP dell'L2: byte dalla pagina dell'L1 e dall'EPT02 */
	vmx_vept_diag_code(vcpu, eptp12, p->cr3_0, p->rip0, &p->c0);
	atomic_add_long(&nested_diag_pfrec_e0, 1);
	n->pfrec_armed = true;
}

/*
 * Parere di Astra 010 §3-4: all'ingresso in L2, se un episodio E0/E1 e' armato
 * su questo vCPU, si guarda che cosa l'L1 sta per iniettare (VMCS12
 * ENTRY_INTR_INFO). #PF (vettore 14) valido -> E2 completo e record committato
 * in un anello; fetch e dati separati. Altrimenti l'episodio si chiude "ok".
 * Si disarma sempre. Chiamato a ingresso (vm_gpa_hold puo' dormire).
 */
static void
nested_diag_pfrec_entry(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	struct nested_pfrec *p = &n->pfst;
	uint32_t info, err;
	uint64_t cr2, rip, cr3, eptp12;
	u_int slot;

	if (!n->pfrec_armed)
		return;
	n->pfrec_armed = false;
	info = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO);
	if ((info & 0x800007ff) != 0x8000030e) {	/* non #PF valido */
		atomic_add_long((info & 0x80000000) ? &nested_diag_pfrec_other :
		    &nested_diag_pfrec_ok, 1);
		return;
	}
	err = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR);
	atomic_add_long((err & PGEX_I) ? &nested_diag_pfrec_pf_fetch :
	    &nested_diag_pfrec_pf_data, 1);
	cr2 = vcpu->ctx.guest_cr2;	/* CR2 che l'L1 prepara per l'L2 */
	rip = vmcs12_read_field(c, VMCS_GUEST_RIP);
	cr3 = vmcs12_read_field(c, VMCS_GUEST_CR3);
	eptp12 = vmcs12_read_field(c, VMCS_EPTP);
	p->t2 = rdtsc();
	p->info2 = info;
	p->err2 = err;
	p->cr2_2 = cr2;
	p->rip2 = rip;
	p->cr3_2 = cr3;
	nested_pfrec_gpr(vcpu, p->gpr2);
	vmx_vept_diag_code(vcpu, eptp12, cr3, rip, &p->c2);
	p->inv_seq = n->diag_invept_seq;
	p->inv_tsc = n->diag_invept_tsc;
	p->inv_type = n->diag_invept_type;
	p->inv_eptp = n->diag_invept_eptp;
	p->inv_kept = n->diag_invept_kept;
	p->inv_wiped = n->diag_invept_wiped;
	/* committa in un anello (prenotazione atomica dello slot) */
	slot = atomic_fetchadd_int(&nested_pfrec_n, 1) % NESTED_PFREC_MAX;
	p->done = 0;
	memcpy(&nested_pfrecs[slot], p, sizeof(*p));
	atomic_store_rel_int(&nested_pfrecs[slot].done, 1);
}

static void
nested_diag_pfinj_note(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	uint32_t info, err;
	uint64_t cr2, rip, cr3, eptp12, pag;
	static int printed;

	info = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO);
	if ((info & 0x800007ff) != 0x8000030e)
		return;
	atomic_add_long(&nested_diag_pfinj_all, 1);
	err = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR);
	if ((err & PGEX_I) == 0)
		return;
	atomic_add_long(&nested_diag_pfinj_fetch, 1);
	if (printed >= 16)
		return;
	printed++;
	cr2 = vcpu->ctx.guest_cr2;	/* il CR2 che l'L1 ha preparato per l'L2 */
	rip = vmcs12_read_field(c, VMCS_GUEST_RIP);
	cr3 = vmcs12_read_field(c, VMCS_GUEST_CR3);
	eptp12 = vmcs12_read_field(c, VMCS_EPTP);
	printf("nested_diag_pfinj #%d vcpu%d err=%#x cr2=%#lx | L2: rip=%#lx "
	    "cr3=%#lx cr0=%#lx cr4=%#lx efer=%#lx rfl=%#lx intr=%#lx act=%#lx "
	    "eptp12=%#lx\n", printed, vcpu->vcpuid, err, (u_long)cr2,
	    (u_long)rip, (u_long)cr3,
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_CR0),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_CR4),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_IA32_EFER),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_RFLAGS),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_INTERRUPTIBILITY),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_ACTIVITY), (u_long)eptp12);
	printf("nested_diag_pfinj #%d   uscita riflessa prima: motivo=%#lx "
	    "qual=%#lx gpa=%#lx gla=%#lx idtv=%#lx/%#lx exit_intr=%#lx/%#lx "
	    "ilen=%#lx entry=%#lx exit=%#lx\n", printed,
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_REASON),
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_QUALIFICATION),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_PHYSICAL_ADDRESS),
	    (u_long)vmcs12_read_field(c, VMCS_GUEST_LINEAR_ADDRESS),
	    (u_long)vmcs12_read_field(c, VMCS_IDT_VECTORING_INFO),
	    (u_long)vmcs12_read_field(c, VMCS_IDT_VECTORING_ERROR),
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_INTR_INFO),
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_INTR_ERRCODE),
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_INSTRUCTION_LENGTH),
	    (u_long)vmcs12_read_field(c, VMCS_ENTRY_CTLS),
	    (u_long)vmcs12_read_field(c, VMCS_EXIT_CTLS));
	/*
	 * Modo a 64 bit dal controllo d'ingresso "IA-32e mode guest", non da
	 * GUEST_IA32_EFER: Hyper-V non usa LOAD_EFER ne' SAVE_EFER per i suoi
	 * guest e quel campo resta un valore mai caricato (0x801 nel panic
	 * LAPIC del 05/11, con l'L2 a 64 bit): la vecchia guardia saltava
	 * proprio il confronto delle tabelle che serviva.
	 */
	if ((vmcs12_proc2(c) & PROCBASED2_ENABLE_EPT) == 0 ||
	    (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_GUEST_LMA) == 0 ||
	    (vmcs12_read_field(c, VMCS_GUEST_CR4) & CR4_LA57) != 0)
		return;
	pag = vmx_vept_diag_walk(vcpu, eptp12, cr3, cr2, "cr2");
	if ((rip & ~(uint64_t)PAGE_MASK) != (cr2 & ~(uint64_t)PAGE_MASK))
		pag = vmx_vept_diag_walk(vcpu, eptp12, cr3, rip, "rip");
	/* parere Opus 009 §1: ultimo INVEPT di questo vCPU e fotografia */
	printf("nested_diag_pfinj #%d   ultimo INVEPT dell'L1 su vcpu%d: #%lu, "
	    "%lu us fa (radici conservate=%d svuotate=%d)\n", printed,
	    vcpu->vcpuid, (u_long)vcpu->nested->diag_invept_seq,
	    vcpu->nested->diag_invept_tsc == 0 ? 0UL :
	    (u_long)((rdtsc() - vcpu->nested->diag_invept_tsc) * 1000000 /
	    tsc_freq), vcpu->nested->diag_invept_kept,
	    vcpu->nested->diag_invept_wiped);
	if (pag != 0)
		vmx_vept_diag_keepstate(vcpu, eptp12, pag);
}

static void
nested_diag_pf_walk(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vm_guest_paging pg;
	uint64_t gla = n->diag_pf_qual, tgpa, l1, pte, exp, sh, swgpa = 0, *p;
	void *ck;
	int lvl, fault = 0, err, count;
	static int count_fbsd, count_altri;

	/*
	 * Sotto Hyper-V anche la partizione radice (Windows) e' un L2, con
	 * codice del kernel paginabile: i suoi #PF di fetch supervisore sono
	 * legittimi. Si stampano fino a 32 eventi nel kernel FreeBSD (da
	 * KERNBASE 0xffffffff80000000) e al piu' 4 degli altri; i contatori
	 * contano tutto.
	 */
	if (n->diag_pf_rip >= 0xffffffff80000000ULL) {
		if (count_fbsd >= 32)
			return;
		count = ++count_fbsd;
	} else {
		if (count_altri >= 4)
			return;
		count = 1000 + ++count_altri;
	}
	pg.cr3 = n->diag_pf_cr3;
	pg.cpl = (n->diag_pf_ss_ar >> 5) & 3;
	pg.cpu_mode = (n->diag_pf_efer & EFER_LMA) ? CPU_MODE_64BIT :
	    CPU_MODE_PROTECTED;
	pg.paging_mode = (n->diag_pf_cr4 & CR4_LA57) ? PAGING_MODE_64_LA57 :
	    PAGING_MODE_64;
	err = vm_gla2gpa_nofault(vcpu->vcpu, &pg, gla, VM_PROT_EXECUTE, &swgpa,
	    &fault);
	printf("nested_diag_pf #%d vcpu%d rip=%#lx cr2=%#lx ec=%#x idtv=%#x "
	    "cpl=%d cr0=%#lx cr3=%#lx cr4=%#lx efer=%#lx | vista L1: gpa=%#lx "
	    "err=%d fault=%d\n", count, vcpu->vcpuid, (u_long)n->diag_pf_rip,
	    (u_long)gla, n->diag_pf_ec, n->diag_pf_idtv, pg.cpl,
	    (u_long)n->diag_pf_cr0, (u_long)n->diag_pf_cr3,
	    (u_long)n->diag_pf_cr4, (u_long)n->diag_pf_efer, (u_long)swgpa, err,
	    fault);
	if ((n->diag_pf_efer & EFER_LMA) == 0 || (n->diag_pf_cr4 & CR4_LA57))
		return;
	tgpa = n->diag_pf_cr3 & 0x000ffffffffff000ULL;
	for (lvl = 3; lvl >= 0; lvl--) {
		if (vmx_vept_l1gpa(vcpu, tgpa, VM_PROT_READ, &l1) != 0) {
			printf("nested_diag_pf   L%d tabella l2gpa=%#lx: l'EPT12 "
			    "non la mappa\n", lvl + 1, (u_long)tgpa);
			return;
		}
		p = vm_gpa_hold(vcpu->vcpu, l1 & ~(uint64_t)PAGE_MASK,
		    PAGE_SIZE, VM_PROT_READ, &ck);
		if (p == NULL) {
			printf("nested_diag_pf   L%d tabella l1gpa=%#lx non RAM\n",
			    lvl + 1, (u_long)l1);
			return;
		}
		exp = DMAP_TO_PHYS((vm_offset_t)p);
		pte = p[(gla >> (12 + 9 * lvl)) & 0x1ff];
		vm_gpa_release(ck);
		sh = vmx_vept_shadow_entry(vcpu, tgpa);
		printf("nested_diag_pf   L%d tabella l2gpa=%#lx l1gpa=%#lx host "
		    "atteso=%#lx shadow=%#lx%s pte=%#lx P=%d U=%d NX=%d\n",
		    lvl + 1, (u_long)tgpa, (u_long)l1, (u_long)exp, (u_long)sh,
		    (sh != 0 && (sh & 0x000ffffffffff000ULL) != exp) ?
		    " <-- DIVERSO" : "", (u_long)pte, (int)(pte & 1),
		    (int)((pte >> 2) & 1), (int)(pte >> 63));
		if ((pte & 1) == 0 || (lvl > 0 && (pte & 0x80) != 0))
			return;
		tgpa = pte & 0x000ffffffffff000ULL;
	}
}

static int
nested_ept_slow(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	struct vmcs12_cache *c;
	uint64_t l1gpa = 0, perm = 0;
	int r;

	r = vmx_vept_fault(vcpu, n->ept_gpa, n->ept_qual, &l1gpa, &perm);
	if (r == VEPT_OK) {
		atomic_add_long(&nested_ept02_faults_l0, 1);
		return (0);
	}
	if (r == VEPT_MMIO && (n->ept_qual & 0x3) != 0 &&
	    (n->ept_qual & 0x180) == 0x180) {
		/* lettura/scrittura dati da un indirizzo lineare (come
		 * ept_emulation_fault per l'L1) */
		vmexit->u.inst_emul = n->ept_emul.u.inst_emul;
		vmexit->u.inst_emul.gpa = l1gpa;
		vmexit->exitcode = VM_EXITCODE_INST_EMUL;
		vmexit->inst_length = 0;
		atomic_add_long(&nested_ept_mmio_emulated, 1);
		return (0);
	}
	if (r == VEPT_MMIO) {
		/*
		 * #135 Fase C. EPT12 CONCEDE (vmx_vept_fault ha gia' confrontato l'accesso coi permessi) ma l'L1-GPA non
		 * ha backing in L0 e l'accesso non e' un dato emulabile (walk delle tabelle, bit 8 = 0; fetch; nessun
		 * GLA). Prima ricadeva nella riflessione qui sotto: reason 48 INVENTATA, con la qualifica riscritta dai
		 * permessi RWX (sessione HM del 30/10, qual 0x6b9). Ora: nessuna riflessione, latch fatale del vCPU,
		 * contatore proprio (RFL torna a contare solo le violation vere). E' un fail-stop, non il supporto delle
		 * tabelle di L2 su MMIO. Nessun VMCS e' caricato qui (si esce prima del VMPTRLD sotto); l'exitcode non
		 * puo' restare VM_EXITCODE_NESTED con un errore (KASSERT in vm_run).
		 */
		atomic_add_long(&nested_vept_mmio_unemulable, 1);
		SDT_PROBE5(vmm, vmx, nested, veptunemul, vcpu->vcpuid, n->ept_gpa,
		    n->ept_qual, l1gpa, vmexit->rip);
		vmexit->exitcode = VM_EXITCODE_BOGUS;
		vmexit->inst_length = 0;
		return (vm_fatal_latch(vcpu->vcpu, EFAULT, VM_FATAL_NESTED_VEPT,
		    vmexit->rip, n->ept_gpa, 0, NULL, 0, VM_FATAL_V_GPA));
	}
	atomic_add_long(r == VEPT_MISCONF ? &nested_ept12_misconf_reflected :
	    &nested_ept12_viol_reflected, 1);
	if ((c = nested_current_cache(n)) != NULL)
		SDT_PROBE6(vmm, vmx, nested, veptrefl, vcpu->vcpuid,
		    vmcs12_read_field(c, VMCS_EPTP), n->ept_gpa, n->ept_qual, r,
		    vmcs12_read_field(c, VMCS_HOST_RIP));
	if (__predict_false(vmx_nested_probe == 9))
		nested_probe_walk(vcpu, r, l1gpa, perm);
	VMPTRLD(vcpu->vmcs);			/* il VMCS02 */
	/*
	 * Parere di Astra 010 §4: E0, lo stato dell'L2 all'uscita MMIO sul LAPIC,
	 * PRIMA della riflessione (dopo, GUEST_RIP del VMCS02 e' gia' quello
	 * dell'L1). Solo per una scrittura sulla pagina del LAPIC e con l'RIP
	 * dell'L2 nella pagina sorvegliata.
	 */
	if (__predict_false(nested_diag_pfrec != 0) && (n->ept_qual & 0x2) != 0 &&
	    (n->ept_gpa & ~0xfffUL) == 0xfee00000UL)
		nested_pfrec_cap_e0(vcpu);
	vmexit->u.vmx.exit_reason = (r == VEPT_MISCONF) ?
	    EXIT_REASON_EPT_MISCONFIG : EXIT_REASON_EPT_FAULT;
	n->slow_reflect = true;
	nested_reflect_to_l1(vcpu, vmexit);
	n->slow_reflect = false;
	/* E1: lo stesso stato ora nel VMCS12, piu' il walk del codice; arma */
	if (__predict_false(nested_diag_pfrec != 0) && n->pfrec_building)
		nested_pfrec_cap_e1(vcpu);
	c = nested_current_cache(n);
	if (c != NULL)
		vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
		    (r == VEPT_MISCONF) ? 0 :
		    ((n->ept_qual & ~0x38ULL) | ((perm & 0x7) << 3)));
	VMCLEAR(vcpu->vmcs01);			/* niente VMCS attivo nello slow path */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP, vmexit->rip);
	return (0);
}

/*
 * Slow path del nested (op vmmops_nested_exit): dispatch sull'istruzione VMX
 * che ha causato l'uscita, col vCPU FROZEN. VMLAUNCH/VMRESUME (T2.4),
 * VMREAD/VMWRITE (T1.8) e VMCALL non sono ancora qui: per ora #UD.
 */
/*
 * #162 R8: in VMX non-root un'istruzione VMX dell'L1 esce verso L0 PRIMA dei
 * controlli che l'SDM fa dopo la VM exit: "ELSIF in VMX non-root operation
 * THEN VM exit; ELSIF CPL > 0 THEN #GP(0)". Prima solo VMXON li rifaceva: a
 * CPL 3 l'L1 poteva eseguire VMPTRLD, VMWRITE, VMLAUNCH... (KVM:
 * nested_vmx_check_permission). Qui, prima di shvmcs_pull, dell'operando e del
 * VMCS12: "non in VMX operation" -> #UD, poi CPL > 0 -> #GP(0); niente VMfail,
 * RIP fermo (l'iniezione fa ripartire l'istruzione). Le uscite di L2 riflesse
 * all'L1 sono gia' tornate (restart_only). VMXON ha regole sue (#UD per
 * CR4.VMXE, #GP a CPL > 0 anche fuori da VMX, poi VMfail in VMX root) e resta
 * nel suo gestore; VMCALL non e' un'istruzione di gestione VMX.
 *
 * La CPL letta qui e' quella di QUESTA uscita (V4) perche' valgono due
 * condizioni, da conservare in ogni modifica futura:
 *  1. vmx.c cattura exit_paging (vmx_paging_info) a OGNI uscita con una delle
 *     ragioni sotto, e quell'uscita lascia vmx_run come VM_EXITCODE_NESTED,
 *     non gestita: nessun'altra uscita puo' sovrascrivere la cattura prima
 *     di arrivare qui;
 *  2. le uscite di L2 sono gia' deviate verso l'L1 (o restart_only) prima del
 *     guard: quando gira L2 la cattura descrive L2, e non arriva qui.
 *
 * Stadio 10, K6 (come KVM handle_invept/handle_invvpid): INVEPT e INVVPID non
 * esposte all'L1 (controllo secondario "enable EPT"/"enable VPID" non
 * consentito, o bit di capacita' INVEPT 20 / INVVPID 32 spento nelle MSR VMX
 * virtuali) danno #UD PRIMA del controllo della CPL. Oggi L0 le espone
 * entrambe (vmx_nested_init_msrs): difesa per configurazioni future.
 */
static bool
nested_inv_esposta(struct vmx_nested *n, uint32_t reason)
{
	uint64_t ctl2 = n->vmx_msr[0x48b - 0x480] >> 32, cap = n->vmx_msr[0x48c - 0x480];

	if (reason == EXIT_REASON_INVEPT)
		return ((ctl2 & PROCBASED2_ENABLE_EPT) != 0 && (cap & (1ULL << 20)) != 0);
	return ((ctl2 & PROCBASED2_ENABLE_VPID) != 0 && (cap & (1ULL << 32)) != 0);
}

static bool
nested_insn_guard(struct vmx_vcpu *vcpu, uint32_t reason)
{
	switch (reason) {
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
		break;
	default:
		return (false);
	}
	if ((reason == EXIT_REASON_INVEPT || reason == EXIT_REASON_INVVPID) &&
	    !nested_inv_esposta(vcpu->nested, reason)) {
		vm_inject_ud(vcpu->vcpu);		/* K6: prima della CPL */
		return (true);
	}
	if (!vcpu->nested->vmxon) {
		vm_inject_ud(vcpu->vcpu);
		return (true);
	}
	if (vcpu->nested->exit_paging.cpl != 0) {	/* CPL dell'L1, catturato all'uscita (vmx_cpl) */
		vm_inject_gp(vcpu->vcpu);
		return (true);
	}
	return (false);
}

int
vmx_nested_exit(void *vcpui)
{
	struct vmx_vcpu *vcpu = vcpui;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	uint32_t reason = vmexit->u.vmx.exit_reason & 0xffff;

	SDT_PROBE1(vmm, vmx, nested, slowpath, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_SLOWPATH, 1);
	if (vcpu->nested != NULL)
		nested_stats_flush(vcpu);

	/*
	 * B1: generazione dei mapping di L0 cambiata -> tutte le radici shadow
	 * si svuotano qui, dove si puo' dormire, prima di qualunque altra cosa.
	 * vmx_run esce apposta (vept_memgen_pending) se se ne accorge prima di
	 * un ingresso in L2: allora non c'e' altro da fare, si riparte.
	 */
	if (vcpu->nested != NULL && vcpu->nested->vept_keep) {
		vmx_vept_memgen_sync(vcpu);
		if (vcpu->nested->vept_memgen_pending) {
			vcpu->nested->vept_memgen_pending = false;
			return (0);
		}
	}

	/* Sessione 1d: violazione EPT12 trovata dall'emulatore, consegnata da
	 * vmx_run prima di rientrare in L2. Fuori da L2 (invariante violato:
	 * emu_viol nasce solo in L2 e decade con l'uscita verso l'L1) la si
	 * scarta e si prosegue con gli altri pending, senza ritornare: un
	 * return qui salterebbe restart_only ed ept_pending (parere #109 §2.B) */
	if (vcpu->nested != NULL && vcpu->nested->emu_viol) {
		if (vcpu->nested->in_l2)
			return (nested_ept_emul_reflect(vcpu));
		vcpu->nested->emu_viol = false;
		atomic_add_long(&nested_ept12_viol_emul_stale, 1);
	}

	/* WSL2-FreeBSD 003: walk diagnostico di un #PF intercettato, poi si
	 * rientra in L2 (l'intercetto e' gia' tolto per UN ingresso) */
	if (vcpu->nested != NULL && vcpu->nested->diag_pf_pending) {
		vcpu->nested->diag_pf_pending = false;
		if (vcpu->nested->in_l2)
			nested_diag_pf_walk(vcpu);
		return (0);
	}

	/* Uscita di L2 gia' riflessa all'L1 in vmx_exit_process: qui va solo
	 * fatto ripartire vmx_run. Il motivo d'uscita e' di L2 (es. VMCALL):
	 * passarlo allo switch sotto inietterebbe un #UD nell'L1. */
	if (vcpu->nested != NULL && vcpu->nested->restart_only) {
		vcpu->nested->restart_only = false;
		return (0);
	}
	/* EPT violation di L2 con shadow EPT, rimandata qui dal percorso veloce */
	if (vcpu->nested != NULL && vcpu->nested->ept_pending) {
		vcpu->nested->ept_pending = false;
		return (nested_ept_slow(vcpu));
	}

	/* #162 R8: VMX non attiva e CPL > 0, prima di qualunque effetto */
	if (vcpu->nested != NULL && nested_insn_guard(vcpu, reason))
		return (0);

	/*
	 * Shadow VMCS (parere #44 §3-4): i gestori che consumano il VMCS12 ne
	 * riprendono prima i campi RW che l'L1 puo' aver scritto in hardware.
	 * VMREAD/VMWRITE emulate toccano solo campi non RW (i RW non escono).
	 */
	switch (reason) {
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMRESUME:
		/* errore: niente gestore, la VM e' gia' sospesa; il prossimo
		 * vmx_run non entra (vmx_shvmcs_enter) */
		if (vcpu->nested != NULL && shvmcs_pull(vcpu) != 0)
			return (0);
		break;
	default:
		break;
	}
	switch (reason) {
	case EXIT_REASON_VMXON:		return (nested_vmxon(vcpu));
	case EXIT_REASON_VMXOFF:	return (nested_vmxoff(vcpu));
	case EXIT_REASON_VMCLEAR:	return (nested_vmclear(vcpu));
	case EXIT_REASON_VMPTRLD:	return (nested_vmptrld(vcpu));
	case EXIT_REASON_VMPTRST:	return (nested_vmptrst(vcpu));
	case EXIT_REASON_VMREAD:	return (nested_vmread(vcpu));
	case EXIT_REASON_VMWRITE:	return (nested_vmwrite(vcpu));
	case EXIT_REASON_VMLAUNCH:	return (nested_vmlaunch(vcpu, false));
	case EXIT_REASON_VMRESUME:	return (nested_vmlaunch(vcpu, true));
	case EXIT_REASON_INVVPID:	return (nested_invvpid(vcpu));
	case EXIT_REASON_INVEPT:	return (nested_invept(vcpu));
	default:
		vm_inject_ud(vcpu->vcpu);
		return (0);
	}
}

/*
 * Prepara la pagina VMCS02 di una voce di cache (T2.2): alloca se serve,
 * scrive la revision ID, VMCLEAR, poi l'host-state FISSO via vmcs_init_host()
 * sulla pagina resa corrente. I campi host PER-CPU (TR/GDTR/GS base) e
 * HOST_CR3 li scrive il chiamante all'ingresso in L2 (T2.4). Al ritorno non
 * resta nessun VMCS corrente: il chiamante ricarica cio' che gli serve.
 */
int
vmx_nested_vmcs02_setup(struct vmcs12_cache *c)
{
	struct vmcs *v;
	int error;

	if (c->vmcs02 == NULL)
		c->vmcs02 = malloc_aligned(sizeof(struct vmcs), PAGE_SIZE,
		    M_VMX_NESTED, M_WAITOK | M_ZERO);
	v = (struct vmcs *)c->vmcs02;
	v->identifier = vmx_revision();
	if ((error = vmclear(v)) != 0)
		return (error);
	VMPTRLD(v);
	error = vmcs_init_host();
	VMCLEAR(v);
	return (error);
}

/* adjust_ctl: rende un controllo valido sull'hardware (must-be-1 nel dword
 * basso, allowed-1 nell'alto della MSR di capability). Come KVM/ACRN. */
static uint32_t
nested_adjust_ctl(uint32_t desired, u_int msr)
{
	uint64_t cap = rdmsr(msr);
	return ((desired | (uint32_t)cap) & (uint32_t)(cap >> 32));
}

/*
 * Compone VMCS02 da VMCS12 (§6.3). Il VMCS02 deve essere GIA' corrente
 * (VMPTRLD dal chiamante, T2.4). Legge VMCS12 dallo store software; scrive
 * VMCS02 con vmwrite. La corrispondenza riga-per-riga con §6.3 e' in
 * docs/nested/T2.3.md (da rivedere).
 */
int
nested_compose_vmcs02(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmx_vcpu *x = vcpu;
	struct vmcs12_cache *c;
	uint32_t pin, proc, proc2, exitc, entryc, excbmp;
	uint64_t g_cr0, g_cr4, m12cr0, m12cr4;
	int i;
	/* guest-state copiato esplicitamente (niente shadowing hw: §6.2 -> T2) */
	static const uint32_t gstate[] = {
		VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_CS_SELECTOR,
		VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_DS_SELECTOR,
		VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_GS_SELECTOR,
		VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_TR_SELECTOR,
		VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_SS_LIMIT,
		VMCS_GUEST_DS_LIMIT, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT,
		VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_TR_LIMIT,
		VMCS_GUEST_GDTR_LIMIT, VMCS_GUEST_IDTR_LIMIT,
		VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_GUEST_CS_ACCESS_RIGHTS,
		VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_GUEST_DS_ACCESS_RIGHTS,
		VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_GUEST_GS_ACCESS_RIGHTS,
		VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_GUEST_TR_ACCESS_RIGHTS,
		VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE, VMCS_GUEST_SS_BASE,
		VMCS_GUEST_DS_BASE, VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE,
		VMCS_GUEST_LDTR_BASE, VMCS_GUEST_TR_BASE,
		VMCS_GUEST_GDTR_BASE, VMCS_GUEST_IDTR_BASE,
		VMCS_GUEST_CR3, VMCS_GUEST_DR7, VMCS_GUEST_RSP, VMCS_GUEST_RIP,
		VMCS_GUEST_RFLAGS, VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
		VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_ESP,
		VMCS_GUEST_IA32_SYSENTER_EIP, VMCS_GUEST_IA32_DEBUGCTL,
		VMCS_GUEST_IA32_PAT, VMCS_GUEST_IA32_EFER,
		VMCS_GUEST_INTERRUPTIBILITY, VMCS_GUEST_ACTIVITY,
		/* con EPT e paging PAE la CPU prende i PDPTE da qui */
		VMCS_GUEST_PDPTE0, VMCS_GUEST_PDPTE1,
		VMCS_GUEST_PDPTE2, VMCS_GUEST_PDPTE3,
	};

	c = nested_current_cache(n);
	if (c == NULL)
		return (EINVAL);

	/* --- Pin-based: VMCS12 U {ext-int, NMI exiting}; posted = 0;
	 *     preemption timer SOLO se l'L1 lo chiede --- */
	pin = (uint32_t)vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
	pin |= PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING;
	pin = nested_adjust_ctl(pin, MSR_VMX_TRUE_PINBASED_CTLS);
	pin &= ~PINBASED_POSTED_INTERRUPT;
	/*
	 * Timer di preemption dell'L1 (prima spento sempre: kvm-unit-tests
	 * 'preemption timer' girava all'infinito aspettando l'uscita 52). Conta
	 * alla frequenza vera: all'L1 esponiamo il rate di IA32_VMX_MISC
	 * dell'host. Il valore iniziale e' quello del VMCS12.
	 */
	if ((vmcs12_read_field(c, VMCS_PIN_BASED_CTLS) &
	    PINBASED_PREMPTION_TIMER) == 0) {
		pin &= ~PINBASED_PREMPTION_TIMER;
		n->preempt_on = false;
	} else
	{
		/*
		 * Scadenza ASSOLUTA (TSC dell'host), come KVM: il timer
		 * hardware si ferma mentre L0 gestisce un'uscita dell'L2, ma il
		 * TSC dell'L2 avanza; senza correzione il timer scadeva in
		 * ritardo di tutto il tempo passato in L0 (kvm-unit-tests
		 * vmx_preemption_timer_expiry_test, 'Last stored guest TSC <
		 * TSC deadline', intermittente). vmx_run riscrive il residuo a
		 * ogni rientro (nested_preempt_refresh).
		 */
		uint64_t val = vmcs12_read_field(c, VMCS_PREEMPTION_TIMER_VALUE);

		n->preempt_rate = (int)(n->vmx_msr[0x485 - 0x480] & 0x1f);
		n->preempt_deadline = rdtsc() + (val << n->preempt_rate);
		n->preempt_on = true;
		vmwrite(VMCS_PREEMPTION_TIMER_VALUE, val);
	}
	vmwrite(VMCS_PIN_BASED_CTLS, pin);
	n->imm_armed = false;		/* pin appena riscritto dal VMCS12 */

	/* --- Primary proc: VMCS12 U requisiti L0; I/O bitmaps=0, TPR shadow=0;
	 *     HLT = SOLO VMCS12 (non si eredita da VMCS01) --- */
	proc = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	proc |= PROCBASED_IO_EXITING | PROCBASED_MSR_BITMAPS |
	    PROCBASED_MWAIT_EXITING | PROCBASED_MONITOR_EXITING |
	    PROCBASED_SECONDARY_CONTROLS | PROCBASED_CR8_LOAD_EXITING |
	    PROCBASED_CR8_STORE_EXITING;
	proc = nested_adjust_ctl(proc, MSR_VMX_TRUE_PROCBASED_CTLS);
	proc &= ~(PROCBASED_IO_BITMAPS | PROCBASED_USE_TPR_SHADOW);
	/*
	 * TPR shadow dell'L1 (come KVM): il VMCS02 usa la STESSA pagina
	 * virtual-APIC dell'L1 (sua pagina host: la memoria del guest e'
	 * wired) e la sua soglia; l'hardware virtualizza CR8 dell'L2 sul VTPR
	 * e le uscite "TPR below threshold" (43) vanno all'L1. Le uscite su CR8
	 * restano solo se l'L1 le chiede. Prima il TPR shadow si toglieva
	 * sempre e CR8 dell'L2 si emulava sul TPR VERO dell'L1: Windows 11 +
	 * Hyper-V, la partizione root alzava l'IRQL a 15 (mov cr8, rdx=0xf) e
	 * il vlapic di Hyper-V restava a TPR 0xf0, sordo a ogni interrupt
	 * (DTrace: zero vlapic_set_intr_ready; CPU 1 mai avviata).
	 * Senza TPR shadow nel VMCS12 resta l'emulazione sul TPR dell'L1:
	 * e' la semantica giusta (l'L2 tocca il TPR "fisico" dell'L1).
	 */
	{
		uint32_t p12 = (uint32_t)vmcs12_read_field(c,
		    VMCS_PRI_PROC_BASED_CTLS);
		/* pagina host calcolata da nested_vmlaunch PRIMA del VMPTRLD:
		 * qui si e' in sezione critica, niente vm_gpa_hold */
		uint64_t hpa = (p12 & PROCBASED_USE_TPR_SHADOW) ?
		    n->vapic_hpa : 0;

		if (hpa != 0) {
			proc |= PROCBASED_USE_TPR_SHADOW;
			proc &= ~(PROCBASED_CR8_LOAD_EXITING |
			    PROCBASED_CR8_STORE_EXITING);
			proc |= p12 & (PROCBASED_CR8_LOAD_EXITING |
			    PROCBASED_CR8_STORE_EXITING);
			vmwrite(VMCS_VIRTUAL_APIC, hpa);
			vmwrite(VMCS_TPR_THRESHOLD,
			    vmcs12_read_field(c, VMCS_TPR_THRESHOLD) & 0xf);
		}
	}
	/* T2.6: se l'L1 ha un evento pendente per se', accendi il window-exiting
	 * cosi' l'L2 esce presto e la finestra viene riflessa all'L1 (§6.5). */
	{
		int vec;
		struct vlapic *vl = vm_lapic(x->vcpu);
		if (vlapic_pending_intr(vl, &vec))
			proc |= PROCBASED_INT_WINDOW_EXITING;
		if (vm_nmi_pending(x->vcpu))
			proc |= PROCBASED_NMI_WINDOW_EXITING;
	}
	vmwrite(VMCS_PRI_PROC_BASED_CTLS, proc);

	/* --- Secondary proc: EPT=1, VPID=1, shadowing=0, APIC-virt=0 --- */
	/*
	 * Secondari dell'L1 solo se li ha attivati (bit 31 dei primari) e solo
	 * quelli che gli esponiamo: altrimenti il campo del VMCS12 va ignorato
	 * (SDM) e puo' contenere residui. Prima lo si copiava sempre nel VMCS02
	 * (dove i secondari sono sempre attivi per l'EPT di L0): con residui
	 * come il mode-based execute control l'L2 prendeva EPT violation di
	 * esecuzione a ciclo continuo, 264.000/s (vmx_guest_state_area_test,
	 * DTrace: vm_fault a 0x40a000 tipo 4, nessuna riflessione).
	 */
	proc2 = 0;
	if (vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_SECONDARY_CONTROLS)
		proc2 = (uint32_t)vmcs12_proc2(c) &
		    (uint32_t)(n->vmx_msr[0x48b - 0x480] >> 32);
	proc2 |= PROCBASED2_ENABLE_EPT | PROCBASED2_ENABLE_VPID;
	proc2 = nested_adjust_ctl(proc2, MSR_VMX_PROCBASED_CTLS2);
	if (n->vpid02_off)		/* ripiego sicuro (parere #49 §5) */
		proc2 &= ~PROCBASED2_ENABLE_VPID;
	proc2 &= ~(PROCBASED2_VMCS_SHADOWING |
	    PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
	    PROCBASED2_VIRTUALIZE_X2APIC_MODE |
	    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);
	vmwrite(VMCS_SEC_PROC_BASED_CTLS, proc2);

	/* --- Exit controls: quelli dell'L0 --- */
	/*
	 * PAT. bhyve non tocca mai il PAT reale (l'L1 gira col PAT dell'host),
	 * quindi exit_ctls non ha LOAD_PAT. Ma qui l'ingresso in L2 lo caricava
	 * SEMPRE dal VMCS12: senza LOAD_PAT all'uscita l'host restava col PAT
	 * dell'L2 (kvm-unit-tests 'null': GUEST_PAT mai scritto = 0 = tutto
	 * UC) -> host lentissimo, "congelato", USB giu'. Ora:
	 *  - all'uscita il PAT dell'host si RICARICA sempre (HOST_IA32_PAT e'
	 *    quello giusto, vmcs_init_host);
	 *  - all'ingresso si carica il PAT dell'L2 solo se l'L1 lo chiede;
	 *  - si salva il PAT dell'L2 all'uscita solo se l'L1 lo chiede.
	 */
	exitc = exit_ctls | VM_EXIT_LOAD_PAT;
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PAT)
		exitc |= VM_EXIT_SAVE_PAT;
	/*
	 * Col timer di preemption attivo il valore residuo si salva SEMPRE: per
	 * l'L1 le uscite gestite da L0 non esistono, quindi al rientro in L2 il
	 * conto alla rovescia deve riprendere da dove era. All'L1 lo si passa
	 * solo se lo chiede (riflessione).
	 */
	exitc &= ~VM_EXIT_SAVE_PREEMPTION_TIMER;
	if (pin & PINBASED_PREMPTION_TIMER)
		exitc |= VM_EXIT_SAVE_PREEMPTION_TIMER;
	exitc = nested_adjust_ctl(exitc, MSR_VMX_TRUE_EXIT_CTLS);
	vmwrite(VMCS_EXIT_CTLS, exitc);

	/* --- Entry controls: IA-32e mode guest = VMCS12; load EFER/dbg=1.
	 *     Mai load PAT: il PAT dell'L2 e' virtuale come quello dell'L1
	 *     (guest_msrs[IDX_MSR_PAT], impostato in nested_vmlaunch) --- */
	entryc = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_CTLS) &
	    VM_ENTRY_GUEST_LMA;
	entryc |= VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_LOAD_EFER;
	entryc = nested_adjust_ctl(entryc, MSR_VMX_TRUE_ENTRY_CTLS);
	entryc &= ~(VM_ENTRY_INTO_SMM | VM_ENTRY_DEACTIVATE_DUAL_MONITOR);
	vmwrite(VMCS_ENTRY_CTLS, entryc);

	/* --- Exception bitmap: VMCS12 U bitmap dell'L0 (#MC, vec30, #DB) --- */
	excbmp = (uint32_t)vmcs12_read_field(c, VMCS_EXCEPTION_BITMAP) |
	    x->cap.exc_bitmap;
	vmwrite(VMCS_EXCEPTION_BITMAP, excbmp);
	vmwrite(VMCS_PF_ERROR_MASK, vmcs12_read_field(c, VMCS_PF_ERROR_MASK));
	vmwrite(VMCS_PF_ERROR_MATCH, vmcs12_read_field(c, VMCS_PF_ERROR_MATCH));
	/* WSL2-FreeBSD 003: intercetto diagnostico (spento di default) */
	vcpu->nested->diag_pf_rearm = false;
	nested_diag_pf_arm(vcpu);

	/* --- CR0/CR4: maschere (mask12), read-shadow (VMCS12), guest con i bit
	 *     fixed dell'host applicati --- */
	m12cr0 = vmcs12_read_field(c, VMCS_CR0_MASK);
	m12cr4 = vmcs12_read_field(c, VMCS_CR4_MASK);
	vmwrite(VMCS_CR0_MASK, m12cr0);
	vmwrite(VMCS_CR4_MASK, m12cr4);
	vmwrite(VMCS_CR0_SHADOW, vmcs12_read_field(c, VMCS_CR0_SHADOW));
	vmwrite(VMCS_CR4_SHADOW, vmcs12_read_field(c, VMCS_CR4_SHADOW));
	g_cr0 = (vmcs12_read_field(c, VMCS_GUEST_CR0) | cr0_ones_mask) &
	    ~cr0_zeros_mask;
	g_cr4 = (vmcs12_read_field(c, VMCS_GUEST_CR4) | cr4_ones_mask) &
	    ~cr4_zeros_mask;
	vmwrite(VMCS_GUEST_CR0, g_cr0);
	vmwrite(VMCS_GUEST_CR4, g_cr4);

	/* --- resto del guest-state copiato esplicitamente --- */
	for (i = 0; i < (int)nitems(gstate); i++)
		vmwrite(gstate[i], vmcs12_read_field(c, gstate[i]));
	/*
	 * Senza "load IA32_EFER" nel VMCS12 l'EFER dell'L2 NON viene dal
	 * VMCS12 (SDM 26.3.2.1): resta quello dell'L1, con LMA = IA-32e mode
	 * guest e, se CR0.PG, anche LME. Il VMCS02 carica EFER comunque: prima
	 * vi finiva GUEST_EFER del VMCS12 e l'hardware rifiutava l'ingresso
	 * (vmx_guest_state_area_test, 'VM-Exit failure on vmresume').
	 */
	if ((vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_LOAD_EFER) == 0) {
		uint64_t e = n->l1_efer & ~(EFER_LMA | EFER_LME);

		if (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_GUEST_LMA) {
			e |= EFER_LMA;
			if (vmcs12_read_field(c, VMCS_GUEST_CR0) & CR0_PG)
				e |= EFER_LME;
		}
		vmwrite(VMCS_GUEST_IA32_EFER, e);
	}
	if (n->pdpte_mem) {			/* PAE senza EPT12: dalla memoria */
		vmwrite(VMCS_GUEST_PDPTE0, n->pdpte[0]);
		vmwrite(VMCS_GUEST_PDPTE1, n->pdpte[1]);
		vmwrite(VMCS_GUEST_PDPTE2, n->pdpte[2]);
		vmwrite(VMCS_GUEST_PDPTE3, n->pdpte[3]);
	}
	/* Senza load debug controls nel VMCS12, DR7/DEBUGCTL dell'L2 sono quelli
	 * che l'L1 aveva (kvm-unit-tests 'debug controls'). */
	if ((vmcs12_read_field(c, VMCS_ENTRY_CTLS) &
	    VM_ENTRY_LOAD_DEBUG_CONTROLS) == 0) {
		vmwrite(VMCS_GUEST_DR7, n->l1_dr7);
		vmwrite(VMCS_GUEST_IA32_DEBUGCTL, n->l1_debugctl);
	}

	/* --- EPTP, VPID, MSR bitmap, TSC offset, liste MSR, link pointer --- */
	/* EPTP: shadow EPT se VMCS12 usa EPT (T2.7), altrimenti EPTP01. */
	if (vmcs12_proc2(c) &
	    PROCBASED2_ENABLE_EPT)
		vmwrite(VMCS_EPTP, vmx_vept_eptp(vcpu));
	else
		vmwrite(VMCS_EPTP, x->vmx->eptp);
	/* VPID02 distinto per l2 (T2.8), per non aliasare la TLB con l1 */
	vmwrite(VMCS_VPID, n->vpid02_off ? 0 : n->vpid2);
	/* HOST_RSP: nel VMCS01 lo scrive vmx_init UNA volta (&vcpu->ctx, lo
	 * stack su cui vmx_exit_guest salva i registri del guest);
	 * vmcs_init_host non lo tocca, quindi nel VMCS02 valeva 0 -> alla
	 * prima uscita da L2 l'host ripartiva con RSP=0 -> triple fault. */
	vmwrite(VMCS_HOST_RSP, (u_long)&x->ctx);
	/* MSR bitmap: fusione L0 | L1 (T6.3) */
	nested_compose_msr_bitmap(x, c);
	/*
	 * TSC offset = quello dell'L0 per l'L1 + quello dell'L1 per l'L2 (se
	 * l'L1 lo usa). Prima solo il secondo: l'L2 vedeva il TSC dell'host,
	 * non quello dell'L1 (kvm-unit-tests rdtsc_vmexit_diff_test). Il
	 * controllo TSC offsetting va acceso se l'offset non e' nullo.
	 */
	{
		uint64_t off = n->l1_tsc_offset;

		if (vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
		    PROCBASED_TSC_OFFSET)
			off += vmcs12_read_field(c, VMCS_TSC_OFFSET);
		vmwrite(VMCS_TSC_OFFSET, off);
		if (off != 0)
			vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    vmcs_read(VMCS_PRI_PROC_BASED_CTLS) |
			    PROCBASED_TSC_OFFSET);
	}
	/* liste MSR a 0 (applicate in software nello slow path, §6.3). */
	vmwrite(VMCS_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VMCS_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_LINK_POINTER, ~0UL);

	/* Evento da iniettare in L2 richiesto dall'L1 (VMCS12): info, codice
	 * d'errore e lunghezza istruzione (interrupt/eccezioni software). Il
	 * bit valid lo azzera la riflessione a ogni uscita, come l'hardware. */
	vmwrite(VMCS_ENTRY_INTR_INFO, vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO));
	vmwrite(VMCS_ENTRY_EXCEPTION_ERROR,
	    vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR));
	vmwrite(VMCS_ENTRY_INST_LENGTH,
	    vmcs12_read_field(c, VMCS_ENTRY_INST_LENGTH));

	c->control_dirty = false;
	SDT_PROBE5(vmm, vmx, nested, compose, vcpu,
	    vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO),
	    vmcs12_read_field(c, VMCS_PIN_BASED_CTLS),
	    vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS),
	    (vmcs12_read_field(c, VMCS_GUEST_RFLAGS) << 32) |
	    (vmcs12_read_field(c, VMCS_GUEST_INTERRUPTIBILITY) & 0xffffffff));
	SDT_PROBE1(vmm, vmx, nested, enter_l2, vcpu);
	return (0);
}

/*
 * Controllo di sicurezza OBBLIGATORIO prima di ogni VMLAUNCH/VMRESUME su
 * VMCS02 (§3). Unico chiamante: subito prima di vmx_enter_guest (T2.4). Il
 * VMCS02 deve essere corrente. Ritorna 0 se e' sicuro entrare.
 */
int
nested_vmcs02_check(struct vmx_vcpu *vcpu)
{
	uint32_t pin, proc, proc2;
	uint64_t link;

	pin   = (uint32_t)vmcs_read(VMCS_PIN_BASED_CTLS);
	proc  = (uint32_t)vmcs_read(VMCS_PRI_PROC_BASED_CTLS);
	proc2 = (uint32_t)vmcs_read(VMCS_SEC_PROC_BASED_CTLS);
	link  = vmcs_read(VMCS_LINK_POINTER);

	/* requisiti dell'L0 presenti */
	if ((pin & (PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING)) !=
	    (PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING))
		return (EINVAL);
	if ((proc & PROCBASED_SECONDARY_CONTROLS) == 0)
		return (EINVAL);
	/* I/O incondizionato e NIENTE I/O bitmaps */
	if ((proc & PROCBASED_IO_EXITING) == 0 ||
	    (proc & PROCBASED_IO_BITMAPS) != 0)
		return (EINVAL);
	/* HLT NON ereditato da VMCS01: non deve essere forzato dall'L0 qui.
	 * (Se c'e', deve venire da VMCS12; non lo possiamo distinguere a
	 * posteriori, quindi e' solo un promemoria per la review.) */
	/* shadowing spento, EPT acceso, link pointer ~0 */
	if ((proc2 & PROCBASED2_VMCS_SHADOWING) != 0)
		return (EINVAL);
	if ((proc2 & PROCBASED2_ENABLE_EPT) == 0)
		return (EINVAL);
	if (link != ~0UL)
		return (EINVAL);
	return (0);
}
