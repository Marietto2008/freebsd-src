#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=8m
/*
 * ptpad-fbt-ripfix-nested.d -- Claude 30/10/2026, parere #142 §4.1. ptpad-fbt.d INVARIATO (stesse sonde, stesse
 * righe, stesso protocollo dei marcatori) piu' il blocco RIPFIX-INIZIO/RIPFIX-FINE con le sonde SDT del latch.
 * test-ptpad.sh verifica che, tolto il blocco, il corpo coincida byte per byte con quello di ptpad-fbt.d.
 * Uso come ptpad-fbt.d: dtrace -s ptpad-fbt-ripfix-nested.d <pid del driver>; a freddo dtrace -e (compila SOLO
 * col modulo RIPFIX nested caricato).
 */
BEGIN { printf("== FBT PRONTA == driver=%d\n", $1); }

syscall::fstatat:entry
/ pid == $1 /
{
	self->p = copyinstr(arg1);
}

syscall::fstatat:return
/ self->p != NULL && strstr(self->p, "/nonexistent/ptpad-mark/") == self->p /
{
	printf("FBTEV t=%d pid=%d tid=%d k=mark m=%s\n", timestamp, pid, tid,
	    substr(self->p, strlen("/nonexistent/ptpad-mark/")));
}

syscall::fstatat:return
/ self->p != NULL /
{
	self->p = 0;
}

fbt:vmm-restore:vm_handle_inst_emul:entry
/ execname == "qemu-system-x86_64" /
{
	@mmio = count();
	printf("FBTEV t=%d pid=%d tid=%d k=mmio\n", timestamp, pid, tid);
}

fbt:vmm-restore:_vm_gla2gpa:entry
/ execname == "qemu-system-x86_64" /
{
	@walk = count();
	printf("FBTEV t=%d pid=%d tid=%d k=walk\n", timestamp, pid, tid);
}

/*
 * #133 §3: PROVENIENZA della qualifica. eptviol = EPT violation HARDWARE di L2 sull'EPT02, qualifica GREZZA
 * (vmx_nested.c, prima di ogni riscrittura); veptrefl = riflessione all'L1 decisa da nested_ept_slow, con la
 * qualifica grezza e r = esito di vmx_vept_fault (1 VIOL, 2 MISCONF, 3 MMIO). L'L1 riceve invece
 * (grezza & ~0x38) | (permessi EPT12 << 3): il confronto fra le due righe e la riga L1 e' l'evidenza.
 * Sonde SDT, sola lettura; il driver non le conta (k diverso da mmio/walk/mark).
 */
vmm:vmx:nested:eptviol
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=eptviol gpa=%x qual=%x\n", timestamp, pid, tid, arg3, arg4);
}

vmm:vmx:nested:veptrefl
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=veptrefl gpa=%x qual=%x r=%d\n", timestamp, pid, tid, arg2, arg3,
	    (int)arg4);
}

/*
 * #136 §6.1: ogni VM_RUN di QEMU (ingresso) e ogni VM_RUN restituito con errore. Prova che, con la porta di QEMU,
 * dopo il primo errore NON arriva nessun altro VM_RUN. Il driver le conta a parte (k diverso da mmio/walk/mark).
 */
fbt:vmm-restore:vm_run:entry
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=vmrun\n", timestamp, pid, tid);
}

fbt:vmm-restore:vm_run:return
/ execname == "qemu-system-x86_64" && arg1 != 0 /
{
	printf("FBTEV t=%d pid=%d tid=%d k=vmrun_err rc=%d\n", timestamp, pid, tid, (int)arg1);
}

/* RIPFIX-INIZIO -- #142 §4.1: sonde del latch fatale, presenti SOLO nel modulo RIPFIX con nesting. Su un modulo senza
 * queste sonde lo script NON compila (dtrace -e): e' anche una prova d'identita' del modulo caricato. La riga
 * "SONDE FATALI" dice all'analisi che le sonde erano ARMATE: senza, l'assenza di un latch non si dichiara.
 *   fatal-latch   (vmm.c, vm_fatal_latch): vcpu, errno ORIGINARIO, stadio (1 FETCH, 2 EMUL, 3 NESTED_VEPT),
 *                 rip, gpa (L2-GPA per NESTED_VEPT), gla. Scrittura unica: scatta una volta per vCPU.
 *   fatal-ritorno (vmm.c, fine di vm_run, solo sull'errore che ha APPENA chiuso il latch): vcpu, nextrip, rip
 *                 dell'uscita, inst_length, fatal.rip. Misura INDIPENDENTE del ripristino: nextrip == rip, len 0.
 *   veptunemul    (vmx_nested.c, Fase C): vcpu, L2-GPA, qualifica grezza, L1-GPA, rip.
 */
BEGIN { printf("== FBT SONDE FATALI ==\n"); }

vmm:::fatal-latch
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=fatal vcpu=%d errno=%d stadio=%d rip=%x gpa=%x gla=%x\n", timestamp, pid,
	    tid, (int)arg0, (int)arg1, (int)arg2, arg3, arg4, arg5);
}

vmm:::fatal-ritorno
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=fatalret vcpu=%d nextrip=%x rip=%x len=%d frip=%x\n", timestamp, pid,
	    tid, (int)arg0, arg1, arg2, (int)arg3, arg4);
}

vmm:vmx:nested:veptunemul
/ execname == "qemu-system-x86_64" /
{
	printf("FBTEV t=%d pid=%d tid=%d k=veptunemul vcpu=%d gpa=%x qual=%x l1gpa=%x rip=%x\n", timestamp, pid,
	    tid, (int)arg0, arg1, arg2, arg3, arg4);
}
/* RIPFIX-FINE */

END
{
	printa("FBT CONTA mmio=%@d\n", @mmio);
	printa("FBT CONTA walk=%@d\n", @walk);
	printf("== FBT CHIUSA ==\n");
}
