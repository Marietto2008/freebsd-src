#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=8m
/*
 * ptpad-fbt.d -- Claude 27/10/2026, pareri #103 §4 / #105 §3.2 / #106. Diagnostica di PERCORSO,
 * READ-ONLY, per le sessioni del test ptpad. Attesta che l'emulazione di un'istruzione di L2 ha
 * attraversato il ramo che aggiorna gli A/D delle PTE ordinarie di L2.
 *
 *   vm_handle_inst_emul  = ingresso nell'emulatore (il ramo VEPT_MMIO -> VM_EXITCODE_INST_EMUL):
 *                          prova di MMIO_PATH_COVERED insieme al contatore nested_ept_mmio_emulated.
 *   _vm_gla2gpa          = il walk software che CONTIENE ptp_hold e le cmpset di PG_A/PG_M.
 *                          ptp_hold NON ha sonda FBT propria (incorporato, verificato con
 *                          `dtrace -l`): etichetta PTP_WALK_PATH_CORRELATED, non prova diretta.
 *
 * Parere #106: la VM e' QEMU `-accel bhyve`, non bhyve. Le sonde scattano nel thread vCPU di
 * QEMU (ioctl VM_RUN) e il suo pid NON e' noto quando la traccia deve gia' essere pronta (il caso
 * B arriva in meno di un secondo dal lancio): si filtra per execname. Il runner garantisce che
 * nessun'altra VM sia viva. $1 = pid del DRIVER (ptpad-drive.py): i suoi fstatat su
 * "/nonexistent/ptpad-mark/<etichetta>" sono i CONFINI dei casi, nello STESSO stream e con lo
 * STESSO orologio (timestamp) delle sonde: la correlazione non confronta orologi diversi.
 *
 * NON e' l'oracolo: l'oracolo architetturale sta in L1 (la EPT violation vista o no).
 * Uso: dtrace -s ptpad-fbt.d <pid del driver>       (lo lancia ptpad-drive.py --fbt)
 * A freddo: dtrace -e -s ptpad-fbt.d 1              (compila e basta; NON abilita, NESSUNA VM)
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

END
{
	printa("FBT CONTA mmio=%@d\n", @mmio);
	printa("FBT CONTA walk=%@d\n", @walk);
	printf("== FBT CHIUSA ==\n");
}
