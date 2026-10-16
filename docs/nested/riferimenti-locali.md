# T0.1 — Rimappatura dei riferimenti del piano sul tree locale

Data: 2026-10-16 · Nessuna modifica al codice.

## HEAD locale

| Albero | HEAD locale | Base del piano | Delta |
|---|---|---|---|
| freebsd-src (ramo di lavoro clonato da `vmm-ottobre-correzioni`) | **e5264af4** | 9bded96 | 1 commit |
| qemu (clonato da `accel-vmm-freebsd-ottobre2026`) | **add5fe45** | 1edba34 | 1 commit |

I due commit in più rispetto alla base del piano sono le correzioni di review
del 16/10 (vedi `reference_review_rami_ottobre_tre_fix`). Entrambi erano
**già previsti dal piano** come osservazioni §11, e ora sono applicati.

## Commit locali oltre la base del piano

### freebsd `9bded96..e5264af4`

```
e5264af4  vmm: due correzioni emerse dalla review dei rami di ottobre
```

File toccati sui percorsi del piano:
- `sys/amd64/vmm/io/vlapic.c`
- `sys/amd64/vmm/vmm_dev_machdep.c`

### qemu `1edba34..add5fe45`

```
add5fe45  (amend di 1edba34) + target/arm/bhyve/ aggiunto al commit
```

Nessuna riga di codice cambiata rispetto a 1edba34: l'amend ha solo aggiunto
i 5 file `target/arm/bhyve/` che il commit referenziava ma non conteneva
(il problema di §0.3, risolto — vedi sotto T0.2).

## ⚠ DIVERGENZE da riportare (regola STOP del §3)

### 1. §11.1 — `VM_PPT_SBR_DEVICE`: GIA' RISOLTO

Il piano (§11.1) segnala il flag `0`. Sul HEAD locale è
`VMMDEV_IOCTL(VM_PPT_SBR_DEVICE, VMMDEV_IOCTL_PPT)`
(`vmm_dev_machdep.c:142`): il controllo di privilegio c'è, i lock no.
**L'osservazione §11.1 non si applica più.** Nessuna azione.

### 2. §0.2.6 / §6.5.5 / §11.2 — guardia INIT CAMBIATA (impatta il nested)

Il piano descrive la guardia come `if (!vlapic->ipi_exit)`
(plan @ `vlapic.c:1218-1229`). Sul HEAD locale è:

```c
if (!(vmflags & VM_OP_F_QEMU)) {   /* vlapic.c:1222 */
    ...vm_smp_rendezvous(..., vlapic_handle_init, ...);
}
```

Conseguenze per il piano:
- **§0.2.6 è obsoleto**: NON è più vero che «se `ipi_exit` è attivo il kernel
  non fa il rendezvous». Ora il rendezvous (quindi `vlapic_reset` del
  bersaglio) avviene per **bhyve nativo** (ipi_exit=1, qemu=0) e si salta
  **solo in modalità QEMU**. Il reset in-kernel del vLAPIC su INIT, che §11.2
  diceva perso per bhyve nativo, **è ripristinato**.
- **§6.5.5** va letto con questa base: l'integrazione del nested in
  `vm_handle_ipi` (latch dell'INIT per i bersagli con capability accesa e in
  VMX operation) resta valida e **ortogonale** a questa guardia; ma il testo
  che motiva lo skip con `ipi_exit` non corrisponde più al codice.
- Le righe di `vlapic.c` dopo ~1206 slittano di **+4** (es. la seconda
  guardia `if (!vlapic->ipi_exit) *retu=false` ora a 1232; il caso STARTUP
  a 1252). Il blocco broadcast ALLESELF/ALLISELF è invariato (~1152-1170).

**Raccomandazione:** basare il nested su e5264af4 (include i fix di sicurezza
e correttezza che il piano stesso chiedeva in §11). Aggiornare la
comprensione di §0.2.6/§6.5.5 di conseguenza. Decisione tua.

### 3. Slittamento righe in `vmm_dev_machdep.c`: +4 dopo la riga 142

Il commit e5264af4 ha allungato il commento di `VM_PPT_SBR_DEVICE`
(+4 righe). I riferimenti del piano a questo file oltre la riga 142
slittano di +4:
- KASSERT di GLA2GPA: plan `564-565` → locale **~568-569**
  (a 564 ora c'è `CTASSERT(PROT_EXEC == VM_PROT_EXECUTE)`).
- ioctl GLA2GPA: plan `555-577` → locale **~559-581**.

## Riferimenti verificati INVARIATI (simbolo e firma)

| Oggetto | plan @9bded96 | locale @e5264af4 | esito |
|---|---|---|---|
| firma hypervisor KVM | `x86.c:56` | `x86.c:56` | OK |
| maschera VMX in CPUID | `x86.c:322` | `x86.c:322` | OK |
| foglia 0x40000001 | `x86.c:626-631` | invariato | OK |
| VMINSN → #UD | `vmm.c:1335-1338` | `vmm.c:1336` | OK |
| enum capability (VM_CAP_MAX) | `vmm.h:391-402` | `vmm.h:402` | OK |
| enum exitcode (VM_EXITCODE_MAX) | `vmm.h:538-565` | `vmm.h:565` | OK |
| VMINSN dispatch | `vmx.c:3045-3056` | `vmx.c:3050` | OK |
| `struct vm` | `dev/vmm/vmm_vm.h:128` | `:128`, flags a `:161` | OK |
| ppt SBR | `vmm_dev_machdep.c:138` (flag 0) | `:142` (PPT) | CAMBIATO (§11.1 risolto) |

Gli altri riferimenti di §4.1/§4.2/§5 non toccati da e5264af4 restano alle
righe del piano (nessun commit locale li sfiora). Da completare riga-per-riga
sul clone quando si attacca il relativo task.

## Esito T0.1

- Nessun simbolo o struttura MANCANTE: il piano è applicabile sul tree locale.
- Due file slittati di +4 righe (vlapic.c, vmm_dev_machdep.c) per e5264af4.
- Una divergenza semantica (guardia INIT) da decidere: vedi punto 2.
- §11.1 già risolto; §11.3 (IOCNUM 40/41 doppi) e §11.4 (firma KVM) invariati,
  restano come nel piano.
