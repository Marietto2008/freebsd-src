# F0 — esito (i9-9900K, 2026-10-16)

**VIA LIBERA.** Raw in `f0-vmxcaps.txt`.

| Voce | Valore | Conseguenza |
|---|---|---|
| VMCS shadowing (bloccante) | **SI** | il piano procede; VMCS a doppio uso disponibile |
| VMWRITE su ogni campo (0x485 bit 29) | **SI** | **variante (a) di §6.2**: S_R include i campi read-only d'uscita. Nessun cambio di design |
| EPT / VPID / unrestricted guest | SI | ok come L0 e come L1 |
| EPT walk 4 / WB / INVEPT single+all / INVVPID tutti i tipi | SI | ok |
| True controls (0x480 bit 55) | SI | si espongono anche 0x48D-0x490 all'L1 (§T1.4) |
| VMCS revision ID | 0x04 | la revisione di VMCS12 sara' propria (§T1.4) |

NO (gia' nel set ESCLUSO dal piano §6.3, nessun impatto):
posted interrupts, APIC-register virt., virtual-interrupt delivery, TSC scaling.
EPT A/D = SI ma escluso dalla v1.

Nessuna voce «Necessari» = NO: lettura coerente con un 9900K su cui bhyve gia' gira.
