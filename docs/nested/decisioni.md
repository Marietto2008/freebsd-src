# Decisioni D1-D7 (scelte da Marietto il 2026-10-16: "vai con le raccomandate")

| Dec. | Scelta | Significato operativo |
|---|---|---|
| **D1** shadow EPT | **(a)** | port di ACRN vept.c: tabelle EPT a mano, per-VM, RAM e MMIO uguali |
| **D2** stato vCPU in L2 | **(A) + D2.b(i)** | get/set register sul VMCS corrente; pseudo-reg NESTED_LEVEL ro; euristiche accel attive solo a livello 1 |
| **D3** capability + privilegio | **(A) + D3.b(i)** | VM_CAP_NESTED_VIRT / "nested_virt"; bhyve -o x86.nested_virt=true; accel -accel bhyve,nested=on; accensione richiede priv_check(PRIV_DRIVER) |
| **D4** controlli VMX all'L1 | **(C) + D4.b si** | set misurato per F1-F3, set KVM -cpu host per F4; ext-int/NMI exiting must-be-1 |
| **D5** reset VM sotto accel | **(B)** | capability 1->0 (vcpu fermo, azzera nested) poi 0->1 sul reset |
| **D6** firma hypervisor | **(A)** | firma KVM, foglia 0x40000001 EAX bit 15 (MSI_EXT_DEST_ID) invece di bit 0 |
| **D7** printf percorsi caldi | **(A)** | T0.7 dietro VMX_DBG |

Deviazioni SDM ambigue -> scelta piu' restrittiva verso l'L1, in deviazioni.md.
