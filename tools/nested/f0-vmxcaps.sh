#!/bin/sh
# f0-vmxcaps.sh — capability VMX del processore che decidono il piano nested.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "serve root" >&2; exit 1; }
kldstat -q -m cpuctl || kldload cpuctl

# cpucontrol stampa: "MSR 0x48b: 0xALTA 0xBASSA"
msr() { cpucontrol -m "$1" /dev/cpuctl0 | awk '{print $3, $4}'; }
b()   { echo $(( ($1 >> $2) & 1 )); }
sn()  { if [ "$1" -eq 1 ]; then echo SI; else echo NO; fi; }

set -- $(msr 0x480); BASIC_HI=$1; BASIC_LO=$2
set -- $(msr 0x481); PIN_HI=$1
set -- $(msr 0x485); MISC_LO=$2
set -- $(msr 0x48b); P2_HI=$1
set -- $(msr 0x48c); EPT_HI=$1; EPT_LO=$2

echo "CPU: $(sysctl -n hw.model)"
printf 'VMCS revision ID: 0x%08x\n' $(( BASIC_LO & 0x7fffffff ))
echo "== Bloccante =="
echo "VMCS shadowing            (0x48B bit 46) $(sn $(b $P2_HI 14))"
echo "== Cambia il design se NO =="
echo "VMWRITE su ogni campo     (0x485 bit 29) $(sn $(b $MISC_LO 29))"
echo "== Necessari a vmm come L0 e come L1 =="
echo "EPT                       (0x48B bit 33) $(sn $(b $P2_HI 1))"
echo "VPID                      (0x48B bit 37) $(sn $(b $P2_HI 5))"
echo "Unrestricted guest        (0x48B bit 39) $(sn $(b $P2_HI 7))"
echo "EPT page walk 4           (0x48C bit 6)  $(sn $(b $EPT_LO 6))"
echo "EPT memtype WB            (0x48C bit 14) $(sn $(b $EPT_LO 14))"
echo "INVEPT                    (0x48C bit 20) $(sn $(b $EPT_LO 20))"
echo "INVEPT single-context     (0x48C bit 25) $(sn $(b $EPT_LO 25))"
echo "INVEPT all-context        (0x48C bit 26) $(sn $(b $EPT_LO 26))"
echo "INVVPID                   (0x48C bit 32) $(sn $(b $EPT_HI 0))"
echo "INVVPID tipi 0/1/2/3      (0x48C bit 40-43) $(b $EPT_HI 8)$(b $EPT_HI 9)$(b $EPT_HI 10)$(b $EPT_HI 11)"
echo "== Informativi =="
echo "True controls             (0x480 bit 55) $(sn $(b $BASIC_HI 23))"
echo "Posted interrupts         (0x481 bit 39) $(sn $(b $PIN_HI 7))"
echo "APIC-register virt.       (0x48B bit 40) $(sn $(b $P2_HI 8))"
echo "Virtual-interrupt deliv.  (0x48B bit 41) $(sn $(b $P2_HI 9))"
echo "TSC scaling               (0x48B bit 57) $(sn $(b $P2_HI 25))"
echo "EPT A/D                   (0x48C bit 21) $(sn $(b $EPT_LO 21))"
echo "== Valori grezzi =="
for m in 0x3a 0x480 0x481 0x482 0x483 0x484 0x485 0x486 0x487 0x488 0x489 \
         0x48a 0x48b 0x48c 0x48d 0x48e 0x48f 0x490; do
    cpucontrol -m "$m" /dev/cpuctl0 || echo "MSR $m: non leggibile"
done
