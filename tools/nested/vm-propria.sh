#!/bin/sh
# vm-propria.sh NOME -- Claude 29/10/2026. Prepara /dev/vmm/NOME per avviare la PROPRIA VM, senza toccare le altre.
#   /dev/vmm/NOME assente             -> niente da fare, rc 0
#   presente e APERTO da un processo  -> la VM e' viva (bhyve/QEMU la tiene aperta): NON si distrugge, rc 1
#   presente e chiuso                 -> residuo di una corsa uccisa: bhyvectl --vm=NOME --destroy
# Non elenca e non distrugge MAI altri nodi di /dev/vmm. Va eseguito da root (fstat vede i descrittori di tutti).
N=${1:?uso: vm-propria.sh NOME}
[ -e "/dev/vmm/$N" ] || exit 0
if [ -n "$(/usr/bin/fstat "/dev/vmm/$N" 2>/dev/null | /usr/bin/sed 1d)" ]; then
	echo "vm-propria: la VM $N e' in uso (/dev/vmm/$N aperto): non la tocco" >&2
	exit 1
fi
echo "vm-propria: $N e' un residuo chiuso: lo distruggo"
/usr/sbin/bhyvectl --vm="$N" --destroy
