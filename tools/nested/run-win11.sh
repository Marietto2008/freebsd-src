#!/bin/sh
# tools/nested/run-win11.sh — F4/T4.1: bhyve(8) NUDO (non l'accel QEMU) avvia
# Windows 11 con la virtualizzazione annidata accesa, cosi' che dentro il guest
# Hyper-V / WSL2 possano a loro volta virtualizzare (L2).
#
# bhyve nudo + nested = '-o x86.nested_virt=true' (serve il vmm-restore.ko
# nested caricato da load.sh; altrimenti bhyve stampa "nested virtualization
# not supported" ed esce).
#
# Windows 11 pretende: UEFI + TPM 2.0 + Secure-Boot-capable + >=4 GB + 2 core.
#   - UEFI:  BHYVE_UEFI_CODE.fd + una copia VARS *scrivibile per-VM*.
#   - TPM 2: swtpm (sysutils/swtpm) avviato come socket prima di bhyve.
#   - disco NVMe e rete e1000 = driver GIA' nativi in Windows 11 (niente
#     virtio da caricare in fase d'installazione).
#
# Regola del workspace: Claude Code lancia SOLO '--prova' (stampa i comandi e
# non esegue nulla); l'avvio reale lo fa Marietto.
#
# uso:
#   sh tools/nested/run-win11.sh --prova                # mostra i comandi
#   sh tools/nested/run-win11.sh --iso /path/Win11.iso  # prima installazione
#   sh tools/nested/run-win11.sh                        # boot successivi
# opzioni:
#   --iso <file>    ISO di Windows 11 su CD AHCI (serve per installare)
#   --disk <file>   disco NVMe (default $VMDIR/win11.img)
#   --size <n>      dimensione disco se da creare (default 64G)
#   --mem <n>       RAM (default 8G: Win11 + Hyper-V + WSL2)
#   --cpus <n>      vCPU (default 4; topologia 1 socket/N core/1 thread)
#   --tap <ifN>     NIC e1000 su questo tap (se omesso: niente rete)
#   --vnc <ip:porta> framebuffer VNC (default 0.0.0.0:5900)
#   --no-wait       non attendere il client VNC prima di avviare
#   --no-swire      non passare -S (wire della RAM; default: attivo)
#   --gpu           passa la NVIDIA RTX 2080 Ti (4 funzioni) al guest, come
#                   UN device multifunzione a slot 6 (GPU+audio+USB-C+TypeC).
#                   Richiede che le funzioni siano GIA' su ppt da loader.conf
#                   (pptdevs); mai legarle a caldo (congela l'host). Forza -S.
#   --gpu-sel "..." selettori bus/slot/func (default "4/0/0 4/0/1 4/0/2 4/0/3")
#   --name <nome>   nome VM bhyve (default win11)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${STAGE:=/nested/stage}"
: "${NESTED_ROOT:=/nested}"
: "${TEST_CPUS:=}"

UEFI_DIR="${UEFI_DIR:-/usr/local/share/uefi-firmware}"
BHYVE="$STAGE/current/sbin/bhyve"
BHYVECTL="$STAGE/current/sbin/bhyvectl"

PROVA=0
ISO=""
DISK=""
SIZE="64G"
MEM="8G"
CPUS=4
TAP=""
VNC="0.0.0.0:5900"
WAIT=1
SWIRE=1
GPU=0
GPU_SEL="4/0/0 4/0/1 4/0/2 4/0/3"	# RTX 2080 Ti: VGA, HD-audio, USB-C, Type-C
VMNAME="win11"
VMDIR="${WIN11_VMDIR:-$NESTED_ROOT/win11}"

while [ $# -gt 0 ]; do
	case "$1" in
	--prova)   PROVA=1; shift;;
	--iso)     ISO="$2"; shift 2;;
	--disk)    DISK="$2"; shift 2;;
	--size)    SIZE="$2"; shift 2;;
	--mem)     MEM="$2"; shift 2;;
	--cpus)    CPUS="$2"; shift 2;;
	--tap)     TAP="$2"; shift 2;;
	--vnc)     VNC="$2"; shift 2;;
	--no-wait) WAIT=0; shift;;
	--no-swire) SWIRE=0; shift;;
	--gpu)     GPU=1; shift;;
	--gpu-sel) GPU_SEL="$2"; shift 2;;
	--name)    VMNAME="$2"; shift 2;;
	-h|--help) sed -n '2,42p' "$0"; exit 0;;
	*) echo "argomento ignoto: $1" >&2; exit 2;;
	esac
done

: "${DISK:=$VMDIR/win11.img}"
TPMDIR="$VMDIR/tpm"
TPMSOCK="$VMDIR/swtpm.sock"
VARS="$VMDIR/BHYVE_UEFI_VARS.fd"
CODE="$UEFI_DIR/BHYVE_UEFI_CODE.fd"
VARS_TMPL="$UEFI_DIR/BHYVE_UEFI_VARS.fd"

say() { echo "[win11 $(date '+%H:%M:%S')] $*"; }
run() { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }
die() { echo "ERRORE: $*" >&2; exit 1; }

# GPU in passthrough: la RAM DEVE essere wired (DMA del dispositivo) -> -S.
if [ "$GPU" = 1 ] && [ "$SWIRE" = 0 ]; then
	say "AVVISO: --gpu richiede -S (DMA); ignoro --no-swire"
	SWIRE=1
fi

# --- controlli -------------------------------------------------------------
if [ "$PROVA" = 0 ]; then
	[ -x "$BHYVE" ] || die "manca $BHYVE (build.sh)"
	kldstat -q -n vmm 2>/dev/null || die "vmm non caricato: lancia prima load.sh"
	if [ "$GPU" = 1 ]; then
		for sel in $GPU_SEL; do
			pci=$(echo "$sel" | tr '/' ':')
			pciconf -l 2>/dev/null | /usr/bin/grep -qE "^ppt[0-9]+@pci0:$pci:" || \
			    die "la funzione $sel NON e' su ppt. Mettila in pptdevs di /boot/loader.conf e RIAVVIA. Mai legarla a caldo (congela l'host)."
		done
	fi
	command -v swtpm >/dev/null 2>&1 || \
	    die "swtpm assente: Windows 11 vuole il TPM 2.0 -> 'pkg install swtpm'"
	command -v swtpm_setup >/dev/null 2>&1 || \
	    die "swtpm_setup assente (parte di sysutils/swtpm)"
	[ -f "$CODE" ] || die "firmware UEFI mancante: $CODE"
	[ -f "$VARS_TMPL" ] || die "template VARS UEFI mancante: $VARS_TMPL"
	[ -z "$ISO" ] || [ -f "$ISO" ] || die "ISO inesistente: $ISO"
fi

# --- preparazione stato (idempotente, nessun rm) ---------------------------
run "mkdir -p '$VMDIR' '$TPMDIR'"

# disco NVMe: crealo solo se assente (mai sovrascrivere un disco esistente)
if [ ! -f "$DISK" ]; then
	say "creo il disco NVMe $DISK ($SIZE)"
	run "truncate -s '$SIZE' '$DISK'"
else
	say "uso il disco esistente $DISK"
fi

# copia VARS per-VM scrivibile: solo se assente (conserva boot entry/SecureBoot)
if [ ! -f "$VARS" ]; then
	say "copio il template VARS UEFI in $VARS (scrivibile per-VM)"
	run "cp '$VARS_TMPL' '$VARS'"
else
	say "uso i VARS UEFI esistenti $VARS"
fi

# inizializza lo stato TPM una sola volta (cartella vuota = prima volta)
if [ "$PROVA" = 1 ] || [ -z "$(ls -A "$TPMDIR" 2>/dev/null)" ]; then
	say "inizializzo lo stato del TPM 2.0 in $TPMDIR"
	run "swtpm_setup --tpm2 --tpmstate '$TPMDIR' \
	      --create-ek-cert --create-platform-cert --lock-nvram --overwrite"
fi

# --- avvia swtpm come socket (daemon per questa VM) ------------------------
SWTPM_CMD="swtpm socket --tpm2 \
  --tpmstate dir='$TPMDIR' \
  --ctrl type=unixio,path='$TPMSOCK' \
  --flags startup-clear \
  --log file='$VMDIR/swtpm.log',level=1"
if [ "$PROVA" = 1 ]; then
	echo "  PROVA> $SWTPM_CMD &"
else
	say "avvio swtpm su $TPMSOCK"
	eval "$SWTPM_CMD &"
	SWTPM_PID=$!
	trap 'kill "$SWTPM_PID" 2>/dev/null || true' EXIT INT TERM
	# attendi che il socket compaia (max ~5 s)
	i=0
	while [ ! -S "$TPMSOCK" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1)); sleep 0.1 2>/dev/null || sleep 1
	done
	[ -S "$TPMSOCK" ] || die "swtpm non ha creato il socket $TPMSOCK (vedi $VMDIR/swtpm.log)"
fi

# --- costruisci la riga bhyve ----------------------------------------------
cpuset_pfx=""
[ -n "$TEST_CPUS" ] && cpuset_pfx="cpuset -l $TEST_CPUS"

SWFLAG=""
[ "$SWIRE" = 1 ] && SWFLAG="-S"

FBUF="-s 29,fbuf,tcp=$VNC,w=1280,h=800"
[ "$WAIT" = 1 ] && FBUF="$FBUF,wait"

CD=""
[ -n "$ISO" ] && CD="-s 4,ahci-cd,'$ISO'"
NET=""
[ -n "$TAP" ] && NET="-s 5,e1000,'$TAP'"

# GPU: le 4 funzioni della 2080 Ti come UN device multifunzione a slot 6,
# conservando i numeri di funzione (0=VGA,1=audio,2=USB-C,3=TypeC) cosi' che
# Windows installi il driver NVIDIA come sul ferro vero.
GPU_DEV=""
if [ "$GPU" = 1 ]; then
	gf=0
	for sel in $GPU_SEL; do
		GPU_DEV="$GPU_DEV -s 6:$gf,passthru,$sel"
		gf=$((gf + 1))
	done
fi

# ripulisci un eventuale residuo della VM precedente (idempotente, non fatale)
run "'$BHYVECTL' --vm='$VMNAME' --destroy 2>/dev/null || true"

# -w  ignora gli MSR non implementati (Windows ne tocca parecchi)
# -H  cede la CPU sull'HLT del guest
# -A  tabelle ACPI (necessarie a Windows/Hyper-V)
# -o x86.nested_virt=true  ESPONE VT-x al guest -> Hyper-V/WSL2 annidati
BHYVE_CMD="$cpuset_pfx '$BHYVE' \
  -c sockets=1,cores=$CPUS,threads=1 -m $MEM $SWFLAG -w -H -A \
  -o x86.nested_virt=true \
  -s 0,hostbridge \
  -s 3,nvme,'$DISK' \
  $CD \
  $NET \
  $GPU_DEV \
  $FBUF \
  -s 30,xhci,tablet \
  -s 31,lpc \
  -l com1,stdio \
  -l tpm,swtpm,'$TPMSOCK' \
  -l bootrom,'$CODE','$VARS' \
  '$VMNAME'"

say "avvio Windows 11 (bhyve nudo, nested ON). VNC su $VNC"
[ "$WAIT" = 1 ] && say "bhyve attende il client VNC: collegati a $VNC per vedere il boot"
run "$BHYVE_CMD"

say "FATTO. In Windows: abilita 'Piattaforma macchine virtuali' + 'Hyper-V'"
say "(e per WSL2: wsl --install). VT-x e' esposto da -o x86.nested_virt=true."
if [ "$GPU" = 1 ]; then
	say "GPU: la 2080 Ti e' a slot 6 (4 funzioni). Il video esce dal monitor"
	say "fisico una volta caricato il driver NVIDIA; fino ad allora usa il VNC."
	say "Se il driver da' 'Codice 43': serve un driver NVIDIA recente (>=465,"
	say "che ammette il passthrough GeForce in VM). Lato host, se il guest vede"
	say "artefatti/DMA incoerente, valuta 'sysctl vm.pmap.ept_ipat=0' (vedi la"
	say "memoria reference_bhyve_iommu_snoop)."
fi
