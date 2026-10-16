#!/bin/sh
# tools/nested/run-l1.sh — avvia una VM L1 con la capability nested accesa, per
# le fasi F3/F4 (hypervisor reali come L1). Sotto bhyve(8) o sotto l'accel
# QEMU. Lo esegue Marietto. Claude Code: solo --prova.
#
# uso: run-l1.sh [--prova] --img <disco> [--mem 4G] [--cpus 2] \
#          [--front bhyve|accel] [--serial]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] && . "$ENV"
: "${STAGE:=/nested/stage}"
: "${NESTED_ROOT:=/nested}"
: "${TEST_CPUS:=}"

PROVA=0; IMG=""; MEM="4G"; CPUS=2; FRONT="bhyve"; SERIAL=0; VMNAME="l1test"
while [ $# -gt 0 ]; do
	case "$1" in
	--prova) PROVA=1; shift;;
	--img) IMG="$2"; shift 2;;
	--mem) MEM="$2"; shift 2;;
	--cpus) CPUS="$2"; shift 2;;
	--front) FRONT="$2"; shift 2;;
	--serial) SERIAL=1; shift;;
	--name) VMNAME="$2"; shift 2;;
	*) echo "argomento ignoto: $1" >&2; exit 2;;
	esac
done
[ -n "$IMG" ] || { echo "manca --img <disco L1>" >&2; exit 2; }

say() { echo "[l1 $(date '+%H:%M:%S')] $*"; }
run() { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }

cpuset_pfx=""
[ -n "$TEST_CPUS" ] && cpuset_pfx="cpuset -l $TEST_CPUS"

if [ "$FRONT" = "accel" ]; then
	# QEMU + accel bhyve, capability nested accesa.
	QEMU="$STAGE/current/bin/qemu-system-x86_64"
	cmd="$cpuset_pfx '$QEMU' -accel bhyve,nested=on -m $MEM -smp $CPUS \
	  -drive file='$IMG',format=raw,if=virtio -serial stdio -display none"
	say "L1 sotto l'ACCEL (QEMU -accel bhyve,nested=on)"
	run "$cmd"
else
	# bhyve(8) nativo, -S (wire), nested via -o x86.nested_virt=true.
	BHYVE="$STAGE/current/sbin/bhyve"
	say "L1 sotto bhyve(8) nativo (-S, -o x86.nested_virt=true)"
	# nota: l'utente fornisce il bootrom/UEFI e la rete nel proprio template;
	# qui lo schema minimo seriale, da adattare.
	cmd="$cpuset_pfx '$BHYVE' -S -c $CPUS -m $MEM \
	  -o x86.nested_virt=true \
	  -s 0,hostbridge -s 31,lpc -l com1,stdio \
	  -s 4,virtio-blk,'$IMG' \
	  -l bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd \
	  '$VMNAME'"
	run "$cmd"
fi
say "FATTO. Dentro l'L1: kldload vmm (FreeBSD) o modprobe kvm_intel (Linux),"
say "poi avvia un L2. Vedi T3.1/T3.2."
