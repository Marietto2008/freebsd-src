#!/bin/sh
# tools/nested/build.sh — build del modulo vmm, di libvmmapi/bhyve/bhyvectl e
# dell'accel QEMU per il lavoro nested, con STAGING in $STAGE.  Nessuna
# installazione di sistema.  (T0.2 del piano nested v2.)
#
# Regole non negoziabili (§3 del piano):
#   - output SOLO in $STAGE e nelle obj dir; mai /boot /usr /etc;
#   - mai make install*; mai kldload; mai avviare bhyve/qemu;
#   - se target/arm/bhyve/meson.build manca -> stop, niente file nell'albero QEMU.
#
# Uso:
#   cp tools/nested/nested.env.example tools/nested/nested.env  # e adattalo
#   sh tools/nested/build.sh            # build completa
#   sh tools/nested/build.sh --prova    # mostra solo cosa farebbe
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ENV="$HERE/nested.env"
[ -f "$ENV" ] || { echo "manca $ENV (copia nested.env.example)" >&2; exit 1; }
# shellcheck disable=SC1090
. "$ENV"

PROVA=0
[ "${1:-}" = "--prova" ] && PROVA=1

: "${SRC:?SRC non impostato in nested.env}"
: "${QEMU_SRC:?QEMU_SRC non impostato}"
: "${KERNCONF:=VMMSNOOP}"
: "${KERNBUILDDIR:?KERNBUILDDIR non impostato}"
: "${STAGE:?STAGE non impostato}"
: "${TEST_CPUS:=}"

BUILD_ID=$(date +%Y%m%d-%H%M%S)
DEST="$STAGE/$BUILD_ID"
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)

say()  { echo "[build $(date +%H:%M:%S)] $*"; }
run()  { if [ "$PROVA" = 1 ]; then echo "  PROVA> $*"; else eval "$*"; fi; }

# --- controlli preliminari ------------------------------------------------
[ -d "$SRC/sys/modules/vmm" ]   || { echo "SRC non e' un albero FreeBSD: $SRC" >&2; exit 1; }
[ -d "$QEMU_SRC/accel/bhyve" ]  || { echo "QEMU_SRC non e' l'albero qemu: $QEMU_SRC" >&2; exit 1; }
[ -d "$KERNBUILDDIR" ]          || { echo "KERNBUILDDIR inesistente: $KERNBUILDDIR" >&2; exit 1; }

# §0.3 / §7.3.4: senza questo file meson entra comunque in target/arm e si ferma.
if [ ! -f "$QEMU_SRC/target/arm/bhyve/meson.build" ]; then
	echo "STOP: manca $QEMU_SRC/target/arm/bhyve/meson.build (§0.3)." >&2
	echo "Non creo nulla nell'albero QEMU. Verifica T0.2." >&2
	exit 2
fi

say "build-id $BUILD_ID -> $DEST"
run "mkdir -p '$DEST/lib' '$DEST/sbin' '$DEST/bin' '$DEST/include'"

# --- coerenza kernel/userland (§7.3.1) ------------------------------------
UK=$(uname -K); UU=$(uname -U)
say "uname -K=$UK  uname -U=$UU  KERNCONF=$KERNCONF"
if [ "$UU" -lt 1600000 ]; then
	say "AVVISO: userland ($UU) < 16.  libvmmapi/bhyve/bhyvectl: uso MAKEOBJDIRPREFIX dedicato."
	say "        (se la build userland fallisce, serve il metodo cross che usi oggi: fermati e chiedi.)"
fi

# --- 1. modulo vmm (§7.3.2) -----------------------------------------------
say "modulo vmm (KERNBUILDDIR=$KERNBUILDDIR)"
run "env MAKEOBJDIRPREFIX='${MAKEOBJDIRPREFIX:-/usr/obj}' \
     make -C '$SRC/sys/modules/vmm' -j$JOBS KERNBUILDDIR='$KERNBUILDDIR' DEBUG_FLAGS=-g"
# gli artefatti stanno nella obj dir del modulo; li copio in $DEST
MODOBJ="${MAKEOBJDIRPREFIX:-/usr/obj}$SRC/amd64.amd64/sys/modules/vmm"
run "cp '$MODOBJ/vmm.ko' '$DEST/vmm-restore.ko'" 2>/dev/null || \
  run "cp '$MODOBJ/vmm-restore.ko' '$DEST/vmm-restore.ko'"
run "cp '$MODOBJ'/vmm*.debug '$DEST/' 2>/dev/null || true"

# --- 2. libvmmapi, bhyve, bhyvectl (§7.3.3) -------------------------------
# libvmmapi SI RICOMPILA SEMPRE: contiene vmm_instruction_emul.c.
OBJTMP="${MAKEOBJDIRPREFIX:-/usr/obj}"
for d in lib/libvmmapi usr.sbin/bhyve usr.sbin/bhyvectl; do
	say "userland: $d"
	run "env MAKEOBJDIRPREFIX='$OBJTMP' make -C '$SRC/$d' -j$JOBS obj"
	run "env MAKEOBJDIRPREFIX='$OBJTMP' make -C '$SRC/$d' -j$JOBS"
done
# staging senza install di sistema: copio gli artefatti
LVOBJ="$OBJTMP$SRC/lib/libvmmapi"
run "cp '$LVOBJ'/libvmmapi.so* '$DEST/lib/' 2>/dev/null || true"
run "cp '$LVOBJ'/libvmmapi.a    '$DEST/lib/' 2>/dev/null || true"
run "cp '$OBJTMP$SRC/usr.sbin/bhyve/bhyve'       '$DEST/sbin/'"
run "cp '$OBJTMP$SRC/usr.sbin/bhyvectl/bhyvectl' '$DEST/sbin/'"
run "cp '$SRC/lib/libvmmapi/vmmapi.h' '$DEST/include/' 2>/dev/null || true"

# --- 3. accel QEMU (§7.3.4) -----------------------------------------------
QBUILD="$DEST/qemu-build"
say "QEMU accel -> $QBUILD (target x86_64-softmmu)"
run "mkdir -p '$QBUILD'"
run "cd '$QBUILD' && '$QEMU_SRC/configure' \
      --target-list=x86_64-softmmu \
      --extra-cflags='-I$DEST/include' \
      --extra-ldflags='-L$DEST/lib' \
      --disable-werror"
run "make -C '$QBUILD' -j$JOBS"
run "cp '$QBUILD/qemu-system-x86_64' '$DEST/bin/' 2>/dev/null || \
     cp '$QBUILD/x86_64-softmmu/qemu-system-x86_64' '$DEST/bin/'"

# --- 4. MANIFEST (§7.2) ----------------------------------------------------
say "MANIFEST"
if [ "$PROVA" = 0 ]; then
	{
		echo "build-id: $BUILD_ID"
		echo "data: $(date '+%F %T %z')"
		echo "kernel in esecuzione: $(uname -v)"
		echo "uname -K: $UK"
		echo "uname -U: $UU"
		echo "KERNCONF: $KERNCONF"
		echo "KERNBUILDDIR: $KERNBUILDDIR"
		echo "--- freebsd ($SRC) ---"
		( cd "$SRC" && echo "commit: $(git rev-parse HEAD)" \
		  && echo "ramo: $(git rev-parse --abbrev-ref HEAD)" \
		  && echo "dirty: $(git status --porcelain | wc -l | tr -d ' ') file" )
		echo "--- qemu ($QEMU_SRC) ---"
		( cd "$QEMU_SRC" && echo "commit: $(git rev-parse HEAD)" \
		  && echo "ramo: $(git rev-parse --abbrev-ref HEAD)" \
		  && echo "dirty: $(git status --porcelain | wc -l | tr -d ' ') file" )
	} > "$DEST/MANIFEST"
	ln -shf "$BUILD_ID" "$STAGE/current"
	cat "$DEST/MANIFEST"
fi

say "FATTO. STAGE: $DEST"
say "NB: niente kldload, niente avvio VM: i collaudi li esegue Marietto (§7.5)."
