#!/bin/sh
# tools/nested/kut-build-ubuntu.sh — compila kvm-unit-tests su Ubuntu 24.04 e
# impacchetta i .flat per il runner su FreeBSD (T0.4). Lo esegue Marietto
# sull'host Ubuntu; poi copia il tarball in $NESTED_ROOT/kut del FreeBSD e
# lo scompatta li'. Verificato il 14/10 (gcc 13.3, binutils 2.42, 5a22134).
set -eu

COMMIT="${1:-5a22134}"
SRC="${KUT_SRC:-$HOME/kvm-unit-tests}"
OUTDIR="${KUT_OUT:-$PWD}"

say() { echo "[kut-build $(date '+%H:%M:%S')] $*"; }

command -v git  >/dev/null || { echo "serve git"  >&2; exit 1; }
command -v make >/dev/null || { echo "serve make" >&2; exit 1; }

if [ ! -d "$SRC/.git" ]; then
	say "clono kvm-unit-tests in $SRC"
	git clone https://gitlab.com/kvm-unit-tests/kvm-unit-tests.git "$SRC" ||
	git clone https://github.com/kvm-unit-tests/kvm-unit-tests.git "$SRC"
fi

say "checkout $COMMIT"
( cd "$SRC" && git fetch --all --quiet || true; git checkout -q "$COMMIT" )

say "configure --arch=x86_64 && make"
( cd "$SRC" && ./configure --arch=x86_64 && make -j"$(nproc)" )

head=$( cd "$SRC" && git rev-parse --short HEAD )
echo "$head" > "$SRC/x86/BUILD_HEAD"
TAR="$OUTDIR/kut-$head.tar.xz"

# Impacchetto da x86/ cosi' l'estrazione mette i .flat PIATTI in kut/
# (kut-run.sh cerca $NESTED_ROOT/kut/vmx.flat, non .../x86/vmx.flat).
say "impacchetto i .flat + unittests.cfg + BUILD_HEAD -> $TAR"
tar -C "$SRC/x86" -cJf "$TAR" \
    $(cd "$SRC/x86" && ls *.flat) unittests.cfg BUILD_HEAD

say "FATTO: $TAR"
say "Sul FreeBSD: tar -C \$NESTED_ROOT/kut -xJf kut-$head.tar.xz"
say "(i .flat finiscono direttamente in \$NESTED_ROOT/kut/, es. vmx.flat)"
