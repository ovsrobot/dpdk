#! /bin/sh

# Convert DPDK API files into RUST.
# DPDK files selection is on demand.
#
# The coversion is done in 4 stages:
# 1. Preparation [Optional]
#    Due to the bindgen conversion utility limitations source file may need
#    manual adjustment.
# 2. Preprocessing [Mandatory]
#    Run preprocessor on a source file before conversion.
# 3. Conversion [Mandatory]
#    Convert preprocessed C file into RUST file
# 4. Post translation [Optional]
#    Manually fix translation.

# DPDK files list
files='
rte_build_config.h
rte_eal.h
rte_ethdev.h
rte_mbuf.h
rte_mbuf_core.h
rte_mempool.h
'
libdir="$1"
rust_dir="${MESON_INSTALL_DESTDIR_PREFIX}/$libdir/rust"
include_dir="${MESON_INSTALL_DESTDIR_PREFIX}/include"

if test -d "$rust_dir"; then
  rm -rf "$rust_dir"
fi

mkdir -p "$rust_dir/src/raw"
if ! test -d "$rust_dir"; then
  echo "failed to create Rust library $rust_dir"
  exit 255
fi

bindgen_opt='--no-layout-tests --no-derive-debug'
bindgen_clang_opt='-Wno-unused-command-line-argument'

create_rust_lib ()
{
  base=$1

  cp $include_dir/${base}.h /tmp/${base}.h

# bindgen cannot process complex macro definitions
# manually simplify macros before conversion
  sed -i -e 's/RTE_BIT64(\([0-9]*\))/(1UL << \1)/g' /tmp/${base}.h
  sed -i -e 's/RTE_BIT32(\([0-9]*\))/(1U << \1)/g' /tmp/${base}.h
  sed -i -e 's/UINT64_C(\([0-9]*\))/\1/g' /tmp/${base}.h

  # clang output has better integration with bindgen than GCC
  clang -E -dD -I$include_dir /tmp/${base}.h > /tmp/$base.i
  bindgen $bindgen_opt --output $rust_dir/src/raw/$base.rs /tmp/$base.i -- $bindgen_clang_opt
  rm -f /tmp/$base.i /tmp/$base.h
}

echo 'pub mod raw;' > "$rust_dir/src/lib.rs"

touch "$rust_dir/src/raw/mod.rs"
for file in $files; do
  base=$(basename $file | cut -d. -f 1)
  create_rust_lib $base
  echo "pub mod $base;" >> "$rust_dir/src/raw/mod.rs"
done

cat > "$rust_dir/Cargo.toml" <<EOF
[package]
name = "dpdk"
version = "$(cat ${MESON_SOURCE_ROOT}/VERSION | sed 's/\.0\([1-9]\)/\.\1/')"
EOF

# post conversion updates
# RUST does not accept aligned structures into packed structure.
# TODO: fix DPDK definitions.
sed -i 's/repr(align(2))/repr(packed(2))/g'  "$rust_dir/src/raw/rte_ethdev.rs"

echo "Install RUST DPDK crate in $rust_dir"
