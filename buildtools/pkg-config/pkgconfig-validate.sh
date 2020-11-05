#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause

if [ "$#" -ne 1 ]; then
	echo "$0: no pkg-config parameter"
	exit 1
fi
PKGCONF="$1"

# if pkgconf could not locate libdpdk.pc from existing PKG_CONFIG_PATH
# check meson template instead
# take the first located file
pc_file=$(find "$MESON_BUILD_ROOT" -type f -name 'libdpdk.pc' -print -quit)
if [ ! -f "$pc_file" ]; then
	echo "$0: cannot locate libdpdk.pc"
	exit 1
fi
pc_dir=$(dirname "$pc_file")
PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:$pc_dir"

# Statically linked private DPDK objects of form
# -l:file.a must be positioned between --whole-archive … --no-whole-archive
# linker parameters.
# Old pkg-config versions misplace --no-whole-archive parameter and put it
# next to --whole-archive.
PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
"$PKGCONF" --libs --static libdpdk | \
grep -q 'whole-archive.*l:lib.*no-whole-archive'
exit "$?"
