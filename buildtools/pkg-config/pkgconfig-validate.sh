#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause

if [ "$#" -ne 1 ]; then
	echo "$0: no pkg-config parameter"
	exit 1
fi

ret=0
PKGCONF="$1"

# take the first result only
pc_file=$(find "$MESON_BUILD_ROOT" -type f -name 'libdpdk.pc' -print -quit)
if [ ! -f "$pc_file" ]; then
	echo "$0: cannot locate libdpdk.pc"
	exit 1
fi

pc_dir=$(dirname "$pc_file")
__pkg_config_path="$PKG_CONFIG_PATH"
PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:$pc_dir"
export PKG_CONFIG_PATH

# Statically linked private DPDK objects of form
# -l:file.a must be positionned between --whole-archive … --no-whole-archive
# linker parameters.
# Old pkg-config versions misplace --no-whole-archive parameter and put it
# next to --whole-archive.
"$PKGCONF" --libs --static libdpdk | \
grep -q 'whole-archive.*l:lib.*no-whole-archive'
if test "$?" -ne 0 ; then
	echo "WARNING: invalid pkg-config"
	ret=1
fi

# restore PKG_CONFIG_PATH
export PKG_CONFIG_PATH="$__pkg_config_path"
exit $ret
