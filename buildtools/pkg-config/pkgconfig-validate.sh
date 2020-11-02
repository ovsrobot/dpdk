#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause

# Statically linked private DPDK objects of form
# -l:file.a must be positionned between --whole-archive … --no-whole-archive
# linker parameters.
# Old pkg-config versions misplace --no-whole-archive parameter and put it
# next to --whole-archive.
test1_static_libs_order () {
	PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:$pc_dir" \
	"$PKGCONF" --libs --static libdpdk | \
	grep -q 'whole-archive.*l:lib.*no-whole-archive'
	if test "$?" -ne 0 ; then
		echo "WARNING: invalid static libraries order"
		ret=1
	fi
	return $ret
}

if [ "$#" -ne 1 ]; then
	echo "$0: no pkg-config parameter"
	exit 1
fi
PKGCONF="$1"

# take the first result only
pc_file=$(find "$MESON_BUILD_ROOT" -type f -name 'libdpdk.pc' -print -quit)
if [ ! -f "$pc_file" ]; then
	echo "$0: cannot locate libdpdk.pc"
	exit 1
fi
pc_dir=$(dirname "$pc_file")

ret=0

test1_static_libs_order
if [ $ret -ne 0 ]; then
	exit $ret
fi

