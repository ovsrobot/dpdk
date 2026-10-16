# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

pkg = import('pkgconfig')
pkg_extra_cflags = ['-include', 'rte_config.h'] + machine_args
if is_freebsd
    pkg_extra_cflags += ['-D__BSD_VISIBLE']
endif

# The output order of the .pc file fields used by pkg-config is:
#   Libs   Libs.private   Requires   Requires.private
# The Requires* fields are for package names, while the flags of the DPDK
# libraries and drivers must be defined in the Libs* fields.
#
# For shared linking, only the Libs field is used, and it lists the DPDK
# libraries and drivers, all with the --as-needed flag to avoid overlinking
# against components that the application does not actually use.
#
# Listing the drivers here is safe even though they are normally loaded at
# runtime with dlopen(). DPDK drivers register themselves through constructor
# functions that must run exactly once. Thanks to --as-needed, a driver whose
# symbols are not referenced by the application is dropped from the binary's
# NEEDED list entirely, so its constructor does not run at startup and EAL
# loads it once at runtime as usual. If the application does reference a driver
# symbol, the driver stays in NEEDED and its constructor runs at startup; EAL's
# later dlopen() of the same file is deduplicated by the dynamic loader (same
# soname and inode, the plugin directory holds symlinks to the installed
# libraries) and does not run the constructor a second time. Either way, the
# constructor runs exactly once.
#
# For static linking, pkg-config appends the Libs.private field after Libs.
# The DPDK drivers must be linked before the libraries they depend upon, so
# both the drivers and the libraries are listed in Libs.private, wrapped in
# --whole-archive so that drivers register themselves at load time. The
# static files are listed with the explicit -l:libfoo.a syntax so that DPDK
# itself is linked statically while its external dependencies may still be
# linked as shared libraries. The DPDK libraries from the Libs field appear a
# second time before Libs.private, but those occurrences are skipped thanks to
# the --as-needed flag.

platform_flags = []
if not is_windows
    platform_flags += ['-Wl,--export-dynamic'] # ELF only
endif
pkg.generate(name: 'DPDK', # main DPDK pkgconfig file
        filebase: 'libdpdk',
        version: meson.project_version(),
        description: '''The Data Plane Development Kit (DPDK).
Note that CFLAGS might contain an -march flag higher than typical baseline.
This is required for a number of static inline functions in the public headers.''',
        subdirs: [get_option('include_subdir_arch'), '.'],
        extra_cflags: pkg_extra_cflags,
        libraries: ['-Wl,--as-needed'] + dpdk_libraries + dpdk_shared_drivers,
        libraries_private: ['-Wl,--whole-archive'] +
            dpdk_static_drivers + dpdk_static_libraries +
            ['-Wl,--no-whole-archive'] + dpdk_extra_ldflags + platform_flags
)

# For static linking with dependencies as shared libraries,
# the internal static libraries must be flagged explicitly.
run_command(py3, files('set-static-linker-flags.py'), check: true)
