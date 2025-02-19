/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 Neil Horman <nhorman@tuxdriver.com>.
 * All rights reserved.
 */

#ifndef _RTE_FUNCTION_VERSIONING_H_
#define _RTE_FUNCTION_VERSIONING_H_
#include <rte_common.h>

#ifndef RTE_USE_FUNCTION_VERSIONING
#error Use of function versioning disabled, is "use_function_versioning=true" in meson.build?
#endif

#ifdef RTE_BUILD_SHARED_LIB

/*
 * Provides backwards compatibility when updating exported functions.
 * When a symbol is exported from a library to provide an API, it also provides a
 * calling convention (ABI) that is embodied in its name, return type,
 * arguments, etc.  On occasion that function may need to change to accommodate
 * new functionality, behavior, etc.  When that occurs, it is desirable to
 * allow for backwards compatibility for a time with older binaries that are
 * dynamically linked to the dpdk.  To support that, the __vsym and
 * VERSION_SYMBOL macros are created.  They, in conjunction with the
 * version.map file for a given library allow for multiple versions of
 * a symbol to exist in a shared library so that older binaries need not be
 * immediately recompiled.
 *
 * Refer to the guidelines document in the docs subdirectory for details on the
 * use of these macros
 */

/*
 * Macro Parameters:
 * b - function base name
 * e - function version extension, to be concatenated with base name
 * n - function symbol version string to be applied
 * f - function prototype
 * p - full function symbol name
 */

/*
 * VERSION_SYMBOL
 * Creates a symbol version table entry binding symbol <b>@DPDK_<n> to the internal
 * function name <b><e>
 */
#define VERSION_SYMBOL(b, e, n) __asm__(".symver " RTE_STR(b) RTE_STR(e) ", " RTE_STR(b) "@DPDK_" RTE_STR(n))

/*
 * VERSION_SYMBOL_EXPERIMENTAL
 * Creates a symbol version table entry binding the symbol <b>@EXPERIMENTAL to the internal
 * function name <b><e>. The macro is used when a symbol matures to become part of the stable ABI,
 * to provide an alias to experimental for some time.
 */
#define VERSION_SYMBOL_EXPERIMENTAL(b, e) __asm__(".symver " RTE_STR(b) RTE_STR(e) ", " RTE_STR(b) "@EXPERIMENTAL")

/*
 * BIND_DEFAULT_SYMBOL
 * Creates a symbol version entry instructing the linker to bind references to
 * symbol <b> to the internal symbol <b><e>
 */
#define BIND_DEFAULT_SYMBOL(b, e, n) __asm__(".symver " RTE_STR(b) RTE_STR(e) ", " RTE_STR(b) "@@DPDK_" RTE_STR(n))

/*
 * __vsym
 * Annotation to be used in declaration of the internal symbol <b><e> to signal
 * that it is being used as an implementation of a particular version of symbol
 * <b>.
 */
#define __vsym __rte_used

/*
 * MAP_STATIC_SYMBOL
 * If a function has been bifurcated into multiple versions, none of which
 * are defined as the exported symbol name in the map file, this macro can be
 * used to alias a specific version of the symbol to its exported name.  For
 * example, if you have 2 versions of a function foo_v1 and foo_v2, where the
 * former is mapped to foo@DPDK_1 and the latter is mapped to foo@DPDK_2 when
 * building a shared library, this macro can be used to map either foo_v1 or
 * foo_v2 to the symbol foo when building a static library, e.g.:
 * MAP_STATIC_SYMBOL(void foo(), foo_v2);
 */
#define MAP_STATIC_SYMBOL(f, p)

/*
 * MAP_STATIC_BASE_SYMBOL
 * Has the same purpose as MAP_STATIC_SYMBOL, but takes a base function name
 * instead of the whole function prototype. It is used to support MSVC.
 */
#define MAP_STATIC_BASE_SYMBOL(b, p)

#else
/*
 * No symbol versioning in use
 */
#define VERSION_SYMBOL(b, e, n)
#define VERSION_SYMBOL_EXPERIMENTAL(b, e)
#define __vsym
#define BIND_DEFAULT_SYMBOL(b, e, n)

#ifdef RTE_TOOLCHAIN_MSVC
#define MAP_STATIC_SYMBOL(f, p)
#define MAP_STATIC_BASE_SYMBOL(b, p) __pragma(comment(linker, "/alternatename:" #b "=" #p))
/*
 * version.map file should also be updated with "b=p;", like
 *     rte_net_crc_set_alg=rte_net_crc_set_alg_v26;
 */
#else
#define MAP_STATIC_SYMBOL(f, p) f __attribute__((alias(RTE_STR(p))))
#define MAP_STATIC_BASE_SYMBOL(b, p)
#endif

/*
 * RTE_BUILD_SHARED_LIB=n
 */
#endif

#endif /* _RTE_FUNCTION_VERSIONING_H_ */
