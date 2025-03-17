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

/*
 * Provides backwards compatibility when updating exported functions.
 * When a symbol is exported from a library to provide an API, it also provides a
 * calling convention (ABI) that is embodied in its name, return type,
 * arguments, etc.  On occasion that function may need to change to accommodate
 * new functionality, behavior, etc.  When that occurs, it is desirable to
 * allow for backwards compatibility for a time with older binaries that are
 * dynamically linked to the dpdk.
 */

#ifdef RTE_BUILD_SHARED_LIB

/*
 * RTE_VERSION_SYMBOL
 * Creates a symbol version table entry binding symbol <name>@DPDK_<ver> to the internal
 * function name <name>_v<ver>.
 */
#define RTE_VERSION_SYMBOL(ver, type, name, args) \
__asm__(".symver " RTE_STR(name) "_v" RTE_STR(ver) ", " RTE_STR(name) "@DPDK_" RTE_STR(ver)); \
__rte_used type name ## _v ## ver args; \
type name ## _v ## ver args

/*
 * RTE_VERSION_EXPERIMENTAL_SYMBOL
 * Similar to RTE_VERSION_SYMBOL but for experimental API symbols.
 * This is mainly used for keeping compatibility for symbols that get promoted to stable ABI.
 */
#define RTE_VERSION_EXPERIMENTAL_SYMBOL(type, name, args) \
__asm__(".symver " RTE_STR(name) "_exp, " RTE_STR(name) "@EXPERIMENTAL") \
__rte_used type name ## _exp args; \
type name ## _exp args

/*
 * RTE_DEFAULT_SYMBOL
 * Creates a symbol version entry instructing the linker to bind references to
 * symbol <name> to the internal symbol <name>_v<ver>.
 */
#define RTE_DEFAULT_SYMBOL(ver, type, name, args) \
__asm__(".symver " RTE_STR(name) "_v" RTE_STR(ver) ", " RTE_STR(name) "@@DPDK_" RTE_STR(ver)); \
__rte_used type name ## _v ## ver args; \
type name ## _v ## ver args

#else /* !RTE_BUILD_SHARED_LIB */

#define RTE_VERSION_SYMBOL(ver, type, name, args) \
type name ## _v ## ver args; \
type name ## _v ## ver args

#define RTE_VERSION_EXPERIMENTAL_SYMBOL(type, name, args) \
type name ## _exp args; \
type name ## _exp args

#define RTE_DEFAULT_SYMBOL(ver, type, name, args) \
type name args

#endif /* RTE_BUILD_SHARED_LIB */

#endif /* _RTE_FUNCTION_VERSIONING_H_ */
