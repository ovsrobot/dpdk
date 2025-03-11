/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Red Hat, Inc.
 */

#ifndef RTE_EXPORT_H
#define RTE_EXPORT_H

/* *Internal* macros for exporting symbols, used by the build system.
 * For RTE_EXPORT_EXPERIMENTAL_SYMBOL, ver indicates the
 * version this symbol was introduced in.
 */
#define RTE_EXPORT_EXPERIMENTAL_SYMBOL(a, ver)
#define RTE_EXPORT_INTERNAL_SYMBOL(a)
#define RTE_EXPORT_SYMBOL(a)

#endif /* RTE_EXPORT_H */
