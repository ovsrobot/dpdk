/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#ifndef RTE_SYSFS_H
#define RTE_SYSFS_H

/**
 * @file
 * @internal
 *
 * Helpers to read and write single values in sysfs, used across DPDK.
 *
 * All of these build the path from a printf-style format, so that
 * callers do not have to construct it separately.
 */

#include <stdarg.h>
#include <stddef.h>

#include <rte_common.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read an unsigned numeric value from a file, typically under /sys.
 *
 * The value is parsed with strtoul() using base 0, so decimal, octal
 * and 0x-prefixed hexadecimal are all accepted. A negative value is
 * rejected rather than wrapping; use rte_sysfs_parse_int() for the
 * attributes that are signed.
 *
 * @param val
 *   Where to store the parsed value, unmodified on failure.
 * @param format
 *   printf-style format describing the path to read.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
__rte_format_printf(2, 3)
int rte_sysfs_parse_uint(unsigned long *val, const char *format, ...);

/**
 * Read an unsigned numeric value from a file, typically under /sys.
 *
 * As rte_sysfs_parse_uint(), but takes a va_list, so that a wrapper
 * can forward its arguments without formatting the path itself.
 *
 * @param val
 *   Where to store the parsed value, unmodified on failure.
 * @param format
 *   printf-style format describing the path to read.
 * @param ap
 *   Arguments for the format.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
__rte_format_printf(2, 0)
int rte_sysfs_vparse_uint(unsigned long *val, const char *format, va_list ap);

/**
 * Read a signed numeric value from a file, typically under /sys.
 *
 * The value is parsed with strtol() using base 0. Some sysfs
 * attributes are signed, most notably "numa_node" which is -1 when
 * the device is not associated with any NUMA node.
 *
 * @param val
 *   Where to store the parsed value, unmodified on failure.
 * @param format
 *   printf-style format describing the path to read.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
__rte_format_printf(2, 3)
int rte_sysfs_parse_int(long *val, const char *format, ...);

/**
 * Read a string value from a file, typically under /sys.
 *
 * The trailing newline, if any, is stripped.
 *
 * @param buf
 *   Where to store the NUL-terminated value. The contents are
 *   indeterminate on failure.
 * @param buflen
 *   Size of buf, the value is truncated if it does not fit.
 * @param format
 *   printf-style format describing the path to read.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
__rte_format_printf(3, 4)
int rte_sysfs_parse_string(char *buf, size_t buflen, const char *format, ...);

/**
 * Write a string value to a file, typically under /sys.
 *
 * @param str
 *   The NUL-terminated value to write.
 * @param format
 *   printf-style format describing the path to write.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
__rte_format_printf(2, 3)
int rte_sysfs_write_string(const char *str, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* RTE_SYSFS_H */
