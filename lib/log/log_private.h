/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LOG_PRIVATE_H
#define LOG_PRIVATE_H

/* Note: same as vfprintf() */
typedef int (*log_print_t)(FILE *f, const char *fmt, va_list ap);

#endif /* LOG_PRIVATE_H */
