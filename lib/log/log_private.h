/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LOG_PRIVATE_H
#define LOG_PRIVATE_H

#ifndef RTE_EXEC_ENV_WINDOWS
FILE *log_syslog_open(const char *id);
#endif

bool log_timestamp_enabled(void);
ssize_t log_timestamp(char *tsbuf, size_t tsbuflen);

__rte_format_printf(2, 0)
int log_print_with_timestamp(FILE *f, const char *format, va_list ap);

#endif /* LOG_PRIVATE_H */
