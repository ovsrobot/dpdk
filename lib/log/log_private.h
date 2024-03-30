/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LOG_PRIVATE_H
#define LOG_PRIVATE_H

typedef int (*log_print_t)(FILE *f, uint32_t level, const char *fmt, va_list ap);

__rte_format_printf(3, 0)
int log_print(FILE *f, uint32_t level, const char *format, va_list ap);

bool log_timestamp_enabled(void);

ssize_t log_timestamp(char *tsbuf, size_t tsbuflen);

__rte_format_printf(3, 0)
int log_print_with_timestamp(FILE *f, uint32_t level, const char *format, va_list ap);

bool log_syslog_enabled(bool is_tty);
void log_syslog_open(const char *id, bool is_terminal);

bool log_journal_enabled(const char *id);

__rte_format_printf(3, 0)
int journal_print(FILE *f, uint32_t level, const char *format, va_list ap);

bool log_color_enabled(bool is_tty);

__rte_format_printf(3, 0)
int color_print(FILE *f, uint32_t level, const char *format, va_list ap);

__rte_format_printf(3, 0)
int color_print_with_timestamp(FILE *f, uint32_t level, const char *format, va_list ap);

#endif /* LOG_PRIVATE_H */
