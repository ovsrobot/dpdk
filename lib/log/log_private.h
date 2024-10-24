/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LOG_PRIVATE_H
#define LOG_PRIVATE_H

#ifdef RTE_EXEC_ENV_WINDOWS
#define log_syslog_enabled()  (false)
#define log_syslog_open(id)   (NULL)
#else
bool log_syslog_enabled(void);
FILE *log_syslog_open(const char *id);
#endif

#ifdef RTE_EXEC_ENV_LINUX
bool log_journal_enabled(void);
FILE *log_journal_open(const char *id);
#else
#define log_journal_enabled() (false)
#define log_journal_open(id)  (NULL)
#endif /* !RTE_EXEC_ENV_LINUX */

bool log_timestamp_enabled(void);
ssize_t log_timestamp(char *tsbuf, size_t tsbuflen);

__rte_format_printf(2, 0)
int log_print_with_timestamp(FILE *f, const char *format, va_list ap);

#endif /* LOG_PRIVATE_H */
