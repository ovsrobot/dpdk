/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LOG_PRIVATE_H
#define LOG_PRIVATE_H

#ifndef RTE_EXEC_ENV_WINDOWS
FILE *log_syslog_open(const char *id);
#endif

#endif /* LOG_PRIVATE_H */
