/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#ifndef EAL_LOG_H
#define EAL_LOG_H

#include <stdio.h>
#include <stdint.h>

/*
 * Initialize the default log stream.
 */
int eal_log_init(const char *id, int facility);

/*
 * Determine where log data is written when no call to rte_openlog_stream.
 */
void eal_log_set_default(FILE *default_log);

/*
 * Save a log option for later.
 */
int eal_log_save_regexp(const char *regexp, int priority);
int eal_log_save_pattern(const char *pattern, int priority);

#endif /* EAL_LOG_H */
