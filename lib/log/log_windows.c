/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */

#include <rte_common.h>
#include <rte_log.h>
#include "log_internal.h"

int
eal_log_syslog(const char *name __rte_unused)
{
	return -1; /* not used */
}

/* set the log to default function, called during eal init process. */
int
eal_log_init(__rte_unused const char *id)
{
	rte_openlog_stream(stderr);

	eal_log_set_default(stderr);

	return 0;
}
