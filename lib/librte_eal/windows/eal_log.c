/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */

#include "eal_private.h"

/* set the log to default function, called during eal init process. */
int
rte_eal_log_init(__rte_unused const char *id, __rte_unused int facility)
{
	rte_openlog_stream(stderr);

	eal_log_set_default(stderr);

	return 0;
}

/*
 * Set the customized logger, it will override the default stream write action,
 * which is writing to syslog and stdout.
 */
void
rte_log_sink_set(rte_log_write_function* logf)
{
	RTE_SET_USED(logf);
	return;
}

/*
 * Retrieve the default log write function.
 */
rte_log_write_function*
rte_log_sink_get(void) {
    return NULL;
}
