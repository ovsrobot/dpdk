/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <fnmatch.h>
#include <sys/queue.h>
#include <unistd.h>
#include <rte_os_shim.h>

#include <rte_log.h>
#include <rte_per_lcore.h>

#include "log_internal.h"
#include "log_private.h"

/* Stubs for Windows */
int
eal_log_syslog(const char *str __rte_unused)
{
	return -1;
}
