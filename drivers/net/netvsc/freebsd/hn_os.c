/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Microsoft Corporation
 */

#include <stdio.h>

#include <rte_common.h>

#include "hn_logs.h"
#include "hn_os.h"

int eth_hn_os_dev_event(void)
{
	PMD_DRV_LOG(DEBUG, "rte_dev_event_monitor_start not supported on FreeBSD");
	return 0;
}
