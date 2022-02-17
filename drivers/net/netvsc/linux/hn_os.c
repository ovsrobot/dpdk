/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Microsoft Corporation
 */

#include <unistd.h>

#include <rte_ethdev.h>

#include "hn_logs.h"
#include "hn_os.h"

int eth_hn_os_dev_event(void)
{
	int ret;

	ret = rte_dev_event_monitor_start();
	if (ret)
		PMD_DRV_LOG(ERR, "Failed to start device event monitoring");

	return ret;
}
