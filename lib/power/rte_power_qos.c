/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 HiSilicon Limited
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_log.h>

#include "power_common.h"
#include "rte_power_qos.h"

#define QOS_CPU_DMA_LATENCY_DEV "/dev/cpu_dma_latency"

struct rte_power_qos_info {
	/*
	 * Keep file descriptor to update QoS request until there are no
	 * necessary anymore.
	 */
	int fd;
	int cur_cpu_latency; /* unit microseconds */
	};

struct rte_power_qos_info g_qos = {
	.fd = -1,
	.cur_cpu_latency = -1,
};

int
rte_power_qos_get_curr_cpu_latency(int *latency)
{
	int fd, ret;

	fd = open(QOS_CPU_DMA_LATENCY_DEV, O_RDONLY);
	if (fd < 0) {
		POWER_LOG(ERR, "Failed to open %s", QOS_CPU_DMA_LATENCY_DEV);
		return -1;
	}

	ret = read(fd, latency, sizeof(*latency));
	if (ret == 0) {
		POWER_LOG(ERR, "Failed to read %s", QOS_CPU_DMA_LATENCY_DEV);
		return -1;
	}
	close(fd);

	return 0;
}

int
rte_power_qos_update_request(int latency)
{
	int ret;

	if (g_qos.fd == -1) {
		POWER_LOG(ERR, "please create QoS request first.");
		return -EINVAL;
	}

	if (latency < 0) {
		POWER_LOG(ERR, "latency should be non negative number.");
		return -EINVAL;
	}

	if (g_qos.cur_cpu_latency != -1 && latency == g_qos.cur_cpu_latency)
		return 0;

	ret = write(g_qos.fd, &latency, sizeof(latency));
	if (ret == 0) {
		POWER_LOG(ERR, "Failed to write %s", QOS_CPU_DMA_LATENCY_DEV);
		return -1;
	}
	g_qos.cur_cpu_latency = latency;

	return 0;
}

int
rte_power_create_qos_request(void)
{
	g_qos.fd = open(QOS_CPU_DMA_LATENCY_DEV, O_WRONLY);
	if (g_qos.fd < 0) {
		POWER_LOG(ERR, "Failed to open %s.", QOS_CPU_DMA_LATENCY_DEV);
		return -1;
	}

	return 0;
}

void
rte_power_release_qos_request(void)
{
	if (g_qos.fd != -1) {
		close(g_qos.fd);
		g_qos.fd = -1;
	}
}
