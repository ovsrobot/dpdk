/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#include <stdint.h>

#include <rte_alarm.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_log.h>
#ifdef RTE_NET_MLX5
#include "mlx5_testpmd.h"
#endif

#include "testpmd.h"

/* Pretty printing of ethdev events */
static const char * const eth_event_desc[] = {
	[RTE_ETH_EVENT_UNKNOWN] = "unknown",
	[RTE_ETH_EVENT_INTR_LSC] = "link state change",
	[RTE_ETH_EVENT_QUEUE_STATE] = "queue state",
	[RTE_ETH_EVENT_INTR_RESET] = "reset",
	[RTE_ETH_EVENT_VF_MBOX] = "VF mbox",
	[RTE_ETH_EVENT_IPSEC] = "IPsec",
	[RTE_ETH_EVENT_MACSEC] = "MACsec",
	[RTE_ETH_EVENT_INTR_RMV] = "device removal",
	[RTE_ETH_EVENT_NEW] = "device probed",
	[RTE_ETH_EVENT_DESTROY] = "device released",
	[RTE_ETH_EVENT_FLOW_AGED] = "flow aged",
	[RTE_ETH_EVENT_RX_AVAIL_THRESH] = "RxQ available descriptors threshold reached",
	[RTE_ETH_EVENT_ERR_RECOVERING] = "error recovering",
	[RTE_ETH_EVENT_RECOVERY_SUCCESS] = "error recovery successful",
	[RTE_ETH_EVENT_RECOVERY_FAILED] = "error recovery failed",
	[RTE_ETH_EVENT_MAX] = NULL,
};

/*
 * Display or mask ether events
 * Default to all events except VF_MBOX
 */
uint32_t event_print_mask = (UINT32_C(1) << RTE_ETH_EVENT_UNKNOWN) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_LSC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_QUEUE_STATE) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_RESET) |
			    (UINT32_C(1) << RTE_ETH_EVENT_IPSEC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_MACSEC) |
			    (UINT32_C(1) << RTE_ETH_EVENT_INTR_RMV) |
			    (UINT32_C(1) << RTE_ETH_EVENT_FLOW_AGED) |
			    (UINT32_C(1) << RTE_ETH_EVENT_ERR_RECOVERING) |
			    (UINT32_C(1) << RTE_ETH_EVENT_RECOVERY_SUCCESS) |
			    (UINT32_C(1) << RTE_ETH_EVENT_RECOVERY_FAILED);

int
get_event_name_mask(const char *name, uint32_t *mask)
{
	if (!strcmp(name, "unknown"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_UNKNOWN;
	else if (!strcmp(name, "intr_lsc"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_LSC;
	else if (!strcmp(name, "queue_state"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_QUEUE_STATE;
	else if (!strcmp(name, "intr_reset"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_RESET;
	else if (!strcmp(name, "vf_mbox"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_VF_MBOX;
	else if (!strcmp(name, "ipsec"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_IPSEC;
	else if (!strcmp(name, "macsec"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_MACSEC;
	else if (!strcmp(name, "intr_rmv"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_RMV;
	else if (!strcmp(name, "dev_probed"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_NEW;
	else if (!strcmp(name, "dev_released"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_DESTROY;
	else if (!strcmp(name, "flow_aged"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_FLOW_AGED;
	else if (!strcmp(name, "err_recovering"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_ERR_RECOVERING;
	else if (!strcmp(name, "recovery_success"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_RECOVERY_SUCCESS;
	else if (!strcmp(name, "recovery_failed"))
		*mask = UINT32_C(1) << RTE_ETH_EVENT_RECOVERY_FAILED;
	else if (!strcmp(name, "all"))
		*mask = ~UINT32_C(0);
	else
		return -1;

	return 0;
}

static void
rmv_port_callback(void *arg)
{
	int need_to_start = 0;
	int org_no_link_check = no_link_check;
	portid_t port_id = (intptr_t)arg;
	struct rte_eth_dev_info dev_info;
	int ret;

	RTE_ETH_VALID_PORTID_OR_RET(port_id);

	if (!test_done && port_is_forwarding(port_id)) {
		need_to_start = 1;
		stop_packet_forwarding();
	}
	no_link_check = 1;
	stop_port(port_id);
	no_link_check = org_no_link_check;

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		TESTPMD_LOG(ERR,
			"Failed to get device info for port %d, not detaching\n",
			port_id);
	else {
		struct rte_device *device = dev_info.device;
		close_port(port_id);
		detach_device(device); /* might be already removed or have more ports */
	}
	if (need_to_start)
		start_packet_forwarding(0);
}

static int need_start_when_recovery_over;

static bool
has_port_in_err_recovering(void)
{
	struct rte_port *port;
	portid_t pid;

	RTE_ETH_FOREACH_DEV(pid) {
		port = &ports[pid];
		if (port->err_recovering)
			return true;
	}

	return false;
}

static void
err_recovering_callback(portid_t port_id)
{
	if (!has_port_in_err_recovering())
		printf("Please stop executing any commands until recovery result events are received!\n");

	ports[port_id].err_recovering = 1;
	ports[port_id].recover_failed = 0;

	/* To simplify implementation, stop forwarding regardless of whether the port is used. */
	if (!test_done) {
		printf("Stop packet forwarding because some ports are in error recovering!\n");
		stop_packet_forwarding();
		need_start_when_recovery_over = 1;
	}
}

static void
recover_success_callback(portid_t port_id)
{
	ports[port_id].err_recovering = 0;
	if (has_port_in_err_recovering())
		return;

	if (need_start_when_recovery_over) {
		printf("Recovery success! Restart packet forwarding!\n");
		start_packet_forwarding(0);
		need_start_when_recovery_over = 0;
	} else {
		printf("Recovery success!\n");
	}
}

static void
recover_failed_callback(portid_t port_id)
{
	struct rte_port *port;
	portid_t pid;

	ports[port_id].err_recovering = 0;
	ports[port_id].recover_failed = 1;
	if (has_port_in_err_recovering())
		return;

	need_start_when_recovery_over = 0;
	printf("The ports:");
	RTE_ETH_FOREACH_DEV(pid) {
		port = &ports[pid];
		if (port->recover_failed)
			printf(" %u", pid);
	}
	printf(" recovery failed! Please remove them!\n");
}

/* This function is used by the interrupt thread */
static int
eth_event_callback(portid_t port_id, enum rte_eth_event_type type, void *param,
		  void *ret_param)
{
	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

	if (type >= RTE_ETH_EVENT_MAX) {
		fprintf(stderr,
			"\nPort %" PRIu16 ": %s called upon invalid event %d\n",
			port_id, __func__, type);
		fflush(stderr);
	} else if (event_print_mask & (UINT32_C(1) << type)) {
		printf("\nPort %" PRIu16 ": %s event\n", port_id,
			eth_event_desc[type]);
		fflush(stdout);
	}

	switch (type) {
	case RTE_ETH_EVENT_NEW:
		ports[port_id].need_setup = 1;
		ports[port_id].port_status = RTE_PORT_HANDLING;
		break;
	case RTE_ETH_EVENT_INTR_RMV:
		if (port_id_is_invalid(port_id, DISABLED_WARN))
			break;
		if (rte_eal_alarm_set(100000,
				rmv_port_callback, (void *)(intptr_t)port_id))
			fprintf(stderr,
				"Could not set up deferred device removal\n");
		break;
	case RTE_ETH_EVENT_DESTROY:
		ports[port_id].port_status = RTE_PORT_CLOSED;
		printf("Port %u is closed\n", port_id);
		break;
	case RTE_ETH_EVENT_RX_AVAIL_THRESH: {
		uint16_t rxq_id;
		int ret;

		/* avail_thresh query API rewinds rxq_id, no need to check max RxQ num */
		for (rxq_id = 0; ; rxq_id++) {
			ret = rte_eth_rx_avail_thresh_query(port_id, &rxq_id,
							    NULL);
			if (ret <= 0)
				break;
			printf("Received avail_thresh event, port: %u, rxq_id: %u\n",
			       port_id, rxq_id);

#ifdef RTE_NET_MLX5
			mlx5_test_avail_thresh_event_handler(port_id, rxq_id);
#endif
		}
		break;
	}
	case RTE_ETH_EVENT_ERR_RECOVERING:
		err_recovering_callback(port_id);
		break;
	case RTE_ETH_EVENT_RECOVERY_SUCCESS:
		recover_success_callback(port_id);
		break;
	case RTE_ETH_EVENT_RECOVERY_FAILED:
		recover_failed_callback(port_id);
		break;
	default:
		break;
	}
	return 0;
}

int
register_eth_event_callback(void)
{
	int ret;
	enum rte_eth_event_type event;

	for (event = RTE_ETH_EVENT_UNKNOWN;
			event < RTE_ETH_EVENT_MAX; event++) {
		ret = rte_eth_dev_callback_register(RTE_ETH_ALL,
				event,
				eth_event_callback,
				NULL);
		if (ret != 0) {
			TESTPMD_LOG(ERR, "Failed to register callback for "
					"%s event\n", eth_event_desc[event]);
			return -1;
		}
	}

	return 0;
}

int
unregister_eth_event_callback(void)
{
	int ret;
	enum rte_eth_event_type event;

	for (event = RTE_ETH_EVENT_UNKNOWN;
			event < RTE_ETH_EVENT_MAX; event++) {
		ret = rte_eth_dev_callback_unregister(RTE_ETH_ALL,
				event,
				eth_event_callback,
				NULL);
		if (ret != 0) {
			TESTPMD_LOG(ERR, "Failed to unregister callback for "
					"%s event\n", eth_event_desc[event]);
			return -1;
		}
	}

	return 0;
}

/* This function is used by the interrupt thread */
static void
dev_event_callback(const char *device_name, enum rte_dev_event_type type,
			     __rte_unused void *arg)
{
	uint16_t port_id;
	int ret;

	if (type >= RTE_DEV_EVENT_MAX) {
		fprintf(stderr, "%s called upon invalid event %d\n",
			__func__, type);
		fflush(stderr);
	}

	switch (type) {
	case RTE_DEV_EVENT_REMOVE:
		RTE_LOG(DEBUG, EAL, "The device: %s has been removed!\n",
			device_name);
		ret = rte_eth_dev_get_port_by_name(device_name, &port_id);
		if (ret) {
			RTE_LOG(ERR, EAL, "can not get port by device %s!\n",
				device_name);
			return;
		}
		/*
		 * Because the user's callback is invoked in eal interrupt
		 * callback, the interrupt callback need to be finished before
		 * it can be unregistered when detaching device. So finish
		 * callback soon and use a deferred removal to detach device
		 * is need. It is a workaround, once the device detaching be
		 * moved into the eal in the future, the deferred removal could
		 * be deleted.
		 */
		if (rte_eal_alarm_set(100000,
				rmv_port_callback, (void *)(intptr_t)port_id))
			RTE_LOG(ERR, EAL,
				"Could not set up deferred device removal\n");
		break;
	case RTE_DEV_EVENT_ADD:
		RTE_LOG(ERR, EAL, "The device: %s has been added!\n",
			device_name);
		/* TODO: After finish kernel driver binding,
		 * begin to attach port.
		 */
		break;
	default:
		break;
	}
}

int
register_dev_event_callback(void)
{
	int ret;

	ret = rte_dev_event_callback_register(NULL,
		dev_event_callback, NULL);
	if (ret != 0) {
		RTE_LOG(ERR, EAL,
			"fail  to register device event callback\n");
		return -1;
	}

	return 0;
}

int
unregister_dev_event_callback(void)
{
	int ret;

	ret = rte_dev_event_callback_unregister(NULL,
		dev_event_callback, NULL);
	if (ret < 0) {
		RTE_LOG(ERR, EAL,
			"fail to unregister device event callback.\n");
		return -1;
	}

	return 0;
}
