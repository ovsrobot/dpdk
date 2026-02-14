/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/rtnetlink.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <ethdev_driver.h>
#include <rte_interrupts.h>

#include "rtap.h"

/* Interrupt handler called by EAL when netlink socket is readable */
static void
rtap_lsc_handler(void *cb_arg)
{
	struct rte_eth_dev *dev = cb_arg;
	struct rtap_pmd *pmd = dev->data->dev_private;
	int fd = rte_intr_fd_get(pmd->intr_handle);

	if (fd >= 0)
		rtap_nl_recv(fd, dev);
}

/*
 * Enable or disable link state change interrupt.
 * When enabled, creates a netlink socket subscribed to RTMGRP_LINK
 * and registers it with the EAL interrupt handler.
 */
int
rtap_lsc_set(struct rte_eth_dev *dev, int set)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	unsigned int retry = 10;
	int ret;

	/* If LSC not configured, just disable if active */
	if (!dev->data->dev_conf.intr_conf.lsc) {
		if (rte_intr_fd_get(pmd->intr_handle) != -1)
			goto disable;
		return 0;
	}

	if (set) {
		int fd = rtap_nl_open(RTMGRP_LINK);
		if (fd < 0)
			return -1;

		rte_intr_fd_set(pmd->intr_handle, fd);
		ret = rte_intr_callback_register(pmd->intr_handle,
						 rtap_lsc_handler, dev);
		if (ret < 0) {
			PMD_LOG(ERR, "Failed to register LSC callback: %s",
				rte_strerror(-ret));
			close(fd);
			rte_intr_fd_set(pmd->intr_handle, -1);
			return ret;
		}
		return 0;
	}

disable:
	do {
		ret = rte_intr_callback_unregister(pmd->intr_handle,
						   rtap_lsc_handler, dev);
		if (ret >= 0) {
			break;
		} else if (ret == -EAGAIN && retry-- > 0) {
			rte_delay_ms(100);
		} else {
			PMD_LOG(ERR, "LSC callback unregister failed: %d", ret);
			break;
		}
	} while (true);

	if (rte_intr_fd_get(pmd->intr_handle) >= 0) {
		close(rte_intr_fd_get(pmd->intr_handle));
		rte_intr_fd_set(pmd->intr_handle, -1);
	}

	return 0;
}

/*
 * Install per-queue Rx interrupt vector.
 *
 * Each Rx queue has an eventfd registered with its io_uring instance.
 * When a CQE is posted (packet received), the kernel signals the eventfd.
 * This function wires those eventfds into an rte_intr_handle so that
 * DPDK's interrupt framework (rte_epoll_wait) can poll them.
 *
 * Only called when dev_conf.intr_conf.rxq is set.
 */
int
rtap_rx_intr_vec_install(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	uint16_t nb_rx = dev->data->nb_rx_queues;

	if (pmd->rx_intr_handle != NULL) {
		PMD_LOG(DEBUG, "Rx interrupt vector already installed");
		return 0;
	}

	pmd->rx_intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_PRIVATE);
	if (pmd->rx_intr_handle == NULL) {
		PMD_LOG(ERR, "Failed to allocate Rx intr handle");
		return -ENOMEM;
	}

	if (rte_intr_type_set(pmd->rx_intr_handle, RTE_INTR_HANDLE_VDEV) < 0)
		goto error;

	if (rte_intr_nb_efd_set(pmd->rx_intr_handle, nb_rx) < 0)
		goto error;

	if (rte_intr_max_intr_set(pmd->rx_intr_handle, nb_rx + 1) < 0)
		goto error;

	for (uint16_t i = 0; i < nb_rx; i++) {
		struct rtap_rx_queue *rxq = dev->data->rx_queues[i];

		if (rxq == NULL || rxq->intr_fd < 0) {
			PMD_LOG(ERR, "Rx queue %u not ready for interrupts", i);
			goto error;
		}

		if (rte_intr_efds_index_set(pmd->rx_intr_handle, i,
					    rxq->intr_fd) < 0) {
			PMD_LOG(ERR, "Failed to set efd for queue %u", i);
			goto error;
		}
	}

	dev->intr_handle = pmd->rx_intr_handle;
	PMD_LOG(DEBUG, "Rx interrupt vector installed for %u queues", nb_rx);
	return 0;

error:
	rte_intr_instance_free(pmd->rx_intr_handle);
	pmd->rx_intr_handle = NULL;
	return -1;
}

/*
 * Remove per-queue Rx interrupt vector.
 * Restores dev->intr_handle to the LSC handle.
 */
void
rtap_rx_intr_vec_uninstall(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	if (pmd->rx_intr_handle == NULL)
		return;

	/* Restore LSC handle as device interrupt handle */
	dev->intr_handle = pmd->intr_handle;

	rte_intr_instance_free(pmd->rx_intr_handle);
	pmd->rx_intr_handle = NULL;

	PMD_LOG(DEBUG, "Rx interrupt vector uninstalled");
}

/*
 * Enable Rx interrupt for a queue.
 *
 * Drain any pending eventfd notification so the next CQE
 * triggers a fresh wakeup in rte_epoll_wait().
 */
int
rtap_rx_queue_intr_enable(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct rtap_rx_queue *rxq = dev->data->rx_queues[queue_id];
	uint64_t val;

	if (rxq == NULL || rxq->intr_fd < 0)
		return -EINVAL;

	/* Drain the eventfd counter to re-arm notification */
	if (read(rxq->intr_fd, &val, sizeof(val)) < 0 && errno != EAGAIN) {
		PMD_LOG(ERR, "eventfd drain failed queue %u: %s",
			queue_id, strerror(errno));
		return -errno;
	}

	return 0;
}

/*
 * Disable Rx interrupt for a queue.
 *
 * Nothing to do - the eventfd stays registered with io_uring
 * but the application simply stops polling it.
 */
int
rtap_rx_queue_intr_disable(struct rte_eth_dev *dev __rte_unused,
			   uint16_t queue_id __rte_unused)
{
	return 0;
}
