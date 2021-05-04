/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef __CNXK_EVENTDEV_H__
#define __CNXK_EVENTDEV_H__

#include <rte_mbuf_pool_ops.h>
#include <rte_pci.h>

#include <eventdev_pmd_pci.h>

#include "roc_api.h"

#define USEC2NSEC(__us) ((__us)*1E3)

#define CNXK_SSO_FC_NAME       "cnxk_evdev_xaq_fc"
#define CNXK_SSO_MZ_NAME       "cnxk_evdev_mz"
#define CNXK_SSO_XAQ_CACHE_CNT (0x7)
#define CNXK_SSO_XAQ_SLACK     (8)

struct cnxk_sso_evdev {
	struct roc_sso sso;
	uint8_t max_event_queues;
	uint8_t max_event_ports;
	uint8_t is_timeout_deq;
	uint8_t nb_event_queues;
	uint8_t nb_event_ports;
	uint32_t deq_tmo_ns;
	uint32_t min_dequeue_timeout_ns;
	uint32_t max_dequeue_timeout_ns;
	int32_t max_num_events;
	uint64_t *fc_mem;
	uint64_t xaq_lmt;
	uint64_t nb_xaq_cfg;
	rte_iova_t fc_iova;
	struct rte_mempool *xaq_pool;
	/* CN9K */
	uint8_t dual_ws;
} __rte_cache_aligned;

static inline struct cnxk_sso_evdev *
cnxk_sso_pmd_priv(const struct rte_eventdev *event_dev)
{
	return event_dev->data->dev_private;
}

/* Configuration functions */
int cnxk_sso_xaq_allocate(struct cnxk_sso_evdev *dev);

/* Common ops API. */
int cnxk_sso_init(struct rte_eventdev *event_dev);
int cnxk_sso_fini(struct rte_eventdev *event_dev);
int cnxk_sso_remove(struct rte_pci_device *pci_dev);
void cnxk_sso_info_get(struct cnxk_sso_evdev *dev,
		       struct rte_event_dev_info *dev_info);
int cnxk_sso_dev_validate(const struct rte_eventdev *event_dev);
void cnxk_sso_queue_def_conf(struct rte_eventdev *event_dev, uint8_t queue_id,
			     struct rte_event_queue_conf *queue_conf);
int cnxk_sso_queue_setup(struct rte_eventdev *event_dev, uint8_t queue_id,
			 const struct rte_event_queue_conf *queue_conf);
void cnxk_sso_queue_release(struct rte_eventdev *event_dev, uint8_t queue_id);
void cnxk_sso_port_def_conf(struct rte_eventdev *event_dev, uint8_t port_id,
			    struct rte_event_port_conf *port_conf);

#endif /* __CNXK_EVENTDEV_H__ */
