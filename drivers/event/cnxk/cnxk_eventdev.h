/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell International Ltd.
 */

#ifndef __CNXK_EVENTDEV_H__
#define __CNXK_EVENTDEV_H__

#include <rte_devargs.h>
#include <rte_kvargs.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_pci.h>

#include <eventdev_pmd_pci.h>

#include "roc_api.h"

#define CNXK_SSO_XAE_CNT   "xae_cnt"
#define CNXK_SSO_GGRP_QOS  "qos"
#define CN9K_SSO_SINGLE_WS "single_ws"
#define CN10K_SSO_GW_MODE  "gw_mode"

#define NSEC2USEC(__ns)		((__ns) / 1E3)
#define USEC2NSEC(__us)		((__us)*1E3)
#define NSEC2TICK(__ns, __freq) (((__ns) * (__freq)) / 1E9)

#define CNXK_SSO_MAX_HWGRP     (RTE_EVENT_MAX_QUEUES_PER_DEV + 1)
#define CNXK_SSO_FC_NAME       "cnxk_evdev_xaq_fc"
#define CNXK_SSO_MZ_NAME       "cnxk_evdev_mz"
#define CNXK_SSO_XAQ_CACHE_CNT (0x7)
#define CNXK_SSO_XAQ_SLACK     (8)

#define CNXK_TT_FROM_TAG(x)	    (((x) >> 32) & SSO_TT_EMPTY)
#define CNXK_TT_FROM_EVENT(x)	    (((x) >> 38) & SSO_TT_EMPTY)
#define CNXK_EVENT_TYPE_FROM_TAG(x) (((x) >> 28) & 0xf)
#define CNXK_SUB_EVENT_FROM_TAG(x)  (((x) >> 20) & 0xff)
#define CNXK_CLR_SUB_EVENT(x)	    (~(0xffu << 20) & x)
#define CNXK_GRP_FROM_TAG(x)	    (((x) >> 36) & 0x3ff)
#define CNXK_SWTAG_PEND(x)	    (BIT_ULL(62) & x)

#define CN9K_SSOW_GET_BASE_ADDR(_GW) ((_GW)-SSOW_LF_GWS_OP_GET_WORK0)

#define CN10K_GW_MODE_NONE     0
#define CN10K_GW_MODE_PREF     1
#define CN10K_GW_MODE_PREF_WFE 2

typedef void *(*cnxk_sso_init_hws_mem_t)(void *dev, uint8_t port_id);
typedef void (*cnxk_sso_hws_setup_t)(void *dev, void *ws, uintptr_t *grp_base);
typedef void (*cnxk_sso_hws_release_t)(void *dev, void *ws);
typedef int (*cnxk_sso_link_t)(void *dev, void *ws, uint16_t *map,
			       uint16_t nb_link);
typedef int (*cnxk_sso_unlink_t)(void *dev, void *ws, uint16_t *map,
				 uint16_t nb_link);
typedef void (*cnxk_handle_event_t)(void *arg, struct rte_event ev);
typedef void (*cnxk_sso_hws_reset_t)(void *arg, void *ws);
typedef void (*cnxk_sso_hws_flush_t)(void *ws, uint8_t queue_id, uintptr_t base,
				     cnxk_handle_event_t fn, void *arg);

struct cnxk_sso_qos {
	uint16_t queue;
	uint8_t xaq_prcnt;
	uint8_t taq_prcnt;
	uint8_t iaq_prcnt;
};

struct cnxk_sso_evdev {
	struct roc_sso sso;
	uint8_t max_event_queues;
	uint8_t max_event_ports;
	uint8_t is_timeout_deq;
	uint8_t nb_event_queues;
	uint8_t nb_event_ports;
	uint8_t configured;
	uint32_t deq_tmo_ns;
	uint32_t min_dequeue_timeout_ns;
	uint32_t max_dequeue_timeout_ns;
	int32_t max_num_events;
	uint64_t *fc_mem;
	uint64_t xaq_lmt;
	uint64_t nb_xaq_cfg;
	rte_iova_t fc_iova;
	struct rte_mempool *xaq_pool;
	/* Dev args */
	uint32_t xae_cnt;
	uint8_t qos_queue_cnt;
	struct cnxk_sso_qos *qos_parse_data;
	/* CN9K */
	uint8_t dual_ws;
	/* CN10K */
	uint8_t gw_mode;
} __rte_cache_aligned;

/* CN10K HWS ops */
#define CN10K_SSO_HWS_OPS                                                      \
	uintptr_t swtag_desched_op;                                            \
	uintptr_t swtag_flush_op;                                              \
	uintptr_t swtag_untag_op;                                              \
	uintptr_t swtag_norm_op;                                               \
	uintptr_t updt_wqe_op;                                                 \
	uintptr_t tag_wqe_op;                                                  \
	uintptr_t getwrk_op

struct cn10k_sso_hws {
	/* Get Work Fastpath data */
	CN10K_SSO_HWS_OPS;
	uint32_t gw_wdata;
	uint8_t swtag_req;
	uint8_t hws_id;
	/* Add Work Fastpath data */
	uint64_t xaq_lmt __rte_cache_aligned;
	uint64_t *fc_mem;
	uintptr_t grps_base[CNXK_SSO_MAX_HWGRP];
	uint64_t base;
	uintptr_t lmt_base;
} __rte_cache_aligned;

/* CN9K HWS ops */
#define CN9K_SSO_HWS_OPS                                                       \
	uintptr_t swtag_desched_op;                                            \
	uintptr_t swtag_flush_op;                                              \
	uintptr_t swtag_norm_op;                                               \
	uintptr_t getwrk_op;                                                   \
	uintptr_t tag_op;                                                      \
	uintptr_t wqp_op

/* Event port aka GWS */
struct cn9k_sso_hws {
	/* Get Work Fastpath data */
	CN9K_SSO_HWS_OPS;
	uint8_t swtag_req;
	uint8_t hws_id;
	/* Add Work Fastpath data */
	uint64_t xaq_lmt __rte_cache_aligned;
	uint64_t *fc_mem;
	uintptr_t grps_base[CNXK_SSO_MAX_HWGRP];
	uint64_t base;
} __rte_cache_aligned;

struct cn9k_sso_hws_state {
	CN9K_SSO_HWS_OPS;
};

struct cn9k_sso_hws_dual {
	/* Get Work Fastpath data */
	struct cn9k_sso_hws_state ws_state[2]; /* Ping and Pong */
	uint8_t swtag_req;
	uint8_t vws; /* Ping pong bit */
	uint8_t hws_id;
	/* Add Work Fastpath data */
	uint64_t xaq_lmt __rte_cache_aligned;
	uint64_t *fc_mem;
	uintptr_t grps_base[CNXK_SSO_MAX_HWGRP];
	uint64_t base[2];
} __rte_cache_aligned;

struct cnxk_sso_hws_cookie {
	const struct rte_eventdev *event_dev;
	bool configured;
} __rte_cache_aligned;

static inline int
parse_kvargs_value(const char *key, const char *value, void *opaque)
{
	RTE_SET_USED(key);

	*(uint32_t *)opaque = (uint32_t)atoi(value);
	return 0;
}

static inline struct cnxk_sso_evdev *
cnxk_sso_pmd_priv(const struct rte_eventdev *event_dev)
{
	return event_dev->data->dev_private;
}

static inline struct cnxk_sso_hws_cookie *
cnxk_sso_hws_get_cookie(void *ws)
{
	return RTE_PTR_SUB(ws, sizeof(struct cnxk_sso_hws_cookie));
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
int cnxk_setup_event_ports(const struct rte_eventdev *event_dev,
			   cnxk_sso_init_hws_mem_t init_hws_mem,
			   cnxk_sso_hws_setup_t hws_setup);
void cnxk_sso_restore_links(const struct rte_eventdev *event_dev,
			    cnxk_sso_link_t link_fn);
void cnxk_sso_queue_def_conf(struct rte_eventdev *event_dev, uint8_t queue_id,
			     struct rte_event_queue_conf *queue_conf);
int cnxk_sso_queue_setup(struct rte_eventdev *event_dev, uint8_t queue_id,
			 const struct rte_event_queue_conf *queue_conf);
void cnxk_sso_queue_release(struct rte_eventdev *event_dev, uint8_t queue_id);
void cnxk_sso_port_def_conf(struct rte_eventdev *event_dev, uint8_t port_id,
			    struct rte_event_port_conf *port_conf);
int cnxk_sso_port_setup(struct rte_eventdev *event_dev, uint8_t port_id,
			cnxk_sso_hws_setup_t hws_setup_fn);
int cnxk_sso_timeout_ticks(struct rte_eventdev *event_dev, uint64_t ns,
			   uint64_t *tmo_ticks);
int cnxk_sso_start(struct rte_eventdev *event_dev,
		   cnxk_sso_hws_reset_t reset_fn,
		   cnxk_sso_hws_flush_t flush_fn);
void cnxk_sso_stop(struct rte_eventdev *event_dev,
		   cnxk_sso_hws_reset_t reset_fn,
		   cnxk_sso_hws_flush_t flush_fn);
int cnxk_sso_close(struct rte_eventdev *event_dev, cnxk_sso_unlink_t unlink_fn);
int cnxk_sso_selftest(const char *dev_name);
void cnxk_sso_dump(struct rte_eventdev *event_dev, FILE *f);

/* CN9K */
void cn9k_sso_set_rsrc(void *arg);

#endif /* __CNXK_EVENTDEV_H__ */
