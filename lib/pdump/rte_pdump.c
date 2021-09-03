/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2018 Intel Corporation
 */

#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_pcapng.h>

#include "rte_pdump.h"

RTE_LOG_REGISTER_DEFAULT(pdump_logtype, NOTICE);

/* Macro for printing using RTE_LOG */
#define PDUMP_LOG(level, fmt, args...)				\
	rte_log(RTE_LOG_ ## level, pdump_logtype, "%s(): " fmt,	\
		__func__, ## args)

/* Used for the multi-process communication */
#define PDUMP_MP	"mp_pdump"

enum pdump_operation {
	DISABLE = 1,
	ENABLE = 2
};

/*
 * Note: version numbers intentionally start at 3
 * in order to catch any application built with older out
 * version of DPDK using incompatiable client request format.
 */
enum pdump_version {
	PDUMP_CLIENT_LEGACY = 3,
	PDUMP_CLIENT_PCAPNG = 4,
};

struct pdump_request {
	uint16_t ver;
	uint16_t op;
	uint16_t flags;
	uint16_t queue;
	struct rte_ring *ring;
	struct rte_mempool *mp;
	const struct rte_bpf *filter;
	uint32_t snaplen;
	char device[RTE_DEV_NAME_MAX_LEN];
};

struct pdump_response {
	uint16_t ver;
	uint16_t res_op;
	int32_t err_value;
};

static struct pdump_rxtx_cbs {
	struct rte_ring *ring;
	struct rte_mempool *mp;
	const struct rte_eth_rxtx_callback *cb;
	const struct rte_bpf *filter;
	enum pdump_version ver;
	uint32_t snaplen;
	struct rte_pdump_stats stats;
} rx_cbs[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT],
tx_cbs[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];


static void
pdump_copy(uint16_t port_id, uint16_t queue,
	   enum rte_pcapng_direction direction,
	   struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_params)
{
	unsigned int i;
	int ring_enq;
	uint16_t d_pkts = 0;
	struct rte_mbuf *dup_bufs[nb_pkts];
	struct pdump_rxtx_cbs *cbs = user_params;
	uint64_t ts;
	struct rte_ring *ring;
	struct rte_mempool *mp;
	struct rte_mbuf *p;
	uint64_t bpf_rc[nb_pkts];

	if (cbs->filter &&
	    !rte_bpf_exec_burst(cbs->filter, (void **)pkts, bpf_rc, nb_pkts))
		return;	/* our work here is done */

	ts = rte_get_tsc_cycles();
	ring = cbs->ring;
	mp = cbs->mp;
	for (i = 0; i < nb_pkts; i++) {
		/*
		 * Similar behavior to rte_bpf_eth callback.
		 * if BPF program returns zero value for a given packet,
		 * then it will be ignored.
		 */
		if (cbs->filter && bpf_rc[i] == 0)
			continue;

		/*
		 * If using pcapng then want to wrap packets
		 * otherwise a simple copy.
		 */
		if (cbs->ver == PDUMP_CLIENT_PCAPNG)
			p = rte_pcapng_copy(port_id, queue,
					    pkts[i], mp, cbs->snaplen,
					    ts, direction);
		else
			p = rte_pktmbuf_copy(pkts[i], mp, 0, cbs->snaplen);

		if (likely(p != NULL))
			dup_bufs[d_pkts++] = p;
	}

	cbs->stats.accepted += d_pkts;
	ring_enq = rte_ring_enqueue_burst(ring, (void *)dup_bufs, d_pkts, NULL);
	if (unlikely(ring_enq < d_pkts)) {
		unsigned int drops = d_pkts - ring_enq;

		cbs->stats.missed += drops;
		PDUMP_LOG(DEBUG,
			"only %d of packets enqueued to ring\n", ring_enq);
		rte_pktmbuf_free_bulk(&dup_bufs[ring_enq], drops);
	}
}

static uint16_t
pdump_rx(uint16_t port, uint16_t queue,
	struct rte_mbuf **pkts, uint16_t nb_pkts,
	uint16_t max_pkts __rte_unused,
	void *user_params)
{
	pdump_copy(port, queue, RTE_PCAPNG_DIRECTION_IN,
		   pkts, nb_pkts, user_params);
	return nb_pkts;
}

static uint16_t
pdump_tx(uint16_t port, uint16_t queue,
		struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_params)
{
	pdump_copy(port, queue, RTE_PCAPNG_DIRECTION_OUT,
		   pkts, nb_pkts, user_params);
	return nb_pkts;
}

static int
pdump_register_rx_callbacks(enum pdump_version ver,
			    uint16_t end_q, uint16_t port, uint16_t queue,
			    struct rte_ring *ring, struct rte_mempool *mp,
			    uint16_t operation, uint32_t snaplen)
{
	uint16_t qid;

	qid = (queue == RTE_PDUMP_ALL_QUEUES) ? 0 : queue;
	for (; qid < end_q; qid++) {
		struct pdump_rxtx_cbs *cbs = &rx_cbs[port][qid];

		if (operation == ENABLE) {
			if (cbs->cb) {
				PDUMP_LOG(ERR,
					"rx callback for port=%d queue=%d, already exists\n",
					port, qid);
				return -EEXIST;
			}
			cbs->ver = ver;
			cbs->ring = ring;
			cbs->mp = mp;
			cbs->snaplen = snaplen;
			memset(&cbs->stats, 0, sizeof(cbs->stats));

			cbs->cb = rte_eth_add_first_rx_callback(port, qid,
								pdump_rx, cbs);
			if (cbs->cb == NULL) {
				PDUMP_LOG(ERR,
					"failed to add rx callback, errno=%d\n",
					rte_errno);
				return rte_errno;
			}
		} else if (operation == DISABLE) {
			int ret;

			if (cbs->cb == NULL) {
				PDUMP_LOG(ERR,
					"no existing rx callback for port=%d queue=%d\n",
					port, qid);
				return -EINVAL;
			}
			ret = rte_eth_remove_rx_callback(port, qid, cbs->cb);
			if (ret < 0) {
				PDUMP_LOG(ERR,
					"failed to remove rx callback, errno=%d\n",
					-ret);
				return ret;
			}
			cbs->cb = NULL;
		}
	}

	return 0;
}

static int
pdump_register_tx_callbacks(enum pdump_version ver,
			    uint16_t end_q, uint16_t port, uint16_t queue,
			    struct rte_ring *ring, struct rte_mempool *mp,
			    uint16_t operation, uint32_t snaplen)
{

	uint16_t qid;

	qid = (queue == RTE_PDUMP_ALL_QUEUES) ? 0 : queue;
	for (; qid < end_q; qid++) {
		struct pdump_rxtx_cbs *cbs = &tx_cbs[port][qid];

		if (operation == ENABLE) {
			if (cbs->cb) {
				PDUMP_LOG(ERR,
					"tx callback for port=%d queue=%d, already exists\n",
					port, qid);
				return -EEXIST;
			}
			cbs->ver = ver;
			cbs->ring = ring;
			cbs->mp = mp;
			cbs->snaplen = snaplen;
			memset(&cbs->stats, 0, sizeof(cbs->stats));
			cbs->cb = rte_eth_add_tx_callback(port, qid, pdump_tx,
								cbs);
			if (cbs->cb == NULL) {
				PDUMP_LOG(ERR,
					"failed to add tx callback, errno=%d\n",
					rte_errno);
				return rte_errno;
			}
		} else if (operation == DISABLE) {
			int ret;

			if (cbs->cb == NULL) {
				PDUMP_LOG(ERR,
					"no existing tx callback for port=%d queue=%d\n",
					port, qid);
				return -EINVAL;
			}
			ret = rte_eth_remove_tx_callback(port, qid, cbs->cb);
			if (ret < 0) {
				PDUMP_LOG(ERR,
					"failed to remove tx callback, errno=%d\n",
					-ret);
				return ret;
			}
			cbs->cb = NULL;
		}
	}

	return 0;
}

static int
set_pdump_rxtx_cbs(const struct pdump_request *p)
{
	uint16_t nb_rx_q = 0, nb_tx_q = 0, end_q, queue;
	uint16_t port;
	int ret = 0;
	uint32_t flags;
	uint16_t operation;
	struct rte_ring *ring;
	struct rte_mempool *mp;

	if (!(p->ver == PDUMP_CLIENT_LEGACY ||
	      p->ver == PDUMP_CLIENT_PCAPNG)) {
		PDUMP_LOG(ERR,
			  "incorrect client version %u\n", p->ver);
		return -EINVAL;
	}

	flags = p->flags;
	operation = p->op;
	queue = p->queue;
	ring = p->ring;
	mp = p->mp;

	ret = rte_eth_dev_get_port_by_name(p->device, &port);
	if (ret < 0) {
		PDUMP_LOG(ERR,
			  "failed to get port id for device id=%s\n",
			  p->device);
		return -EINVAL;
	}

	/* validation if packet capture is for all queues */
	if (queue == RTE_PDUMP_ALL_QUEUES) {
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(port, &dev_info);
		if (ret != 0) {
			PDUMP_LOG(ERR,
				"Error during getting device (port %u) info: %s\n",
				port, strerror(-ret));
			return ret;
		}

		nb_rx_q = dev_info.nb_rx_queues;
		nb_tx_q = dev_info.nb_tx_queues;
		if (nb_rx_q == 0 && flags & RTE_PDUMP_FLAG_RX) {
			PDUMP_LOG(ERR,
				"number of rx queues cannot be 0\n");
			return -EINVAL;
		}
		if (nb_tx_q == 0 && flags & RTE_PDUMP_FLAG_TX) {
			PDUMP_LOG(ERR,
				"number of tx queues cannot be 0\n");
			return -EINVAL;
		}
		if ((nb_tx_q == 0 || nb_rx_q == 0) &&
			flags == RTE_PDUMP_FLAG_RXTX) {
			PDUMP_LOG(ERR,
				"both tx&rx queues must be non zero\n");
			return -EINVAL;
		}
	}

	/* register RX callback */
	if (flags & RTE_PDUMP_FLAG_RX) {
		end_q = (queue == RTE_PDUMP_ALL_QUEUES) ? nb_rx_q : queue + 1;
		ret = pdump_register_rx_callbacks(p->ver, end_q, port, queue, ring, mp,
						  operation, p->snaplen);
		if (ret < 0)
			return ret;
	}

	/* register TX callback */
	if (flags & RTE_PDUMP_FLAG_TX) {
		end_q = (queue == RTE_PDUMP_ALL_QUEUES) ? nb_tx_q : queue + 1;
		ret = pdump_register_tx_callbacks(p->ver, end_q, port, queue, ring, mp,
						  operation, p->snaplen);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static int
pdump_server(const struct rte_mp_msg *mp_msg, const void *peer)
{
	struct rte_mp_msg mp_resp;
	const struct pdump_request *cli_req;
	struct pdump_response *resp = (struct pdump_response *)&mp_resp.param;

	/* recv client requests */
	if (mp_msg->len_param != sizeof(*cli_req)) {
		PDUMP_LOG(ERR, "failed to recv from client\n");
		resp->err_value = -EINVAL;
	} else {
		cli_req = (const struct pdump_request *)mp_msg->param;
		resp->ver = cli_req->ver;
		resp->res_op = cli_req->op;
		resp->err_value = set_pdump_rxtx_cbs(cli_req);
	}

	strlcpy(mp_resp.name, PDUMP_MP, RTE_MP_MAX_NAME_LEN);
	mp_resp.len_param = sizeof(*resp);
	mp_resp.num_fds = 0;
	if (rte_mp_reply(&mp_resp, peer) < 0) {
		PDUMP_LOG(ERR, "failed to send to client:%s\n",
			  strerror(rte_errno));
		return -1;
	}

	return 0;
}

int
rte_pdump_init(void)
{
	int ret;

	rte_pcapng_init();

	ret = rte_mp_action_register(PDUMP_MP, pdump_server);
	if (ret && rte_errno != ENOTSUP)
		return -1;
	return 0;
}

int
rte_pdump_uninit(void)
{
	rte_mp_action_unregister(PDUMP_MP);

	return 0;
}

static int
pdump_validate_ring_mp(struct rte_ring *ring, struct rte_mempool *mp)
{
	if (ring == NULL || mp == NULL) {
		PDUMP_LOG(ERR, "NULL ring or mempool\n");
		rte_errno = EINVAL;
		return -1;
	}
	if (mp->flags & MEMPOOL_F_SP_PUT || mp->flags & MEMPOOL_F_SC_GET) {
		PDUMP_LOG(ERR,
			  "mempool with SP or SC set not valid for pdump,"
			  "must have MP and MC set\n");
		rte_errno = EINVAL;
		return -1;
	}
	if (rte_ring_is_prod_single(ring) || rte_ring_is_cons_single(ring)) {
		PDUMP_LOG(ERR,
			  "ring with SP or SC set is not valid for pdump,"
			  "must have MP and MC set\n");
		rte_errno = EINVAL;
		return -1;
	}

	return 0;
}

static int
pdump_validate_flags(uint32_t flags)
{
	if ((flags & RTE_PDUMP_FLAG_RXTX) == 0) {
		PDUMP_LOG(ERR,
			"invalid flags, should be either rx/tx/rxtx\n");
		rte_errno = EINVAL;
		return -1;
	}

	/* mask off the flags we know about */
	if (flags & ~(RTE_PDUMP_FLAG_RXTX | RTE_PDUMP_FLAG_PCAPNG)) {
		PDUMP_LOG(ERR,
			  "unknown flags: %#x\n", flags);
		rte_errno = ENOTSUP;
		return -1;
	}

	return 0;
}

static int
pdump_validate_port(uint16_t port, char *name)
{
	int ret = 0;

	if (port >= RTE_MAX_ETHPORTS) {
		PDUMP_LOG(ERR, "Invalid port id %u\n", port);
		rte_errno = EINVAL;
		return -1;
	}

	ret = rte_eth_dev_get_name_by_port(port, name);
	if (ret < 0) {
		PDUMP_LOG(ERR, "port %u to name mapping failed\n",
			  port);
		rte_errno = EINVAL;
		return -1;
	}

	return 0;
}

static int
pdump_prepare_client_request(const char *device, uint16_t queue,
			     uint32_t flags, uint32_t snaplen,
			     uint16_t operation,
			     struct rte_ring *ring,
			     struct rte_mempool *mp,
			     const struct rte_bpf *filter)
{
	int ret = -1;
	struct rte_mp_msg mp_req, *mp_rep;
	struct rte_mp_reply mp_reply;
	struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
	struct pdump_request *req = (struct pdump_request *)mp_req.param;
	struct pdump_response *resp;

	memset(req, 0, sizeof(*req));
	if (flags & RTE_PDUMP_FLAG_PCAPNG)
		req->ver = PDUMP_CLIENT_PCAPNG;
	else
		req->ver = PDUMP_CLIENT_LEGACY;

	req->flags = flags & RTE_PDUMP_FLAG_RXTX;
	req->op = operation;
	req->queue = queue;
	strlcpy(req->device, device,sizeof(req->device));

	if ((operation & ENABLE) != 0) {
		req->queue = queue;
		req->ring = ring;
		req->mp = mp;
		req->filter = filter;
		req->snaplen = snaplen;
	}

	strlcpy(mp_req.name, PDUMP_MP, RTE_MP_MAX_NAME_LEN);
	mp_req.len_param = sizeof(*req);
	mp_req.num_fds = 0;
	if (rte_mp_request_sync(&mp_req, &mp_reply, &ts) == 0) {
		mp_rep = &mp_reply.msgs[0];
		resp = (struct pdump_response *)mp_rep->param;
		rte_errno = resp->err_value;
		if (!resp->err_value)
			ret = 0;
		free(mp_reply.msgs);
	}

	if (ret < 0)
		PDUMP_LOG(ERR,
			"client request for pdump enable/disable failed\n");
	return ret;
}

/*
 * There are two versions of this function, because although original API
 * left place holder for future filter, it never checked the value.
 * Therefore the API can't depend on application passing a non
 * bogus value.
 */
static int
pdump_enable(uint16_t port, uint16_t queue,
	     uint32_t flags, uint32_t snaplen,
	     struct rte_ring *ring, struct rte_mempool *mp,
	     const struct rte_bpf *filter)
{
	int ret;
	char name[RTE_DEV_NAME_MAX_LEN];

	ret = pdump_validate_port(port, name);
	if (ret < 0)
		return ret;
	ret = pdump_validate_ring_mp(ring, mp);
	if (ret < 0)
		return ret;
	ret = pdump_validate_flags(flags);
	if (ret < 0)
		return ret;

	if (snaplen == 0)
		snaplen = UINT32_MAX;

	return pdump_prepare_client_request(name, queue, flags, snaplen,
					    ENABLE, ring, mp, filter);
}

int
rte_pdump_enable(uint16_t port, uint16_t queue, uint32_t flags,
		 struct rte_ring *ring,
		 struct rte_mempool *mp,
		 void *filter __rte_unused)
{
	return pdump_enable(port, queue, flags, 0,
			    ring, mp, NULL);
}

int
rte_pdump_enable_bpf(uint16_t port, uint16_t queue,
		     uint32_t flags, uint32_t snaplen,
		     struct rte_ring *ring,
		     struct rte_mempool *mp,
		     const struct rte_bpf *filter)
{
	return pdump_enable(port, queue, flags, snaplen,
			    ring, mp, filter);
}

static int
pdump_enable_by_deviceid(const char *device_id, uint16_t queue,
			 uint32_t flags, uint32_t snaplen,
			 struct rte_ring *ring,
			 struct rte_mempool *mp,
			 const struct rte_bpf *filter)
{
	int ret;

	ret = pdump_validate_ring_mp(ring, mp);
	if (ret < 0)
		return ret;
	ret = pdump_validate_flags(flags);
	if (ret < 0)
		return ret;

	return pdump_prepare_client_request(device_id, queue, flags, snaplen,
					    ENABLE, ring, mp, filter);
}

int
rte_pdump_enable_by_deviceid(char *device_id, uint16_t queue,
			     uint32_t flags,
			     struct rte_ring *ring,
			     struct rte_mempool *mp,
			     void *filter __rte_unused)
{
	return pdump_enable_by_deviceid(device_id, queue, flags, 0,
					ring, mp, NULL);
}

int
rte_pdump_enable_bpf_by_deviceid(const char *device_id, uint16_t queue,
				 uint32_t flags, uint32_t snaplen,
				 struct rte_ring *ring,
				 struct rte_mempool *mp,
				 const struct rte_bpf *filter)
{
	return pdump_enable_by_deviceid(device_id, queue, flags, snaplen,
					ring, mp, filter);
}

int
rte_pdump_disable(uint16_t port, uint16_t queue, uint32_t flags)
{
	int ret = 0;
	char name[RTE_DEV_NAME_MAX_LEN];

	ret = pdump_validate_port(port, name);
	if (ret < 0)
		return ret;
	ret = pdump_validate_flags(flags);
	if (ret < 0)
		return ret;

	ret = pdump_prepare_client_request(name, queue, flags, 0,
					   DISABLE, NULL, NULL, NULL);

	return ret;
}

int
rte_pdump_disable_by_deviceid(char *device_id, uint16_t queue,
				uint32_t flags)
{
	int ret = 0;

	ret = pdump_validate_flags(flags);
	if (ret < 0)
		return ret;

	ret = pdump_prepare_client_request(device_id, queue, flags, 0,
					   DISABLE, NULL, NULL, NULL);

	return ret;
}

static void
pdump_sum_stats(struct rte_pdump_stats *total,
		const struct pdump_rxtx_cbs *cbs,
		uint16_t nq)
{
	uint16_t qid;

	memset(total, 0, sizeof(*total));

	for (qid = 0; qid < nq; qid++) {
		total->received += cbs[qid].stats.received;
		total->missed += cbs[qid].stats.missed;
		total->accepted += cbs[qid].stats.accepted;
	}
}

int
rte_pdump_get_stats(uint16_t port, uint16_t queue,
		    struct rte_pdump_stats *rx_stats,
		    struct rte_pdump_stats *tx_stats)
{
	uint16_t nb_rx_q = 0, nb_tx_q = 0;

	if (port >= RTE_MAX_ETHPORTS) {
		PDUMP_LOG(ERR, "Invalid port id %u\n", port);
		rte_errno = EINVAL;
		return -1;
	}

	if (queue == RTE_PDUMP_ALL_QUEUES) {
		struct rte_eth_dev_info dev_info;
		int ret;

		ret = rte_eth_dev_info_get(port, &dev_info);
		if (ret != 0) {
			PDUMP_LOG(ERR,
				"Error during getting device (port %u) info: %s\n",
				port, strerror(-ret));
			return ret;
		}
		nb_rx_q = dev_info.nb_rx_queues;
		nb_tx_q = dev_info.nb_tx_queues;
	} else if (queue >= RTE_MAX_QUEUES_PER_PORT) {
		PDUMP_LOG(ERR, "Invalid queue id %u\n", queue);
		rte_errno = EINVAL;
		return -1;
	}

	if (rx_stats) {
		if (queue == RTE_PDUMP_ALL_QUEUES)
			pdump_sum_stats(rx_stats, &rx_cbs[port][0], nb_rx_q);
		else
			*rx_stats = rx_cbs[port][queue].stats;
	}

	if (tx_stats) {
		if (queue == RTE_PDUMP_ALL_QUEUES)
			pdump_sum_stats(tx_stats, &tx_cbs[port][0], nb_tx_q);
		else
			*tx_stats = tx_cbs[port][queue].stats;
	}

	return 0;
}
