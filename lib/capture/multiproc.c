/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Multi-process support.
 *
 * The ethdev callback lists are per-process, so the primary passes the capture
 * to the other processes over EAL IPC and each attaches to its own queues.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "private.h"

/* IPC endpoint used to tell secondaries to attach/detach their callbacks. */
#define CAPTURE_MP		"mp_capture"
#define CAPTURE_MP_VERSION	1
#define CAPTURE_MP_TIMEOUT_S	1

struct capture_mp_request {
	uint16_t version;
	uint16_t op;
	/*
	 * Capture in shared memory. Valid in every process because it comes
	 * from rte_zmalloc; the secondary only reads the datapath fields and
	 * never the creator's (output, capture thread state).
	 */
	struct capture *cap;
};

struct capture_mp_response {
	uint16_t version;
	uint16_t op;
	int32_t err;
};

/*
 * Callbacks this process attached to a capture created elsewhere.
 *
 * A secondary cannot record its blocks in cap->cbs[], which is sized for one
 * process's queues, so it keeps them here. Guarded by capture_lock.
 */
struct capture_secondary {
	TAILQ_ENTRY(capture_secondary) next;
	struct capture *cap;
	struct capture_filter_prog *prog;
	uint16_t nb_cbs;
	struct capture_rxtx_cb *cbs[];
};

static TAILQ_HEAD(, capture_secondary) capture_secondary_list =
	TAILQ_HEAD_INITIALIZER(capture_secondary_list);

/* Attach this process's callbacks to a capture owned by the primary. */
static int
capture_mp_attach(struct capture *cap)
{
	struct capture_secondary *sec;
	struct rte_eth_dev_info dev_info;
	uint16_t num_queues;

	/* each process decides for itself */
	if (!rte_eal_has_capture())
		return -EPERM;

	if (rte_eth_dev_info_get(cap->port_id, &dev_info) < 0)
		return -EINVAL;

	/*
	 * Queue counts come from this process's view of the device: it is the
	 * one registering the callbacks.
	 */
	num_queues = dev_info.nb_tx_queues + dev_info.nb_rx_queues;
	sec = calloc(1, sizeof(*sec) + num_queues * sizeof(sec->cbs[0]));
	if (sec == NULL)
		return -ENOMEM;

	sec->cap = cap;
	if (capture_attach_queues(cap, sec->cbs, &sec->nb_cbs, &sec->prog) < 0) {
		capture_detach_queues(cap, sec->cbs, &sec->nb_cbs, sec->prog);
		free(sec);
		return -ENOBUFS;
	}

	rte_spinlock_lock(&capture_lock);
	TAILQ_INSERT_TAIL(&capture_secondary_list, sec, next);
	rte_spinlock_unlock(&capture_lock);

	return 0;
}

/* Detach this process's callbacks from a capture owned by the primary. */
static int
capture_mp_detach(struct capture *cap)
{
	struct capture_secondary *sec;

	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(sec, &capture_secondary_list, next) {
		if (sec->cap == cap) {
			TAILQ_REMOVE(&capture_secondary_list, sec, next);
			break;
		}
	}
	rte_spinlock_unlock(&capture_lock);

	if (sec == NULL)
		return -ENOENT;

	capture_detach_queues(cap, sec->cbs, &sec->nb_cbs, sec->prog);
	free(sec);
	return 0;
}

/*
 * Runs on the IPC thread, but attaching sends nothing, so unlike pdump there
 * is no need to defer to the interrupt thread.
 */
static int
capture_mp_handler(const struct rte_mp_msg *msg, const void *peer)
{
	const struct capture_mp_request *req;
	struct rte_mp_msg reply = { };
	struct capture_mp_response *resp = (struct capture_mp_response *)reply.param;

	resp->err = -EINVAL;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* the primary sends these and attaches its own callbacks */
		resp->err = -EPERM;
	} else if (msg->len_param != sizeof(*req)) {
		CAPTURE_LOG(ERR, "Invalid capture request length %d", msg->len_param);
	} else {
		req = (const struct capture_mp_request *)msg->param;

		if (req->version != CAPTURE_MP_VERSION) {
			CAPTURE_LOG(ERR, "Unsupported capture request version %u",
				    req->version);
		} else {
			resp->version = req->version;
			resp->op = req->op;

			switch (req->op) {
			case CAPTURE_MP_START:
				resp->err = capture_mp_attach(req->cap);
				break;
			case CAPTURE_MP_STOP:
				resp->err = capture_mp_detach(req->cap);
				break;
			default:
				CAPTURE_LOG(ERR, "Unknown capture op %u", req->op);
			}
		}
	}

	rte_strscpy(reply.name, CAPTURE_MP, sizeof(reply.name));
	reply.len_param = sizeof(*resp);

	return rte_mp_reply(&reply, peer);
}

/*
 * Registered from the constructor so no rte_pdump_init() equivalent is needed.
 * Only inserts into a list, so it is safe this early.
 *
 * The process type is not yet known here (it defaults to primary until EAL
 * init parses the arguments), so both ends register and the handler rejects
 * a request that arrives in the sending process.
 */
void
capture_mp_register(void)
{
	if (rte_mp_action_register(CAPTURE_MP, capture_mp_handler) < 0 &&
	    rte_errno != ENOTSUP)
		CAPTURE_LOG(NOTICE, "Could not register ipc action: %s",
			    rte_strerror(rte_errno));
}

/*
 * Must not be called holding a lock, the reply timeout is in seconds.
 * On stop the result decides whether the ring can be freed.
 */
int
capture_mp_broadcast(struct capture *cap, enum capture_mp_op op)
{
	struct rte_mp_msg msg = { };
	struct capture_mp_request *req = (struct capture_mp_request *)msg.param;
	struct rte_mp_reply mp_reply = { };
	struct timespec ts = { .tv_sec = CAPTURE_MP_TIMEOUT_S };
	int ret;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	req->version = CAPTURE_MP_VERSION;
	req->op = op;
	req->cap = cap;

	rte_strscpy(msg.name, CAPTURE_MP, sizeof(msg.name));
	msg.len_param = sizeof(*req);

	if (rte_mp_request_sync(&msg, &mp_reply, &ts) != 0) {
		/* no secondary running at all is the common case */
		if (rte_errno == ENOTSUP)
			return 0;

		CAPTURE_LOG(ERR, "Capture %s request failed: %s",
			    op == CAPTURE_MP_START ? "start" : "stop",
			    rte_strerror(rte_errno));
		return -1;
	}

	ret = 0;
	for (int i = 0; i < mp_reply.nb_received; i++) {
		const struct capture_mp_response *resp
			= (const struct capture_mp_response *)mp_reply.msgs[i].param;

		/*
		 * ENOENT: nothing to detach, it was not polling this port.
		 * EPERM: started with --no-capture, which is not an error.
		 */
		if (resp->err != 0 && resp->err != -ENOENT &&
		    resp->err != -EPERM) {
			CAPTURE_LOG(ERR, "Secondary could not %s capture: %s",
				    op == CAPTURE_MP_START ? "start" : "stop",
				    rte_strerror(-resp->err));
			ret = -1;
		}
	}

	if (mp_reply.nb_received != mp_reply.nb_sent) {
		CAPTURE_LOG(ERR, "Only %u of %u secondaries replied",
			    mp_reply.nb_received, mp_reply.nb_sent);
		ret = -1;
	}

	free(mp_reply.msgs);
	return ret;
}
