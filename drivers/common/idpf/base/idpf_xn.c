/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#include "idpf_xn.h"
#include "virtchnl2.h"
#include "idpf_controlq.h"

/**
 * idpf_ctlq_xn_pop_free - get a free xn entry from the free list
 * @xnmn: pointer to transaction manager
 *
 * Retrieve a free xn entry from the free list
 *
 */
static struct idpf_ctlq_xn *
idpf_ctlq_xn_pop_free(struct idpf_ctlq_xn_manager *xnm)
{
	struct idpf_ctlq_xn *xn;

	IDPF_LOCK_ACQUIRE(&xnm->xn_list_lock);
	if (IDPF_LIST_EMPTY(&xnm->free_xns)) {
		IDPF_LOCK_RELEASE(&xnm->xn_list_lock);
		return NULL;
	}

	xn = IDPF_LIST_FIRST(&xnm->free_xns);
	IDPF_LIST_DEL(&xnm->free_xns);
	xn->cookie = xnm->cookie++;
	IDPF_LOCK_RELEASE(&xnm->xn_list_lock);

	return xn;
}

/**
 * idpf_ctlq_xn_push_free - push a xn entry into free list
 * @xnm: pointer to transaction manager
 * @xn: pointer to xn entry
 *
 * Add the used xn entry back to the free list
 *
 */
static void idpf_ctlq_xn_push_free(struct idpf_ctlq_xn_manager *xnm, struct idpf_ctlq_xn *xn)
{
	if (xn->state == IDPF_CTLQ_XN_SHUTDOWN)
		return;

	xn->recv_buf.iov_base = NULL;
	xn->recv_buf.iov_len = 0;
	xn->state = IDPF_CTLQ_XN_IDLE;
	IDPF_LOCK_ACQUIRE(&xnm->xn_list_lock);
	IDPF_LIST_ADD(&xnm->free_xns, xn);
	IDPF_LOCK_RELEASE(&xnm->xn_list_lock);
}

/**
 * idpf_ctlq_xn_deinit_dma - Free the dma memory that allocated for send messages
 * @hw: pointer to hw structure
 * @xnm: pointer to transaction manager
 *
 * Free the dma memory that allocated for send messages
 *
 */
static void idpf_ctlq_xn_deinit_dma(struct idpf_hw *hw, struct idpf_ctlq_xn_manager *xnm)
{
	int i;

	for (i = 0; i < MAX_XN_ENTRIES; i++) {
		struct idpf_ctlq_xn *xn = &xnm->ring[i];

		if (xn->dma_mem) {
			idpf_free_dma_mem(hw, xn->dma_mem);
			idpf_free(hw, xn->dma_mem);
		}
	}

	return;
}

/**
 * idpf_ctlq_xn_init_dma - pre allocate dma memory for send messages in xn
 * @hw: pointer to hw structure
 * @xnm: pointer to transaction manager
 *
 * pre allocate dma memory for send messages in xn
 *
 */
static int idpf_ctlq_xn_init_dma(struct idpf_hw *hw, struct idpf_ctlq_xn_manager *xnm)
{
	struct idpf_dma_mem *dma_mem;
	int i;

	for (i = 0; i < MAX_XN_ENTRIES; i++) {
		struct idpf_ctlq_xn *xn = &xnm->ring[i];

		dma_mem = (struct idpf_dma_mem *)idpf_calloc(hw, 1, sizeof(*dma_mem));
		if (!dma_mem)
			break;
		dma_mem->va = idpf_alloc_dma_mem(hw, dma_mem, IDPF_DFLT_MBX_BUF_SIZE);
		if (!dma_mem->va) {
			idpf_free(hw, dma_mem);
			break;
		}
		xn->dma_mem = dma_mem;
	}

	/* error case, dma allocate failed, so free the allocated ones and fail the init */
	if (i < MAX_XN_ENTRIES) {
  	idpf_ctlq_xn_deinit_dma(hw, xnm);
		return -ENOMEM;
	}
	return 0;
}

/**
 * idpf_ctlq_xn_process_recv - process a control queue receive message
 * @params: pointer to receive param structure
 * @ctlq_msg: pointer to control queue message
 *
 * Process a control queue receive message and send a complete event notification
 *
 */
static int idpf_ctlq_xn_process_recv(struct idpf_ctlq_xn_recv_params *params, struct idpf_ctlq_msg *ctlq_msg)
{
	async_ctlq_xn_resp_cb async_resp_cb = NULL;
	size_t payload_size, return_size;
	struct idpf_ctlq_xn *xn;
	IDPF_IOVEC recv_buf;
	u16 msg_cookie;
	void *payload;
	u16 xn_index;
	int status;
	int ret;

	xn_index = FIELD_GET(IDPF_CTLQ_XN_INDEX_M, ctlq_msg->ctx.sw_cookie.data);
	msg_cookie = FIELD_GET(IDPF_CTLQ_XN_COOKIE_M, ctlq_msg->ctx.sw_cookie.data);
	payload = ctlq_msg->ctx.indirect.payload->va;
	payload_size = ctlq_msg->ctx.indirect.payload->size;
	status = (ctlq_msg->cookie.mbx.chnl_retval) ? -EBADMSG : 0;

	if (xn_index >= MAX_XN_ENTRIES) {
		IDPF_DEBUG_PRINT("Out of bounds cookie received: %02x\n", xn_index);
		return -ENXIO;
	}
	xn = &params->xnm->ring[xn_index];

	if (xn->cookie != msg_cookie) {
		IDPF_DEBUG_PRINT("Transaction cookie does not match (%02x != %02x)\n", xn->cookie, msg_cookie);
		return -ENXIO;
	}

	IDPF_LOCK_ACQUIRE(&xn->lock);
	if ((xn->state != IDPF_CTLQ_XN_ASYNC) && (xn->state != IDPF_CTLQ_XN_WAITING)) {
		IDPF_DEBUG_PRINT(" Recv error xn state %d\n", xn->state);
		ret = -EBADMSG;
		goto exit;
	}

	return_size = (xn->recv_buf.iov_len < payload_size) ? xn->recv_buf.iov_len : payload_size;
	if (xn->recv_buf.iov_base && return_size)
		idpf_memcpy(xn->recv_buf.iov_base, payload, return_size, IDPF_DMA_TO_NONDMA);

	if (status)
		IDPF_DEBUG_PRINT("Async message failure (op %d)\n", ctlq_msg->cookie.mbx.chnl_opcode);

	if (xn->state == IDPF_CTLQ_XN_ASYNC) {
		async_resp_cb = xn->async_resp_cb;
		recv_buf = xn->recv_buf;
		ret = 0;
		goto exit;
	}

	xn->state = status ? IDPF_CTLQ_XN_COMPLETED_FAILED : IDPF_CTLQ_XN_COMPLETED_SUCCESS;
	IDPF_LOCK_RELEASE(&xn->lock);
	IDPF_CMD_COMPLETION_SIG(&xn->cmd_completion_event, 1);
	return 0;

exit:
	idpf_ctlq_xn_push_free(params->xnm, xn);
	IDPF_LOCK_RELEASE(&xn->lock);

	/* call the callback after xn unlock */
	if (async_resp_cb)
		async_resp_cb(params->hw, recv_buf.iov_base, return_size, status);
	return ret;
}

/**
 * idpf_ctlq_xn_recv - Function to handle a receive message
 * @params: pointer to receive param structure
 *
 * Process a receive message and update the receive queue buffer
 *
 */
int idpf_ctlq_xn_recv(struct idpf_ctlq_xn_recv_params *params)
{
	struct idpf_dma_mem *dma_mem = NULL;
	struct idpf_ctlq_msg ctlq_msg;
	u16 num_recv = 1;
	int ret;

	if (!params || !params->hw || !params->xnm ||
	    !params->ctlq_info || !params->default_msg_handler)
		return -EBADR;

	ret = idpf_ctlq_recv(params->ctlq_info, &num_recv, &ctlq_msg);
	if (ret)
		return ret;

	if (ctlq_msg.data_len)
		dma_mem = ctlq_msg.ctx.indirect.payload;

	ret = idpf_ctlq_xn_process_recv(params, &ctlq_msg);
	/* Call the default handler for HMA event messages */
	if (ret == -ENXIO)
		ret = params->default_msg_handler(params->hw, &ctlq_msg);
	ret = idpf_ctlq_post_rx_buffs(params->hw, params->ctlq_info, &num_recv, &dma_mem);

	return ret;
}

/**
 * idpf_ctlq_xn_process_msg - process and send a control queue message
 * @params: pointer to send params structure
 * @xn: pointer to xn entry
 *
 * Process and send a control queue message
 *
 */
static int idpf_ctlq_xn_process_send(struct idpf_ctlq_xn_send_params *params, struct idpf_ctlq_xn *xn)
{
	u16 cookie;
	int ret;

	/* It's possible we're just sending an opcode but no buffer */
	if (params->send_buf.iov_base && params->send_buf.iov_len) {
		if (params->send_buf.iov_len >= IDPF_DFLT_MBX_BUF_SIZE)
			return -EBADMSG;

		idpf_memcpy(xn->dma_mem->va, params->send_buf.iov_base, params->send_buf.iov_len, IDPF_NONDMA_TO_DMA);
		params->ctlq_msg->ctx.indirect.payload = xn->dma_mem;
	}
	cookie = FIELD_PREP(IDPF_CTLQ_XN_COOKIE_M, xn->cookie) | FIELD_PREP(IDPF_CTLQ_XN_INDEX_M, xn->index);
	params->ctlq_msg->ctx.sw_cookie.data = cookie;
	ret = idpf_ctlq_send(params->hw, params->ctlq_info, 1, params->ctlq_msg);

	return ret;
}

/**
 * idpf_ctlq_xn_send - Function to send a control queue message
 * @params: pointer to send param structure
 *
 * Send a control queue (mailbox or config) message.
 * Based on the params value, the call can be completed synchronusly or asynchronusly.
 *
 */
int idpf_ctlq_xn_send(struct idpf_ctlq_xn_send_params *params)
{
	struct idpf_ctlq_xn *xn;
	int ret;

	if (!params || !params->hw || !params->xnm ||
	    !params->ctlq_msg || !params->ctlq_info)
		return -EBADR;

	xn = idpf_ctlq_xn_pop_free(params->xnm);
	/* no free transactions available */
	if (!xn)
		return -EBUSY;

	IDPF_LOCK_ACQUIRE(&xn->lock);
	if (xn->state != IDPF_CTLQ_XN_IDLE) {
		ret = -EBUSY;
		goto error;
	}
	xn->recv_buf = params->recv_buf;
	xn->state = params->async_resp_cb ? IDPF_CTLQ_XN_ASYNC : IDPF_CTLQ_XN_WAITING;
	xn->send_ctlq_info = params->ctlq_info;
	/* if callback is not provided then process it as a synchronous message */
	if (!params->async_resp_cb)
		IDPF_CMD_COMPLETION_REINIT(&xn->cmd_completion_event);
	else
		xn->async_resp_cb = params->async_resp_cb;
	IDPF_LOCK_RELEASE(&xn->lock);

	ret = idpf_ctlq_xn_process_send(params, xn);
	if (ret)
		goto error;

	if (params->async_resp_cb)
		return 0;
	/* wait for the command completion */
	IDPF_CMD_COMPLETION_WAIT(&xn->cmd_completion_event, params->timeout_ms);

	IDPF_LOCK_ACQUIRE(&xn->lock);
	switch (xn->state) {
	case IDPF_CTLQ_XN_WAITING:
		ret = -ETIMEDOUT;
		break;
	case IDPF_CTLQ_XN_COMPLETED_SUCCESS:
		ret = 0;
		break;
	default:
		ret = -EBADMSG;
		break;
	}

error:
	IDPF_LOCK_RELEASE(&xn->lock);
	idpf_ctlq_xn_push_free(params->xnm, xn);
	return ret;
}

/**
 * idpf_ctlq_xn_send_clean - cleanup the send control queue message buffers
 * @hw: pointer to hardware structure
 * @ctlq_info: pointer to control queue info to be cleaned
 *
 * Cleanup the send buffers for the given control queue, if force is set, then
 * clear all the outstanding send messages irrrespective their send status. Force should be
 * used during deinit or reset.
 *
 */
int idpf_ctlq_xn_send_clean(struct idpf_ctlq_xn_clean_params *params)
{
	int ret = 0;

	if (!params || !params->hw || !params->ctlq_info ||
	    !params->num_msgs || !params->q_msg)
		return -EBADR;

	if (params->force)
		ret = idpf_ctlq_clean_sq_force(params->ctlq_info, &params->num_msgs, params->q_msg);
	else
		ret = idpf_ctlq_clean_sq(params->ctlq_info, &params->num_msgs, params->q_msg);

	return ret;
}

/**
 * idpf_ctlq_xn_deinit - deallocate and free the transaction manager resources
 * @xn_mngr: pointer to xn init params
 *
 * Deallocate and free the transaction manager structure.
 *
 */
int idpf_ctlq_xn_deinit(struct idpf_ctlq_xn_init_params *params)
{
	enum idpf_ctlq_xn_state prev_state;
	int i;

	if (!params || !params->hw || !params->xnm)
		return -EBADR;

	for (i = 0; i < MAX_XN_ENTRIES; i++) {
		struct idpf_ctlq_xn *xn = &params->xnm->ring[i];

		IDPF_LOCK_ACQUIRE(&xn->lock);
		prev_state = xn->state;
		xn->state = IDPF_CTLQ_XN_SHUTDOWN;
		switch (prev_state) {
		case IDPF_CTLQ_XN_WAITING:
			IDPF_CMD_COMPLETION_SIG(&xn->cmd_completion_event, 1);
			break;
		case IDPF_CTLQ_XN_ASYNC:
			xn->async_resp_cb(params->hw, xn->recv_buf.iov_base, 0, -EBADMSG);
			break;
		default:
			break;
		}
		IDPF_CMD_COMPLETION_DEINIT(&xn->cmd_completion_event);
		IDPF_LOCK_RELEASE(&xn->lock);
		IDPF_LOCK_DESTROY(&xn->lock);
	}

	IDPF_LOCK_ACQUIRE(&params->xnm->xn_list_lock);
	while (IDPF_LIST_EMPTY(&params->xnm->free_xns))
		IDPF_LIST_DEL(&params->xnm->free_xns);
	IDPF_LOCK_RELEASE(&params->xnm->xn_list_lock);
	IDPF_LOCK_DESTROY(&params->xnm->xn_list_lock);
	idpf_ctlq_xn_deinit_dma(params->hw, params->xnm);

	idpf_free(params->hw, params->xnm);
	idpf_ctlq_deinit(params->hw);

	return 0;
}

/**
 * idpf_ctlq_xn_init - initialize transaction manager
 * @xn_mngr: pointer to xn init params
 *
 * Allocate and initialize transaction manager structure.
 * Return success if no errors occur.
 *
 */
int idpf_ctlq_xn_init(struct idpf_ctlq_xn_init_params *params)
{
	struct idpf_ctlq_xn_manager *xnm;
	int i, ret;

	if (!params || !params->hw || !params->cctlq_info ||
	    !params->num_qs)
		return -EBADR;

	ret = idpf_ctlq_init(params->hw, params->num_qs, params->cctlq_info);
	if (ret)
		return ret;

	xnm = idpf_calloc(params->hw, 1, sizeof(struct idpf_ctlq_xn_manager));
	if (!xnm) {
		idpf_ctlq_deinit(params->hw);
		return -ENOMEM;
	}

	ret = idpf_ctlq_xn_init_dma(params->hw, xnm);
	if (ret) {
		idpf_free(params->hw, xnm);
		idpf_ctlq_deinit(params->hw);
		return -ENOMEM;
	}

	IDPF_LIST_HEAD_INIT(&xnm->free_xns);
	IDPF_LOCK_INIT(&xnm->xn_list_lock);

	for (i = 0; i < MAX_XN_ENTRIES; i++) {
		struct idpf_ctlq_xn *xn = &xnm->ring[i];

		xn->state = IDPF_CTLQ_XN_IDLE;
		xn->index = i;
		IDPF_CMD_COMPLETION_INIT(&xn->cmd_completion_event);
		IDPF_LIST_ADD(&xnm->free_xns, xn);
		IDPF_LOCK_INIT(&xn->lock);
	}

	params->xnm = xnm;
	return 0;
}
