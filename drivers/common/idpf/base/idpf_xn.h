/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#ifndef _IDPF_XN_H_
#define _IDPF_XN_H_

#include "idpf_osdep.h"

#define MAX_XN_ENTRIES 256
#define IDPF_CTLQ_XN_INDEX_M              GENMASK(7, 0)
#define IDPF_CTLQ_XN_COOKIE_M             GENMASK(15, 8)
#define IN
#define OUT

struct idpf_ctlq_msg;
typedef int (*async_ctlq_xn_resp_cb) (struct idpf_hw *, void *, size_t len, int status);
typedef int (*default_ctlq_msg_handler) (struct idpf_hw *, struct idpf_ctlq_msg *ctlq_msg);

enum idpf_ctlq_xn_state {
	IDPF_CTLQ_XN_IDLE = 1,
	IDPF_CTLQ_XN_WAITING,
	IDPF_CTLQ_XN_COMPLETED_SUCCESS,
	IDPF_CTLQ_XN_COMPLETED_FAILED,
	IDPF_CTLQ_XN_SHUTDOWN,
	IDPF_CTLQ_XN_ASYNC,
};

struct idpf_ctlq_xn {
	IDPF_LIST_ENTRY(idpf_ctlq_xn) entry;
	u8			cookie;
	u8			index;
	IDPF_IOVEC		recv_buf;
	IDPF_LOCK		lock;
	enum idpf_ctlq_xn_state state;
	struct idpf_ctlq_info  *send_ctlq_info;
	IDPF_CMD_COMPLETION	cmd_completion_event;
	struct idpf_dma_mem  *dma_mem;
	async_ctlq_xn_resp_cb	async_resp_cb;
};

/* The below structures are available for user APIs */
struct idpf_ctlq_xn_manager {
	u8			cookie;
	IDPF_LOCK		xn_list_lock;
	IDPF_LIST_HEAD(head, idpf_ctlq_xn) free_xns;
	struct idpf_ctlq_xn	ring[MAX_XN_ENTRIES];
};

/* Base driver fills all these values before calling send */
struct idpf_ctlq_xn_send_params {
	IN struct idpf_hw   *hw;
	IN struct idpf_ctlq_xn_manager *xnm;
	IN struct idpf_ctlq_info  *ctlq_info;
	IN struct idpf_ctlq_msg  *ctlq_msg;
	IN IDPF_IOVEC			send_buf;
	IN IDPF_IOVEC			recv_buf;
	IN u64				timeout_ms;
	IN async_ctlq_xn_resp_cb	async_resp_cb;
};

struct idpf_ctlq_xn_recv_params {
	IN struct idpf_ctlq_xn_manager *xnm;
	IN struct idpf_hw   *hw;
	IN struct idpf_ctlq_info  *ctlq_info;
	IN default_ctlq_msg_handler	default_msg_handler;
};

struct idpf_ctlq_xn_clean_params {
	IN bool				force;
	IN u16				num_msgs;
	IN struct idpf_hw   *hw;
	IN struct idpf_ctlq_info  *ctlq_info;
	IN OUT struct idpf_ctlq_msg **q_msg;
};

struct idpf_ctlq_xn_init_params {
	IN u8					num_qs;
	IN struct idpf_ctlq_create_info *cctlq_info;
	IN struct idpf_hw *hw;
	OUT struct idpf_ctlq_xn_manager *xnm;
};

int idpf_ctlq_xn_init(struct idpf_ctlq_xn_init_params *params);
int idpf_ctlq_xn_deinit(struct idpf_ctlq_xn_init_params *params);

int idpf_ctlq_xn_send(struct idpf_ctlq_xn_send_params *params);
int idpf_ctlq_xn_recv(struct idpf_ctlq_xn_recv_params *params);
int idpf_ctlq_xn_send_clean(struct idpf_ctlq_xn_clean_params *params);
#endif /* _ISEP_XN_H_ */
