/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _HOTPLUG_MP_H_
#define _HOTPLUG_MP_H_

#include "rte_dev.h"
#include "rte_eal.h"

#define EAL_DEV_MP_ACTION_REQUEST      "eal_dev_mp_request"
#define EAL_DEV_MP_ACTION_RESPONSE     "eal_dev_mp_response"

#define EAL_DEV_MP_DEV_NAME_MAX_LEN RTE_DEV_NAME_MAX_LEN
#define EAL_DEV_MP_BUS_NAME_MAX_LEN 32
#ifndef EAL_DEV_MP_DEV_ARGS_MAX_LEN
#define EAL_DEV_MP_DEV_ARGS_MAX_LEN 128
#endif

enum eal_dev_req_type {
	EAL_DEV_REQ_TYPE_ATTACH,
	EAL_DEV_REQ_TYPE_DETACH,
	EAL_DEV_REQ_TYPE_ATTACH_ROLLBACK,
	EAL_DEV_REQ_TYPE_DETACH_ROLLBACK,
};

struct eal_dev_mp_req {
	enum eal_dev_req_type t;
	char devargs[EAL_DEV_MP_DEV_ARGS_MAX_LEN];
	int result;
};

static_assert(sizeof(struct eal_dev_mp_req) <= RTE_MP_MAX_PARAM_LEN,
	"eal_dev_mp_req exceeds RTE_MP_MAX_PARAM_LEN, increase mp_max_param_len");

/**
 * Register all mp action callbacks for hotplug.
 *
 * @return
 *   0 on success, negative on error.
 */
int
eal_mp_dev_hotplug_init(void);

/**
 * Unregister all mp action callbacks for hotplug.
 */
void
eal_mp_dev_hotplug_cleanup(void);

/**
 * This is a synchronous wrapper for secondary process send
 * request to primary process, this is invoked when an attach
 * or detach request is issued from primary process.
 */
int eal_dev_hotplug_request_to_primary(struct eal_dev_mp_req *req);

/**
 * this is a synchronous wrapper for primary process send
 * request to secondary process, this is invoked when an attach
 * or detach request issued from secondary process.
 */
int eal_dev_hotplug_request_to_secondary(struct eal_dev_mp_req *req);


#endif /* _HOTPLUG_MP_H_ */
