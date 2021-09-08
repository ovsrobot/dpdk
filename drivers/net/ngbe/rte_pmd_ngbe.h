/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2021 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

/**
 * @file rte_pmd_ngbe.h
 * ngbe PMD specific functions.
 *
 **/

#ifndef _PMD_NGBE_H_
#define _PMD_NGBE_H_

#include <rte_compat.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

/**
 * Response sent back to ngbe driver from user app after callback
 */
enum rte_pmd_ngbe_mb_event_rsp {
	RTE_PMD_NGBE_MB_EVENT_NOOP_ACK,  /**< skip mbox request and ACK */
	RTE_PMD_NGBE_MB_EVENT_NOOP_NACK, /**< skip mbox request and NACK */
	RTE_PMD_NGBE_MB_EVENT_PROCEED,  /**< proceed with mbox request  */
	RTE_PMD_NGBE_MB_EVENT_MAX       /**< max value of this enum */
};

/**
 * Data sent to the user application when the callback is executed.
 */
struct rte_pmd_ngbe_mb_event_param {
	uint16_t vfid;     /**< Virtual Function number */
	uint16_t msg_type; /**< VF to PF message type, defined in ngbe_mbx.h */
	uint16_t retval;   /**< return value */
	void *msg;         /**< pointer to message */
};

#endif /* _PMD_NGBE_H_ */
