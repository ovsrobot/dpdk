/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_MSG_H_
#define _ZXDH_MSG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <ethdev_driver.h>

enum DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
};

enum BAR_MSG_RTN {
	BAR_MSG_OK = 0,
	BAR_MSG_ERR_MSGID,
	BAR_MSG_ERR_NULL,
	BAR_MSG_ERR_TYPE, /* Message type exception */
	BAR_MSG_ERR_MODULE, /* Module ID exception */
	BAR_MSG_ERR_BODY_NULL, /* Message body exception */
	BAR_MSG_ERR_LEN, /* Message length exception */
	BAR_MSG_ERR_TIME_OUT, /* Message sending length too long */
	BAR_MSG_ERR_NOT_READY, /* Abnormal message sending conditions*/
	BAR_MEG_ERR_NULL_FUNC, /* Empty receive processing function pointer*/
	BAR_MSG_ERR_REPEAT_REGISTER, /* Module duplicate registration*/
	BAR_MSG_ERR_UNGISTER, /* Repeated deregistration*/
	/**
	 * The sending interface parameter boundary structure pointer is empty
	 */
	BAR_MSG_ERR_NULL_PARA,
	BAR_MSG_ERR_REPSBUFF_LEN, /* The length of reps_buff is too short*/
	/**
	 * Unable to find the corresponding message processing function for this module
	 */
	BAR_MSG_ERR_MODULE_NOEXIST,
	/**
	 * The virtual address in the parameters passed in by the sending interface is empty
	 */
	BAR_MSG_ERR_VIRTADDR_NULL,
	BAR_MSG_ERR_REPLY, /* sync msg resp_error */
	BAR_MSG_ERR_MPF_NOT_SCANNED,
	BAR_MSG_ERR_KERNEL_READY,
	BAR_MSG_ERR_USR_RET_ERR,
	BAR_MSG_ERR_ERR_PCIEID,
	BAR_MSG_ERR_SOCKET, /* netlink sockte err */
};

int zxdh_msg_chan_init(void);
int zxdh_bar_msg_chan_exit(void);
int zxdh_msg_chan_hwlock_init(struct rte_eth_dev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_MSG_H_  */
