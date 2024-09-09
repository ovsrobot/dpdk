/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_LOGS_H_
#define _ZXDH_LOGS_H_

#include <rte_log.h>

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

extern int32_t zxdh_logtype_init;
#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zxdh_logtype_init, \
	"offload_zxdh %s(): " fmt "\n", __func__, ## args)

extern int32_t zxdh_logtype_driver;
#define PMD_DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zxdh_logtype_driver, \
	"offload_zxdh %s(): " fmt "\n", __func__, ## args)

extern int zxdh_logtype_rx;
#define PMD_RX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zxdh_logtype_rx, \
	"offload_zxdh %s(): " fmt "\n", __func__, ## args)

extern int zxdh_logtype_tx;
#define PMD_TX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zxdh_logtype_tx, \
	"offload_zxdh %s(): " fmt "\n", __func__, ## args)

extern int32_t zxdh_logtype_msg;
#define PMD_MSG_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, zxdh_logtype_msg, \
	"offload_zxdh %s(): " fmt "\n", __func__, ## args)

#endif /* _ZXDH_LOGS_H_ */

