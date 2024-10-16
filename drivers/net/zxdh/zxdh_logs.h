/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_LOGS_H_
#define _ZXDH_LOGS_H_

#include <rte_log.h>

extern int zxdh_logtype_init;
#define RTE_LOGTYPE_ZXDH_INIT zxdh_logtype_init
#define PMD_INIT_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_INIT, "offload_zxdh %s(): ", \
		__func__, __VA_ARGS__)

extern int zxdh_logtype_driver;
#define RTE_LOGTYPE_ZXDH_DRIVER zxdh_logtype_driver
#define PMD_DRV_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_DRIVER, "offload_zxdh %s(): ", \
		__func__, __VA_ARGS__)

extern int zxdh_logtype_rx;
#define RTE_LOGTYPE_ZXDH_RX zxdh_logtype_rx
#define PMD_RX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_RX, "offload_zxdh %s(): ", \
		__func__, __VA_ARGS__)

extern int zxdh_logtype_tx;
#define RTE_LOGTYPE_ZXDH_TX zxdh_logtype_tx
#define PMD_TX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_TX, "offload_zxdh %s(): ", \
		__func__, __VA_ARGS__)

extern int zxdh_logtype_msg;
#define RTE_LOGTYPE_ZXDH_MSG zxdh_logtype_msg
#define PMD_MSG_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_MSG, "offload_zxdh %s(): ", \
		__func__, __VA_ARGS__)

#endif /* _ZXDH_LOGS_H_ */
