/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_CRYPTO_LOGS_H_
#define _VIRTIO_CRYPTO_LOGS_H_

#include <rte_log.h>

#include "virtio_logs.h"

extern int virtio_logtype_init;

#define VIRTIO_CRYPTO_INIT_LOG_IMPL(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_logtype_init, \
		"INIT: %s(): " fmt "\n", __func__, ##args)

#define VIRTIO_CRYPTO_INIT_LOG_INFO(fmt, ...) \
	VIRTIO_CRYPTO_INIT_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_INIT_LOG_DBG(fmt, ...) \
	VIRTIO_CRYPTO_INIT_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_INIT_LOG_ERR(fmt, ...) \
	VIRTIO_CRYPTO_INIT_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_crypto_logtype_session;
#define RTE_LOGTYPE_VIRTIO_CRYPTO_SESSION virtio_crypto_logtype_session

#define VIRTIO_CRYPTO_SESSION_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_CRYPTO_SESSION, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_CRYPTO_SESSION_LOG_INFO(fmt, ...) \
	VIRTIO_CRYPTO_SESSION_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_SESSION_LOG_DBG(fmt, ...) \
	VIRTIO_CRYPTO_SESSION_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_SESSION_LOG_ERR(fmt, ...) \
	VIRTIO_CRYPTO_SESSION_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_crypto_logtype_rx;
#define RTE_LOGTYPE_VIRTIO_CRYPTO_RX virtio_crypto_logtype_rx

#define VIRTIO_CRYPTO_RX_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_CRYPTO_RX, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_CRYPTO_RX_LOG_INFO(fmt, ...) \
	VIRTIO_CRYPTO_RX_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_RX_LOG_DBG(fmt, ...) \
	VIRTIO_CRYPTO_RX_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_RX_LOG_ERR(fmt, ...) \
	VIRTIO_CRYPTO_RX_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_crypto_logtype_tx;
#define RTE_LOGTYPE_VIRTIO_CRYPTO_TX virtio_crypto_logtype_tx

#define VIRTIO_CRYPTO_TX_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_CRYPTO_TX, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_CRYPTO_TX_LOG_INFO(fmt, ...) \
	VIRTIO_CRYPTO_TX_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_TX_LOG_DBG(fmt, ...) \
	VIRTIO_CRYPTO_TX_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_TX_LOG_ERR(fmt, ...) \
	VIRTIO_CRYPTO_TX_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_logtype_driver;

#define VIRTIO_CRYPTO_DRV_LOG_IMPL(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_logtype_driver, \
		"DRIVER: %s(): " fmt "\n", __func__, ##args)

#define VIRTIO_CRYPTO_DRV_LOG_INFO(fmt, ...) \
	VIRTIO_CRYPTO_DRV_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_DRV_LOG_DBG(fmt, ...) \
	VIRTIO_CRYPTO_DRV_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_CRYPTO_DRV_LOG_ERR(fmt, ...) \
	VIRTIO_CRYPTO_DRV_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

#endif /* _VIRTIO_CRYPTO_LOGS_H_ */
