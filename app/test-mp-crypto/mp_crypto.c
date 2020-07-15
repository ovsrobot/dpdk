/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#include "mp_crypto.h"
#include "mp_crypto_parser.h"

int			mp_app_driver_id;
/* Global driver id, one per mp_app */
int			mp_app_device_id;
/* For now we use only one device type, so for session
 * init only one need to be provided
 */
struct mp_app_dev	mp_app_devs[MP_APP_MAX_DEVS];
/* Global devices list */
uint16_t		mp_app_devs_cnt;
/* Global device counter */
uint8_t			mp_app_max_queues;
/* Per process queue counter */
const struct rte_memzone *mp_app_process_mz;
struct mp_app_process_data *mp_shared_data;
/* Data shared across processes
 * memzone name = MP_PROC_SHARED_MZ
 */

int mp_crypto_exit_flag;
/* Global exit flag */

struct rte_mempool *mp_crypto_session_mempool;
/* Global crypto mempool used by all processes */
struct rte_mempool *mp_crypto_session_mempool_local;
/* Local crypto mempool used by this process */
struct rte_mempool *mp_crypto_priv_session_mp;
/* Global crypto private session mempool used by all processes */
struct rte_mempool *mp_crypto_priv_session_mp_local;
/* Local crypto private session mempool used by this process */
struct rte_mempool *mp_crypto_op_pool;
/* Per process op pool */
struct rte_mempool *mp_crypto_mbuf_pool;
/* Per process mbuf pool */
struct rte_crypto_op *mp_crypto_ops[MP_CRYPTO_OPS_NUM];
/* Per process set of rte crypto ops */
struct rte_crypto_op *mp_crypto_ops_ret[MP_CRYPTO_OPS_NUM];
/* Per process set of return rte crypto ops */
struct rte_mbuf *mp_crypto_mbufs[MP_CRYPTO_OPS_NUM];
/* Per process set of rte mbufs */
