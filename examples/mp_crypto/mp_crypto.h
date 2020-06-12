/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#ifndef _MP_CRYPTO_SAMPLE_APP_
#define _MP_CRYPTO_SAMPLE_APP_

#include <stdint.h>
#include <rte_hexdump.h>
#include "mp_crypto_vectors.h"

/* Intel QuickAssist  Technology Symmetric service PMD name */
#define CRYPTODEV_NAME_QAT_SYM_PMD	"crypto_qat"
/* Maximum number of devices to configure with this app */
#define MP_APP_MAX_DEVS			64
/* Maximum number of queue pairs per device */
#define MP_APP_QUEUE_PAIRS_NUM		2

#define MP_APP_PROC_SHARED_NAME		"MP_PROC_SHARED_MZ"
/* Memzone name for shared data across processes */
#define MP_APP_IPC_NAME			"MP_APP_IPC_NAME"

/* Session pool informations */
#define MP_APP_SESSION_POOL_NAME	"MP_APP_SESSION_POOL_NAME"
#define MP_APP_PRIV_SESSION_POOL_NAME	"MP_APP_PRIV_SESSPOL_NAME"

#define MP_APP_SESSION_POOL_NAME_LOC		"MP_APP_SESSP_NAME_LOC"
#define MP_APP_PRIV_SESSION_POOL_NAME_LOC	"MP_APP_PRIV_SPOL_NLOC"

#define MAX_NUM_OF_SESSIONS 		(16)

/* Crypto op informations */
#define MP_APP_CRYPTO_OP_POOL_NAME	"MP_APP_OP_NAME"
/* Mbuf informations */
#define MP_APP_MBUFPOOL_NAME 		"MP_APP_MBUF_NAME"

extern int mp_crypto_exit_flag;
/* Global exit flag */

/*
 * IPC COMMANDS
 */
#define PRIMARY_PROC_EXIT		"PRIMARY_EXIT"
#define SECONDARY_PROC_EXIT		"SECONDARY_EXIT"

#define MP_APP_DEV_NAME_LEN	64
/* Max name lenght */

/* Op pool constants */
#define MP_APP_NUM_MBUFS                       (4096)
/* Same number as default/max ops */
#define MP_APP_MBUF_CACHE_SIZE                 (256)
#define MP_APP_DEFAULT_NUM_XFORMS              (2)
#define MP_APP_MAXIMUM_IV_LENGTH			   (16)
/* Mbuf constants */
#define MP_APP_MBUF_SIZE			(sizeof(struct rte_mbuf) + \
		RTE_PKTMBUF_HEADROOM + MBUF_DATAPAYLOAD_SIZE)
/* qps constants */
#define MP_CRYPTO_QP_DESC_NUM		(4096)
#define NP_CRYPTO_OPS_TO_ENQ		(160000)
#define NP_CRYPTO_OPS_TO_DEQ		(160000)
/* Enqueue constants */
#define MP_CRYPTO_BURST_NUM		(64)
#define MP_CRYPTO_OPS_NUM		(MP_APP_NUM_MBUFS)

extern struct rte_crypto_op *mp_crypto_ops[];
/* Per process set of rte crypto ops */
extern struct rte_crypto_op *mp_crypto_ops_ret[];
/* Per process set of return rte crypto ops */
extern struct rte_mbuf *mp_crypto_mbufs[];
/* Per process set of rte mbufs */

/* Name of the device */
struct mp_app_dev_name {
	char name[MP_APP_DEV_NAME_LEN];
};

extern struct rte_cryptodev_sym_session *mp_crypto_local_sessions[];
/* Array of private sessions */

/* Symmetric session + ref count*/
struct mp_app_shared_sym_session {
	struct rte_cryptodev_sym_session *session;
	/* Pointer to symmetric session */
	int refcnt;
	/* Reference count, process that created this session
	 * does not increment this value */
};

/* Data for session array to be shared */
struct mp_app_session_array {
	struct mp_app_shared_sym_session sym_sessions[MAX_NUM_OF_SESSIONS];
	/* Array of pointers to sessions */
	int sym_session_counter;
	/* Counter of allocated sessions */
	rte_spinlock_t lock;
	/* Spinlock guarding this array */
};

/* Data to be shared across processes */
struct mp_app_process_data {
	uint16_t proc_counter;
	/* Counter of processes */
	uint16_t proc_counter_total;
	/* Number of processes that joined, not decremented
	 * can be used for naming in particular processes
	 */
	uint16_t devices_number;
	/* Number of devices probed by primary process */
	struct mp_app_dev_name prim_dev_name[MP_APP_MAX_DEVS];
	/* Names of devices probed by primary process */
	struct mp_app_session_array sessions;
	/* Array of sessions to be visible by all processes */
};

extern const struct rte_memzone *mp_app_process_mz;
extern struct mp_app_process_data *mp_shared_data;
/* Data shared across processes
 * memzone name = MP_PROC_SHARED_MZ */

extern struct rte_mempool *mp_crypto_session_mempool;
/* Global crypto session mempool used by all processes */
extern struct rte_mempool *mp_crypto_session_mempool_local;
/* Local crypto mempool used by this process */
extern struct rte_mempool *mp_crypto_priv_session_mp;
/* Global crypto private session mempool used by all processes */
extern struct rte_mempool *mp_crypto_priv_session_mp_local;
/* Local crypto private session mempool used by this process */
extern struct rte_mempool *mp_crypto_op_pool;
/* Per process op pool */
extern struct rte_mempool *mp_crypto_mbuf_pool;
/* Per process mbuf pool */

struct mp_app_dev {
	int8_t id;
	/* Cryptodev id of this dev */
	int queue_pair_flag[MP_APP_QUEUE_PAIRS_NUM];
	/* 1 means qp was configured for this device,
	 * 0 not configured by this process, but still
	 * could be initialized by another
	 * -2 means this qp is to be configured
	 */
	uint16_t max_queue_pairs;
	/* Per device info */
	uint8_t probed;
	/* If device was probed by EAL */
	uint8_t configured;
	/* Was this device configured */
	const struct rte_memzone *shared_data;
	/* This data is shared across processes
	 * memzone name = MZ_DEV_SHARED_DATA_DEV_[ID]
	 */
};

extern int 			mp_app_driver_id;
/* Global driver id, one per mp_app */
extern int					mp_app_device_id;
/* For now we use only one device type, so for session
 * init only one need to be provided
 */
extern struct mp_app_dev	mp_app_devs[];
/* Global devices list */
extern uint16_t			mp_app_devs_cnt;
/* Global device counter */
extern uint8_t			mp_app_max_queues;
/* Per process queue counter */

void mp_crypto_exit_app(void);
/* Exit function for both primary and secondary */

int mp_crypto_setup_mpool(void);
/* Function to set or lookup for mempools */

int mp_crypto_flow(void);
/* Flow function for enqueue dequeue */

/*
 * Primary process IPC handler
 */
int
mp_crypto_primary_handler(const struct rte_mp_msg *mp_msg,
		  const void *peer);
int
mp_crypto_secondary_handler(const struct rte_mp_msg *mp_msg,
		  const void *peer);

int mp_crypto_setup_qps(void);
/* Function to setup queues according to input string */

int mp_crypto_init_sessions(void);
/* Function to setup session according to mask */

int mp_crypto_init_devs(void);
/* Function to setup devices according to mask */

int mp_crypto_setup_ops(void);
/* Function to setup opse according to input string enq=[] */

/* Create and init symmetric session */
struct rte_cryptodev_sym_session *mp_app_create_session
		(int dev_id, const struct mp_crypto_session_vector *vector);

/* Create AEAD session */
struct rte_cryptodev_sym_session*
		mp_app_create_aead_session(int dev_id,
		const struct mp_crypto_session_vector *vector);

/* Create op */
int
mp_crypto_create_op(struct rte_crypto_op *op, struct rte_mbuf *mbuf,
					uint16_t vector_number,
					struct rte_cryptodev_sym_session *sess);

#define IV_OFFSET			(sizeof(struct rte_crypto_op) + \
		sizeof(struct rte_crypto_sym_op) + DEFAULT_NUM_XFORMS * \
		sizeof(struct rte_crypto_sym_xform))

#define MBUF_DATAPAYLOAD_SIZE		(2048)
#define DEFAULT_NUM_XFORMS			(2)

#endif