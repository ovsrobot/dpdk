/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#ifndef _MP_CRYPTO_SAMPLE_APP_PARSER_
#define _MP_CRYPTO_SAMPLE_APP_PARSER_

#include <rte_hexdump.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cryptodev.h>
#include <cmdline_parse.h>

/* Make debug colorful! */
#define COL_NORM	"\x1B[0m"
#define COL_WHITE	"\x1B[37m"
#define COL_RED		"\x1B[31m"
#define COL_GREEN	"\x1B[32m"
#define COL_YEL		"\x1B[33m"
#define COL_BLUE	"\x1B[34m"
#define COL_MAG		"\x1B[35m"

#define MP_APP_LOG(level, color, str, args...) \
	do {		\
	printf("%s", color);			\
	RTE_LOG(level, USER1, str, args);	\
	printf("%s\n", COL_NORM);	\
	} while (0)

#define MP_APP_LOG_2(level, color, str) \
	do {		\
	printf("%s", color);			\
	RTE_LOG(level, USER1, str);	\
	printf("%s\n", COL_NORM);	\
	} while (0)

#define MP_APP_LOG_NO_RET(level, color, str, args...) \
	do {		\
	printf("\r%s", color);			\
	RTE_LOG(level, USER1, str, args);	\
	printf("%s", COL_NORM);	\
	} while (0)

#define MP_APP_QP_PARAM_LEN		(64 * 4)
#define MP_APP_ENQ_PARAM_LEN	1024

#define EMPTY_FLAGS		0

#define MP_DEVTYPE_NAME		("devtype")
#define MP_DEV_CONFIGURE	("config-dev")
#define MP_QP_CONFIGURE		("qp-config")
#define MP_ENQ				("enq")
#define MP_DEQ				("deq")
#define MP_SESSION_MASK		("session-mask")
#define MP_PRINT_STATS		("print-stats")

#define MP_APP_MAX_VECTORS	64

extern const char *comp_perf_test_type_strs[];
/* Command line parameters */
extern struct mp_crypto_app_parameters *mp_app_params;
/* Parser params */

static const char livesign_print_char[4] = { '-', '\\', '|', '/'};

int16_t
get_options(int argc, char *argv[]);

struct mp_crypto_app_enqdeq {
	int dev_id;
	int qp_id;
	int vector_number[MP_APP_MAX_VECTORS];
	int ops_no;
	int checkpoint;
};

#define QP_TO_CONFIGURE		(-2)

struct mp_crypto_app_parameters {
	char devtype_name[RTE_DEV_NAME_MAX_LEN];
	/* Driver to be used in this process */
	char qp_config[MP_APP_QP_PARAM_LEN];
	/* Queue Pairs configuration per device in process
	 * in format q0,q1;q0,q1;, '-' means queue pair will not
	 * be configured
	 * Example: queue_pairs="0,1;0,-;-,1;" means that
	 * device 0 will configure queue pairs 0 and 1,
	 * device 1 will configure queue pairs 0
	 * device 2 will configure queue pairs 1
	 * Devices are order dependent
	 */
	char flow_config[MP_APP_ENQ_PARAM_LEN];
	/* Enqueue configuration per process
	 * Format "[dev_id]=qp_id:[op,]
	 * Example: [0]=0:[enq, deq];[1]=0:[enq]
	 * Mean that for this process qp 0 on device 0 will be
	 * enqueuing and dequeuing in one queue pair,
	 * meanwhile device 0 will only enqueue data on qpair 0.
	 * Other process can then dequeue this data with
	 * [1]=0:[deq]
	 */
	uint64_t dev_to_configure_mask;
	/* Devices to configure, uint64 bitmask
	 * 1 means dev 0, 2 dev 1, 4 dev... etc
	 */
	uint64_t session_mask;
	/* Session to be created by this process,
	 * if session was already created this step will be ommited.
	 * Usage: session-mask=0x6 -> create session number 1 and 2.
	 * Number of session refer to predefined array of sessions
	 */
	char enq[MP_APP_ENQ_PARAM_LEN];
	struct mp_crypto_app_enqdeq enq_param;
	char deq[MP_APP_ENQ_PARAM_LEN];
	struct mp_crypto_app_enqdeq deq_param;
	/* Enqueue/dequeue string used by this process.
	 * Usage: [dev_id]:[qp_id]:[crypto_vector],[crypto_vector]...
	 * Example 2:1:0,1,2, -> device no 2 on qp 1 enqueues ops from
	 * vectors 0, 1, 2 .note ',' comma needs to be put after last arg
	 */
	int print_stats;
	/* Print stats on the end on flow function */

	uint16_t qp_id;
	uint16_t waiting_qp_id;

	int16_t configure_device;
	int16_t setup_qp;
	int16_t create_session_pool;
	int16_t create_op_pool;
	int16_t init_sessions;
	int16_t build_ops;
	int16_t dequeue;
	int16_t enqueue;
	int16_t dump_mempools;
};

int
options_parse(struct mp_crypto_app_parameters *mp_params, int argc,
			char **argv);
void
options_default(struct mp_crypto_app_parameters *mp_params);

int
options_check(struct mp_crypto_app_parameters *mp_params);

#endif