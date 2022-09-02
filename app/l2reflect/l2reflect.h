/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */

#include <stdatomic.h>

#ifndef _L2REFLECT_L2REFLECT_H_
#define _L2REFLECT_L2REFLECT_H_

#define RTE_LOGTYPE_L2REFLECT RTE_LOGTYPE_USER1

/* max size that common 1G NICs support */
#define MAX_JUMBO_PKT_LEN 9600

/* Used to compare MAC addresses. */
#define MAC_ADDR_CMP 0xFFFFFFFFFFFFull

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

enum {
	TRACE_TYPE_DATA,
	TRACE_TYPE_HELO,
	TRACE_TYPE_EHLO,
	TRACE_TYPE_RSET,
	TRACE_TYPE_QUIT,
};

enum STATE {
	/* elect the initial sender */
	S_ELECT_LEADER = 1,
	/* reset the counters */
	S_RESET_TRX = 2,
	/* measurement S_RUNNING */
	S_RUNNING = 4,
	/* terminated by local event */
	S_LOCAL_TERM = 8,
	/* terminated by remote event */
	S_REMOTE_TERM = 16
};

extern int l2reflect_hist;
extern unsigned int l2reflect_hist_buckets;
extern atomic_int l2reflect_output_hist;
extern int l2reflect_interrupt;
extern uint64_t l2reflect_sleep_msec;
extern uint64_t l2reflect_pkt_bytes;
extern uint16_t l2reflect_port_number;
extern atomic_int l2reflect_state;
extern struct rte_ether_addr l2reflect_port_eth_addr;
extern struct rte_ether_addr l2reflect_remote_eth_addr;

#endif /* _L2REFLECT_L2REFLECT_H_ */
