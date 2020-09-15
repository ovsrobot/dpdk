/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */
#ifndef _L2REFLECT_H_
#define _L2REFLECT_H_
#define MAGIC_TRACE_PAYLOAD 0xd00faffeaffed00full
/* IEEE Std 802 - Local Experimental Ethertype */
#define ETHER_TYPE_L2REFLECT 0x88B5
/* Used to compare MAC addresses. */
#define MAC_ADDR_CMP 0xFFFFFFFFFFFFull

enum {
	TRACE_TYPE_DATA,
	TRACE_TYPE_HELO,
	TRACE_TYPE_EHLO,
	TRACE_TYPE_RSET,
	TRACE_TYPE_QUIT,
};

struct my_magic_packet {
	struct rte_ether_hdr eth;
	uint8_t type;
	uint64_t magic;
	uint64_t breakval;
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
extern atomic_int l2reflect_output_hist;
extern uint64_t l2reflect_sleep_msec;
extern uint16_t l2reflect_port_number;
extern atomic_int l2reflect_state;
extern struct rte_ether_addr l2reflect_port_eth_addr;
extern struct rte_ether_addr l2reflect_remote_eth_addr;

#endif /* _L2REFLECT_H_ */
