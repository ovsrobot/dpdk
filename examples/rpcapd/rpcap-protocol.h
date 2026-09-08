/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 *
 * On-the-wire RPCAP protocol definitions, transcribed from libpcap's
 * rpcap-protocol.h.  See:
 *   https://github.com/the-tcpdump-group/libpcap/blob/master/rpcap-protocol.h
 *
 * Only the subset needed by the DPDK rpcd POC is included here.  All
 * multi-byte fields in the structures below are big-endian on the wire.
 */

#ifndef _RPCAP_PROTOCOL_H_
#define _RPCAP_PROTOCOL_H_

#include <stdint.h>

#define RPCAP_VERSION              0
#define RPCAP_DEFAULT_NETPORT      2002

/* Message types */
#define RPCAP_MSG_ERROR            0x01
#define RPCAP_MSG_FINDALLIF_REQ    0x02
#define RPCAP_MSG_OPEN_REQ         0x03
#define RPCAP_MSG_STARTCAP_REQ     0x04
#define RPCAP_MSG_UPDATEFILTER_REQ 0x05
#define RPCAP_MSG_CLOSE            0x06
#define RPCAP_MSG_PACKET           0x07
#define RPCAP_MSG_AUTH_REQ         0x08
#define RPCAP_MSG_STATS_REQ        0x09
#define RPCAP_MSG_ENDCAP_REQ       0x0a
#define RPCAP_MSG_IS_REPLY         0x80

#define RPCAP_MSG_FINDALLIF_REPLY    (RPCAP_MSG_FINDALLIF_REQ    | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_OPEN_REPLY         (RPCAP_MSG_OPEN_REQ         | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_STARTCAP_REPLY     (RPCAP_MSG_STARTCAP_REQ     | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_UPDATEFILTER_REPLY (RPCAP_MSG_UPDATEFILTER_REQ | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_AUTH_REPLY         (RPCAP_MSG_AUTH_REQ         | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_ENDCAP_REPLY       (RPCAP_MSG_ENDCAP_REQ       | RPCAP_MSG_IS_REPLY)
#define RPCAP_MSG_STATS_REPLY	     (RPCAP_MSG_STATS_REQ	 | RPCAP_MSG_IS_REPLY)

/* Subset of pcap interface flags (pcap.h) */
#define PCAP_IF_UP                 0x00000002
#define PCAP_IF_RUNNING            0x00000004

/* DLT_EN10MB - ethernet, the only link type we report */
#define DLT_EN10MB                 1

struct rpcap_header {
	uint8_t  ver;
	uint8_t  type;
	uint16_t value;
	uint32_t plen;
};

struct rpcap_findalldevs_if {
	uint16_t namelen;
	uint16_t desclen;
	uint32_t flags;
	uint16_t naddr;
	uint16_t dummy;
};

struct rpcap_openreply {
	int32_t  linktype;
	int32_t  tzoff;
};

struct rpcap_startcapreq {
	uint32_t snaplen;
	uint32_t read_timeout;
	uint16_t flags;
	uint16_t portdata;
};

struct rpcap_startcapreply {
	int32_t  bufsize;
	uint16_t portdata;
	uint16_t dummy;
};

struct rpcap_stats {
	uint32_t ifrecv;
	uint32_t ifdrop;
	uint32_t krnldrop;
	uint32_t svrcapt;
};

struct rpcap_pkthdr {
	uint32_t timestamp_sec;
	uint32_t timestamp_usec;
	uint32_t caplen;
	uint32_t len;
	uint32_t npkt;
};

#endif /* _RPCAP_PROTOCOL_H_ */
