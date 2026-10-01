/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * On-the-wire RPCAP protocol definitions, transcribed from libpcap's
 * rpcap-protocol.h which is an internal file and not exported.
 * See:
 *   https://github.com/the-tcpdump-group/libpcap/blob/master/rpcap-protocol.h
 *
 * Only the subset needed by dpdk-rpcapd is included here.
 * All multi-byte fields in the structures below are big-endian on the wire.
 */

#ifndef _RPCAP_PROTOCOL_H_
#define _RPCAP_PROTOCOL_H_

#include <stdint.h>

#include <rte_byteorder.h>

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

/* Error codes carried in the 'value' field of RPCAP_MSG_ERROR */
#define PCAP_ERR_WRONGVER          17
#define PCAP_ERR_AUTH_TYPE_NOTSUP  20

/* Authentication types in rpcap_auth.type */
#define RPCAP_RMTAUTH_NULL         0	/* no credentials supplied */
#define RPCAP_RMTAUTH_PWD          1	/* username and password follow */

/* Filter encoding: the filter is a BPF/NPF program */
#define RPCAP_UPDATEFILTER_BPF     1

/* Flags in rpcap_startcapreq.flags */
#define RPCAP_STARTCAPREQ_FLAG_PROMISC     0x00000001	/* promiscuous mode */
#define RPCAP_STARTCAPREQ_FLAG_DGRAM       0x00000002	/* use UDP for data */
#define RPCAP_STARTCAPREQ_FLAG_SERVEROPEN  0x00000004	/* server connects out */
#define RPCAP_STARTCAPREQ_FLAG_INBOUND     0x00000008	/* capture inbound only */
#define RPCAP_STARTCAPREQ_FLAG_OUTBOUND    0x00000010	/* capture outbound only */

/* Subset of pcap interface flags (pcap.h) */
#define PCAP_IF_UP                 0x00000002
#define PCAP_IF_RUNNING            0x00000004

/* DLT_EN10MB - ethernet, the only link type we report */
#define DLT_EN10MB                 1

struct rpcap_header {
	uint8_t     ver;
	uint8_t     type;
	rte_be16_t  value;
	rte_be32_t  plen;
};

struct rpcap_findalldevs_if {
	rte_be16_t  namelen;
	rte_be16_t  desclen;
	rte_be32_t  flags;
	rte_be16_t  naddr;
	uint16_t    dummy;
};

struct rpcap_openreply {
	rte_be32_t  linktype;
	rte_be32_t  tzoff;
};

struct rpcap_auth {
	rte_be16_t  type;	/* RPCAP_RMTAUTH_* */
	uint16_t    dummy;
	rte_be16_t  slen1;	/* length of username, if any */
	rte_be16_t  slen2;	/* length of password, if any */
};

struct rpcap_startcapreq {
	rte_be32_t  snaplen;
	rte_be32_t  read_timeout;
	rte_be16_t  flags;
	rte_be16_t  portdata;
};

struct rpcap_startcapreply {
	rte_be32_t  bufsize;
	rte_be16_t  portdata;
	uint16_t    dummy;
};

/*
 * A filter, sent either after rpcap_startcapreq or in an
 * RPCAP_MSG_UPDATEFILTER_REQ, followed by nitems instructions.
 */
struct rpcap_filter {
	rte_be16_t  filtertype;
	uint16_t    dummy;
	rte_be32_t  nitems;
};

/* One cBPF instruction, repeated nitems times after rpcap_filter. */
struct rpcap_filterbpf_insn {
	rte_be16_t  code;
	uint8_t     jt;
	uint8_t     jf;
	rte_be32_t  k;
};

struct rpcap_stats {
	rte_be32_t  ifrecv;
	rte_be32_t  ifdrop;
	rte_be32_t  krnldrop;
	rte_be32_t  svrcapt;
};

struct rpcap_pkthdr {
	rte_be32_t  timestamp_sec;
	rte_be32_t  timestamp_usec;
	rte_be32_t  caplen;
	rte_be32_t  len;
	rte_be32_t  npkt;
};

#endif /* _RPCAP_PROTOCOL_H_ */
