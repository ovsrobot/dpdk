/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../tap_rss.h"

/*
 * This map provides configuration information about flows
 * which need BPF RSS.
 *
 * The hash is indexed by the tc_index.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u16));
	__uint(value_size, sizeof(struct rss_key));
	__uint(max_entries, TAP_RSS_MAX);
} rss_map SEC(".maps");


#define IP_MF		0x2000		/** IP header Flags **/
#define IP_OFFSET	0x1FFF		/** IP header fragment offset **/

/*
 * Compute Toeplitz hash over the input tuple.
 * This is same as rte_softrss_be in lib/hash
 * but loop needs to be setup to match BPF restrictions.
 */
static __u32 __attribute__((always_inline))
softrss_be(const __u32 *input_tuple, __u32 input_len, const __u32 *key)
{
	__u32 i, j, hash = 0;

#pragma unroll
	for (j = 0; j < input_len; j++) {
#pragma unroll
		for (i = 0; i < 32; i++) {
			if (input_tuple[j] & (1U << (31 - i)))
				hash ^= key[j] << i | key[j + 1] >> (32 - i);
		}
	}
	return hash;
}

/* Compute RSS hash for IPv4 packet.
 * return in 0 if RSS not specified
 */
static __u32 __attribute__((always_inline))
parse_ipv4(const struct __sk_buff *skb, __u32 hash_type, const __u32 *key)
{
	struct iphdr iph;
	__u32 off = 0;

	if (bpf_skb_load_bytes_relative(skb, off, &iph, sizeof(iph), BPF_HDR_START_NET))
		return 0;	/* no IP header present */

	struct {
		__u32    src_addr;
		__u32    dst_addr;
		__u16    dport;
		__u16    sport;
	} v4_tuple = {
		.src_addr = bpf_ntohl(iph.saddr),
		.dst_addr = bpf_ntohl(iph.daddr),
	};

	/* If only calculating L3 hash, do it now */
	if (hash_type & (1 << HASH_FIELD_IPV4_L3))
		return softrss_be((__u32 *)&v4_tuple, sizeof(v4_tuple) / sizeof(__u32) - 1, key);

	/* No L4 if packet is a fragmented */
	if ((iph.frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0)
		return 0;

	/* Do RSS on UDP or TCP ports */
	if (iph.protocol == IPPROTO_UDP || iph.protocol == IPPROTO_TCP) {
		__u16 src_dst_port[2];

		off += iph.ihl * 4;
		if (bpf_skb_load_bytes_relative(skb, off, &src_dst_port, sizeof(src_dst_port),
						BPF_HDR_START_NET))
			return 0; /* TCP or UDP header missing */

		v4_tuple.sport = bpf_ntohs(src_dst_port[0]);
		v4_tuple.dport = bpf_ntohs(src_dst_port[1]);
		return softrss_be((__u32 *)&v4_tuple, sizeof(v4_tuple) / sizeof(__u32), key);
	}

	/* Other protocol */
	return 0;
}

/* parse ipv6 extended headers, update offset and return next proto.
 * returns next proto on success, -1 on malformed header
 */
static int __attribute__((always_inline))
skip_ip6_ext(__u16 proto, const struct __sk_buff *skb, __u32 *off, int *frag)
{
	struct ext_hdr {
		__u8 next_hdr;
		__u8 len;
	} xh;
	unsigned int i;

	*frag = 0;

#define MAX_EXT_HDRS 5
#pragma unroll
	for (i = 0; i < MAX_EXT_HDRS; i++) {
		switch (proto) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			if (bpf_skb_load_bytes_relative(skb, *off, &xh, sizeof(xh),
							BPF_HDR_START_NET))
				return -1;

			*off += (xh.len + 1) * 8;
			proto = xh.next_hdr;
			break;
		case IPPROTO_FRAGMENT:
			if (bpf_skb_load_bytes_relative(skb, *off, &xh, sizeof(xh),
							BPF_HDR_START_NET))
				return -1;

			*off += 8;
			proto = xh.next_hdr;
			*frag = 1;
			return proto; /* this is always the last ext hdr */
		default:
			return proto;
		}
	}

	/* too many extension headers give up */
	return -1;
}

static __u32 __attribute__((always_inline))
parse_ipv6(const struct __sk_buff *skb, __u32 hash_type, const __u32 *key)
{
	struct {
		__u32       src_addr[4];
		__u32       dst_addr[4];
		__u16       dport;
		__u16       sport;
	} v6_tuple = { };
	struct ipv6hdr ip6h;
	__u32 off = 0, j;
	int proto, frag;

	if (bpf_skb_load_bytes_relative(skb, off, &ip6h, sizeof(ip6h), BPF_HDR_START_NET))
		return 0;

#pragma unroll
	for (j = 0; j < 4; j++) {
		v6_tuple.src_addr[j] = bpf_ntohl(ip6h.saddr.in6_u.u6_addr32[j]);
		v6_tuple.dst_addr[j] = bpf_ntohl(ip6h.daddr.in6_u.u6_addr32[j]);
	}

	if (hash_type & (1 << HASH_FIELD_IPV6_L3))
		return softrss_be((__u32 *)&v6_tuple, sizeof(v6_tuple) / sizeof(__u32) - 1, key);

	off += sizeof(ip6h);
	proto = skip_ip6_ext(ip6h.nexthdr, skb, &off, &frag);
	if (proto < 0)
		return 0;

	if (frag)
		return 0;

	/* Do RSS on UDP or TCP ports */
	if (proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
		__u16 src_dst_port[2];

		if (bpf_skb_load_bytes_relative(skb, off, &src_dst_port, sizeof(src_dst_port),
						BPF_HDR_START_NET))
			return 0;

		v6_tuple.sport = bpf_ntohs(src_dst_port[0]);
		v6_tuple.dport = bpf_ntohs(src_dst_port[1]);

		return softrss_be((__u32 *)&v6_tuple, sizeof(v6_tuple) / sizeof(__u32), key);
	}

	return 0;
}

/*
 * Compute RSS hash for packets.
 * Returns 0 if no hash is possible.
 */
static __u32 __attribute__((always_inline))
calculate_rss_hash(const struct __sk_buff *skb, const struct rss_key *rsskey)
{
	const __u32 *key = (const __u32 *)rsskey->key;

	if (skb->protocol == bpf_htons(ETH_P_IP))
		return parse_ipv4(skb, rsskey->hash_fields, key);
	else if (skb->protocol == bpf_htons(ETH_P_IPV6))
		return parse_ipv6(skb, rsskey->hash_fields, key);
	else
		return 0;
}

/* scale value to be into range [0, n), assumes val is large */
static __u32  __attribute__((always_inline))
reciprocal_scale(__u32 val, __u32 n)
{
	return (__u32)(((__u64)val * n) >> 32);
}

/* layout of qdisc skb cb (from sch_generic.h) */
struct qdisc_skb_cb {
	struct {
		unsigned int	pkt_len;
		__u16		dev_queue_mapping;
		__u16		tc_classid;
	};
#define QDISC_CB_PRIV_LEN 20
	unsigned char		data[QDISC_CB_PRIV_LEN];
};

/*
 * When this BPF program is run by tc from the filter classifier,
 * it is able to read skb metadata and packet data.
 *
 * For packets where RSS is not possible, then just return TC_ACT_OK.
 * When RSS is desired, change the skb->queue_mapping and set TC_ACT_PIPE
 * to continue processing.
 *
 * This should be BPF_PROG_TYPE_SCHED_ACT so section needs to be "action"
 */
SEC("action") int
rss_flow_action(struct __sk_buff *skb)
{
	const struct rss_key *rsskey;
	__u16 classid;
	__u32 hash;

	/* TC layer puts the BPF_CLASSID into the skb cb area */
	classid = ((const struct qdisc_skb_cb *)skb->cb)->tc_classid;

	/* Lookup RSS configuration for that BPF class */
	rsskey = bpf_map_lookup_elem(&rss_map, &classid);
	if (rsskey == NULL) {
		bpf_printk("hash(): rss not configured");
		return TC_ACT_OK;
	}

	hash = calculate_rss_hash(skb, rsskey);
	bpf_printk("hash %u\n", hash);
	if (hash) {
		/* Fold hash to the number of queues configured */
		skb->queue_mapping = reciprocal_scale(hash, rsskey->nb_queues);
		bpf_printk("queue %u\n", skb->queue_mapping);
		return TC_ACT_PIPE;
	}
	return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
