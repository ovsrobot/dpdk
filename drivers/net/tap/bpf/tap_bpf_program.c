/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include "../tap_rss.h"

/*
 * The queue number is offset by a unique QUEUE_OFFSET, to distinguish
 * packets that have gone through this rule (skb->cb[1] != 0) from others.
 */
#define QUEUE_OFFSET		0x7cafe800

#define IP_MF		0x2000		/** IP header Flags **/
#define IP_OFFSET	0x1FFF		/** IP header fragment offset **/


struct  {
	__uint(type,       BPF_MAP_TYPE_HASH);
	__type(key,  __u32);
	__type(value,     struct rss_key);
	__uint(max_entries,      256);
} map_keys SEC(".maps");

SEC("cls_q")
int match_q(struct __sk_buff *skb)
{
	__u32 queue = skb->cb[1];
	volatile __u32 q = 0xdeadbeef;
	__u32 match_queue = QUEUE_OFFSET + q;

	if (queue != match_queue)
		return TC_ACT_OK;

	/* queue match */
	skb->cb[1] = 0;
	return TC_ACT_UNSPEC;
}

struct ipv4_l3_l4_tuple {
	__u32    src_addr;
	__u32    dst_addr;
	__u16    dport;
	__u16    sport;
} __attribute__((packed));

struct ipv6_l3_l4_tuple {
	__u8        src_addr[16];
	__u8        dst_addr[16];
	__u16       dport;
	__u16       sport;
} __attribute__((packed));

struct neth {
	struct iphdr iph;
	struct udphdr udph;
} __attribute__((packed));

struct net6h {
	struct ipv6hdr ip6h;
	struct udphdr udph;
} __attribute__((packed));

static const __u8 def_rss_key[TAP_RSS_HASH_KEY_SIZE] = {
	0xd1, 0x81, 0xc6, 0x2c,
	0xf7, 0xf4, 0xdb, 0x5b,
	0x19, 0x83, 0xa2, 0xfc,
	0x94, 0x3e, 0x1a, 0xdb,
	0xd9, 0x38, 0x9e, 0x6b,
	0xd1, 0x03, 0x9c, 0x2c,
	0xa7, 0x44, 0x99, 0xad,
	0x59, 0x3d, 0x56, 0xd9,
	0xf3, 0x25, 0x3c, 0x06,
	0x2a, 0xdc, 0x1f, 0xfc,
};

static __u64  __attribute__((always_inline))
rte_softrss_be(const __u32 *input_tuple, __u8 input_len)
{
	__u32 i, j;
	__u64 hash = 0;
#pragma clang loop unroll(full)
	for (j = 0; j < input_len; j++) {
#pragma clang loop unroll(full)
		for (i = 0; i < 32; i++) {
			if (input_tuple[j] & (1U << (31 - i))) {
				hash ^= ((const __u32 *)def_rss_key)[j] << i |
				(__u32)((__u64)
				(((const __u32 *)def_rss_key)[j + 1])
					>> (32 - i));
			}
		}
	}
	return hash;
}

SEC("l3_l4")
int __attribute__((always_inline))
rss_l3_l4(struct __sk_buff *skb)
{
	struct neth nh;
	struct net6h n6h;
	__u32 key_idx = 0xdeadbeef;
	__u64 hash;
	struct rss_key *rsskey;
	int j, k, ret;
	__u32 len;
	__u32 queue = 0;

	rsskey = bpf_map_lookup_elem(&map_keys, &key_idx);
	if (rsskey == NULL) {
		return TC_ACT_OK;
	}

	if (bpf_skb_load_bytes_relative(skb, 0, &nh, sizeof(nh), BPF_HDR_START_NET))
		return TC_ACT_OK;
	if (nh.iph.version == 4) {
		struct ipv4_l3_l4_tuple v4_tuple = {
			.src_addr = bpf_ntohl(nh.iph.saddr),
			.dst_addr = bpf_ntohl(nh.iph.daddr),
			.sport = 0,
			.dport = 0,
		};
		if (nh.iph.protocol == IPPROTO_UDP || nh.iph.protocol == IPPROTO_TCP) {
			/** Is IP fragmented **/
			if ((nh.iph.frag_off & bpf_htons(IP_MF | IP_OFFSET)) == 0) {
				v4_tuple.sport = bpf_ntohs(nh.udph.source);
				v4_tuple.dport = bpf_ntohs(nh.udph.dest);
			}
		}
		hash = rte_softrss_be((__u32 *)&v4_tuple, 3);
	} else if (nh.iph.version == 6) {
		struct ipv6_l3_l4_tuple v6_tuple;
		if (bpf_skb_load_bytes_relative(skb, 0, &n6h, sizeof(n6h), BPF_HDR_START_NET))
			return TC_ACT_OK;
#pragma clang loop unroll(full)
		for (j = 0; j < 4; j++) {
			*((__u32 *)&v6_tuple.src_addr + j) =
							bpf_ntohl(n6h.ip6h.saddr.in6_u.u6_addr32[j]);
			*((__u32 *)&v6_tuple.dst_addr + j) =
							bpf_ntohl(n6h.ip6h.daddr.in6_u.u6_addr32[j]);
		}
		if (n6h.ip6h.nexthdr == IPPROTO_UDP || n6h.ip6h.nexthdr == IPPROTO_UDP) {
			v6_tuple.sport = bpf_ntohs(n6h.udph.source);
			v6_tuple.dport = bpf_ntohs(n6h.udph.dest);
		}
		else {
			v6_tuple.sport = 0;
			v6_tuple.dport = 0;
		}
		hash = rte_softrss_be((__u32 *)&v6_tuple, 9);
	} else {
		return TC_ACT_PIPE;
	}

	hash = (hash % rsskey->nb_queues) & (TAP_MAX_QUEUES - 1);
#pragma clang loop unroll(full)
	for (k = 0; k < TAP_MAX_QUEUES; k++) {
		if(k == hash)
			queue = rsskey->queues[k];
	}

	skb->cb[1] = (__u32)(QUEUE_OFFSET + queue);

	return TC_ACT_RECLASSIFY;

}

char _license[] SEC("license") = "Dual BSD/GPL";
