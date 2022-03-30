/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef __L3FWD_ACL_H__
#define __L3FWD_ACL_H__

#if RTE_LOG_DP_LEVEL >= RTE_LOG_DEBUG
#define L3FWDACL_DEBUG
#endif

#define MAX_ACL_RULE_NUM	100000
#define DEFAULT_MAX_CATEGORIES	1
#define L3FWD_ACL_IPV4_NAME	"l3fwd-acl-ipv4"
#define L3FWD_ACL_IPV6_NAME	"l3fwd-acl-ipv6"

#define ACL_DENY_SIGNATURE	0xf0000000
#define RTE_LOGTYPE_L3FWDACL	RTE_LOGTYPE_USER3
#define acl_log(format, ...)	RTE_LOG(ERR, L3FWDACL, format, ##__VA_ARGS__)
#define OFF_ETHHEAD	(sizeof(struct rte_ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct rte_ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct rte_ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

/*
 * ACL rules should have higher priorities than route ones to ensure ACL rule
 * always be found when input packets have multi-matches in the database.
 * A exception case is performance measure, which can define route rules with
 * higher priority and route rules will always be returned in each lookup.
 * Reserve range from ACL_RULE_PRIORITY_MAX + 1 to
 * RTE_ACL_MAX_PRIORITY for route entries in performance measure
 */
#define ACL_RULE_PRIORITY_MAX 0x10000000

/*
 * Forward port info save in ACL lib starts from 1
 * since ACL assume 0 is invalid.
 * So, need add 1 when saving and minus 1 when forwarding packets.
 */
#define FWD_PORT_SHIFT 1

static void
print_one_ipv4_rule(struct acl4_rule *rule, int extra)
{
	char abuf[INET6_ADDRSTRLEN];
	uint32_t ipv4_addr;
	ipv4_addr = ntohl(rule->field[SRC_FIELD_IPV4].value.u32);
	printf("%s/%u ", inet_ntop(AF_INET,
			&(ipv4_addr), abuf,
			sizeof(abuf)), rule->field[SRC_FIELD_IPV4].mask_range.u32);
	ipv4_addr = ntohl(rule->field[DST_FIELD_IPV4].value.u32);
	printf("%s/%u ", inet_ntop(AF_INET,
			&(ipv4_addr), abuf,
			sizeof(abuf)), rule->field[DST_FIELD_IPV4].mask_range.u32);
	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV4].value.u16,
		rule->field[SRCP_FIELD_IPV4].mask_range.u16,
		rule->field[DSTP_FIELD_IPV4].value.u16,
		rule->field[DSTP_FIELD_IPV4].mask_range.u16,
		rule->field[PROTO_FIELD_IPV4].value.u8,
		rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
			rule->data.category_mask,
			rule->data.priority,
			rule->data.userdata);
}

static void
print_one_ipv6_rule(struct acl6_rule *rule, int extra)
{
	char abuf[INET6_ADDRSTRLEN];
	uint32_t ipv6_addr[4];

	ipv6_addr[0] = rule->field[SRC1_FIELD_IPV6].value.u32;
	ipv6_addr[1] = rule->field[SRC2_FIELD_IPV6].value.u32;
	ipv6_addr[2] = rule->field[SRC3_FIELD_IPV6].value.u32;
	ipv6_addr[3] = rule->field[SRC4_FIELD_IPV6].value.u32;

	printf("%s", inet_ntop(AF_INET6, ipv6_addr,
		abuf, sizeof(abuf)));
	printf("/%u ",
			rule->field[SRC1_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC2_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC3_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC4_FIELD_IPV6].mask_range.u32);

	ipv6_addr[0] = rule->field[DST1_FIELD_IPV6].value.u32;
	ipv6_addr[1] = rule->field[DST2_FIELD_IPV6].value.u32;
	ipv6_addr[2] = rule->field[DST3_FIELD_IPV6].value.u32;
	ipv6_addr[3] = rule->field[DST4_FIELD_IPV6].value.u32;

	printf("%s", inet_ntop(AF_INET6, ipv6_addr,
		abuf, sizeof(abuf)));
	printf("/%u ",
			rule->field[DST1_FIELD_IPV6].mask_range.u32
			+ rule->field[DST2_FIELD_IPV6].mask_range.u32
			+ rule->field[DST3_FIELD_IPV6].mask_range.u32
			+ rule->field[DST4_FIELD_IPV6].mask_range.u32);

	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV6].value.u16,
		rule->field[SRCP_FIELD_IPV6].mask_range.u16,
		rule->field[DSTP_FIELD_IPV6].value.u16,
		rule->field[DSTP_FIELD_IPV6].mask_range.u16,
		rule->field[PROTO_FIELD_IPV6].value.u8,
		rule->field[PROTO_FIELD_IPV6].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
			rule->data.category_mask,
			rule->data.priority,
			rule->data.userdata);
}

#endif /* __L3FWD_ACL_H__ */
