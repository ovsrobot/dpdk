/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_acl.h>

#include "l3fwd.h"
#include "l3fwd_route.h"

/*
 * Rule and trace formats definitions.
 */

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4VLAN classifications:
 *  - PROTO
 *  - VLAN (TAG and DOMAIN)
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
	RTE_ACL_IPV4VLAN_PROTO,
	RTE_ACL_IPV4VLAN_VLAN,
	RTE_ACL_IPV4VLAN_SRC,
	RTE_ACL_IPV4VLAN_DST,
	RTE_ACL_IPV4VLAN_PORTS,
	RTE_ACL_IPV4VLAN_NUM
};

struct acl_algorithms acl_alg[] = {
	{
		.name = "scalar",
		.alg = RTE_ACL_CLASSIFY_SCALAR,
	},
	{
		.name = "sse",
		.alg = RTE_ACL_CLASSIFY_SSE,
	},
	{
		.name = "avx2",
		.alg = RTE_ACL_CLASSIFY_AVX2,
	},
	{
		.name = "neon",
		.alg = RTE_ACL_CLASSIFY_NEON,
	},
	{
		.name = "altivec",
		.alg = RTE_ACL_CLASSIFY_ALTIVEC,
	},
	{
		.name = "avx512x16",
		.alg = RTE_ACL_CLASSIFY_AVX512X16,
	},
	{
		.name = "avx512x32",
		.alg = RTE_ACL_CLASSIFY_AVX512X32,
	},
};

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_SRC,
		.offset = offsetof(struct rte_ipv4_hdr, src_addr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_DST,
		.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct rte_ipv4_hdr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct rte_ipv4_hdr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id) +
			sizeof(uint16_t),
	},
};

enum {
	PROTO_FIELD_IPV6,
	SRC1_FIELD_IPV6,
	SRC2_FIELD_IPV6,
	SRC3_FIELD_IPV6,
	SRC4_FIELD_IPV6,
	DST1_FIELD_IPV6,
	DST2_FIELD_IPV6,
	DST3_FIELD_IPV6,
	DST4_FIELD_IPV6,
	SRCP_FIELD_IPV6,
	DSTP_FIELD_IPV6,
	NUM_FIELDS_IPV6
};

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV6,
		.input_index = PROTO_FIELD_IPV6,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC1_FIELD_IPV6,
		.input_index = SRC1_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, src_addr) -
			offsetof(struct rte_ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC2_FIELD_IPV6,
		.input_index = SRC2_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, src_addr) -
			offsetof(struct rte_ipv6_hdr, proto) + sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC3_FIELD_IPV6,
		.input_index = SRC3_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, src_addr) -
			offsetof(struct rte_ipv6_hdr, proto) +
			2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC4_FIELD_IPV6,
		.input_index = SRC4_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, src_addr) -
			offsetof(struct rte_ipv6_hdr, proto) +
			3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IPV6,
		.input_index = DST1_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr)
				- offsetof(struct rte_ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IPV6,
		.input_index = DST2_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr) -
			offsetof(struct rte_ipv6_hdr, proto) + sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IPV6,
		.input_index = DST3_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr) -
			offsetof(struct rte_ipv6_hdr, proto) +
			2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IPV6,
		.input_index = DST4_FIELD_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr) -
			offsetof(struct rte_ipv6_hdr, proto) +
			3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = sizeof(struct rte_ipv6_hdr) -
			offsetof(struct rte_ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = sizeof(struct rte_ipv6_hdr) -
			offsetof(struct rte_ipv6_hdr, proto) + sizeof(uint16_t),
	},
};

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	CB_FLD_USERDATA,
	CB_FLD_NUM,
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

struct acl_search_t {
	const uint8_t *data_ipv4[MAX_PKT_BURST];
	struct rte_mbuf *m_ipv4[MAX_PKT_BURST];
	uint32_t res_ipv4[MAX_PKT_BURST];
	int num_ipv4;

	const uint8_t *data_ipv6[MAX_PKT_BURST];
	struct rte_mbuf *m_ipv6[MAX_PKT_BURST];
	uint32_t res_ipv6[MAX_PKT_BURST];
	int num_ipv6;
};

static struct {
	struct rte_acl_ctx *acx_ipv4[NB_SOCKETS];
	struct rte_acl_ctx *acx_ipv6[NB_SOCKETS];
#ifdef L3FWDACL_DEBUG
	struct acl4_rule *rule_ipv4;
	struct acl6_rule *rule_ipv6;
#endif
} acl_config;

static const char cb_port_delim[] = ":";

static struct rte_acl_rule *acl_base_ipv4, *route_base_ipv4,
		*acl_base_ipv6, *route_base_ipv6;
static unsigned int acl_num_ipv4, route_num_ipv4,
		acl_num_ipv6, route_num_ipv6;

#include "l3fwd_acl.h"

#include "l3fwd_acl_scalar.h"

/*
 * Parse IPV6 address, expects the following format:
 * XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX (where X is a hexadecimal digit).
 */
static int
parse_ipv6_addr(char *in, uint32_t v[IPV6_ADDR_U32], uint32_t *mask)
{
	char *sa, *sm, *sv;
	const char *dlm =  "/";

	sv = NULL;
	sa = strtok_r(in, dlm, &sv);
	if (sa == NULL)
		return -EINVAL;
	sm = strtok_r(NULL, dlm, &sv);
	if (sm == NULL)
		return -EINVAL;

	if (inet_pton(AF_INET6, sa, v) != 1)
		return -EINVAL;

	GET_CB_FIELD(sm, *mask, 0, 128, 0);
	return 0;
}

static int
parse_ipv6_net(char *in, struct rte_acl_field field[4])
{
	int32_t rc;
	uint32_t i, v[4];
	uint32_t m;
	const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;

	/* get address. */
	rc = parse_ipv6_addr(in, v, &m);
	if (rc != 0)
		return rc;

	/* put all together. */
	for (i = 0; i != RTE_DIM(v); i++) {
		if (m >= (i + 1) * nbu32)
			field[i].mask_range.u32 = nbu32;
		else
			field[i].mask_range.u32 = m > (i * nbu32) ?
				m - (i * 32) : 0;

		field[i].value.u32 = v[i];
	}

	return 0;
}

static int
parse_cb_ipv6_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;
	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv6_net(in[CB_FLD_SRC_ADDR], v->field + SRC1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv6_net(in[CB_FLD_DST_ADDR], v->field + DST1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	/* source port. */
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		v->field[SRCP_FIELD_IPV6].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		v->field[SRCP_FIELD_IPV6].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	/* destination port. */
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		v->field[DSTP_FIELD_IPV6].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		v->field[DSTP_FIELD_IPV6].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (v->field[SRCP_FIELD_IPV6].mask_range.u16
			< v->field[SRCP_FIELD_IPV6].value.u16
			|| v->field[DSTP_FIELD_IPV6].mask_range.u16
			< v->field[DSTP_FIELD_IPV6].value.u16)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].value.u8,
		0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].mask_range.u8,
		0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata,
			0, UINT32_MAX, 0);

	return 0;
}

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len)
{
	char *sa, *sm, *sv;
	const char *dlm =  "/";

	sv = NULL;
	sa = strtok_r(in, dlm, &sv);
	if (sa == NULL)
		return -EINVAL;
	sm = strtok_r(NULL, dlm, &sv);
	if (sm == NULL)
		return -EINVAL;

	if (inet_pton(AF_INET, sa, addr) != 1)
		return -EINVAL;

	GET_CB_FIELD(sm, *mask_len, 0, 32, 0);
	*addr = ntohl(*addr);
	return 0;
}

static int
parse_cb_ipv4vlan_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;
	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		v->field[SRCP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		v->field[SRCP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0) {
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		v->field[DSTP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		v->field[DSTP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0) {
		return -EINVAL;
	}

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
			< v->field[SRCP_FIELD_IPV4].value.u16
			|| v->field[DSTP_FIELD_IPV4].mask_range.u16
			< v->field[DSTP_FIELD_IPV4].value.u16) {
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
		0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
		0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0,
			UINT32_MAX, 0);

	return 0;
}

static int
acl_add_rules(const char *rule_path,
		struct rte_acl_rule **proute_base,
		unsigned int *proute_num,
		struct rte_acl_rule **pacl_base,
		unsigned int *pacl_num, uint32_t rule_size,
		int (*parser)(char *, struct rte_acl_rule*, int))
{
	uint8_t *acl_rules, *route_rules;
	struct rte_acl_rule *next;
	unsigned int acl_num = 0, route_num = 0, total_num = 0;
	unsigned int acl_cnt = 0, route_cnt = 0;
	char buff[LINE_MAX];
	FILE *fh = fopen(rule_path, "rb");
	unsigned int i = 0;
	int val;

	if (fh == NULL)
		rte_exit(EXIT_FAILURE, "%s: Open %s failed\n", __func__,
			rule_path);

	while ((fgets(buff, LINE_MAX, fh) != NULL)) {
		if (buff[0] == ROUTE_LEAD_CHAR)
			route_num++;
		else if (buff[0] == ACL_LEAD_CHAR)
			acl_num++;
	}

	if (route_num == 0)
		rte_exit(EXIT_FAILURE, "Not find any route entries in %s!\n",
				rule_path);

	val = fseek(fh, 0, SEEK_SET);
	if (val < 0) {
		rte_exit(EXIT_FAILURE, "%s: File seek operation failed\n",
			__func__);
	}

	acl_rules = calloc(acl_num, rule_size);

	if (acl_rules == NULL)
		rte_exit(EXIT_FAILURE, "%s: failed to malloc memory\n",
			__func__);

	route_rules = calloc(route_num, rule_size);

	if (route_rules == NULL)
		rte_exit(EXIT_FAILURE, "%s: failed to malloc memory\n",
			__func__);

	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))
			continue;

		char s = buff[0];

		/* Route entry */
		if (s == ROUTE_LEAD_CHAR)
			next = (struct rte_acl_rule *)(route_rules +
				route_cnt * rule_size);

		/* ACL entry */
		else if (s == ACL_LEAD_CHAR)
			next = (struct rte_acl_rule *)(acl_rules +
				acl_cnt * rule_size);

		/* Illegal line */
		else
			rte_exit(EXIT_FAILURE,
				"%s Line %u: should start with leading "
				"char %c or %c\n",
				rule_path, i, ROUTE_LEAD_CHAR, ACL_LEAD_CHAR);

		if (parser(buff + 1, next, s == ROUTE_LEAD_CHAR) != 0)
			rte_exit(EXIT_FAILURE,
				"%s Line %u: parse rules error\n",
				rule_path, i);

		if (s == ROUTE_LEAD_CHAR) {
			/* Check the forwarding port number */
			if ((enabled_port_mask & (1 << next->data.userdata)) ==
					0)
				rte_exit(EXIT_FAILURE,
					"%s Line %u: fwd number illegal:%u\n",
					rule_path, i, next->data.userdata);
			next->data.userdata += FWD_PORT_SHIFT;
			route_cnt++;
		} else {
			next->data.userdata = ACL_DENY_SIGNATURE + acl_cnt;
			acl_cnt++;
		}

		next->data.priority = RTE_ACL_MAX_PRIORITY - total_num;
		next->data.category_mask = -1;
		total_num++;
	}

	fclose(fh);

	*pacl_base = (struct rte_acl_rule *)acl_rules;
	*pacl_num = acl_num;
	*proute_base = (struct rte_acl_rule *)route_rules;
	*proute_num = route_cnt;

	return 0;
}

static const char *
str_acl_alg(enum rte_acl_classify_alg alg)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(acl_alg); i++) {
		if (alg == acl_alg[i].alg)
			return acl_alg[i].name;
	}

	return "default";
}

static void
dump_acl_config(void)
{
	printf("ACL options are:\n");
	printf("rule_ipv4: %s\n", parm_config.rule_ipv4_name);
	printf("rule_ipv6: %s\n", parm_config.rule_ipv6_name);
	printf("alg: %s\n", str_acl_alg(parm_config.alg));
}

static int
check_acl_config(void)
{
	if (parm_config.rule_ipv4_name == NULL) {
		acl_log("ACL IPv4 rule file not specified\n");
		return -1;
	} else if (parm_config.rule_ipv6_name == NULL) {
		acl_log("ACL IPv6 rule file not specified\n");
		return -1;
	}

	return 0;
}

static struct rte_acl_ctx*
app_acl_init(struct rte_acl_rule *route_base,
		struct rte_acl_rule *acl_base, unsigned int route_num,
		unsigned int acl_num, int ipv6, int socketid)
{
	char name[PATH_MAX];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx *context;
	int dim = ipv6 ? RTE_DIM(ipv6_defs) : RTE_DIM(ipv4_defs);

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "%s%d",
			ipv6 ? L3FWD_ACL_IPV6_NAME : L3FWD_ACL_IPV4_NAME,
			socketid);

	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	context = rte_acl_create(&acl_param);
	if (context == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");

	if (parm_config.alg != RTE_ACL_CLASSIFY_DEFAULT &&
			rte_acl_set_ctx_classify(context, parm_config.alg) != 0)
		rte_exit(EXIT_FAILURE,
			"Failed to setup classify method for  ACL context\n");

	if (rte_acl_add_rules(context, route_base, route_num) < 0)
		rte_exit(EXIT_FAILURE, "add rules failed\n");

	if (rte_acl_add_rules(context, acl_base, acl_num) < 0)
		rte_exit(EXIT_FAILURE, "add rules failed\n");

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	memcpy(&acl_build_param.defs, ipv6 ? ipv6_defs : ipv4_defs,
		ipv6 ? sizeof(ipv6_defs) : sizeof(ipv4_defs));

	if (rte_acl_build(context, &acl_build_param) != 0)
		rte_exit(EXIT_FAILURE, "Failed to build ACL trie\n");

	rte_acl_dump(context);

	return context;
}

void
acl_free_routes(void)
{
	free(route_base_ipv4);
	free(route_base_ipv6);
	route_base_ipv4 = NULL;
	route_base_ipv6 = NULL;
	route_num_ipv4 = 0;
	route_num_ipv6 = 0;
	free(acl_base_ipv4);
	free(acl_base_ipv6);
	acl_base_ipv4 = NULL;
	acl_base_ipv4 = NULL;
}

/* Load rules from the input file */
void
read_config_files_acl(void)
{
	/* ipv4 check */
	if (parm_config.rule_ipv4_name != NULL) {
		if (acl_add_rules(parm_config.rule_ipv4_name, &route_base_ipv4,
				&route_num_ipv4, &acl_base_ipv4, &acl_num_ipv4,
				sizeof(struct acl4_rule), &parse_cb_ipv4vlan_rule) < 0) {
			acl_free_routes();
			rte_exit(EXIT_FAILURE, "Failed to add IPv4 rules\n");
		}
	} else {
		RTE_LOG(ERR, L3FWD, "IPv4 rule file not specified\n");
		rte_exit(EXIT_FAILURE, "Failed to get valid route options\n");
	}

	/* ipv6 check */
	if (parm_config.rule_ipv6_name != NULL) {
		if (acl_add_rules(parm_config.rule_ipv6_name, &route_base_ipv6,
				&route_num_ipv6,
				&acl_base_ipv6, &acl_num_ipv6,
				sizeof(struct acl6_rule), &parse_cb_ipv6_rule) < 0) {
			acl_free_routes();
			rte_exit(EXIT_FAILURE, "Failed to add IPv6 rules\n");
		}
	} else {
		RTE_LOG(ERR, L3FWD, "IPv6 rule file not specified\n");
		rte_exit(EXIT_FAILURE, "Failed to get valid route options\n");
	}
}

#ifdef L3FWDACL_DEBUG
static inline void
dump_acl4_rule(struct rte_mbuf *m, uint32_t sig)
{
	char abuf[INET6_ADDRSTRLEN];
	uint32_t offset = sig & ~ACL_DENY_SIGNATURE;
	struct rte_ipv4_hdr *ipv4_hdr =
		rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
					sizeof(struct rte_ether_hdr));

	printf("Packet Src:%s ", inet_ntop(AF_INET, ipv4_hdr->src_addr,
		abuf, sizeof(abuf)));
	printf("Dst:%s ", inet_ntop(AF_INET, ipv4_hdr->dst_addr,
		abuf, sizeof(abuf)));

	printf("Src port:%hu,Dst port:%hu ",
			rte_bswap16(*(uint16_t *)(ipv4_hdr + 1)),
			rte_bswap16(*((uint16_t *)(ipv4_hdr + 1) + 1)));
	printf("hit ACL %d - ", offset);

	print_one_ipv4_rule(acl_config.rule_ipv4 + offset, 1);

	printf("\n\n");
}

static inline void
dump_acl6_rule(struct rte_mbuf *m, uint32_t sig)
{
	char abuf[INET6_ADDRSTRLEN];
	uint32_t offset = sig & ~ACL_DENY_SIGNATURE;
	struct rte_ipv6_hdr *ipv6_hdr =
		rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
					sizeof(struct rte_ether_hdr));

	printf("Packet Src");
	printf("%s", inet_ntop(AF_INET6, ipv6_hdr->src_addr,
		abuf, sizeof(abuf)));
	printf("\nDst");
	printf("%s", inet_ntop(AF_INET6, ipv6_hdr->dst_addr,
		abuf, sizeof(abuf)));

	printf("\nSrc port:%hu,Dst port:%hu ",
			rte_bswap16(*(uint16_t *)(ipv6_hdr + 1)),
			rte_bswap16(*((uint16_t *)(ipv6_hdr + 1) + 1)));
	printf("hit ACL %d - ", offset);

	print_one_ipv6_rule(acl_config.rule_ipv6 + offset, 1);

	printf("\n\n");
}
#endif /* L3FWDACL_DEBUG */

static inline void
dump_ipv4_rules(struct acl4_rule *rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv4_rule(rule, extra);
		printf("\n");
	}
}

static inline void
dump_ipv6_rules(struct acl6_rule *rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv6_rule(rule, extra);
		printf("\n");
	}
}

void
setup_acl(const int socket_id)
{
	if (check_acl_config() != 0)
		rte_exit(EXIT_FAILURE, "Failed to get valid ACL options\n");

	dump_acl_config();

	acl_log("IPv4 Route entries %u:\n", route_num_ipv4);
	dump_ipv4_rules((struct acl4_rule *)route_base_ipv4, route_num_ipv4, 1);

	acl_log("IPv4 ACL entries %u:\n", acl_num_ipv4);
	dump_ipv4_rules((struct acl4_rule *)acl_base_ipv4, acl_num_ipv4, 1);

	acl_log("IPv6 Route entries %u:\n", route_num_ipv6);
	dump_ipv6_rules((struct acl6_rule *)route_base_ipv6, route_num_ipv6, 1);

	acl_log("IPv6 ACL entries %u:\n", acl_num_ipv6);
	dump_ipv6_rules((struct acl6_rule *)acl_base_ipv6, acl_num_ipv6, 1);

	memset(&acl_config, 0, sizeof(acl_config));

	/* Check sockets a context should be created on */
	if (socket_id >= NB_SOCKETS) {
		acl_log("Socket %d is out "
			"of range %d\n",
			socket_id, NB_SOCKETS);
		acl_free_routes();
		return;
	}

	acl_config.acx_ipv4[socket_id] = app_acl_init(route_base_ipv4,
		acl_base_ipv4, route_num_ipv4, acl_num_ipv4,
		0, socket_id);

	acl_config.acx_ipv6[socket_id] = app_acl_init(route_base_ipv6,
		acl_base_ipv6, route_num_ipv6, acl_num_ipv6,
		1, socket_id);

#ifdef L3FWDACL_DEBUG
	acl_config.rule_ipv4 = (struct acl4_rule *)acl_base_ipv4;
	acl_config.rule_ipv6 = (struct acl6_rule *)acl_base_ipv6;
#endif

}

/* main processing loop */
int
acl_main_loop(__rte_unused void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint16_t portid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	int socketid;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)
			/ US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;
	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	socketid = rte_lcore_to_socket_id(lcore_id);

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {

			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid,
				pkts_burst, MAX_PKT_BURST);

			if (nb_rx > 0) {
				struct acl_search_t acl_search;

				l3fwd_acl_prepare_acl_parameter(pkts_burst, &acl_search,
					nb_rx);

				if (acl_search.num_ipv4) {
					rte_acl_classify(
						acl_config.acx_ipv4[socketid],
						acl_search.data_ipv4,
						acl_search.res_ipv4,
						acl_search.num_ipv4,
						DEFAULT_MAX_CATEGORIES);

					l3fwd_acl_send_packets(qconf,
						acl_search.m_ipv4,
						acl_search.res_ipv4,
						acl_search.num_ipv4);
				}

				if (acl_search.num_ipv6) {
					rte_acl_classify(
						acl_config.acx_ipv6[socketid],
						acl_search.data_ipv6,
						acl_search.res_ipv6,
						acl_search.num_ipv6,
						DEFAULT_MAX_CATEGORIES);

					l3fwd_acl_send_packets(qconf,
						acl_search.m_ipv6,
						acl_search.res_ipv6,
						acl_search.num_ipv6);
				}
			}
		}
	}
	return 0;
}

static inline void
acl_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	void *l3;
	int hdr_len;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr);
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ipv4_hdr = (struct rte_ipv4_hdr *)l3;
		hdr_len = rte_ipv4_hdr_len(ipv4_hdr);
		if (hdr_len == sizeof(struct rte_ipv4_hdr)) {
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		} else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	} else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		ipv6_hdr = (struct rte_ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}

	m->packet_type = packet_type;
}

uint16_t
acl_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused, struct rte_mbuf *pkts[],
		  uint16_t nb_pkts, uint16_t max_pkts __rte_unused, void *user_param __rte_unused)
{
	unsigned int i;

	for (i = 0; i < nb_pkts; ++i)
		acl_parse_ptype(pkts[i]);

	return nb_pkts;
}

int
acl_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4_ext = 0;
	int ptype_l3_ipv6_ext = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		switch (ptypes[i]) {
		case RTE_PTYPE_L3_IPV4_EXT:
			ptype_l3_ipv4_ext = 1;
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
			ptype_l3_ipv6_ext = 1;
			break;
		case RTE_PTYPE_L4_TCP:
			ptype_l4_tcp = 1;
			break;
		case RTE_PTYPE_L4_UDP:
			ptype_l4_udp = 1;
			break;
		}
	}

	if (ptype_l3_ipv4_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4_EXT\n", portid);
	if (ptype_l3_ipv6_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6_EXT\n", portid);
	if (!ptype_l3_ipv4_ext || !ptype_l3_ipv6_ext)
		return 0;

	if (ptype_l4_tcp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_TCP\n", portid);
	if (ptype_l4_udp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_UDP\n", portid);
	if (ptype_l4_tcp && ptype_l4_udp)
		return 1;

	return 0;
}

/* Not used by L3fwd ACL. */
void *
acl_get_ipv4_l3fwd_lookup_struct(__rte_unused const int socketid)
{
	return NULL;
}

void *
acl_get_ipv6_l3fwd_lookup_struct(__rte_unused const int socketid)
{
	return NULL;
}
