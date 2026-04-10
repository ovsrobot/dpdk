/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 DynaNIC Semiconductors, Ltd.
 */

/*
 * Flow Parsing Example
 * ====================
 * This example demonstrates how to use the ethdev flow parser to parse
 * flow rule strings into rte_flow C structures. The library provides ONE WAY
 * to create rte_flow structures - by parsing testpmd-style command strings.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_flow_parser.h>
#include <rte_flow_parser_cmdline.h>

/* Helper to print flow attributes */
static void
print_attr(const struct rte_flow_attr *attr)
{
	printf("  Attributes:\n");
	printf("    group=%u priority=%u\n", attr->group, attr->priority);
	printf("    ingress=%u egress=%u transfer=%u\n",
	       attr->ingress, attr->egress, attr->transfer);
}

/* Helper to print a MAC address */
static void
print_mac(const char *label, const struct rte_ether_addr *mac)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, sizeof(buf), mac);
	printf("    %s: %s\n", label, buf);
}

/* Helper to print pattern items */
static void
print_pattern(const struct rte_flow_item *pattern, uint32_t pattern_n)
{
	uint32_t i;

	printf("  Pattern (%u items):\n", pattern_n);
	for (i = 0; i < pattern_n; i++) {
		const struct rte_flow_item *item = &pattern[i];

		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_END:
			printf("    [%u] END\n", i);
			break;
		case RTE_FLOW_ITEM_TYPE_ETH:
			printf("    [%u] ETH", i);
			if (item->spec) {
				const struct rte_flow_item_eth *eth = item->spec;

				printf("\n");
				print_mac("dst", &eth->hdr.dst_addr);
				print_mac("src", &eth->hdr.src_addr);
			} else {
				printf(" (any)\n");
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			printf("    [%u] IPV4", i);
			if (item->spec) {
				const struct rte_flow_item_ipv4 *ipv4 = item->spec;
				const uint8_t *s = (const uint8_t *)&ipv4->hdr.src_addr;
				const uint8_t *d = (const uint8_t *)&ipv4->hdr.dst_addr;

				printf(" src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
				       s[0], s[1], s[2], s[3],
				       d[0], d[1], d[2], d[3]);
			} else {
				printf(" (any)\n");
			}
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			printf("    [%u] TCP", i);
			if (item->spec) {
				const struct rte_flow_item_tcp *tcp = item->spec;

				printf(" sport=%u dport=%u\n",
				       rte_be_to_cpu_16(tcp->hdr.src_port),
				       rte_be_to_cpu_16(tcp->hdr.dst_port));
			} else {
				printf(" (any)\n");
			}
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			printf("    [%u] UDP", i);
			if (item->spec) {
				const struct rte_flow_item_udp *udp = item->spec;

				printf(" sport=%u dport=%u\n",
				       rte_be_to_cpu_16(udp->hdr.src_port),
				       rte_be_to_cpu_16(udp->hdr.dst_port));
			} else {
				printf(" (any)\n");
			}
			break;
		default:
			printf("    [%u] type=%d\n", i, item->type);
			break;
		}
	}
}

/* Helper to print actions */
static void
print_actions(const struct rte_flow_action *actions, uint32_t actions_n)
{
	uint32_t i;

	printf("  Actions (%u items):\n", actions_n);
	for (i = 0; i < actions_n; i++) {
		const struct rte_flow_action *action = &actions[i];

		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_END:
			printf("    [%u] END\n", i);
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			printf("    [%u] DROP\n", i);
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			if (action->conf) {
				const struct rte_flow_action_queue *q = action->conf;

				printf("    [%u] QUEUE index=%u\n", i, q->index);
			} else {
				printf("    [%u] QUEUE\n", i);
			}
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			if (action->conf) {
				const struct rte_flow_action_mark *m = action->conf;

				printf("    [%u] MARK id=%u\n", i, m->id);
			} else {
				printf("    [%u] MARK\n", i);
			}
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			printf("    [%u] COUNT\n", i);
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			if (action->conf) {
				const struct rte_flow_action_port_id *p = action->conf;

				printf("    [%u] PORT_ID id=%u\n", i, p->id);
			} else {
				printf("    [%u] PORT_ID\n", i);
			}
			break;
		default:
			printf("    [%u] type=%d\n", i, action->type);
			break;
		}
	}
}

/*
 * Demonstrate parsing flow attributes
 */
static void
demo_parse_attr(void)
{
	static const char * const attr_strings[] = {
		"ingress",
		"egress",
		"ingress priority 5",
		"ingress group 1 priority 10",
		"transfer",
	};
	struct rte_flow_attr attr;
	unsigned int i;
	int ret;

	printf("\n=== Parsing Flow Attributes ===\n");
	printf("Use rte_flow_parser_parse_attr_str() to parse attribute strings.\n\n");

	for (i = 0; i < RTE_DIM(attr_strings); i++) {
		printf("Input: \"%s\"\n", attr_strings[i]);
		memset(&attr, 0, sizeof(attr));
		ret = rte_flow_parser_parse_attr_str(attr_strings[i], &attr);
		if (ret == 0)
			print_attr(&attr);
		else
			printf("  ERROR: %d (%s)\n", ret, strerror(-ret));
		printf("\n");
	}
}

/*
 * Demonstrate parsing flow patterns
 */
static void
demo_parse_pattern(void)
{
	static const char * const pattern_strings[] = {
		"eth / end",
		"eth dst is 90:61:ae:fd:41:43 / end",
		"eth / ipv4 src is 192.168.1.1 / end",
		"eth / ipv4 / tcp dst is 80 / end",
		"eth / ipv4 src is 10.0.0.1 dst is 10.0.0.2 / udp src is 1234 dst is 5678 / end",
	};
	const struct rte_flow_item *pattern;
	uint32_t pattern_n;
	unsigned int i;
	int ret;

	printf("\n=== Parsing Flow Patterns ===\n");
	printf("Use rte_flow_parser_parse_pattern_str() to parse pattern strings.\n\n");

	for (i = 0; i < RTE_DIM(pattern_strings); i++) {
		printf("Input: \"%s\"\n", pattern_strings[i]);
		ret = rte_flow_parser_parse_pattern_str(pattern_strings[i],
							&pattern, &pattern_n);
		if (ret == 0)
			print_pattern(pattern, pattern_n);
		else
			printf("  ERROR: %d (%s)\n", ret, strerror(-ret));
		printf("\n");
	}
}

/*
 * Demonstrate parsing flow actions
 */
static void
demo_parse_actions(void)
{
	static const char * const action_strings[] = {
		"drop / end",
		"queue index 3 / end",
		"mark id 42 / end",
		"count / queue index 1 / end",
		"mark id 100 / count / queue index 5 / end",
	};
	const struct rte_flow_action *actions;
	uint32_t actions_n;
	unsigned int i;
	int ret;

	printf("\n=== Parsing Flow Actions ===\n");
	printf("Use rte_flow_parser_parse_actions_str() to parse action strings.\n\n");

	for (i = 0; i < RTE_DIM(action_strings); i++) {
		printf("Input: \"%s\"\n", action_strings[i]);
		ret = rte_flow_parser_parse_actions_str(action_strings[i],
							&actions, &actions_n);
		if (ret == 0)
			print_actions(actions, actions_n);
		else
			printf("  ERROR: %d (%s)\n", ret, strerror(-ret));
		printf("\n");
	}
}

/*
 * Demonstrate full command parsing
 */
static void
demo_full_command_parse(void)
{
	uint8_t buf[4096];
	struct rte_flow_parser_output *out = (void *)buf;
	int ret;

	static const char * const commands[] = {
		"flow create 0 ingress pattern eth / ipv4 / end actions drop / end",
		"flow validate 0 ingress pattern eth / ipv4 / tcp dst is 80 / end actions queue index 3 / end",
		"flow list 0",
		"flow flush 0",
	};

	printf("\n=== Full Command Parsing ===\n");
	printf("Use rte_flow_parser_parse() from rte_flow_parser_cmdline.h\n");
	printf("to parse complete flow CLI commands.\n\n");

	for (unsigned int i = 0; i < RTE_DIM(commands); i++) {
		printf("Input: \"%s\"\n", commands[i]);
		memset(buf, 0, sizeof(buf));
		ret = rte_flow_parser_parse(commands[i], out, sizeof(buf));
		if (ret == 0) {
			printf("  command=%d port=%u\n",
			       out->command, out->port);
			if (out->command == RTE_FLOW_PARSER_CMD_CREATE ||
			    out->command == RTE_FLOW_PARSER_CMD_VALIDATE)
				printf("  pattern_n=%u actions_n=%u\n",
				       out->args.vc.pattern_n,
				       out->args.vc.actions_n);
		} else {
			printf("  ERROR: %d (%s)\n", ret, strerror(-ret));
		}
		printf("\n");
	}
}

/*
 * Demonstrate configuration registration
 */
static void
demo_config_registration(void)
{
	static struct rte_flow_parser_vxlan_encap_conf vxlan;
	static struct rte_flow_parser_raw_encap_data raw_encap[2];
	const struct rte_flow_item *items;
	uint32_t items_n;
	int ret;

	printf("\n=== Configuration Registration ===\n");
	printf("Applications own config storage and register it\n");
	printf("with rte_flow_parser_config_register().\n\n");

	memset(raw_encap, 0, sizeof(raw_encap));

	struct rte_flow_parser_config cfg = {
		.vxlan_encap = &vxlan,
		.raw_encap = { raw_encap, 2 },
	};
	ret = rte_flow_parser_config_register(&cfg);
	printf("config_register: %s\n\n", ret == 0 ? "OK" : "FAILED");

	/* Write directly to app-owned config */
	vxlan.select_ipv4 = 1;
	vxlan.vni[0] = 0x12;
	vxlan.vni[1] = 0x34;
	vxlan.vni[2] = 0x56;
	/*
	 * Parse a flow rule that references vxlan_encap.
	 * The parser reads the config we just wrote above.
	 */
	uint8_t buf[4096];
	struct rte_flow_parser_output *out = (void *)buf;

	ret = rte_flow_parser_parse(
		"flow create 0 transfer pattern eth / end "
		"actions vxlan_encap / port_id id 1 / end",
		out, sizeof(buf));
	if (ret == 0 && out->args.vc.actions_n > 0) {
		const struct rte_flow_action *act = &out->args.vc.actions[0];

		printf("Parsed vxlan_encap action: type=%d conf=%s\n",
		       act->type, act->conf ? "present" : "NULL");
		if (act->conf) {
			const struct rte_flow_action_vxlan_encap *ve =
				act->conf;
			const struct rte_flow_item *item = ve->definition;
			unsigned int n = 0;

			printf("  Encap tunnel headers:");
			while (item && item->type != RTE_FLOW_ITEM_TYPE_END) {
				printf(" 0x%02x", item->type);
				item++;
				n++;
			}
			printf(" (%u items)\n", n);
		}
	} else {
		printf("vxlan_encap parse: %s\n",
		       ret == 0 ? "no actions" : strerror(-ret));
	}

	printf("VXLAN config: ipv4=%u vni=0x%02x%02x%02x\n",
	       vxlan.select_ipv4,
	       vxlan.vni[0], vxlan.vni[1], vxlan.vni[2]);
	printf("\n");

	/* Use setter API for raw encap */
	ret = rte_flow_parser_parse_pattern_str(
		"eth / ipv4 / udp / vxlan / end", &items, &items_n);
	if (ret == 0) {
		ret = rte_flow_parser_raw_encap_conf_set(0, items, items_n);
		printf("raw_encap_conf_set: %s\n",
		       ret == 0 ? "OK" : "FAILED");
	}

	const struct rte_flow_action_raw_encap *encap =
		rte_flow_parser_raw_encap_conf(0);
	if (encap != NULL)
		printf("raw_encap[0]: %zu bytes serialized\n", encap->size);
	printf("\n");
}

int
main(void)
{
	printf("Flow Parser Library Example\n");
	printf("===========================\n");

	/* Run demonstrations */
	demo_parse_attr();
	demo_parse_pattern();
	demo_parse_actions();
	demo_config_registration();
	demo_full_command_parse();

	printf("\n=== Example Complete ===\n");
	return 0;
}
