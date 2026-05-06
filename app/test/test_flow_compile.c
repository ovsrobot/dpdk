/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

/*
 * Unit tests for rte_flow_compile.
 *
 * These exercise the parser only -- they don't need a real ethdev
 * port.  They check both successful parses (asserting the resulting
 * pattern/action arrays) and parse failures (asserting that the
 * error buffer contains a recognizable substring).
 */

#include <stdint.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_flow.h>

#include "test.h"
#include "rte_flow_compile.h"

static int
test_simple_eth_drop(void)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	struct rte_flow_compile *fc =
		rte_flow_compile("ingress pattern eth / end actions drop / end",
				 err);
	TEST_ASSERT_NOT_NULL(fc, "compile failed: %s", err);

	TEST_ASSERT_EQUAL(rte_flow_compile_attr(fc)->ingress, 1,
			  "ingress not set");
	TEST_ASSERT_EQUAL(rte_flow_compile_attr(fc)->egress, 0,
			  "egress should not be set");

	unsigned int n;
	const struct rte_flow_item *p = rte_flow_compile_pattern(fc, &n);
	TEST_ASSERT_EQUAL(n, 2u, "expected 2 items, got %u", n);
	TEST_ASSERT_EQUAL(p[0].type, RTE_FLOW_ITEM_TYPE_ETH,
			  "item 0 type");
	TEST_ASSERT_NULL(p[0].spec, "eth spec should be NULL");
	TEST_ASSERT_EQUAL(p[1].type, RTE_FLOW_ITEM_TYPE_END,
			  "item 1 should be END");

	const struct rte_flow_action *a = rte_flow_compile_actions(fc, &n);
	TEST_ASSERT_EQUAL(n, 2u, "expected 2 actions, got %u", n);
	TEST_ASSERT_EQUAL(a[0].type, RTE_FLOW_ACTION_TYPE_DROP,
			  "action 0 type");
	TEST_ASSERT_EQUAL(a[1].type, RTE_FLOW_ACTION_TYPE_END,
			  "action 1 should be END");

	rte_flow_compile_free(fc);
	return 0;
}

static int
test_ipv4_match_queue(void)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	const char *src =
		"ingress group 0 priority 1\n"
		"pattern eth / ipv4 src is 10.0.0.1 dst is 10.0.0.2 /"
		"   udp dst is 4789 / end\n"
		"actions queue index 3 / count / end\n";

	struct rte_flow_compile *fc = rte_flow_compile(src, err);
	TEST_ASSERT_NOT_NULL(fc, "compile failed: %s", err);

	TEST_ASSERT_EQUAL(rte_flow_compile_attr(fc)->priority, 1u,
			  "priority not set");

	unsigned int n;
	const struct rte_flow_item *p = rte_flow_compile_pattern(fc, &n);
	TEST_ASSERT_EQUAL(n, 4u, "expected 4 items");
	TEST_ASSERT_EQUAL(p[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
			  "item 1 should be IPV4");

	const struct rte_flow_item_ipv4 *ipv4 = p[1].spec;
	const struct rte_flow_item_ipv4 *m4   = p[1].mask;
	TEST_ASSERT_NOT_NULL(ipv4, "ipv4 spec");
	TEST_ASSERT_NOT_NULL(m4,   "ipv4 mask");

	/* 10.0.0.1 in network order = bytes 0a 00 00 01 */
	const uint8_t *src_b = (const uint8_t *)&ipv4->hdr.src_addr;
	const uint8_t *dst_b = (const uint8_t *)&ipv4->hdr.dst_addr;
	TEST_ASSERT_EQUAL(src_b[0], 0x0a, "src[0]");
	TEST_ASSERT_EQUAL(src_b[3], 0x01, "src[3]");
	TEST_ASSERT_EQUAL(dst_b[0], 0x0a, "dst[0]");
	TEST_ASSERT_EQUAL(dst_b[3], 0x02, "dst[3]");

	const uint8_t *src_m = (const uint8_t *)&m4->hdr.src_addr;
	for (int i = 0; i < 4; i++)
		TEST_ASSERT_EQUAL(src_m[i], 0xff, "src mask byte %d", i);

	TEST_ASSERT_EQUAL(p[2].type, RTE_FLOW_ITEM_TYPE_UDP,
			  "item 2 should be UDP");
	const struct rte_flow_item_udp *u = p[2].spec;
	TEST_ASSERT_EQUAL(rte_be_to_cpu_16(u->hdr.dst_port), 4789,
			  "udp dst port");

	const struct rte_flow_action *a = rte_flow_compile_actions(fc, &n);
	TEST_ASSERT_EQUAL(n, 3u, "expected 3 actions");
	TEST_ASSERT_EQUAL(a[0].type, RTE_FLOW_ACTION_TYPE_QUEUE,
			  "action 0 should be QUEUE");
	const struct rte_flow_action_queue *q = a[0].conf;
	TEST_ASSERT_EQUAL(q->index, 3u, "queue index");
	TEST_ASSERT_EQUAL(a[1].type, RTE_FLOW_ACTION_TYPE_COUNT,
			  "action 1 should be COUNT");

	rte_flow_compile_free(fc);
	return 0;
}

static int
test_ipv4_prefix(void)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	struct rte_flow_compile *fc = rte_flow_compile(
		"pattern eth / ipv4 src spec 192.168.0.0 src prefix 16 / end "
		"actions drop / end", err);
	TEST_ASSERT_NOT_NULL(fc, "compile failed: %s", err);

	const struct rte_flow_item *p = rte_flow_compile_pattern(fc, NULL);
	const struct rte_flow_item_ipv4 *m = p[1].mask;
	TEST_ASSERT_NOT_NULL(m, "ipv4 mask");
	TEST_ASSERT_EQUAL(rte_be_to_cpu_32(m->hdr.src_addr), 0xffff0000u,
			  "/16 prefix mask");

	rte_flow_compile_free(fc);
	return 0;
}

static int
test_mac(void)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	struct rte_flow_compile *fc = rte_flow_compile(
		"pattern eth dst is 11:22:33:44:55:66 / end "
		"actions drop / end", err);
	TEST_ASSERT_NOT_NULL(fc, "compile failed: %s", err);

	const struct rte_flow_item *p = rte_flow_compile_pattern(fc, NULL);
	const struct rte_flow_item_eth *e = p[0].spec;
	TEST_ASSERT_EQUAL(e->hdr.dst_addr.addr_bytes[0], 0x11,
			  "MAC byte 0");
	TEST_ASSERT_EQUAL(e->hdr.dst_addr.addr_bytes[5], 0x66,
			  "MAC byte 5");

	rte_flow_compile_free(fc);
	return 0;
}

static int
test_ipv6(void)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	struct rte_flow_compile *fc = rte_flow_compile(
		"pattern eth / ipv6 dst is 2001:db8::1 / end "
		"actions drop / end", err);
	TEST_ASSERT_NOT_NULL(fc, "compile failed: %s", err);

	const struct rte_flow_item *p = rte_flow_compile_pattern(fc, NULL);
	const struct rte_flow_item_ipv6 *v6 = p[1].spec;
	const uint8_t *b = (const uint8_t *)&v6->hdr.dst_addr;
	TEST_ASSERT_EQUAL(b[0],  0x20, "ipv6[0]");
	TEST_ASSERT_EQUAL(b[1],  0x01, "ipv6[1]");
	TEST_ASSERT_EQUAL(b[2],  0x0d, "ipv6[2]");
	TEST_ASSERT_EQUAL(b[3],  0xb8, "ipv6[3]");
	TEST_ASSERT_EQUAL(b[15], 0x01, "ipv6[15]");

	rte_flow_compile_free(fc);
	return 0;
}

static int
expect_error(const char *src, const char *needle)
{
	char err[RTE_FLOW_COMPILE_ERRBUF_SIZE];
	struct rte_flow_compile *fc = rte_flow_compile(src, err);

	TEST_ASSERT_NULL(fc, "expected failure, got success: %s", src);
	TEST_ASSERT(strstr(err, needle) != NULL,
		    "error '%s' did not contain '%s'", err, needle);
	return 0;
}

static int
test_errors(void)
{
	TEST_ASSERT_SUCCESS(expect_error("",
		"expected"), "empty input");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern bogus / end actions drop / end",
		"unknown flow item"), "unknown item");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern eth bogus is 1 / end actions drop / end",
		"unknown field"), "unknown field");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern eth dst is 1 / end actions drop / end",
		"MAC"), "non-MAC value for MAC field");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern eth / end actions queue bogus 1 / end",
		"unknown parameter"), "unknown action parameter");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern eth / end actions queue index 99999 / end",
		"out of range"), "out-of-range action parameter");
	TEST_ASSERT_SUCCESS(expect_error(
		"pattern eth ; / end actions drop / end",
		"unexpected"), "unexpected character");
	return 0;
}

static struct unit_test_suite flow_compile_suite = {
	.suite_name = "flow_compile",
	.unit_test_cases = {
		TEST_CASE(test_simple_eth_drop),
		TEST_CASE(test_ipv4_match_queue),
		TEST_CASE(test_ipv4_prefix),
		TEST_CASE(test_mac),
		TEST_CASE(test_ipv6),
		TEST_CASE(test_errors),
		TEST_CASES_END(),
	},
};

static int
test_flow_compile(void)
{
	return unit_test_suite_runner(&flow_compile_suite);
}

REGISTER_FAST_TEST(flow_compile_autotest, NOHUGE_OK, ASAN_OK, test_flow_compile);
