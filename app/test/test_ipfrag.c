/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Red Hat, Inc.
 */

#include "test.h"

#include <time.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_hexdump.h>
#include <rte_ip.h>

#ifdef RTE_EXEC_ENV_WINDOWS
static int
test_ipfrag(void)
{
	printf("ipfrag not supported on Windows, skipping test\n");
	return TEST_SKIPPED;
}

#else

#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_random.h>

#define NUM_MBUFS 128
#define BURST 32

/* IP options */
#define RTE_IPOPT_EOL				0
#define RTE_IPOPT_NOP				1
#define RTE_IPOPT_COPIED(v)			((v) & 0x80)
#define RTE_IPOPT_MAX_LEN			40

#define RTE_IPOPT_MANUAL

#ifdef RTE_IPOPT_MANUAL
uint8_t expected_first_frag_ipv4_opts[] = {
	0x07, 0x0b, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x83,
	0x07, 0x04, 0xc0, 0xa8,
	0xe3, 0x96, 0x00, 0x00,
};

#ifdef RTE_IPOPT_KEEP_IP_HLEN
uint8_t expected_sub_frag_ipv4_opts[] = {
	RTE_IPOPT_NOP, RTE_IPOPT_NOP, RTE_IPOPT_NOP, RTE_IPOPT_NOP,
	RTE_IPOPT_NOP, RTE_IPOPT_NOP, RTE_IPOPT_NOP, RTE_IPOPT_NOP,
	RTE_IPOPT_NOP, RTE_IPOPT_NOP, RTE_IPOPT_NOP, 0x83,
	0x07, 0x04, 0xc0, 0xa8,
	0xe3, 0x96, 0x00, 0x00,
};
#else
uint8_t expected_sub_frag_ipv4_opts[] = {
	0x83, 0x07, 0x04, 0xc0,
	0xa8, 0xe3, 0x96, 0x00,
};
#endif
#else
/**
 * IPv4 Options
 */
struct test_ipv4_opt {
	__extension__
	union {
		uint8_t type;		    /**< option type */
		struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			uint8_t number:5;   /**< option number */
			uint8_t category:2; /**< option class */
			uint8_t copied:1;   /**< option copy flag */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
			uint8_t copied:1;   /**< option copy flag */
			uint8_t category:2; /**< option class */
			uint8_t number:5;   /**< option number */
#endif
		} s_type;
	};
	uint8_t length;			    /**< option length */
	uint8_t pointer;		    /**< option pointer */
	uint8_t data[37];		    /**< option data */
} __rte_packed;

struct test_ipv4_opt test_ipv4_opts[] = {
	{
		.s_type.copied = 0,
		.s_type.category = 0,
		.s_type.number = 7,
		.length = 11,
		.pointer = 4,
	},
	{
		.s_type.copied = 1,
		.s_type.category = 0,
		.s_type.number = 3,
		.length = 7,
		.pointer = 4,
		.data[0] = 0xc0,
		.data[1] = 0xa8,
		.data[2] = 0xe3,
		.data[3] = 0x96,
	},
};
#endif

struct test_opt_data {
	bool is_first_frag;		 /**< offset is 0 */
	uint16_t len;			 /**< option data len */
	uint8_t data[RTE_IPOPT_MAX_LEN]; /**< option data */
};

static struct rte_mempool *pkt_pool,
			  *direct_pool,
			  *indirect_pool;

static inline void
hex_to_str(uint8_t *hex, uint16_t len, char *str)
{
	int i;

	for (i = 0; i < len; i++) {
		sprintf(str, "%02x", hex[i]);
		str += 2;
	}
	*str = 0;
}

static int
setup_buf_pool(void)
{
	pkt_pool = rte_pktmbuf_pool_create("FRAG_MBUF_POOL",
					   NUM_MBUFS, BURST, 0,
					   RTE_MBUF_DEFAULT_BUF_SIZE,
					   SOCKET_ID_ANY);
	if (pkt_pool == NULL) {
		printf("%s: Error creating pkt mempool\n", __func__);
		goto bad_setup;
	}

	direct_pool = rte_pktmbuf_pool_create("FRAG_D_MBUF_POOL",
					      NUM_MBUFS, BURST, 0,
					      RTE_MBUF_DEFAULT_BUF_SIZE,
					      SOCKET_ID_ANY);
	if (direct_pool == NULL) {
		printf("%s: Error creating direct mempool\n", __func__);
		goto bad_setup;
	}

	indirect_pool = rte_pktmbuf_pool_create("FRAG_I_MBUF_POOL",
						NUM_MBUFS, BURST, 0,
						0, SOCKET_ID_ANY);
	if (indirect_pool == NULL) {
		printf("%s: Error creating indirect mempool\n", __func__);
		goto bad_setup;
	}

	return TEST_SUCCESS;

bad_setup:
	rte_mempool_free(pkt_pool);
	pkt_pool = NULL;

	rte_mempool_free(direct_pool);
	direct_pool = NULL;

	return TEST_FAILED;
}

static int testsuite_setup(void)
{
	return setup_buf_pool();
}

static void testsuite_teardown(void)
{
	rte_mempool_free(pkt_pool);
	rte_mempool_free(direct_pool);
	rte_mempool_free(indirect_pool);

	pkt_pool = NULL;
	direct_pool = NULL;
	indirect_pool = NULL;
}

static int ut_setup(void)
{
	return TEST_SUCCESS;
}

static void ut_teardown(void)
{
}

static inline void
test_get_ipv4_opt(bool is_first_frag,
	struct test_opt_data *expected_opt)
{
#ifdef RTE_IPOPT_MANUAL
	if (is_first_frag) {
		expected_opt->len = sizeof(expected_first_frag_ipv4_opts);
		rte_memcpy(expected_opt->data, expected_first_frag_ipv4_opts,
			sizeof(expected_first_frag_ipv4_opts));
	} else {
		expected_opt->len = sizeof(expected_sub_frag_ipv4_opts);
		rte_memcpy(expected_opt->data, expected_sub_frag_ipv4_opts,
			sizeof(expected_sub_frag_ipv4_opts));
	}
#else
	uint16_t i;
	uint16_t pos = 0;
	expected_opt->len = 0;

	for (i = 0; i < RTE_DIM(test_ipv4_opts); i++) {
		if (unlikely(pos + test_ipv4_opts[i].length >
				RTE_IPOPT_MAX_LEN))
			return;

		if (is_first_frag) {
			rte_memcpy(expected_opt->data + pos, &test_ipv4_opts[i],
				test_ipv4_opts[i].length);
			expected_opt->len += test_ipv4_opts[i].length;
			pos += test_ipv4_opts[i].length;
		} else {
			if (test_ipv4_opts[i].s_type.copied) {
				rte_memcpy(expected_opt->data + pos,
					&test_ipv4_opts[i],
					test_ipv4_opts[i].length);
				expected_opt->len += test_ipv4_opts[i].length;
				pos += test_ipv4_opts[i].length;
#ifdef RTE_IPOPT_KEEP_IP_HLEN
			} else {
				memset(expected_opt->data + pos, RTE_IPOPT_NOP,
					test_ipv4_opts[i].length);
				expected_opt->len += test_ipv4_opts[i].length;
				pos += test_ipv4_opts[i].length;
#endif
			}
		}
	}

	expected_opt->len = RTE_ALIGN_CEIL(expected_opt->len, 4);
	memset(expected_opt->data + pos, RTE_IPOPT_EOL,
		expected_opt->len - pos);
#endif
}

static void
v4_allocate_packet_of(struct rte_mbuf *b, int fill, size_t s,
	int df, uint8_t mf, uint16_t off, uint8_t ttl, uint8_t proto,
	uint16_t pktid, bool have_opt, bool is_first_frag)
{
	/* Create a packet, 2k bytes long */
	b->data_off = 0;
	char *data = rte_pktmbuf_mtod(b, char *);
	rte_be16_t fragment_offset = 0;	/* fragmentation offset */
	uint16_t iph_len;
	struct test_opt_data opt;

	opt.len = 0;

	if (have_opt)
		test_get_ipv4_opt(is_first_frag, &opt);

	iph_len = sizeof(struct rte_ipv4_hdr) + opt.len;
	memset(data, fill, iph_len + s);

	struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)data;

	hdr->version_ihl = 0x40; /* ipv4 */
	hdr->version_ihl += (iph_len / 4);
	hdr->type_of_service = 0;
	b->pkt_len = s + iph_len;
	b->data_len = b->pkt_len;
	hdr->total_length = rte_cpu_to_be_16(b->pkt_len);
	hdr->packet_id = rte_cpu_to_be_16(pktid);

	if (df)
		fragment_offset |= 0x4000;

	if (mf)
		fragment_offset |= 0x2000;

	if (off)
		fragment_offset |= off;

	hdr->fragment_offset = rte_cpu_to_be_16(fragment_offset);

	if (!ttl)
		ttl = 64; /* default to 64 */

	if (!proto)
		proto = 1; /* icmp */

	hdr->time_to_live = ttl;
	hdr->next_proto_id = proto;
	hdr->hdr_checksum = 0;
	hdr->src_addr = rte_cpu_to_be_32(0x8080808);
	hdr->dst_addr = rte_cpu_to_be_32(0x8080404);

	rte_memcpy(hdr + 1, opt.data, opt.len);
}

static void
v6_allocate_packet_of(struct rte_mbuf *b, int fill, size_t s, uint8_t ttl,
		      uint8_t proto, uint16_t pktid)
{
	/* Create a packet, 2k bytes long */
	b->data_off = 0;
	char *data = rte_pktmbuf_mtod(b, char *);

	memset(data, fill, sizeof(struct rte_ipv6_hdr) + s);

	struct rte_ipv6_hdr *hdr = (struct rte_ipv6_hdr *)data;
	b->pkt_len = s + sizeof(struct rte_ipv6_hdr);
	b->data_len = b->pkt_len;

	/* basic v6 header */
	hdr->vtc_flow = rte_cpu_to_be_32(0x60 << 24 | pktid);
	hdr->payload_len = rte_cpu_to_be_16(b->pkt_len);
	hdr->proto = proto;
	hdr->hop_limits = ttl;

	memset(hdr->src_addr, 0x08, sizeof(hdr->src_addr));
	memset(hdr->dst_addr, 0x04, sizeof(hdr->src_addr));
}

static inline void
test_free_fragments(struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i;
	for (i = 0; i < num; i++)
		rte_pktmbuf_free(mb[i]);
}

static inline void
test_get_offset(struct rte_mbuf **mb, int32_t len,
	uint16_t *offset, int ipv)
{
	int32_t i;

	for (i = 0; i < len; i++) {
		if (ipv == 4) {
			struct rte_ipv4_hdr *iph =
			    rte_pktmbuf_mtod(mb[i], struct rte_ipv4_hdr *);
			offset[i] = iph->fragment_offset;
		} else if (ipv == 6) {
			struct ipv6_extension_fragment *fh =
			    rte_pktmbuf_mtod_offset(
					mb[i],
					struct ipv6_extension_fragment *,
					sizeof(struct rte_ipv6_hdr));
			offset[i] = fh->frag_data;
		}
	}
}

static inline void
test_get_frag_opt(struct rte_mbuf **mb, int32_t num,
	struct test_opt_data *opt, int ipv)
{
	int32_t i;

	for (i = 0; i < num; i++) {
		if (ipv == 4) {
			struct rte_ipv4_hdr *iph =
			    rte_pktmbuf_mtod(mb[i], struct rte_ipv4_hdr *);
			uint16_t header_len = (iph->version_ihl &
				RTE_IPV4_HDR_IHL_MASK) *
				RTE_IPV4_IHL_MULTIPLIER;
			uint16_t opt_len = header_len -
				sizeof(struct rte_ipv4_hdr);

			if ((rte_be_to_cpu_16(iph->fragment_offset) &
				    RTE_IPV4_HDR_OFFSET_MASK) == 0)
				opt->is_first_frag = true;
			else
				opt->is_first_frag = false;

			if (opt_len && (opt_len <= RTE_IPOPT_MAX_LEN)) {
				char *iph_opt = rte_pktmbuf_mtod_offset(mb[i],
				    char *, sizeof(struct rte_ipv4_hdr));
				opt->len = opt_len;
				rte_memcpy(opt->data, iph_opt, opt_len);
			} else {
				opt->len = RTE_IPOPT_MAX_LEN;
				memset(opt->data, RTE_IPOPT_EOL,
				    sizeof(opt->data));
			}
			opt++;
		}
	}
}

static int
test_ip_frag(void)
{
	static const uint16_t RND_ID = UINT16_MAX;
	int result = TEST_SUCCESS;
	size_t i, j;

	struct test_ip_frags {
		int      ipv;
		size_t   mtu_size;
		size_t   pkt_size;
		int      set_df;
		uint8_t  set_mf;
		uint16_t set_of;
		uint8_t  ttl;
		uint8_t  proto;
		uint16_t pkt_id;
		int      expected_frags;
		uint16_t expected_fragment_offset[BURST];
		bool have_opt;
		bool is_first_frag;
	} tests[] = {
		 {4, 1280, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,       2,
		  {0x2000, 0x009D}, 0},
		 {4, 1280, 1400, 0, 0, 0, 64, IPPROTO_ICMP, 0,            2,
		  {0x2000, 0x009D}, 0},
		 {4,  600, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,       3,
		  {0x2000, 0x2048, 0x0090}, 0},
		 {4, 4, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,    -EINVAL},
		 {4, 600, 1400, 1, 0, 0, 64, IPPROTO_ICMP, RND_ID, -ENOTSUP},
		 {4, 600, 1400, 0, 0, 0, 0, IPPROTO_ICMP, RND_ID,         3,
		  {0x2000, 0x2046, 0x008C}, 1, 1},
		 /* The first fragment */
		 {4, 68, 104, 0, 1, 0, 0, IPPROTO_ICMP, RND_ID,           5,
		  {0x2000, 0x2003, 0x2006, 0x2009, 0x200C}, 1, 1},
#ifdef RTE_IPOPT_KEEP_IP_HLEN
		 /* The middle fragment */
		 {4, 68, 104, 0, 1, 13, 0, IPPROTO_ICMP, RND_ID,          5,
		  {0x200D, 0x2010, 0x2013, 0x2016, 0x2019}, 1, 0},
#else
		 /* The middle fragment */
		 {4, 68, 104, 0, 1, 13, 0, IPPROTO_ICMP, RND_ID,          3,
		  {0x200D, 0x2012, 0x2017}, 1, 0},
#endif
#ifdef RTE_IPOPT_KEEP_IP_HLEN
		 /* The last fragment */
		 {4, 68, 104, 0, 0, 26, 0, IPPROTO_ICMP, RND_ID,          5,
		  {0x201A, 0x201D, 0x2020, 0x2023, 0x0026}, 1, 0},
#else
		 /* The last fragment */
		 {4, 68, 104, 0, 0, 26, 0, IPPROTO_ICMP, RND_ID,          3,
		  {0x201A, 0x201F, 0x0024}, 1, 0},
#endif
		 {6, 1280, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,       2,
		  {0x0001, 0x04D0}, 0},
		 {6, 1300, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,       2,
		  {0x0001, 0x04E0}, 0},
		 {6, 4, 1400, 0, 0, 0, 64, IPPROTO_ICMP, RND_ID,    -EINVAL},
		 {6, 1300, 1400, 0, 0, 0, 0, IPPROTO_ICMP, RND_ID,        2,
		  {0x0001, 0x04E0}, 0},
	};

	for (i = 0; i < RTE_DIM(tests); i++) {
		int32_t len = 0;
		uint16_t fragment_offset[BURST];
		struct test_opt_data opt_res[BURST];
		struct test_opt_data opt_exp;
		uint16_t pktid = tests[i].pkt_id;
		struct rte_mbuf *pkts_out[BURST];
		struct rte_mbuf *b = rte_pktmbuf_alloc(pkt_pool);

		RTE_TEST_ASSERT_NOT_EQUAL(b, NULL,
					  "Failed to allocate pkt.");

		if (tests[i].pkt_id == RND_ID)
			pktid = rte_rand_max(UINT16_MAX);

		if (tests[i].ipv == 4) {
			v4_allocate_packet_of(b, 0x41414141,
					      tests[i].pkt_size,
					      tests[i].set_df,
					      tests[i].set_mf,
					      tests[i].set_of,
					      tests[i].ttl,
					      tests[i].proto,
					      pktid,
					      tests[i].have_opt,
					      tests[i].is_first_frag);
		} else if (tests[i].ipv == 6) {
			v6_allocate_packet_of(b, 0x41414141,
					      tests[i].pkt_size,
					      tests[i].ttl,
					      tests[i].proto,
					      pktid);
		}

		if (tests[i].ipv == 4)
			len = rte_ipv4_fragment_packet(b, pkts_out, BURST,
						       tests[i].mtu_size,
						       direct_pool,
						       indirect_pool);
		else if (tests[i].ipv == 6)
			len = rte_ipv6_fragment_packet(b, pkts_out, BURST,
						       tests[i].mtu_size,
						       direct_pool,
						       indirect_pool);

		rte_pktmbuf_free(b);

		if (len > 0) {
			test_get_offset(pkts_out, len,
			    fragment_offset, tests[i].ipv);
			if (tests[i].have_opt)
				test_get_frag_opt(pkts_out, len,
					opt_res,
					tests[i].ipv);
			test_free_fragments(pkts_out, len);
		}

		printf("[check frag number]%zd: checking %d with %d\n", i, len,
		       tests[i].expected_frags);
		RTE_TEST_ASSERT_EQUAL(len, tests[i].expected_frags,
				      "Failed case %zd.\n", i);

		if (len > 0) {
			for (j = 0; j < (size_t)len; j++) {
				printf("[check offset]%zd-%zd: checking %d with %d\n",
				    i, j, fragment_offset[j],
				    rte_cpu_to_be_16(
					tests[i].expected_fragment_offset[j]));
				RTE_TEST_ASSERT_EQUAL(fragment_offset[j],
				    rte_cpu_to_be_16(
					tests[i].expected_fragment_offset[j]),
				    "Failed case %zd.\n", i);
			}

			if (tests[i].have_opt && (tests[i].ipv == 4)) {
				for (j = 0; j < (size_t)len; j++) {
					char opt_res_str[2 *
						RTE_IPOPT_MAX_LEN + 1];
					char opt_exp_str[2 *
						RTE_IPOPT_MAX_LEN + 1];

					test_get_ipv4_opt(
						opt_res[j].is_first_frag,
						&opt_exp);
					hex_to_str(opt_res[j].data,
						opt_res[j].len,
						opt_res_str);
					hex_to_str(opt_exp.data,
						opt_exp.len,
						opt_exp_str);

					printf(
						"[check ipv4 option]%zd-%zd: checking (%u)%s with (%u)%s\n",
						i, j,
						opt_res[j].len, opt_res_str,
						opt_exp.len, opt_exp_str);
						RTE_TEST_ASSERT_SUCCESS(
							strcmp(opt_res_str,
								opt_exp_str),
						"Failed case %zd.\n", i);
				}
			}
		}

	}

	return result;
}

static struct unit_test_suite ipfrag_testsuite  = {
	.suite_name = "IP Frag Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown,
			     test_ip_frag),

		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_ipfrag(void)
{
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level(RTE_LOGTYPE_EAL, RTE_LOG_DEBUG);

	return unit_test_suite_runner(&ipfrag_testsuite);
}

#endif /* !RTE_EXEC_ENV_WINDOWS */

REGISTER_TEST_COMMAND(ipfrag_autotest, test_ipfrag);
