/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#ifndef _TEST_INLINE_IPSEC_REASSEMBLY_VECTORS_H_
#define _TEST_INLINE_IPSEC_REASSEMBLY_VECTORS_H_

#include "test_cryptodev_security_ipsec.h"

uint8_t dummy_ipv4_eth_hdr[] = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,
};
uint8_t dummy_ipv6_eth_hdr[] = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,
};

#define MAX_FRAG_LEN		 1500
#define MAX_FRAGS		 6
#define MAX_PKT_LEN		 (MAX_FRAG_LEN * MAX_FRAGS)

struct ip_reassembly_test_packet {
	uint32_t len;
	uint32_t l4_offset;
	uint8_t data[MAX_PKT_LEN];
};

struct reassembly_vector {
	/* input/output text in struct ipsec_test_data are not used */
	struct ipsec_test_data *sa_data;
	struct ip_reassembly_test_packet *full_pkt;
	struct ip_reassembly_test_packet *frags[MAX_FRAGS];
	uint16_t nb_frags;
	bool burst;
};

/* The source file includes below test vectors */
/* IPv6:
 *
 *	1) pkt_ipv6_udp_p1
 *		pkt_ipv6_udp_p1_f1
 *		pkt_ipv6_udp_p1_f2
 *
 *	2) pkt_ipv6_udp_p2
 *		pkt_ipv6_udp_p2_f1
 *		pkt_ipv6_udp_p2_f2
 *		pkt_ipv6_udp_p2_f3
 *		pkt_ipv6_udp_p2_f4
 *
 *	3) pkt_ipv6_udp_p3
 *		pkt_ipv6_udp_p3_f1
 *		pkt_ipv6_udp_p3_f2
 *		pkt_ipv6_udp_p3_f3
 *		pkt_ipv6_udp_p3_f4
 *		pkt_ipv6_udp_p3_f5
 */

/* IPv4:
 *
 *	1) pkt_ipv4_udp_p1
 *		pkt_ipv4_udp_p1_f1
 *		pkt_ipv4_udp_p1_f2
 *
 *	2) pkt_ipv4_udp_p2
 *		pkt_ipv4_udp_p2_f1
 *		pkt_ipv4_udp_p2_f2
 *		pkt_ipv4_udp_p2_f3
 *		pkt_ipv4_udp_p2_f4
 *
 *	3) pkt_ipv4_udp_p3
 *		pkt_ipv4_udp_p3_f1
 *		pkt_ipv4_udp_p3_f2
 *		pkt_ipv4_udp_p3_f3
 *		pkt_ipv4_udp_p3_f4
 *		pkt_ipv4_udp_p3_f5
 */

struct ip_reassembly_test_packet pkt_ipv6_udp_p1 = {
	.len = 1500,
	.l4_offset = 40,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0xb4, 0x2C, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xb4, 0x2b, 0xe8,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p1_f1 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x00, 0x01, 0x5c, 0x92, 0xac, 0xf1,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xb4, 0x2b, 0xe8,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p1_f2 = {
	.len = 172,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x84, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x05, 0x38, 0x5c, 0x92, 0xac, 0xf1,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p2 = {
	.len = 4482,
	.l4_offset = 40,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x11, 0x5a, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x5a, 0x8a, 0x11,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p2_f1 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x00, 0x01, 0x64, 0x6c, 0x68, 0x9f,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x5a, 0x8a, 0x11,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p2_f2 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x05, 0x39, 0x64, 0x6c, 0x68, 0x9f,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p2_f3 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0a, 0x71, 0x64, 0x6c, 0x68, 0x9f,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p2_f4 = {
	.len = 482,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x01, 0xba, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0f, 0xa8, 0x64, 0x6c, 0x68, 0x9f,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3 = {
	.len = 5782,
	.l4_offset = 40,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x16, 0x6e, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x16, 0x6e, 0x2f, 0x99,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3_f1 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x00, 0x01, 0x65, 0xcf, 0x5a, 0xae,

		/* UDP */
		0x80, 0x00, 0x27, 0x10, 0x16, 0x6e, 0x2f, 0x99,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3_f2 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x05, 0x39, 0x65, 0xcf, 0x5a, 0xae,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3_f3 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0a, 0x71, 0x65, 0xcf, 0x5a, 0xae,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3_f4 = {
	.len = 1384,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0f, 0xa9, 0x65, 0xcf, 0x5a, 0xae,
	},
};

struct ip_reassembly_test_packet pkt_ipv6_udp_p3_f5 = {
	.len = 446,
	.l4_offset = 48,
	.data = {
		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x01, 0x96, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x14, 0xe0, 0x65, 0xcf, 0x5a, 0xae,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p1 = {
	.len = 1500,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0xdc, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x66, 0x0d, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xc8, 0xb8, 0x4c,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p1_f1 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x01, 0x20, 0x00,
		0x40, 0x11, 0x46, 0x5d, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xc8, 0xb8, 0x4c,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p1_f2 = {
	.len = 100,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x00, 0x64, 0x00, 0x01, 0x00, 0xaf,
		0x40, 0x11, 0x6a, 0xd6, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p2 = {
	.len = 4482,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x11, 0x82, 0x00, 0x02, 0x00, 0x00,
		0x40, 0x11, 0x5a, 0x66, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x6e, 0x16, 0x76,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p2_f1 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x20, 0x00,
		0x40, 0x11, 0x46, 0x5c, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x6e, 0x16, 0x76,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p2_f2 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x20, 0xaf,
		0x40, 0x11, 0x45, 0xad, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p2_f3 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x21, 0x5e,
		0x40, 0x11, 0x44, 0xfe, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p2_f4 = {
	.len = 282,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x01, 0x1a, 0x00, 0x02, 0x02, 0x0d,
		0x40, 0x11, 0x68, 0xc1, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3 = {
	.len = 5782,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x16, 0x96, 0x00, 0x03, 0x00, 0x00,
		0x40, 0x11, 0x55, 0x51, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x16, 0x82, 0xbb, 0xfd,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3_f1 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x03, 0x20, 0x00,
		0x40, 0x11, 0x46, 0x5b, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x80, 0x00, 0x27, 0x10, 0x16, 0x82, 0xbb, 0xfd,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3_f2 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x03, 0x20, 0xaf,
		0x40, 0x11, 0x45, 0xac, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3_f3 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x03, 0x21, 0x5e,
		0x40, 0x11, 0x44, 0xfd, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3_f4 = {
	.len = 1420,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x03, 0x22, 0x0d,
		0x40, 0x11, 0x44, 0x4e, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

struct ip_reassembly_test_packet pkt_ipv4_udp_p3_f5 = {
	.len = 182,
	.l4_offset = 20,
	.data = {
		/* IP */
		0x45, 0x00, 0x00, 0xb6, 0x00, 0x03, 0x02, 0xbc,
		0x40, 0x11, 0x68, 0x75, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

static inline void
test_vector_payload_populate(struct ip_reassembly_test_packet *pkt,
		bool first_frag)
{
	uint32_t i = pkt->l4_offset;

	/**
	 * For non-fragmented packets and first frag, skip 8 bytes from
	 * l4_offset for UDP header.
	 */
	if (first_frag)
		i += 8;

	for (; i < pkt->len; i++)
		pkt->data[i] = 0x58;
}

struct ipsec_test_data conf_aes_128_gcm = {
	.key = {
		.data = {
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
		},
	},

	.salt = {
		.data = {
			0xca, 0xfe, 0xba, 0xbe
		},
		.len = 4,
	},

	.iv = {
		.data = {
			0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
		},
	},

	.ipsec_xform = {
		.spi = 0xa5f8,
		.salt = 0xbebafeca,
		.options.esn = 0,
		.options.udp_encap = 0,
		.options.copy_dscp = 0,
		.options.copy_flabel = 0,
		.options.copy_df = 0,
		.options.dec_ttl = 0,
		.options.ecn = 0,
		.options.stats = 0,
		.options.tunnel_hdr_verify = 0,
		.options.ip_csum_enable = 0,
		.options.l4_csum_enable = 0,
		.options.ip_reassembly_en = 1,
		.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
		.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
		.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
		.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4,
		.replay_win_sz = 0,
	},

	.aead = true,

	.xform = {
		.aead = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_AEAD,
			.aead = {
				.op = RTE_CRYPTO_AEAD_OP_ENCRYPT,
				.algo = RTE_CRYPTO_AEAD_AES_GCM,
				.key.length = 16,
				.iv.length = 12,
				.iv.offset = 0,
				.digest_length = 16,
				.aad_length = 12,
			},
		},
	},
};

struct ipsec_test_data conf_aes_128_gcm_v6_tunnel = {
	.key = {
		.data = {
			0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
			0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
		},
	},

	.salt = {
		.data = {
			0xca, 0xfe, 0xba, 0xbe
		},
		.len = 4,
	},

	.iv = {
		.data = {
			0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
		},
	},

	.ipsec_xform = {
		.spi = 0xa5f8,
		.salt = 0xbebafeca,
		.options.esn = 0,
		.options.udp_encap = 0,
		.options.copy_dscp = 0,
		.options.copy_flabel = 0,
		.options.copy_df = 0,
		.options.dec_ttl = 0,
		.options.ecn = 0,
		.options.stats = 0,
		.options.tunnel_hdr_verify = 0,
		.options.ip_csum_enable = 0,
		.options.l4_csum_enable = 0,
		.options.ip_reassembly_en = 1,
		.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
		.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
		.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
		.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4,
		.replay_win_sz = 0,
	},

	.aead = true,

	.xform = {
		.aead = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_AEAD,
			.aead = {
				.op = RTE_CRYPTO_AEAD_OP_ENCRYPT,
				.algo = RTE_CRYPTO_AEAD_AES_GCM,
				.key.length = 16,
				.iv.length = 12,
				.iv.offset = 0,
				.digest_length = 16,
				.aad_length = 12,
			},
		},
	},
};

const struct reassembly_vector ipv4_2frag_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p1,
	.frags[0] = &pkt_ipv4_udp_p1_f1,
	.frags[1] = &pkt_ipv4_udp_p1_f2,
	.nb_frags = 2,
	.burst = false,
};

const struct reassembly_vector ipv6_2frag_vector = {
	.sa_data = &conf_aes_128_gcm_v6_tunnel,
	.full_pkt = &pkt_ipv6_udp_p1,
	.frags[0] = &pkt_ipv6_udp_p1_f1,
	.frags[1] = &pkt_ipv6_udp_p1_f2,
	.nb_frags = 2,
	.burst = false,
};

const struct reassembly_vector ipv4_4frag_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p2,
	.frags[0] = &pkt_ipv4_udp_p2_f1,
	.frags[1] = &pkt_ipv4_udp_p2_f2,
	.frags[2] = &pkt_ipv4_udp_p2_f3,
	.frags[3] = &pkt_ipv4_udp_p2_f4,
	.nb_frags = 4,
	.burst = false,
};

const struct reassembly_vector ipv6_4frag_vector = {
	.sa_data = &conf_aes_128_gcm_v6_tunnel,
	.full_pkt = &pkt_ipv6_udp_p2,
	.frags[0] = &pkt_ipv6_udp_p2_f1,
	.frags[1] = &pkt_ipv6_udp_p2_f2,
	.frags[2] = &pkt_ipv6_udp_p2_f3,
	.frags[3] = &pkt_ipv6_udp_p2_f4,
	.nb_frags = 4,
	.burst = false,
};
const struct reassembly_vector ipv4_5frag_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p3,
	.frags[0] = &pkt_ipv4_udp_p3_f1,
	.frags[1] = &pkt_ipv4_udp_p3_f2,
	.frags[2] = &pkt_ipv4_udp_p3_f3,
	.frags[3] = &pkt_ipv4_udp_p3_f4,
	.frags[4] = &pkt_ipv4_udp_p3_f5,
	.nb_frags = 5,
	.burst = false,
};
const struct reassembly_vector ipv6_5frag_vector = {
	.sa_data = &conf_aes_128_gcm_v6_tunnel,
	.full_pkt = &pkt_ipv6_udp_p3,
	.frags[0] = &pkt_ipv6_udp_p3_f1,
	.frags[1] = &pkt_ipv6_udp_p3_f2,
	.frags[2] = &pkt_ipv6_udp_p3_f3,
	.frags[3] = &pkt_ipv6_udp_p3_f4,
	.frags[4] = &pkt_ipv6_udp_p3_f5,
	.nb_frags = 5,
	.burst = false,
};
/* Negative test cases. */
const struct reassembly_vector ipv4_incomplete_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p2,
	.frags[0] = &pkt_ipv4_udp_p2_f1,
	.frags[1] = &pkt_ipv4_udp_p2_f2,
	.nb_frags = 2,
	.burst = false,
};
const struct reassembly_vector ipv4_overlap_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p1,
	.frags[0] = &pkt_ipv4_udp_p1_f1,
	.frags[1] = &pkt_ipv4_udp_p1_f1, /* Overlap */
	.frags[2] = &pkt_ipv4_udp_p1_f2,
	.nb_frags = 3,
	.burst = false,
};
const struct reassembly_vector ipv4_out_of_order_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p2,
	.frags[0] = &pkt_ipv4_udp_p2_f1,
	.frags[1] = &pkt_ipv4_udp_p2_f3,
	.frags[2] = &pkt_ipv4_udp_p2_f4,
	.frags[3] = &pkt_ipv4_udp_p2_f2, /* out of order */
	.nb_frags = 4,
	.burst = false,
};
const struct reassembly_vector ipv4_4frag_burst_vector = {
	.sa_data = &conf_aes_128_gcm,
	.full_pkt = &pkt_ipv4_udp_p2,
	.frags[0] = &pkt_ipv4_udp_p2_f1,
	.frags[1] = &pkt_ipv4_udp_p2_f2,
	.frags[2] = &pkt_ipv4_udp_p2_f3,
	.frags[3] = &pkt_ipv4_udp_p2_f4,
	.nb_frags = 4,
	.burst = true,
};

#endif
