/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <stdint.h>
#include <rte_ip.h>

struct ipv4_l3fwd_common_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct ipv6_l3fwd_common_route {
	uint8_t ip[16];
	uint8_t  depth;
	uint8_t  if_out;
};

/*
 * 198.18.0.0/16 are set aside for RFC2544 benchmarking (RFC5735).
 * 198.18.{0-7}.0/24 = Port {0-7}
 */
static const struct ipv4_l3fwd_common_route ipv4_l3fwd_common_route_array[] = {
	{RTE_IPV4(198, 18, 0, 0), 24, 0},
	{RTE_IPV4(198, 18, 1, 0), 24, 1},
	{RTE_IPV4(198, 18, 2, 0), 24, 2},
	{RTE_IPV4(198, 18, 3, 0), 24, 3},
	{RTE_IPV4(198, 18, 4, 0), 24, 4},
	{RTE_IPV4(198, 18, 5, 0), 24, 5},
	{RTE_IPV4(198, 18, 6, 0), 24, 6},
	{RTE_IPV4(198, 18, 7, 0), 24, 7},
};

/*
 * 2001:200::/48 is IANA reserved range for IPv6 benchmarking (RFC5180).
 * 2001:200:0:{0-7}::/64 = Port {0-7}
 */
static const struct ipv6_l3fwd_common_route ipv6_l3fwd_common_route_array[] = {
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 0},
	{{32, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 1},
	{{32, 1, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 2},
	{{32, 1, 2, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 3},
	{{32, 1, 2, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 4},
	{{32, 1, 2, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 5},
	{{32, 1, 2, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 6},
	{{32, 1, 2, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0}, 64, 7},
};
