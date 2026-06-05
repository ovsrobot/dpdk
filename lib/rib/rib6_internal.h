/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _RIB6_INTERNAL_H_
#define _RIB6_INTERNAL_H_

#include <stdint.h>

#include <rte_ip6.h>

struct rte_rib6_node {
	struct rte_rib6_node	*left;
	struct rte_rib6_node	*right;
	struct rte_rib6_node	*parent;
	uint64_t		nh;
	struct rte_ipv6_addr	ip;
	uint8_t			depth;
	uint8_t			flag;
	uint64_t ext[];
};

#endif /* _RIB6_INTERNAL_H_ */
