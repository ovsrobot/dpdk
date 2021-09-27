/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_INET_H_
#define RTE_PMD_MLX5_INET_H_

#include <net/if.h>
#include <netinet/in.h>

#include <rte_ether.h>

#include "mlx5_common.h"


/* VLAN netdev for VLAN workaround. */
struct mlx5_nl_vlan_dev {
	uint32_t refcnt;
	uint32_t ifindex; /**< Own interface index. */
};

/*
 * Array of VLAN devices created on the base of VF
 * used for workaround in virtual environments.
 */

struct mlx5_nl_vlan_vmwa_context {
	int nl_socket;
	uint32_t vf_ifindex;
	rte_spinlock_t sl;
	struct mlx5_nl_vlan_dev vlan_dev[4096];
};

__rte_internal
void mlx5_nl_vlan_vmwa_delete(struct mlx5_nl_vlan_vmwa_context *vmwa,
			      uint32_t ifindex);

__rte_internal
uint32_t mlx5_nl_vlan_vmwa_create(struct mlx5_nl_vlan_vmwa_context *vmwa,
				  uint32_t ifindex, uint16_t tag);
int
mlx5_inet_check_allmulti_flag(int inetsk_fd, char *ifname, uint16_t port_id);

int
mlx5_inet_device_flags(int inetsk_fd, char *ifname, int flags, int enable);

int
mlx5_inet_promisc(int inetsk_fd, char *ifname, int enable, uint16_t port_id);

int
mlx5_inet_mac_addr_modify(int inetsk_fd, char *ifname,
			struct rte_ether_addr *mac, uint16_t port_id);

int
mlx5_inet_mac_addr_set(int inetsk_fd, char *ifname,
			struct rte_ether_addr *mac, uint32_t index,
			uint16_t port_id, uint64_t *mac_own);

int
mlx5_inet_mac_addr_add(struct rte_ether_addr *mac __rte_unused,
			uint32_t index __rte_unused,
			uint32_t vmdq __rte_unused,
			uint16_t port_id);

void
mlx5_inet_mac_addr_flush(int inetsk_fd, char *ifname,
			struct rte_ether_addr *lladdr,
			uint16_t port_id);

void
mlx5_inet_mac_addr_remove(uint16_t port_id, uint32_t index __rte_unused);

int
mlx5_inet_init(void);
#endif /* RTE_PMD_MLX5_INET_H_ */
