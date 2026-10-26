/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_NL_H_
#define RTE_PMD_MLX5_NL_H_

#include <linux/netlink.h>

#include <rte_compat.h>
#include <rte_ether.h>

#include "mlx5_common.h"
#include "mlx5_common_utils.h"

typedef void (mlx5_nl_event_cb)(struct nlmsghdr *hdr, void *user_data);

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

#define MLX5_NL_CMD_GET_IB_NAME (1 << 0)
#define MLX5_NL_CMD_GET_IB_INDEX (1 << 1)
#define MLX5_NL_CMD_GET_NET_INDEX (1 << 2)
#define MLX5_NL_CMD_GET_PORT_INDEX (1 << 3)
#define MLX5_NL_CMD_GET_PORT_STATE (1 << 4)
#define MLX5_NL_CMD_GET_EVENT_TYPE (1 << 5)

/** Data structure used by mlx5_nl_cmdget_cb(). */
struct mlx5_nl_port_info {
	const char *name; /**< IB device name (in). */
	uint32_t flags; /**< found attribute flags (out). */
	uint32_t ibindex; /**< IB device index (out). */
	uint32_t ifindex; /**< Network interface index (out). */
	uint32_t portnum; /**< IB device max port number (out). */
	uint16_t state; /**< IB device port state (out). */
	uint8_t event_type; /**< IB RDMA event type (out). */
};

#define MLX5_NL_RDMA_NETDEV_ATTACH_EVENT (1)
#define MLX5_NL_RDMA_NETDEV_DETACH_EVENT (2)

/* Maximal physical port name length. */
#define MLX5_PHYS_PORT_NAME_MAX 128

/* Maximum length of parent device name. */
#define MLX5_PARENT_DEV_NAME_MAX 128

/* Maximum length of parent device bus name. */
#define MLX5_PARENT_DEV_BUS_NAME_MAX 128

/* Maximum length of a name stored inside netdev info */
#define MLX5_NETDEV_INFO_NAME_MAX 128

#define MLX5_NETDEV_INFO_FLAG_NUM_VF RTE_BIT32(0)
#define MLX5_NETDEV_INFO_FLAG_PHYS_PORT_NAME RTE_BIT32(1)
#define MLX5_NETDEV_INFO_FLAG_PHYS_SWITCH_ID RTE_BIT32(2)
#define MLX5_NETDEV_INFO_FLAG_PARENT_DEV_NAME RTE_BIT32(3)
#define MLX5_NETDEV_INFO_FLAG_PARENT_DEV_BUS_NAME RTE_BIT32(4)
#define MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_BUS_NAME RTE_BIT32(5)
#define MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_DEV_NAME RTE_BIT32(6)
#define MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_INDEX RTE_BIT32(7)

struct mlx5_netdev_info {
	unsigned int ifindex; /* [in] */
	uint32_t flags; /* [out] */
	uint32_t num_vf; /* [out] */
	char phys_port_name[MLX5_PHYS_PORT_NAME_MAX]; /* [out] */
	uint64_t phys_switch_id; /* [out] */
	char parent_dev_name[MLX5_PARENT_DEV_NAME_MAX]; /* [out] */
	char parent_dev_bus_name[MLX5_PARENT_DEV_BUS_NAME_MAX]; /* [out] */
	char devlink_port_bus_name[MLX5_NETDEV_INFO_NAME_MAX]; /* [out] */
	char devlink_port_dev_name[MLX5_NETDEV_INFO_NAME_MAX]; /* [out] */
	uint32_t devlink_port_index; /* [out] */
};

static inline bool
mlx5_netdev_info_has_devlink_port(struct mlx5_netdev_info *info)
{
	return (info->flags & MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_BUS_NAME) &&
	       (info->flags & MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_DEV_NAME) &&
	       (info->flags & MLX5_NETDEV_INFO_FLAG_DEVLINK_PORT_INDEX);
}

#define MLX5_DEVLINK_PORT_INFO_FLAG_FLAVOUR RTE_BIT32(0)

#define MLX5_DEVLINK_PORT_FLAVOUR_PHYSICAL (0)
#define MLX5_DEVLINK_PORT_FLAVOUR_CPU (1)
#define MLX5_DEVLINK_PORT_FLAVOUR_DSA (2)
#define MLX5_DEVLINK_PORT_FLAVOUR_PCI_PF (3)
#define MLX5_DEVLINK_PORT_FLAVOUR_PCI_VF (4)
#define MLX5_DEVLINK_PORT_FLAVOUR_VIRTUAL (5)
#define MLX5_DEVLINK_PORT_FLAVOUR_UNUSED (6)
#define MLX5_DEVLINK_PORT_FLAVOUR_PCI_SF (7)

struct mlx5_devlink_port_info {
	const char *bus_name; /* [in] */
	const char *dev_name; /* [in] */
	uint32_t index; /* [in] */
	uint32_t flags; /* [out] */
	uint16_t flavour; /* [out] */
};

__rte_internal
int mlx5_nl_init(int protocol, int groups);
__rte_internal
int mlx5_nl_mac_addr_add(int nlsk_fd, unsigned int iface_idx,
			 struct rte_ether_addr *mac);
__rte_internal
int mlx5_nl_mac_addr_remove(int nlsk_fd, unsigned int iface_idx,
			    struct rte_ether_addr *mac);
__rte_internal
void mlx5_nl_mac_addr_sync(int nlsk_fd, unsigned int iface_idx,
			   struct rte_ether_addr *mac_addrs, int uc_n, int n);
__rte_internal
int mlx5_nl_promisc(int nlsk_fd, unsigned int iface_idx, int enable);
__rte_internal
int mlx5_nl_allmulti(int nlsk_fd, unsigned int iface_idx, int enable);
__rte_internal
bool mlx5_nl_get_promisc(int nlsk_fd, unsigned int iface_idx);
__rte_internal
bool mlx5_nl_get_allmulti(int nlsk_fd, unsigned int iface_idx);
__rte_internal
unsigned int mlx5_nl_portnum(int nl, const char *name, struct mlx5_dev_info *dev_info);
__rte_internal
unsigned int mlx5_nl_ifindex(int nl, const char *name, uint32_t pindex,
			     struct mlx5_dev_info *info);
__rte_internal
int mlx5_nl_port_state(int nl, const char *name, uint32_t pindex, struct mlx5_dev_info *dev_info);
__rte_internal
int mlx5_nl_vf_mac_addr_modify(int nlsk_fd, unsigned int iface_idx,
			       struct rte_ether_addr *mac, int vf_index);
__rte_internal
int mlx5_nl_switch_info(int nl, unsigned int ifindex,
			struct mlx5_switch_info *info);

__rte_internal
void mlx5_nl_vlan_vmwa_delete(struct mlx5_nl_vlan_vmwa_context *vmwa,
			      uint32_t ifindex);
__rte_internal
uint32_t mlx5_nl_vlan_vmwa_create(struct mlx5_nl_vlan_vmwa_context *vmwa,
				  uint32_t ifindex, uint16_t tag);

__rte_internal
int mlx5_nl_devlink_family_id_get(int nlsk_fd);
int mlx5_nl_enable_roce_get(int nlsk_fd, int family_id, const char *pci_addr,
			    int *enable);
int mlx5_nl_enable_roce_set(int nlsk_fd, int family_id, const char *pci_addr,
			    int enable);

__rte_internal
int mlx5_nl_read_events(int nlsk_fd, mlx5_nl_event_cb *cb, void *cb_arg);
__rte_internal
int mlx5_nl_parse_link_status_update(struct nlmsghdr *hdr, uint32_t *ifindex);

__rte_internal
int mlx5_nl_devlink_esw_multiport_get(int nlsk_fd, int family_id,
				      const char *pci_addr, int *enable);

__rte_internal
int mlx5_nl_rdma_monitor_init(void);
__rte_internal
void mlx5_nl_rdma_monitor_info_get(struct nlmsghdr *hdr, struct mlx5_nl_port_info *data);
__rte_internal
int mlx5_nl_rdma_monitor_cap_get(int nl, uint8_t *cap);

__rte_internal
int mlx5_nl_get_mtu_bounds(int nl, unsigned int ifindex, uint16_t *min_mtu, uint16_t *max_mtu);

int mlx5_nl_netdev_info_get(int nl, struct mlx5_netdev_info *info);

#endif /* RTE_PMD_MLX5_NL_H_ */
