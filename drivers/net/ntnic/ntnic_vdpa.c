/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdio.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_vhost.h>
#include <linux/virtio_net.h>
#include <rte_vdpa.h>
#include <rte_pci.h>
#include <rte_string_fns.h>
#include <rte_bus_pci.h>
#include <vhost.h>
#include "ntnic_vf_vdpa.h"
#include "ntnic_vdpa.h"
#include "ntnic_ethdev.h"
#include "nt_util.h"
#include "ntlog.h"
#include "ntnic_vfio.h"

#define MAX_PATH_LEN 128
#define MAX_VDPA_PORTS 128UL

struct vdpa_port {
	char ifname[MAX_PATH_LEN];
	struct rte_vdpa_device *vdev;
	int vid;
	uint32_t index;
	uint32_t host_id;
	uint32_t rep_port;
	int rxqs;
	int txqs;
	uint64_t flags;
	struct rte_pci_addr addr;
};

static struct vdpa_port vport[MAX_VDPA_PORTS];
static uint32_t nb_vpda_devcnt;

static int nthw_vdpa_start(struct vdpa_port *vport);

int nthw_vdpa_get_queue_id_info(struct rte_vdpa_device *vdpa_dev, int rx,
				int queue_id, uint32_t *hw_index,
				uint32_t *host_id, uint32_t *rep_port)
{
	uint32_t i;

	for (i = 0; i < nb_vpda_devcnt; i++) {
		if (vport[i].vdev == vdpa_dev) {
			if (rx) {
				if (queue_id >= vport[i].rxqs) {
					NT_LOG(ERR, VDPA,
					       "Failed: %s: Queue ID not configured. vDPA dev %p, rx queue_id %i, rxqs %i\n",
					       __func__, vdpa_dev, queue_id,
					       vport[i].rxqs);
					return -1;
				}
				*hw_index = vport[i].index + queue_id;
			} else {
				if (queue_id >= vport[i].txqs) {
					NT_LOG(ERR, VDPA,
					       "Failed: %s: Queue ID not configured. vDPA dev %p, tx queue_id %i, rxqs %i\n",
					       __func__, vdpa_dev, queue_id,
					       vport[i].rxqs);
					return -1;
				}
				*hw_index = vport[i].index + queue_id;
			}

			*host_id = vport[i].host_id;
			*rep_port = vport[i].rep_port;
			return 0;
		}
	}

	NT_LOG(ERR, VDPA,
	       "Failed: %s: Ask on vDPA dev %p, queue_id %i, nb_vpda_devcnt %i\n",
	       __func__, vdpa_dev, queue_id, nb_vpda_devcnt);
	return -1;
}

int nthw_vdpa_init(const struct rte_pci_device *vdev,
		   const char *backing_devname _unused, const char *socket_path,
		   uint32_t index, int rxqs, int txqs, uint32_t rep_port,
		   int *vhid)
{
	int ret;
	uint32_t host_id = nt_vfio_vf_num(vdev);

	struct rte_vdpa_device *vdpa_dev =
		rte_vdpa_find_device_by_name(vdev->name);
	if (!vdpa_dev) {
		NT_LOG(ERR, VDPA, "vDPA device with name %s - not found\n",
		       vdev->name);
		return -1;
	}

	vport[nb_vpda_devcnt].vdev = vdpa_dev;
	vport[nb_vpda_devcnt].host_id = host_id; /* VF # */
	vport[nb_vpda_devcnt].index = index; /* HW ring index */
	vport[nb_vpda_devcnt].rep_port = rep_port; /* in port override on Tx */
	vport[nb_vpda_devcnt].rxqs = rxqs;
	vport[nb_vpda_devcnt].txqs = txqs;
	vport[nb_vpda_devcnt].addr = vdev->addr;

	vport[nb_vpda_devcnt].flags = RTE_VHOST_USER_CLIENT;
	strlcpy(vport[nb_vpda_devcnt].ifname, socket_path, MAX_PATH_LEN);

	NT_LOG(INF, VDPA,
	       "vDPA%u: device %s (host_id %u), backing device %s, index %u, queues %i, rep port %u, ifname %s\n",
	       nb_vpda_devcnt, vdev->name, host_id, backing_devname, index,
	       rxqs, rep_port, vport[nb_vpda_devcnt].ifname);

	ret = nthw_vdpa_start(&vport[nb_vpda_devcnt]);

	*vhid = nb_vpda_devcnt;
	nb_vpda_devcnt++;
	return ret;
}

void nthw_vdpa_close(void)
{
	uint32_t i;

	for (i = 0; i < MAX_VDPA_PORTS; i++) {
		if (vport[i].ifname[0] != '\0') {
			int ret;
			char *socket_path = vport[i].ifname;

			ret = rte_vhost_driver_detach_vdpa_device(socket_path);
			if (ret != 0) {
				NT_LOG(ERR, VDPA,
				       "detach vdpa device failed: %s\n",
				       socket_path);
			}

			ret = rte_vhost_driver_unregister(socket_path);
			if (ret != 0) {
				NT_LOG(ERR, VDPA,
				       "Fail to unregister vhost driver for %s.\n",
				       socket_path);
			}

			vport[i].ifname[0] = '\0';
			return;
		}
	}
}

#ifdef DUMP_VIRTIO_FEATURES
#define VIRTIO_F_NOTIFICATION_DATA 38
#define NUM_FEATURES 40
struct {
	uint64_t id;
	const char *name;
} virt_features[NUM_FEATURES] = {
	{ VIRTIO_NET_F_CSUM, "VIRTIO_NET_F_CSUM" },
	{ VIRTIO_NET_F_GUEST_CSUM, "VIRTIO_NET_F_GUEST_CSUM" },
	{	VIRTIO_NET_F_CTRL_GUEST_OFFLOADS,
		"  VIRTIO_NET_F_CTRL_GUEST_OFFLOADS"
	},
	{ VIRTIO_NET_F_MTU, "  VIRTIO_NET_F_MTU" },
	{ VIRTIO_NET_F_MAC, "  VIRTIO_NET_F_MAC" },
	{ VIRTIO_NET_F_GSO, "  VIRTIO_NET_F_GSO" },
	{ VIRTIO_NET_F_GUEST_TSO4, "  VIRTIO_NET_F_GUEST_TSO4" },
	{ VIRTIO_NET_F_GUEST_TSO6, "  VIRTIO_NET_F_GUEST_TSO6" },
	{ VIRTIO_NET_F_GUEST_ECN, "  VIRTIO_NET_F_GUEST_ECN" },
	{ VIRTIO_NET_F_GUEST_UFO, "  VIRTIO_NET_F_GUEST_UFO" },
	{ VIRTIO_NET_F_HOST_TSO4, "  VIRTIO_NET_F_HOST_TSO4" },
	{ VIRTIO_NET_F_HOST_TSO6, "  VIRTIO_NET_F_HOST_TSO6" },
	{ VIRTIO_NET_F_HOST_ECN, "  VIRTIO_NET_F_HOST_ECN" },
	{ VIRTIO_NET_F_HOST_UFO, "  VIRTIO_NET_F_HOST_UFO" },
	{ VIRTIO_NET_F_MRG_RXBUF, "  VIRTIO_NET_F_MRG_RXBUF" },
	{ VIRTIO_NET_F_STATUS, "  VIRTIO_NET_F_STATUS" },
	{ VIRTIO_NET_F_CTRL_VQ, "  VIRTIO_NET_F_CTRL_VQ" },
	{ VIRTIO_NET_F_CTRL_RX, "  VIRTIO_NET_F_CTRL_RX" },
	{ VIRTIO_NET_F_CTRL_VLAN, "  VIRTIO_NET_F_CTRL_VLAN" },
	{ VIRTIO_NET_F_CTRL_RX_EXTRA, "  VIRTIO_NET_F_CTRL_RX_EXTRA" },
	{ VIRTIO_NET_F_GUEST_ANNOUNCE, "  VIRTIO_NET_F_GUEST_ANNOUNCE" },
	{ VIRTIO_NET_F_MQ, "  VIRTIO_NET_F_MQ" },
	{ VIRTIO_NET_F_CTRL_MAC_ADDR, "  VIRTIO_NET_F_CTRL_MAC_ADDR" },
	{ VIRTIO_NET_F_HASH_REPORT, "  VIRTIO_NET_F_HASH_REPORT" },
	{ VIRTIO_NET_F_RSS, "  VIRTIO_NET_F_RSS" },
	{ VIRTIO_NET_F_RSC_EXT, "  VIRTIO_NET_F_RSC_EXT" },
	{ VIRTIO_NET_F_STANDBY, "  VIRTIO_NET_F_STANDBY" },
	{ VIRTIO_NET_F_SPEED_DUPLEX, "  VIRTIO_NET_F_SPEED_DUPLEX" },
	{ VIRTIO_F_NOTIFY_ON_EMPTY, "  VIRTIO_F_NOTIFY_ON_EMPTY" },
	{ VIRTIO_F_ANY_LAYOUT, "  VIRTIO_F_ANY_LAYOUT" },
	{ VIRTIO_RING_F_INDIRECT_DESC, "  VIRTIO_RING_F_INDIRECT_DESC" },
	{ VIRTIO_F_VERSION_1, "  VIRTIO_F_VERSION_1" },
	{ VIRTIO_F_IOMMU_PLATFORM, "  VIRTIO_F_IOMMU_PLATFORM" },
	{ VIRTIO_F_RING_PACKED, "  VIRTIO_F_RING_PACKED" },
	{ VIRTIO_TRANSPORT_F_START, "  VIRTIO_TRANSPORT_F_START" },
	{ VIRTIO_TRANSPORT_F_END, "  VIRTIO_TRANSPORT_F_END" },
	{ VIRTIO_F_IN_ORDER, "  VIRTIO_F_IN_ORDER" },
	{ VIRTIO_F_ORDER_PLATFORM, "  VIRTIO_F_ORDER_PLATFORM" },
	{ VIRTIO_F_NOTIFICATION_DATA, "  VIRTIO_F_NOTIFICATION_DATA" },
};

static void dump_virtio_features(uint64_t features)
{
	int i;

	for (i = 0; i < NUM_FEATURES; i++) {
		if ((1ULL << virt_features[i].id) ==
				(features & (1ULL << virt_features[i].id)))
			printf("Virtio feature: %s\n", virt_features[i].name);
	}
}
#endif

static int nthw_vdpa_new_device(int vid)
{
	char ifname[MAX_PATH_LEN];
	uint64_t negotiated_features = 0;
	unsigned int vhid = -1;

	rte_vhost_get_ifname(vid, ifname, sizeof(ifname));

	for (vhid = 0; vhid < MAX_VDPA_PORTS; vhid++) {
		if (strncmp(ifname, vport[vhid].ifname, MAX_PATH_LEN) == 0) {
			vport[vhid].vid = vid;
			break;
		}
	}

	if (vhid >= MAX_VDPA_PORTS)
		return -1;

	int max_loops = 2000;
	struct pmd_internals *intern;

	while ((intern = vp_vhid_instance_ready(vhid)) == NULL) {
		usleep(1000);
		if (--max_loops == 0) {
			NT_LOG(INF, VDPA,
			       "FAILED CREATING (vhost could not get ready) New port %s, vDPA dev: %s\n",
			       ifname, vport[vhid].vdev->device->name);
			return -1;
		}
	}

	/* set link up on virtual port */
	intern->vport_comm = VIRT_PORT_NEGOTIATED_NONE;

	/* Store ifname (vhost_path) */
	strlcpy(intern->vhost_path, ifname, MAX_PATH_LEN);

	NT_LOG(INF, VDPA, "New port %s, vDPA dev: %s\n", ifname,
	       vport[vhid].vdev->device->name);
	rte_vhost_get_negotiated_features(vid, &negotiated_features);
	NT_LOG(INF, VDPA, "Virtio Negotiated features %016lx\n",
	       negotiated_features);

#ifdef DUMP_VIRTIO_FEATURES
	dump_virtio_features(negotiated_features);
#endif

	if ((((negotiated_features & (1ULL << VIRTIO_F_IN_ORDER))) ||
			((negotiated_features & (1ULL << VIRTIO_F_RING_PACKED))))) {
		/* IN_ORDER negotiated - we can run HW-virtio directly (vDPA) */
		NT_LOG(INF, VDPA, "Running virtio in vDPA mode : %s  %s\n",
		       (negotiated_features & (1ULL << VIRTIO_F_RING_PACKED)) ?
		       "\"Packed-Ring\"" :
		       "\"Split-Ring\"",
		       (negotiated_features & (1ULL << VIRTIO_F_IN_ORDER)) ?
		       "\"In-Order\"" :
		       "\"No In-Order Requested\"");

		intern->vport_comm =
			(negotiated_features & (1ULL << VIRTIO_F_RING_PACKED)) ?
			VIRT_PORT_NEGOTIATED_PACKED :
			VIRT_PORT_NEGOTIATED_SPLIT;
	} else {
		NT_LOG(ERR, VDPA, "Incompatible virtio negotiated features.\n");
		return -1;
	}
	return 0;
}

static void nthw_vdpa_destroy_device(int vid)
{
	char ifname[MAX_PATH_LEN];
	uint32_t i;
	unsigned int vhid;

	rte_vhost_get_ifname(vid, ifname, sizeof(ifname));
	for (i = 0; i < MAX_VDPA_PORTS; i++) {
		if (strcmp(ifname, vport[i].ifname) == 0) {
			NT_LOG(INF, VDPA, "\ndestroy port %s, vDPA dev: %s\n",
			       ifname, vport[i].vdev->device->name);
			break;
		}
	}

	struct pmd_internals *intern;

	/* set link down on virtual port */
	for (vhid = 0; vhid < MAX_VDPA_PORTS; vhid++) {
		if (strncmp(ifname, vport[vhid].ifname, MAX_PATH_LEN) == 0) {
			intern = vp_vhid_instance_ready(vhid);
			if (intern)
				intern->vport_comm = VIRT_PORT_NEGOTIATED_NONE;
			break;
		}
	}
}

static const struct rte_vhost_device_ops vdpa_devops = {
	.new_device = nthw_vdpa_new_device,
	.destroy_device = nthw_vdpa_destroy_device,
};

static int nthw_vdpa_start(struct vdpa_port *vport)
{
	int ret;
	char *socket_path = vport->ifname;

	ret = rte_vhost_driver_register(socket_path, vport->flags);
	if (ret != 0) {
		NT_LOG(ERR, VDPA, "register driver failed: %s\n", socket_path);
		return -1;
	}

	ret = rte_vhost_driver_callback_register(socket_path, &vdpa_devops);
	if (ret != 0) {
		NT_LOG(ERR, VDPA, "register driver ops failed: %s\n",
		       socket_path);
		return -1;
	}

	ret = rte_vhost_driver_disable_features(socket_path, (1ULL << VIRTIO_NET_F_HOST_TSO4) |
						(1ULL << VIRTIO_NET_F_HOST_TSO6) |
						(1ULL << VIRTIO_NET_F_CSUM) |
						(1ULL << VIRTIO_RING_F_EVENT_IDX) |
						(1ULL << VIRTIO_RING_F_INDIRECT_DESC) |
						(1ULL << VIRTIO_NET_F_HOST_UFO) |
						(1ULL << VIRTIO_NET_F_HOST_ECN) |
						(1ULL << VIRTIO_NET_F_GUEST_CSUM) |
						(1ULL << VIRTIO_NET_F_GUEST_TSO4) |
						(1ULL << VIRTIO_NET_F_GUEST_TSO6) |
						(1ULL << VIRTIO_NET_F_GUEST_UFO) |
						(1ULL << VIRTIO_NET_F_GUEST_ECN) |
						(1ULL << VIRTIO_NET_F_CTRL_VQ) |
						(1ULL << VIRTIO_NET_F_CTRL_RX) |
						(1ULL << VIRTIO_NET_F_GSO) |
						(1ULL << VIRTIO_NET_F_MTU));

	if (ret != 0) {
		NT_LOG(INF, VDPA,
		       "rte_vhost_driver_disable_features failed for vhost user client port: %s\n",
		       socket_path);
		return -1;
	}

	if (rte_vhost_driver_start(socket_path) < 0) {
		NT_LOG(ERR, VDPA, "start vhost driver failed: %s\n",
		       socket_path);
		return -1;
	}
	return 0;
}
