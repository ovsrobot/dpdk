/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/queue.h>

#include <ntdrv_4ga.h>

#include <rte_common.h>
#include <rte_kvargs.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_bus_vdev.h>
#include <rte_ether.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_dev.h>
#include <rte_vfio.h>
#include <rte_flow_driver.h>
#include <vdpa_driver.h>
#include <rte_pmd_ntnic.h>

#include "ntlog.h"

#include "stream_binary_flow_api.h"
#include "ntos_drv.h"
#include "ntoss_virt_queue.h"
#include "nthw_fpga.h"
#include "nthw_fpga_instances.h"
#include "ntnic_ethdev.h"
#include "ntnic_vfio.h"
#include "nthw_fpga_param_defs.h"
#include "flow_api.h"
#include "ntnic_mod_reg.h"
#include "dpdk_mod_reg.h"
#include "nt_util.h"

/* Feature defines: */

#undef DEBUG_REG_ACCESS

#if defined(DEBUG_REG_ACCESS)
#include "nthw_debug.h"
#endif	/* DEBUG_REG_ACCESS */

/* Defines: */
#if RTE_VERSION_NUM(23, 11, 0, 0) < RTE_VERSION
const rte_thread_attr_t thread_attr = { .priority = RTE_THREAD_PRIORITY_NORMAL };
#define THREAD_CREATE(a, b, c) rte_thread_create(a, &thread_attr, b, c)
#define THREAD_CTRL_CREATE(a, b, c, d) rte_thread_create_control(a, b, c, d)
#define THREAD_JOIN(a) rte_thread_join(a, NULL)
#define THREAD_FUNC static uint32_t
#define THREAD_RETURN (0)
#else
#define THREAD_CREATE(a, b, c) pthread_create(a, NULL, b, c)
#define THREAD_CTRL_CREATE(a, b, c, d) rte_ctrl_thread_create(a, b, NULL, c, d)
#define THREAD_JOIN(a) pthread_join(a, NULL)
#define THREAD_FUNC static void *
#define THREAD_RETURN (NULL)
#endif

#define HW_MAX_PKT_LEN (10000)
#define MAX_MTU (HW_MAX_PKT_LEN - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define MIN_MTU 46
#define MIN_MTU_INLINE 512

#define EXCEPTION_PATH_HID 0

#define MAX_TOTAL_QUEUES 128

#define ONE_G_SIZE 0x40000000
#define ONE_G_MASK (ONE_G_SIZE - 1)

#define VIRTUAL_TUNNEL_PORT_OFFSET 72

#define MAX_RX_PACKETS 128
#define MAX_TX_PACKETS 128


/* Global statics: */
struct pmd_internals *pmd_internals_base;
uint64_t rte_tsc_freq;

/* ------- Tables to store DPDK EAL log levels for nt log modules---------- */
static int nt_log_module_logtype[NT_LOG_MODULE_COUNT] = { -1 };
/* Register the custom module binding to EAL --log-level option here */
static const char *nt_log_module_eal_name[NT_LOG_MODULE_COUNT] = {
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_GENERAL)] = "pmd.net.ntnic.general",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTHW)] = "pmd.net.ntnic.nthw",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_FILTER)] = "pmd.net.ntnic.filter",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_DRV)] = "pmd.net.ntnic.drv",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_VDPA)] = "pmd.net.ntnic.vdpa",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_FPGA)] = "pmd.net.ntnic.fpga",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_SENSOR)] = "pmd.net.ntnic.sensor",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTCONNECT)] = "pmd.net.ntnic.ntconnect",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_ETHDEV)] = "pmd.net.ntnic.ethdev"
};
/* -------------------------------------------------------------------------- */

rte_spinlock_t hwlock = RTE_SPINLOCK_INITIALIZER;

static void (*previous_handler)(int sig);
#if RTE_VERSION_NUM(23, 11, 0, 0) < RTE_VERSION
static rte_thread_t shutdown_tid;
#else
static pthread_t shutdown_tid;
#endif
int kill_pmd;

#define ETH_DEV_NTNIC_HELP_ARG "help"
#define ETH_DEV_NTHW_LINK_SPEED_ARG "port.link_speed"
#define ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG "supported-fpgas"

#define DVIO_VHOST_DIR_NAME "/usr/local/var/run/"

static const char *const valid_arguments[] = {
	ETH_DEV_NTNIC_HELP_ARG,
	ETH_DEV_NTHW_LINK_SPEED_ARG,
	ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG,
	NULL,
};

/* Functions: */

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id nthw_pci_id_map[] = {
	{ RTE_PCI_DEVICE(NT_HW_PCI_VENDOR_ID_LENOVO, NT_HW_PCI_DEVICE_ID_NT200A02_LENOVO) },
	{ RTE_PCI_DEVICE(NT_HW_PCI_VENDOR_ID, NT_HW_PCI_DEVICE_ID_NT200A02) },
	{
		.vendor_id = 0,
	},	/* sentinel */
};

static const struct sg_ops_s *sg_ops;

/*
 * Store and get adapter info
 */

static struct drv_s *_g_p_drv[NUM_ADAPTER_MAX] = { NULL };

static void store_pdrv(struct drv_s *p_drv)
{
	if (p_drv->adapter_no > NUM_ADAPTER_MAX) {
		NT_LOG(ERR, ETHDEV,
			"Internal error adapter number %u out of range. Max number of adapters: %u\n",
			p_drv->adapter_no, NUM_ADAPTER_MAX);
		return;
	}

	if (_g_p_drv[p_drv->adapter_no] != 0) {
		NT_LOG(WRN, ETHDEV,
			"Overwriting adapter structure for PCI  " PCIIDENT_PRINT_STR
			" with adapter structure for PCI  " PCIIDENT_PRINT_STR "\n",
			PCIIDENT_TO_DOMAIN(_g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
			PCIIDENT_TO_BUSNR(_g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
			PCIIDENT_TO_DEVNR(_g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
			PCIIDENT_TO_FUNCNR(_g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
			PCIIDENT_TO_DOMAIN(p_drv->ntdrv.pciident),
			PCIIDENT_TO_BUSNR(p_drv->ntdrv.pciident),
			PCIIDENT_TO_DEVNR(p_drv->ntdrv.pciident),
			PCIIDENT_TO_FUNCNR(p_drv->ntdrv.pciident));
	}

	rte_spinlock_lock(&hwlock);
	_g_p_drv[p_drv->adapter_no] = p_drv;
	rte_spinlock_unlock(&hwlock);
}

static void clear_pdrv(struct drv_s *p_drv)
{
	if (p_drv->adapter_no > NUM_ADAPTER_MAX)
		return;

	rte_spinlock_lock(&hwlock);
	_g_p_drv[p_drv->adapter_no] = NULL;
	rte_spinlock_unlock(&hwlock);
}

struct drv_s *get_pdrv(uint8_t adapter_no)
{
	struct drv_s *pdrv;

	if (adapter_no > NUM_ADAPTER_MAX) {
		NT_LOG(ERR, ETHDEV,
			"Internal error adapter number %u out of range. Max number of adapters: %u\n",
			adapter_no, NUM_ADAPTER_MAX);
		return NULL;
	}

	rte_spinlock_lock(&hwlock);
	pdrv = _g_p_drv[adapter_no];
	rte_spinlock_unlock(&hwlock);
	return pdrv;
}

static struct drv_s *get_pdrv_from_pci(struct rte_pci_addr addr)
{
	int i;
	struct drv_s *p_drv = NULL;
	rte_spinlock_lock(&hwlock);

	for (i = 0; i < NUM_ADAPTER_MAX; i++) {
		if (_g_p_drv[i]) {
			if (PCIIDENT_TO_DOMAIN(_g_p_drv[i]->ntdrv.pciident) == addr.domain &&
				PCIIDENT_TO_BUSNR(_g_p_drv[i]->ntdrv.pciident) == addr.bus) {
				p_drv = _g_p_drv[i];
				break;
			}
		}
	}

	rte_spinlock_unlock(&hwlock);
	return p_drv;
}

struct port_link_speed {
	int port_id;
	int link_speed;
};

/* Parse <port>:<link speed Mbps>, e.g 1:10000 */
static int string_to_port_link_speed(const char *key_str __rte_unused, const char *value_str,
	void *extra_args)
{
	if (!value_str || !extra_args)
		return -1;

	char *semicol;
	const uint32_t pid = strtol(value_str, &semicol, 10);

	if (*semicol != ':')
		return -1;

	const uint32_t lspeed = strtol(++semicol, NULL, 10);
	struct port_link_speed *pls = *(struct port_link_speed **)extra_args;
	pls->port_id = pid;
	pls->link_speed = lspeed;
	++(*((struct port_link_speed **)(extra_args)));
	return 0;
}

/* NOTE: please note the difference between RTE_ETH_SPEED_NUM_xxx and RTE_ETH_LINK_SPEED_xxx */
static int nt_link_speed_to_eth_speed_num(enum nt_link_speed_e nt_link_speed)
{
	int eth_speed_num = RTE_ETH_SPEED_NUM_NONE;

	switch (nt_link_speed) {
	case NT_LINK_SPEED_10M:
		eth_speed_num = RTE_ETH_SPEED_NUM_10M;
		break;

	case NT_LINK_SPEED_100M:
		eth_speed_num = RTE_ETH_SPEED_NUM_100M;
		break;

	case NT_LINK_SPEED_1G:
		eth_speed_num = RTE_ETH_SPEED_NUM_1G;
		break;

	case NT_LINK_SPEED_10G:
		eth_speed_num = RTE_ETH_SPEED_NUM_10G;
		break;

	case NT_LINK_SPEED_25G:
		eth_speed_num = RTE_ETH_SPEED_NUM_25G;
		break;

	case NT_LINK_SPEED_40G:
		eth_speed_num = RTE_ETH_SPEED_NUM_40G;
		break;

	case NT_LINK_SPEED_50G:
		eth_speed_num = RTE_ETH_SPEED_NUM_50G;
		break;

	case NT_LINK_SPEED_100G:
		eth_speed_num = RTE_ETH_SPEED_NUM_100G;
		break;

	default:
		eth_speed_num = RTE_ETH_SPEED_NUM_NONE;
		break;
	}

	return eth_speed_num;
}

static int nt_link_duplex_to_eth_duplex(enum nt_link_duplex_e nt_link_duplex)
{
	int eth_link_duplex = 0;

	switch (nt_link_duplex) {
	case NT_LINK_DUPLEX_FULL:
		eth_link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		break;

	case NT_LINK_DUPLEX_HALF:
		eth_link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
		break;

	case NT_LINK_DUPLEX_UNKNOWN:	/* fall-through */
	default:
		break;
	}

	return eth_link_duplex;
}

static int eth_link_update(struct rte_eth_dev *eth_dev, int wait_to_complete __rte_unused)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;

	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info = &internals->p_drv->ntdrv.adapter_info;

	if (eth_dev->data->dev_started) {
		if (internals->type == PORT_TYPE_VIRTUAL ||
			internals->type == PORT_TYPE_OVERRIDE) {
			eth_dev->data->dev_link.link_status =
				((internals->vport_comm == VIRT_PORT_NEGOTIATED_NONE)
					? RTE_ETH_LINK_DOWN
					: RTE_ETH_LINK_UP);
			eth_dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_NONE;
			eth_dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
			return 0;
		}

		const bool port_link_status = port_ops->get_link_status(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_status =
			port_link_status ? RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;

		nt_link_speed_t port_link_speed =
			port_ops->get_link_speed(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_speed =
			nt_link_speed_to_eth_speed_num(port_link_speed);

		nt_link_duplex_t nt_link_duplex =
			port_ops->get_link_duplex(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_duplex = nt_link_duplex_to_eth_duplex(nt_link_duplex);

	} else {
		eth_dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
		eth_dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_NONE;
		eth_dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	}

	return 0;
}

static uint32_t nt_link_speed_capa_to_eth_speed_capa(int nt_link_speed_capa)
{
	uint32_t eth_speed_capa = 0;

	if (nt_link_speed_capa & NT_LINK_SPEED_10M)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_10M;

	if (nt_link_speed_capa & NT_LINK_SPEED_100M)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_100M;

	if (nt_link_speed_capa & NT_LINK_SPEED_1G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_1G;

	if (nt_link_speed_capa & NT_LINK_SPEED_10G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_10G;

	if (nt_link_speed_capa & NT_LINK_SPEED_25G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_25G;

	if (nt_link_speed_capa & NT_LINK_SPEED_40G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_40G;

	if (nt_link_speed_capa & NT_LINK_SPEED_50G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_50G;

	if (nt_link_speed_capa & NT_LINK_SPEED_100G)
		eth_speed_capa |= RTE_ETH_LINK_SPEED_100G;

	return eth_speed_capa;
}

static int eth_dev_infos_get(struct rte_eth_dev *eth_dev, struct rte_eth_dev_info *dev_info)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;

	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info = &internals->p_drv->ntdrv.adapter_info;

	dev_info->if_index = internals->if_index;
	dev_info->driver_name = internals->name;
	dev_info->max_mac_addrs = NUM_MAC_ADDRS_PER_PORT;
	dev_info->max_rx_pktlen = HW_MAX_PKT_LEN;
	dev_info->max_mtu = MAX_MTU;

	if (p_adapter_info->fpga_info.profile == FPGA_INFO_PROFILE_INLINE) {
		dev_info->min_mtu = MIN_MTU_INLINE;
		dev_info->flow_type_rss_offloads = NT_ETH_RSS_OFFLOAD_MASK;
		dev_info->hash_key_size = MAX_RSS_KEY_LEN;
#if (RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION)
		dev_info->rss_algo_capa = RTE_ETH_HASH_ALGO_CAPA_MASK(DEFAULT) |
			RTE_ETH_HASH_ALGO_CAPA_MASK(TOEPLITZ);
#endif

	} else {
		dev_info->min_mtu = MIN_MTU;
		/* NTH10 hashing algorithm for vswitch doesn't use key */
		dev_info->flow_type_rss_offloads = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP |
			RTE_ETH_RSS_UDP | RTE_ETH_RSS_C_VLAN | RTE_ETH_RSS_LEVEL_INNERMOST |
			RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_LEVEL_OUTERMOST |
			RTE_ETH_RSS_L3_DST_ONLY;
		dev_info->hash_key_size = 0;
#if (RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION)
		dev_info->rss_algo_capa = RTE_ETH_HASH_ALGO_CAPA_MASK(DEFAULT);
#endif
	}

	if (internals->p_drv) {
		dev_info->max_rx_queues = internals->nb_rx_queues;
		dev_info->max_tx_queues = internals->nb_tx_queues;

		dev_info->min_rx_bufsize = 64;

		const uint32_t nt_port_speed_capa =
			port_ops->get_link_speed_capabilities(p_adapter_info, n_intf_no);
		dev_info->speed_capa = nt_link_speed_capa_to_eth_speed_capa(nt_port_speed_capa);
	}

	return 0;
}

static void eth_mac_addr_remove(struct rte_eth_dev *eth_dev, uint32_t index)
{
	struct rte_ether_addr *const eth_addrs = eth_dev->data->mac_addrs;

	assert(index < NUM_MAC_ADDRS_PER_PORT);

	if (index >= NUM_MAC_ADDRS_PER_PORT) {
		const struct pmd_internals *const internals =
			(struct pmd_internals *)eth_dev->data->dev_private;
		NT_LOG(ERR, ETHDEV, "%s: [%s:%i]: Port %i: illegal index %u (>= %u)\n", __FILE__,
			__func__, __LINE__, internals->if_index, index, NUM_MAC_ADDRS_PER_PORT);
		return;
	}

	(void)memset(&eth_addrs[index], 0, sizeof(eth_addrs[index]));
}

static int eth_mac_addr_add(struct rte_eth_dev *eth_dev,
	struct rte_ether_addr *mac_addr,
	uint32_t index,
	uint32_t vmdq __rte_unused)
{
	struct rte_ether_addr *const eth_addrs = eth_dev->data->mac_addrs;

	assert(index < NUM_MAC_ADDRS_PER_PORT);

	if (index >= NUM_MAC_ADDRS_PER_PORT) {
		const struct pmd_internals *const internals =
			(struct pmd_internals *)eth_dev->data->dev_private;
		NT_LOG(ERR, ETHDEV, "%s: [%s:%i]: Port %i: illegal index %u (>= %u)\n", __FILE__,
			__func__, __LINE__, internals->if_index, index, NUM_MAC_ADDRS_PER_PORT);
		return -1;
	}

	eth_addrs[index] = *mac_addr;

	return 0;
}

static int eth_mac_addr_set(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr)
{
	struct rte_ether_addr *const eth_addrs = dev->data->mac_addrs;

	eth_addrs[0U] = *mac_addr;

	return 0;
}

static int eth_set_mc_addr_list(struct rte_eth_dev *eth_dev,
	struct rte_ether_addr *mc_addr_set,
	uint32_t nb_mc_addr)
{
	struct pmd_internals *const internals = (struct pmd_internals *)eth_dev->data->dev_private;
	struct rte_ether_addr *const mc_addrs = internals->mc_addrs;
	size_t i;

	if (nb_mc_addr >= NUM_MULTICAST_ADDRS_PER_PORT) {
		NT_LOG(ERR, ETHDEV,
			"%s: [%s:%i]: Port %i: too many multicast addresses %u (>= %u)\n", __FILE__,
			__func__, __LINE__, internals->if_index, nb_mc_addr,
			NUM_MULTICAST_ADDRS_PER_PORT);
		return -1;
	}

	for (i = 0U; i < NUM_MULTICAST_ADDRS_PER_PORT; i++)
		if (i < nb_mc_addr)
			mc_addrs[i] = mc_addr_set[i];

		else
			(void)memset(&mc_addrs[i], 0, sizeof(mc_addrs[i]));

	return 0;
}

static int eth_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] Called for eth_dev %p\n", __func__, __func__, __LINE__,
		eth_dev);

	p_drv->probe_finished = 1;

	/* The device is ALWAYS running promiscuous mode. */
	eth_dev->data->promiscuous ^= ~eth_dev->data->promiscuous;
	return 0;
}

static int eth_dev_start(struct rte_eth_dev *eth_dev)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;

	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info = &internals->p_drv->ntdrv.adapter_info;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] - Port %u, %u\n", __func__, __func__, __LINE__,
		internals->n_intf_no, internals->if_index);

	if (internals->type == PORT_TYPE_VIRTUAL || internals->type == PORT_TYPE_OVERRIDE) {
		eth_dev->data->dev_link.link_status = RTE_ETH_LINK_UP;

	} else {
		/* Enable the port */
		port_ops->set_adm_state(p_adapter_info, internals->if_index, true);

		/*
		 * wait for link on port
		 * If application starts sending too soon before FPGA port is ready, garbage is
		 * produced
		 */
		int loop = 0;

		while (port_ops->get_link_status(p_adapter_info, n_intf_no) == RTE_ETH_LINK_DOWN) {
			/* break out after 5 sec */
			if (++loop >= 50) {
				NT_LOG(DBG, ETHDEV,
					"%s: TIMEOUT No link on port %i (5sec timeout)\n", __func__,
					internals->n_intf_no);
				break;
			}

			nt_os_wait_usec(100 * 1000);
		}

		assert(internals->n_intf_no == internals->if_index);	/* Sanity check */

		if (internals->lpbk_mode) {
			if (internals->lpbk_mode & 1 << 0) {
				port_ops->set_loopback_mode(p_adapter_info, n_intf_no,
					NT_LINK_LOOPBACK_HOST);
			}

			if (internals->lpbk_mode & 1 << 1) {
				port_ops->set_loopback_mode(p_adapter_info, n_intf_no,
					NT_LINK_LOOPBACK_LINE);
			}
		}
	}

	return 0;
}

static int eth_dev_stop(struct rte_eth_dev *eth_dev)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] - Port %u, %u, type %u\n", __func__, __func__, __LINE__,
		internals->n_intf_no, internals->if_index, internals->type);

	eth_dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	return 0;
}

static int eth_dev_set_link_up(struct rte_eth_dev *eth_dev)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *const internals = (struct pmd_internals *)eth_dev->data->dev_private;

	struct adapter_info_s *p_adapter_info = &internals->p_drv->ntdrv.adapter_info;
	const int port = internals->if_index;

	if (internals->type == PORT_TYPE_VIRTUAL || internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	assert(port >= 0 && port < NUM_ADAPTER_PORTS_MAX);
	assert(port == internals->n_intf_no);

	port_ops->set_adm_state(p_adapter_info, port, true);

	return 0;
}

static int eth_dev_set_link_down(struct rte_eth_dev *eth_dev)
{
	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	struct pmd_internals *const internals = (struct pmd_internals *)eth_dev->data->dev_private;

	struct adapter_info_s *p_adapter_info = &internals->p_drv->ntdrv.adapter_info;
	const int port = internals->if_index;

	if (internals->type == PORT_TYPE_VIRTUAL || internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	assert(port >= 0 && port < NUM_ADAPTER_PORTS_MAX);
	assert(port == internals->n_intf_no);

	port_ops->set_link_status(p_adapter_info, port, false);

	return 0;
}

static void drv_deinit(struct drv_s *p_drv)
{
	const struct profile_inline_ops *profile_inline_ops = get_profile_inline_ops();

	if (profile_inline_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: profile_inline module uninitialized\n", __func__);
		return;
	}

	const struct adapter_ops *adapter_ops = get_adapter_ops();

	if (adapter_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Adapter module uninitialized\n", __func__);
		return;
	}

	if (p_drv == NULL)
		return;

	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;

	/*
	 * Mark the global pdrv for cleared. Used by some threads to terminate.
	 * 1 second to give the threads a chance to see the termonation.
	 */
	clear_pdrv(p_drv);
	nt_os_wait_usec(1000000);

	/* stop adapter */
	adapter_ops->deinit(&p_nt_drv->adapter_info);

	/* clean memory */
	rte_free(p_drv);
	p_drv = NULL;
}

static int eth_dev_close(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;

	NT_LOG(DBG, ETHDEV, "%s: enter [%s:%u]\n", __func__, __func__, __LINE__);

	internals->p_drv = NULL;

	/* free */
	rte_free(internals);
	internals = NULL;
	eth_dev->data->dev_private = NULL;
	eth_dev->data->mac_addrs = NULL;

#if RTE_VERSION_NUM(23, 11, 0, 0) > RTE_VERSION
	/* release */
	rte_eth_dev_release_port(eth_dev);
#endif

	NT_LOG(DBG, ETHDEV, "%s: %d [%s:%u]\n", __func__, p_drv->n_eth_dev_init_count, __func__,
		__LINE__);
	/* decrease initialized ethernet devices */
	p_drv->n_eth_dev_init_count--;

	/*
	 * rte_pci_dev has no private member for p_drv
	 * wait until all rte_eth_dev's are closed - then close adapters via p_drv
	 */
	if (!p_drv->n_eth_dev_init_count && p_drv) {
		NT_LOG(DBG, ETHDEV, "%s: %d [%s:%u]\n", __func__, p_drv->n_eth_dev_init_count,
			__func__, __LINE__);
		drv_deinit(p_drv);
	}

	NT_LOG(DBG, ETHDEV, "%s: leave [%s:%u]\n", __func__, __func__, __LINE__);
	return 0;
}

static int eth_fw_version_get(struct rte_eth_dev *eth_dev, char *fw_version, size_t fw_size)
{
	struct pmd_internals *internals = (struct pmd_internals *)eth_dev->data->dev_private;

	if (internals->type == PORT_TYPE_VIRTUAL || internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	fpga_info_t *fpga_info = &internals->p_drv->ntdrv.adapter_info.fpga_info;
	const int length = snprintf(fw_version, fw_size, "%03d-%04d-%02d-%02d",
			fpga_info->n_fpga_type_id, fpga_info->n_fpga_prod_id,
			fpga_info->n_fpga_ver_id, fpga_info->n_fpga_rev_id);

	if ((size_t)length < fw_size) {
		/* We have space for the version string */
		return 0;

	} else {
		/* We do not have space for the version string -return the needed space */
		return length + 1;
	}
}

static int promiscuous_enable(struct rte_eth_dev __rte_unused(*dev))
{
	NT_LOG(DBG, NTHW, "The device always run promiscuous mode.");
	return 0;
}

static struct eth_dev_ops nthw_eth_dev_ops = {
	.dev_configure = eth_dev_configure,
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_set_link_up = eth_dev_set_link_up,
	.dev_set_link_down = eth_dev_set_link_down,
	.dev_close = eth_dev_close,
	.link_update = eth_link_update,
	.stats_get = NULL,
	.stats_reset = NULL,
	.dev_infos_get = eth_dev_infos_get,
	.fw_version_get = eth_fw_version_get,
	.rx_queue_setup = NULL,
	.rx_queue_start = NULL,
	.rx_queue_stop = NULL,
	.rx_queue_release = NULL,
	.tx_queue_setup = NULL,
	.tx_queue_start = NULL,
	.tx_queue_stop = NULL,
	.tx_queue_release = NULL,
	.mac_addr_remove = eth_mac_addr_remove,
	.mac_addr_add = eth_mac_addr_add,
	.mac_addr_set = eth_mac_addr_set,
	.set_mc_addr_list = eth_set_mc_addr_list,
	.xstats_get = NULL,
	.xstats_get_names = NULL,
	.xstats_reset = NULL,
	.xstats_get_by_id = NULL,
	.xstats_get_names_by_id = NULL,
	.mtu_set = NULL,
	.mtr_ops_get = NULL,
	.flow_ops_get = NULL,
	.promiscuous_disable = NULL,
	.promiscuous_enable = promiscuous_enable,
	.rss_hash_update = NULL,
	.rss_hash_conf_get = NULL,
};

/* Converts link speed provided in Mbps to NT specific definitions.*/
static nt_link_speed_t convert_link_speed(int link_speed_mbps)
{
	switch (link_speed_mbps) {
	case 10:
		return NT_LINK_SPEED_10M;

	case 100:
		return NT_LINK_SPEED_100M;

	case 1000:
		return NT_LINK_SPEED_1G;

	case 10000:
		return NT_LINK_SPEED_10G;

	case 40000:
		return NT_LINK_SPEED_40G;

	case 100000:
		return NT_LINK_SPEED_100G;

	case 50000:
		return NT_LINK_SPEED_50G;

	case 25000:
		return NT_LINK_SPEED_25G;

	default:
		return NT_LINK_SPEED_UNKNOWN;
	}
}

static int nthw_pci_dev_init(struct rte_pci_device *pci_dev)
{
	const struct flow_filter_ops *flow_filter_ops = get_flow_filter_ops();

	if (flow_filter_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: flow_filter module uninitialized\n", __func__);
		/* Return statement is not neccessary here to allow traffic proccesing by SW  */
	}

	const struct profile_inline_ops *profile_inline_ops = get_profile_inline_ops();

	if (profile_inline_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: profile_inline module uninitialized\n", __func__);
		/* Return statement is not neccessary here to allow traffic proccesing by SW  */
	}

	const struct port_ops *port_ops = get_port_ops();

	if (port_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Link management module uninitialized\n", __func__);
		return -1;
	}

	const struct adapter_ops *adapter_ops = get_adapter_ops();

	if (adapter_ops == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: Adapter module uninitialized\n", __func__);
		return -1;
	}

	int res;
	struct drv_s *p_drv;
	ntdrv_4ga_t *p_nt_drv;
	fpga_info_t *fpga_info;
	hw_info_t *p_hw_info;
	(void)p_hw_info;
	uint32_t n_port_mask = -1;	/* All ports enabled by default */
	uint32_t nb_rx_queues = 1;
	uint32_t nb_tx_queues = 1;
	uint32_t exception_path = 0;
	struct flow_queue_id_s queue_ids[FLOW_MAX_QUEUES];
	int n_phy_ports;
	struct port_link_speed pls_mbps[NUM_ADAPTER_PORTS_MAX] = { 0 };
	int num_port_speeds = 0;
	enum flow_eth_dev_profile profile;

	NT_LOG(DBG, ETHDEV, "Dev %s PF #%i Init : %02x:%02x:%i %s\n", pci_dev->name,
		pci_dev->addr.function, pci_dev->addr.bus, pci_dev->addr.devid,
		pci_dev->addr.function, __func__);

	/*
	 * Process options/arguments
	 */
	if (pci_dev->device.devargs && pci_dev->device.devargs->args) {
		struct rte_kvargs *kvlist =
			rte_kvargs_parse(pci_dev->device.devargs->args, valid_arguments);

		if (kvlist == NULL)
			return -1;

		/*
		 * Argument: help
		 * NOTE: this argument/option check should be the first as it will stop
		 * execution after producing its output
		 */
		{
			if (rte_kvargs_get(kvlist, ETH_DEV_NTNIC_HELP_ARG)) {
				size_t i;

				for (i = 0; i < RTE_DIM(valid_arguments); i++)
					if (valid_arguments[i] == NULL)
						break;

				exit(0);
			}
		}

		/*
		 * Argument: supported-fpgas=list|verbose
		 * NOTE: this argument/option check should be the first as it will stop
		 * execution after producing its output
		 */
		{
			const char *val_str =
				rte_kvargs_get(kvlist, ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG);

			if (val_str != NULL) {
				int detail_level = 0;
				nthw_fpga_mgr_t *p_fpga_mgr = NULL;

				if (strcmp(val_str, "list") == 0) {
					detail_level = 0;

				} else if (strcmp(val_str, "verbose") == 0) {
					detail_level = 1;

				} else {
					NT_LOG(ERR, ETHDEV,
						"%s: argument '%s': '%s': unsupported value\n",
						__func__, ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG,
						val_str);
					exit(1);
				}

				/* Produce fpgamgr output and exit hard */
				p_fpga_mgr = nthw_fpga_mgr_new();

				if (p_fpga_mgr) {
					nthw_fpga_mgr_init(p_fpga_mgr, nthw_fpga_instances, NULL);
					nthw_fpga_mgr_show(p_fpga_mgr, stdout, detail_level);
					nthw_fpga_mgr_delete(p_fpga_mgr);
					p_fpga_mgr = NULL;

				} else {
					NT_LOG(ERR, ETHDEV, "%s: %s cannot complete\n", __func__,
						ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG);
					exit(1);
				}

				exit(0);
			}
		}

		/* link_speed options/argument only applicable for physical ports. */
		num_port_speeds = rte_kvargs_count(kvlist, ETH_DEV_NTHW_LINK_SPEED_ARG);

		if (num_port_speeds != 0) {
			assert(num_port_speeds <= NUM_ADAPTER_PORTS_MAX);
			void *pls_mbps_ptr = &pls_mbps[0];
			res = rte_kvargs_process(kvlist, ETH_DEV_NTHW_LINK_SPEED_ARG,
					&string_to_port_link_speed, &pls_mbps_ptr);

			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
					"%s: problem with port link speed command line arguments: res=%d\n",
					__func__, res);
				return -1;
			}

			for (int i = 0; i < num_port_speeds; ++i) {
				int pid = pls_mbps[i].port_id;
				int lspeed = pls_mbps[i].link_speed;
				(void)lspeed;
				NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%d.%d\n", __func__,
					ETH_DEV_NTHW_LINK_SPEED_ARG, pid, lspeed);

				if (pls_mbps[i].port_id >= NUM_ADAPTER_PORTS_MAX) {
					NT_LOG(ERR, ETHDEV,
						"%s: problem with port link speed command line arguments: port id should be 0 to %d, got %d\n",
						__func__, NUM_ADAPTER_PORTS_MAX, pid);
					return -1;
				}
			}
		}
	}

	/* alloc */
	p_drv = rte_zmalloc_socket(pci_dev->name, sizeof(struct drv_s), RTE_CACHE_LINE_SIZE,
			pci_dev->device.numa_node);

	if (!p_drv) {
		NT_LOG(ERR, ETHDEV, "%s: error %d (%s:%u)\n",
			(pci_dev->name[0] ? pci_dev->name : "NA"), -1, __func__, __LINE__);
		return -1;
	}

	/* Setup VFIO context */
	int vfio = nt_vfio_setup(pci_dev);

	if (vfio < 0) {
		NT_LOG(ERR, ETHDEV, "%s: vfio_setup error %d (%s:%u)\n",
			(pci_dev->name[0] ? pci_dev->name : "NA"), -1, __func__, __LINE__);
		rte_free(p_drv);
		return -1;
	}

	/* context */
	p_nt_drv = &p_drv->ntdrv;
	fpga_info = &p_nt_drv->adapter_info.fpga_info;
	p_hw_info = &p_nt_drv->adapter_info.hw_info;

	p_drv->p_dev = pci_dev;

	/* Set context for NtDrv */
	p_nt_drv->pciident = BDF_TO_PCIIDENT(pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function);
	p_nt_drv->adapter_info.n_rx_host_buffers = nb_rx_queues;
	p_nt_drv->adapter_info.n_tx_host_buffers = nb_tx_queues;

	fpga_info->bar0_addr = (void *)pci_dev->mem_resource[0].addr;
	fpga_info->bar0_size = pci_dev->mem_resource[0].len;
	NT_LOG(DBG, ETHDEV, "bar0=0x%" PRIX64 " len=%d\n", fpga_info->bar0_addr,
		fpga_info->bar0_size);
	fpga_info->numa_node = pci_dev->device.numa_node;
	fpga_info->pciident = p_nt_drv->pciident;
	fpga_info->adapter_no = p_drv->adapter_no;

	p_nt_drv->adapter_info.hw_info.pci_class_id = pci_dev->id.class_id;
	p_nt_drv->adapter_info.hw_info.pci_vendor_id = pci_dev->id.vendor_id;
	p_nt_drv->adapter_info.hw_info.pci_device_id = pci_dev->id.device_id;
	p_nt_drv->adapter_info.hw_info.pci_sub_vendor_id = pci_dev->id.subsystem_vendor_id;
	p_nt_drv->adapter_info.hw_info.pci_sub_device_id = pci_dev->id.subsystem_device_id;

	NT_LOG(DBG, ETHDEV, "%s: " PCIIDENT_PRINT_STR " %04X:%04X: %04X:%04X:\n",
		p_nt_drv->adapter_info.mp_adapter_id_str, PCIIDENT_TO_DOMAIN(p_nt_drv->pciident),
		PCIIDENT_TO_BUSNR(p_nt_drv->pciident), PCIIDENT_TO_DEVNR(p_nt_drv->pciident),
		PCIIDENT_TO_FUNCNR(p_nt_drv->pciident),
		p_nt_drv->adapter_info.hw_info.pci_vendor_id,
		p_nt_drv->adapter_info.hw_info.pci_device_id,
		p_nt_drv->adapter_info.hw_info.pci_sub_vendor_id,
		p_nt_drv->adapter_info.hw_info.pci_sub_device_id);

	p_nt_drv->b_shutdown = false;
	p_nt_drv->adapter_info.pb_shutdown = &p_nt_drv->b_shutdown;

	for (int i = 0; i < num_port_speeds; ++i) {
		struct adapter_info_s *p_adapter_info = &p_nt_drv->adapter_info;
		nt_link_speed_t link_speed = convert_link_speed(pls_mbps[i].link_speed);
		port_ops->set_link_speed(p_adapter_info, i, link_speed);
	}

	/* store context */
	store_pdrv(p_drv);

	/* initialize nt4ga nthw fpga module instance in drv */
	int err = adapter_ops->init(&p_nt_drv->adapter_info);

	if (err != 0) {
		NT_LOG(ERR, ETHDEV, "%s: Cannot initialize the adapter instance\n",
			p_nt_drv->adapter_info.mp_adapter_id_str);
		return -1;
	}

	const struct meter_ops_s *meter_ops = get_meter_ops();

	if (meter_ops != NULL)
		nthw_eth_dev_ops.mtr_ops_get = meter_ops->eth_mtr_ops_get;

	else
		NT_LOG(DBG, ETHDEV, "%s: Meter module is not initialized\n", __func__);

	/* Initialize the queue system */
	if (err == 0) {
		sg_ops = get_sg_ops();

		if (sg_ops != NULL) {
			err = sg_ops->nthw_virt_queue_init(fpga_info);

			if (err != 0) {
				NT_LOG(ERR, ETHDEV,
					"%s: Cannot initialize scatter-gather queues\n",
					p_nt_drv->adapter_info.mp_adapter_id_str);

			} else {
				NT_LOG(DBG, ETHDEV, "%s: Initialized scatter-gather queues\n",
					p_nt_drv->adapter_info.mp_adapter_id_str);
			}

		} else {
			NT_LOG(DBG, ETHDEV, "%s: SG module is not initialized\n", __func__);
		}
	}

	switch (fpga_info->profile) {
	case FPGA_INFO_PROFILE_VSWITCH:
		profile = FLOW_ETH_DEV_PROFILE_VSWITCH;
		break;

	case FPGA_INFO_PROFILE_INLINE:
		profile = FLOW_ETH_DEV_PROFILE_INLINE;
		break;

	case FPGA_INFO_PROFILE_UNKNOWN:

	/* fallthrough */
	case FPGA_INFO_PROFILE_CAPTURE:

	/* fallthrough */
	default:
		NT_LOG(ERR, ETHDEV, "%s: fpga profile not supported [%s:%u]\n",
			(pci_dev->name[0] ? pci_dev->name : "NA"), __func__, __LINE__);
		return -1;
	}

#if defined(DEBUG_REG_ACCESS) && (DEBUG_REG_ACCESS)
	{
		int res;
		NT_LOG(DBG, ETHDEV, "%s: DEBUG_REG_ACCESS: [%s:%u]\n", __func__, __func__,
			__LINE__);
		res = THREAD_CTRL_CREATE(&p_nt_drv->stat_thread, "reg_acc_thr",
				nthw_debug_reg_access_thread_fn, (void *)fpga_info);

		if (res) {
			NT_LOG(ERR, ETHDEV, "%s: error=%d [%s:%u]\n",
				(pci_dev->name[0] ? pci_dev->name : "NA"), res, __func__, __LINE__);
			return -1;
		}
	}
#endif	/* DEBUG_REG_ACCESS */

	/* Start ctrl, monitor, stat thread only for primary process. */
	if (err == 0) {
		/* mp_adapter_id_str is initialized after nt4ga_adapter_init(p_nt_drv) */
		const char *const p_adapter_id_str = p_nt_drv->adapter_info.mp_adapter_id_str;
		(void)p_adapter_id_str;
		NT_LOG(DBG, ETHDEV,
			"%s: %s: AdapterPCI=" PCIIDENT_PRINT_STR " Hw=0x%02X_rev%d PhyPorts=%d\n",
			(pci_dev->name[0] ? pci_dev->name : "NA"), p_adapter_id_str,
			PCIIDENT_TO_DOMAIN(p_nt_drv->adapter_info.fpga_info.pciident),
			PCIIDENT_TO_BUSNR(p_nt_drv->adapter_info.fpga_info.pciident),
			PCIIDENT_TO_DEVNR(p_nt_drv->adapter_info.fpga_info.pciident),
			PCIIDENT_TO_FUNCNR(p_nt_drv->adapter_info.fpga_info.pciident),
			p_hw_info->hw_platform_id, fpga_info->nthw_hw_info.hw_id,
			fpga_info->n_phy_ports);

	} else {
		NT_LOG(ERR, ETHDEV, "%s: error=%d [%s:%u]\n",
			(pci_dev->name[0] ? pci_dev->name : "NA"), err, __func__, __LINE__);
		return -1;
	}

	n_phy_ports = fpga_info->n_phy_ports;

	for (int n_intf_no = 0; n_intf_no < n_phy_ports; n_intf_no++) {
		const char *const p_port_id_str = p_nt_drv->adapter_info.mp_port_id_str[n_intf_no];
		(void)p_port_id_str;
		struct pmd_internals *internals = NULL;
		struct rte_eth_dev *eth_dev = NULL;
		char name[32];
		int i;

		if ((1 << n_intf_no) & ~n_port_mask) {
			NT_LOG(DBG, ETHDEV,
				"%s: %s: interface #%d: skipping due to portmask 0x%02X\n",
				__func__, p_port_id_str, n_intf_no, n_port_mask);
			continue;
		}

		snprintf(name, sizeof(name), "ntnic%d", n_intf_no);
		NT_LOG(DBG, ETHDEV, "%s: %s: interface #%d: %s: '%s'\n", __func__, p_port_id_str,
			n_intf_no, (pci_dev->name[0] ? pci_dev->name : "NA"), name);

		internals = rte_zmalloc_socket(name, sizeof(struct pmd_internals),
				RTE_CACHE_LINE_SIZE, pci_dev->device.numa_node);

		if (!internals) {
			NT_LOG(ERR, ETHDEV, "%s: %s: error=%d [%s:%u]\n",
				(pci_dev->name[0] ? pci_dev->name : "NA"), name, -1, __func__,
				__LINE__);
			return -1;
		}

		internals->pci_dev = pci_dev;
		internals->n_intf_no = n_intf_no;
		internals->if_index = n_intf_no;
		internals->min_tx_pkt_size = 64;
		internals->max_tx_pkt_size = 10000;
		internals->type = PORT_TYPE_PHYSICAL;
		internals->vhid = -1;
		internals->port = n_intf_no;
		internals->nb_rx_queues = nb_rx_queues;
		internals->nb_tx_queues = nb_tx_queues;

		/* Not used queue index as dest port in bypass - use 0x80 + port nr */
		for (i = 0; i < MAX_QUEUES; i++)
			internals->vpq[i].hw_id = -1;

		/* Setup queue_ids */
		if (nb_rx_queues > 1) {
			NT_LOG(DBG, ETHDEV,
				"(%i) NTNIC configured with Rx multi queues. %i queues\n",
				0 /*port*/, nb_rx_queues);
		}

		if (nb_tx_queues > 1) {
			NT_LOG(DBG, ETHDEV,
				"(%i) NTNIC configured with Tx multi queues. %i queues\n",
				0 /*port*/, nb_tx_queues);
		}

		/* Set MAC address (but only if the MAC address is permitted) */
		if (n_intf_no < fpga_info->nthw_hw_info.vpd_info.mn_mac_addr_count) {
			const uint64_t mac =
				fpga_info->nthw_hw_info.vpd_info.mn_mac_addr_value + n_intf_no;
			internals->eth_addrs[0].addr_bytes[0] = (mac >> 40) & 0xFFu;
			internals->eth_addrs[0].addr_bytes[1] = (mac >> 32) & 0xFFu;
			internals->eth_addrs[0].addr_bytes[2] = (mac >> 24) & 0xFFu;
			internals->eth_addrs[0].addr_bytes[3] = (mac >> 16) & 0xFFu;
			internals->eth_addrs[0].addr_bytes[4] = (mac >> 8) & 0xFFu;
			internals->eth_addrs[0].addr_bytes[5] = (mac >> 0) & 0xFFu;
		}

		eth_dev = rte_eth_dev_allocate(name);	/* TODO: name */

		if (!eth_dev) {
			NT_LOG(ERR, ETHDEV, "%s: %s: error=%d [%s:%u]\n",
				(pci_dev->name[0] ? pci_dev->name : "NA"), name, -1, __func__,
				__LINE__);
			return -1;
		}

		if (flow_filter_ops != NULL) {
			int *rss_target_id = &internals->txq_scg[0].rss_target_id;
			internals->flw_dev =
				flow_filter_ops->flow_get_eth_dev(0, n_intf_no,
					eth_dev->data->port_id,
					nb_rx_queues, queue_ids,
					rss_target_id, profile,
					exception_path);

			if (!internals->flw_dev) {
				NT_LOG(ERR, VDPA,
					"Error creating port. Resource exhaustion in HW\n");
				return -1;
			}
		}

		NT_LOG(DBG, ETHDEV, "%s: [%s:%u] eth_dev %p, port_id %u, if_index %u\n", __func__,
			__func__, __LINE__, eth_dev, eth_dev->data->port_id, n_intf_no);

		/* connect structs */
		internals->p_drv = p_drv;
		eth_dev->data->dev_private = internals;
		eth_dev->data->mac_addrs = internals->eth_addrs;

		internals->port_id = eth_dev->data->port_id;

		struct rte_eth_link pmd_link;
		pmd_link.link_speed = RTE_ETH_SPEED_NUM_NONE;
		pmd_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		pmd_link.link_status = RTE_ETH_LINK_DOWN;
		pmd_link.link_autoneg = RTE_ETH_LINK_AUTONEG;

		eth_dev->device = &pci_dev->device;
		eth_dev->data->dev_link = pmd_link;
		eth_dev->data->numa_node = pci_dev->device.numa_node;
		eth_dev->dev_ops = &nthw_eth_dev_ops;
		eth_dev->state = RTE_ETH_DEV_ATTACHED;

		rte_eth_copy_pci_info(eth_dev, pci_dev);
		/* performs rte_eth_copy_pci_info() */
		eth_dev_pci_specific_init(eth_dev, pci_dev);

		/* increase initialized ethernet devices - PF */
		p_drv->n_eth_dev_init_count++;
	}

	p_drv->setup_finished = 1;

	return 0;
}

static int nthw_pci_dev_deinit(struct rte_eth_dev *eth_dev __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "PCI device deinitialization %s\n", __func__);

	if (sg_ops == NULL) {
		nt_vfio_remove(EXCEPTION_PATH_HID);
		return 0;
	}

	return 0;
}

static void signal_handler_func_int(int sig)
{
	if (sig != SIGINT) {
		signal(sig, previous_handler);
		raise(sig);
		return;
	}

	kill_pmd = 1;
}

THREAD_FUNC shutdown_thread(void *arg __rte_unused)
{
	struct rte_eth_dev dummy;

	while (!kill_pmd)
		nt_os_wait_usec(100 * 1000);

	NT_LOG(DBG, ETHDEV, "%s: Shutting down because of ctrl+C\n", __func__);
	nthw_pci_dev_deinit(&dummy);

	signal(SIGINT, previous_handler);
	raise(SIGINT);

	return THREAD_RETURN;
}

static int init_shutdown(void)
{
	NT_LOG(DBG, ETHDEV, "%s: Starting shutdown handler\n", __func__);
	kill_pmd = 0;
	previous_handler = signal(SIGINT, signal_handler_func_int);
	THREAD_CREATE(&shutdown_tid, shutdown_thread, NULL);

	/*
	 * 1 time calculation of 1 sec stat update rtc cycles to prevent stat poll
	 * flooding by OVS from multiple virtual port threads - no need to be precise
	 */
	uint64_t now_rtc = rte_get_tsc_cycles();
	nt_os_wait_usec(10 * 1000);
	rte_tsc_freq = 100 * (rte_get_tsc_cycles() - now_rtc);

	return 0;
}

static int nthw_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	int res;

#if defined(DEBUG)
	NT_LOG(DBG, NTHW, "Testing NTHW %u [%s:%u]\n",
		nt_log_module_logtype[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTHW)], __func__, __LINE__);
#endif

	NT_LOG(DBG, ETHDEV, "%s: pcidev: name: '%s'\n", __func__, pci_dev->name);
	NT_LOG(DBG, ETHDEV, "%s: devargs: name: '%s'\n", __func__, pci_dev->device.name);

	if (pci_dev->device.devargs) {
		NT_LOG(DBG, ETHDEV, "%s: devargs: args: '%s'\n", __func__,
			(pci_dev->device.devargs->args ? pci_dev->device.devargs->args : "NULL"));
		NT_LOG(DBG, ETHDEV, "%s: devargs: data: '%s'\n", __func__,
			(pci_dev->device.devargs->data ? pci_dev->device.devargs->data : "NULL"));
	}

	const int n_rte_has_pci = rte_eal_has_pci();
	NT_LOG(DBG, ETHDEV, "has_pci=%d\n", n_rte_has_pci);

	if (n_rte_has_pci == 0) {
		NT_LOG(ERR, ETHDEV, "has_pci=%d: this PMD needs hugepages\n", n_rte_has_pci);
		return -1;
	}

	const int n_rte_vfio_no_io_mmu_enabled = rte_vfio_noiommu_is_enabled();
	NT_LOG(DBG, ETHDEV, "vfio_no_iommu_enabled=%d\n", n_rte_vfio_no_io_mmu_enabled);

	if (n_rte_vfio_no_io_mmu_enabled) {
		NT_LOG(ERR, ETHDEV, "vfio_no_iommu_enabled=%d: this PMD needs VFIO IOMMU\n",
			n_rte_vfio_no_io_mmu_enabled);
		return -1;
	}

	const enum rte_iova_mode n_rte_io_va_mode = rte_eal_iova_mode();
	NT_LOG(DBG, ETHDEV, "iova mode=%d\n", n_rte_io_va_mode);

	if (n_rte_io_va_mode != RTE_IOVA_PA) {
		NT_LOG(WRN, ETHDEV, "iova mode (%d) should be PA for performance reasons\n",
			n_rte_io_va_mode);
	}

	const int n_rte_has_huge_pages = rte_eal_has_hugepages();
	NT_LOG(DBG, ETHDEV, "has_hugepages=%d\n", n_rte_has_huge_pages);

	if (n_rte_has_huge_pages == 0) {
		NT_LOG(ERR, ETHDEV, "has_hugepages=%d: this PMD needs hugepages\n",
			n_rte_has_huge_pages);
		return -1;
	}

	NT_LOG(DBG, ETHDEV,
		"busid=" PCI_PRI_FMT
		" pciid=%04x:%04x_%04x:%04x locstr=%s @ numanode=%d: drv=%s drvalias=%s\n",
		pci_dev->addr.domain, pci_dev->addr.bus, pci_dev->addr.devid,
		pci_dev->addr.function, pci_dev->id.vendor_id, pci_dev->id.device_id,
		pci_dev->id.subsystem_vendor_id, pci_dev->id.subsystem_device_id,
		pci_dev->name[0] ? pci_dev->name : "NA",	/* locstr */
		pci_dev->device.numa_node,
		pci_dev->driver->driver.name ? pci_dev->driver->driver.name : "NA",
		pci_dev->driver->driver.alias ? pci_dev->driver->driver.alias : "NA");

	if (pci_dev->id.vendor_id == NT_HW_PCI_VENDOR_ID) {
		if (pci_dev->id.device_id == NT_HW_PCI_DEVICE_ID_NT200A01 ||
			pci_dev->id.device_id == NT_HW_PCI_DEVICE_ID_NT50B01) {
			if (pci_dev->id.subsystem_device_id != 0x01) {
				NT_LOG(DBG, ETHDEV,
					"%s: PCIe bifurcation - secondary endpoint found - leaving probe\n",
					__func__);
				return -1;
			}
		}
	}

	res = nthw_pci_dev_init(pci_dev);

	init_shutdown();

	NT_LOG(DBG, ETHDEV, "%s: leave: res=%d\n", __func__, res);
	return res;
}

static int nthw_pci_remove(struct rte_pci_device *pci_dev)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);

	struct drv_s *p_drv = get_pdrv_from_pci(pci_dev->addr);
	drv_deinit(p_drv);

	return rte_eth_dev_pci_generic_remove(pci_dev, nthw_pci_dev_deinit);
}

static int nt_log_init_impl(void)
{
	rte_log_set_global_level(RTE_LOG_DEBUG);

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);

	for (int i = NT_LOG_MODULE_GENERAL; i < NT_LOG_MODULE_END; ++i) {
		int index = NT_LOG_MODULE_INDEX(i);
		nt_log_module_logtype[index] =
			rte_log_register_type_and_pick_level(nt_log_module_eal_name[index],
				RTE_LOG_INFO);
	}

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);

	return 0;
}

static int nt_log_log_impl(enum nt_log_level level, uint32_t module, const char *format,
	va_list args)
{
	uint32_t rte_level = 0;
	uint32_t rte_module = 0;

	switch (level) {
	case NT_LOG_ERR:
		rte_level = RTE_LOG_ERR;
		break;

	case NT_LOG_WRN:
		rte_level = RTE_LOG_WARNING;
		break;

	case NT_LOG_INF:
		rte_level = RTE_LOG_INFO;
		break;

	default:
		rte_level = RTE_LOG_DEBUG;
	}

	rte_module = (module >= NT_LOG_MODULE_GENERAL && module < NT_LOG_MODULE_END)
		? (uint32_t)nt_log_module_logtype[NT_LOG_MODULE_INDEX(module)]
		: module;

	return (int)rte_vlog(rte_level, rte_module, format, args);
}

static int nt_log_is_debug_impl(uint32_t module)
{
	if (module < NT_LOG_MODULE_GENERAL || module >= NT_LOG_MODULE_END)
		return -1;

	int index = NT_LOG_MODULE_INDEX(module);
	return rte_log_get_level(nt_log_module_logtype[index]) == RTE_LOG_DEBUG;
}

RTE_INIT(ntnic_rte_init);	/* must go before function */

static void ntnic_rte_init(void)
{
	static struct nt_log_impl impl = { .init = &nt_log_init_impl,
		       .log = &nt_log_log_impl,
		       .is_debug = &nt_log_is_debug_impl
	};

	nt_log_init(&impl);
}

static struct rte_pci_driver rte_nthw_pmd = {
	.driver = {
		.name = "net_ntnic",
	},

	.id_table = nthw_pci_id_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = nthw_pci_probe,
	.remove = nthw_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ntnic, rte_nthw_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ntnic, nthw_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ntnic, "* vfio-pci");

static inline const char *_rte_vdev_device_name(const struct rte_pci_device *dev)
{
	if (dev && dev->device.name)
		return dev->device.name;

	return NULL;
}

/*
 * Necessary for satisfying version.map
 * requirement for both 21.11 and 22.11
 */
void _dummy_(void);
void _dummy_(void) {}
