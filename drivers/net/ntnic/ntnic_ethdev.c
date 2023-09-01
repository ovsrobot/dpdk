/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <unistd.h> /* sleep() */
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <sys/queue.h>

#include "ntdrv_4ga.h"

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

#include "ntlog.h"

#include "stream_binary_flow_api.h"
#include "nthw_fpga.h"
#include "ntnic_xstats.h"
#include "ntnic_hshconfig.h"
#include "ntnic_ethdev.h"
#include "ntnic_vdpa.h"
#include "ntnic_vf.h"
#include "ntnic_vfio.h"
#include "ntnic_meter.h"

#include "flow_api.h"

#ifdef NT_TOOLS
#include "ntconnect.h"
#include "ntconnect_api.h"
#include "ntconnect_modules/ntconn_modules.h"
#endif

/* Defines: */

#define HW_MAX_PKT_LEN (10000)
#define MAX_MTU (HW_MAX_PKT_LEN - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define MIN_MTU 46
#define MIN_MTU_INLINE 512

#include "ntnic_dbsconfig.h"

#define EXCEPTION_PATH_HID 0

#define MAX_TOTAL_QUEUES 128

#define ONE_G_SIZE 0x40000000
#define ONE_G_MASK (ONE_G_SIZE - 1)

#define VIRTUAL_TUNNEL_PORT_OFFSET 72

int lag_active;

static struct {
	struct nthw_virt_queue *vq;
	int managed;
	int rx;
} rel_virt_queue[MAX_REL_VQS];

#define MAX_RX_PACKETS 128
#define MAX_TX_PACKETS 128

#if defined(RX_SRC_DUMP_PKTS_DEBUG) || defined(RX_DST_DUMP_PKTS_DEBUG) || \
	defined(TX_SRC_DUMP_PKTS_DEBUG) || defined(TX_DST_DUMP_PKTS_DEBUG)
static void dump_packet_seg(const char *text, uint8_t *data, int len)
{
	int x;

	if (text)
		printf("%s (%p, len %i)", text, data, len);
	for (x = 0; x < len; x++) {
		if (!(x % 16))
			printf("\n%04X:", x);
		printf(" %02X", *(data + x));
	}
	printf("\n");
}
#endif

/* Global statistics: */
extern const struct rte_flow_ops _dev_flow_ops;
struct pmd_internals *pmd_intern_base;
uint64_t rte_tsc_freq;

/*------- Tables to store DPDK EAL log levels for nt log modules----------*/
static int nt_log_module_logtype[NT_LOG_MODULE_COUNT] = { -1 };
/*Register the custom module binding to EAL --log-level option here*/
static const char *nt_log_module_eal_name[NT_LOG_MODULE_COUNT] = {
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_GENERAL)] = "pmd.net.ntnic.general",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTHW)] = "pmd.net.ntnic.nthw",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_FILTER)] = "pmd.net.ntnic.filter",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_VDPA)] = "pmd.net.ntnic.vdpa",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_FPGA)] = "pmd.net.ntnic.fpga",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTCONNECT)] =
	"pmd.net.ntnic.ntconnect",
	[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_ETHDEV)] = "pmd.net.ntnic.ethdev"
};

/*--------------------------------------------------------------------------*/

rte_spinlock_t hwlock = RTE_SPINLOCK_INITIALIZER;

static void *lag_management(void *arg);
static void (*previous_handler)(int sig);
static pthread_t shutdown_tid;
int kill_pmd;

#define ETH_DEV_NTNIC_HELP_ARG "help"
#define ETH_DEV_NTHW_PORTMASK_ARG "portmask"
#define ETH_DEV_NTHW_RXQUEUES_ARG "rxqs"
#define ETH_DEV_NTHW_TXQUEUES_ARG "txqs"
#define ETH_DEV_NTHW_PORTQUEUES_ARG "portqueues"
#define ETH_DEV_NTHW_REPRESENTOR_ARG "representor"
#define ETH_DEV_NTHW_EXCEPTION_PATH_ARG "exception_path"
#define ETH_NTNIC_LAG_PRIMARY_ARG "primary"
#define ETH_NTNIC_LAG_BACKUP_ARG "backup"
#define ETH_NTNIC_LAG_MODE_ARG "mode"
#define ETH_DEV_NTHW_LINK_SPEED_ARG "port.link_speed"
#define ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG "supported-fpgas"

#define DVIO_VHOST_DIR_NAME "/usr/local/var/run/"

static const char *const valid_arguments[] = {
	ETH_DEV_NTNIC_HELP_ARG,
	ETH_DEV_NTHW_PORTMASK_ARG,
	ETH_DEV_NTHW_RXQUEUES_ARG,
	ETH_DEV_NTHW_TXQUEUES_ARG,
	ETH_DEV_NTHW_PORTQUEUES_ARG,
	ETH_DEV_NTHW_REPRESENTOR_ARG,
	ETH_DEV_NTHW_EXCEPTION_PATH_ARG,
	ETH_NTNIC_LAG_PRIMARY_ARG,
	ETH_NTNIC_LAG_BACKUP_ARG,
	ETH_NTNIC_LAG_MODE_ARG,
	ETH_DEV_NTHW_LINK_SPEED_ARG,
	ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG,
	NULL,
};

static struct rte_ether_addr eth_addr_vp[MAX_FPGA_VIRTUAL_PORTS_SUPPORTED];

/* Functions: */

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id nthw_pci_id_map[] = {
	{ RTE_PCI_DEVICE(NT_HW_PCI_VENDOR_ID, NT_HW_PCI_DEVICE_ID_NT200A02) },
	{ RTE_PCI_DEVICE(NT_HW_PCI_VENDOR_ID, NT_HW_PCI_DEVICE_ID_NT50B01) },
	{
		.vendor_id = 0,
	}, /* sentinel */
};

/*
 * Store and get adapter info
 */

static struct drv_s *g_p_drv[NUM_ADAPTER_MAX] = { NULL };

static void store_pdrv(struct drv_s *p_drv)
{
	if (p_drv->adapter_no > NUM_ADAPTER_MAX) {
		NT_LOG(ERR, ETHDEV,
		       "Internal error adapter number %u out of range. Max number of adapters: %u\n",
		       p_drv->adapter_no, NUM_ADAPTER_MAX);
		return;
	}
	if (g_p_drv[p_drv->adapter_no] != 0) {
		NT_LOG(WRN, ETHDEV,
		       "Overwriting adapter structure for PCI  " PCIIDENT_PRINT_STR
		       " with adapter structure for PCI  " PCIIDENT_PRINT_STR
		       "\n",
		       PCIIDENT_TO_DOMAIN(g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
		       PCIIDENT_TO_BUSNR(g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
		       PCIIDENT_TO_DEVNR(g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
		       PCIIDENT_TO_FUNCNR(g_p_drv[p_drv->adapter_no]->ntdrv.pciident),
		       PCIIDENT_TO_DOMAIN(p_drv->ntdrv.pciident),
		       PCIIDENT_TO_BUSNR(p_drv->ntdrv.pciident),
		       PCIIDENT_TO_DEVNR(p_drv->ntdrv.pciident),
		       PCIIDENT_TO_FUNCNR(p_drv->ntdrv.pciident));
	}
	rte_spinlock_lock(&hwlock);
	g_p_drv[p_drv->adapter_no] = p_drv;
	rte_spinlock_unlock(&hwlock);
}

static struct drv_s *get_pdrv_from_pci(struct rte_pci_addr addr)
{
	int i;
	struct drv_s *p_drv = NULL;

	rte_spinlock_lock(&hwlock);
	for (i = 0; i < NUM_ADAPTER_MAX; i++) {
		if (g_p_drv[i]) {
			if (PCIIDENT_TO_DOMAIN(g_p_drv[i]->ntdrv.pciident) ==
					addr.domain &&
					PCIIDENT_TO_BUSNR(g_p_drv[i]->ntdrv.pciident) ==
					addr.bus) {
				p_drv = g_p_drv[i];
				break;
			}
		}
	}
	rte_spinlock_unlock(&hwlock);
	return p_drv;
}

static struct drv_s *get_pdrv_from_pciident(uint32_t pciident)
{
	struct rte_pci_addr addr;

	addr.domain = PCIIDENT_TO_DOMAIN(pciident);
	addr.bus = PCIIDENT_TO_BUSNR(pciident);
	addr.devid = PCIIDENT_TO_DEVNR(pciident);
	addr.function = PCIIDENT_TO_FUNCNR(pciident);
	return get_pdrv_from_pci(addr);
}

int debug_adapter_show_info(uint32_t pciident, FILE *pfh)
{
	struct drv_s *p_drv = get_pdrv_from_pciident(pciident);

	return nt4ga_adapter_show_info(&p_drv->ntdrv.adapter_info, pfh);
}

nthw_dbs_t *get_pdbs_from_pci(struct rte_pci_addr pci_addr)
{
	nthw_dbs_t *p_nthw_dbs = NULL;
	struct drv_s *p_drv;

	p_drv = get_pdrv_from_pci(pci_addr);
	if (p_drv) {
		p_nthw_dbs = p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_dbs;
	}	else {
		NT_LOG(ERR, ETHDEV,
		       "Adapter DBS %p (p_drv=%p) info for adapter with PCI " PCIIDENT_PRINT_STR
		       " is not found\n",
		       p_nthw_dbs, p_drv, pci_addr.domain, pci_addr.bus, pci_addr.devid,
		       pci_addr.function);
	}
	return p_nthw_dbs;
}

enum fpga_info_profile get_fpga_profile_from_pci(struct rte_pci_addr pci_addr)
{
	enum fpga_info_profile fpga_profile = FPGA_INFO_PROFILE_UNKNOWN;
	struct drv_s *p_drv;

	p_drv = get_pdrv_from_pci(pci_addr);
	if (p_drv) {
		fpga_profile = p_drv->ntdrv.adapter_info.fpga_info.profile;
	} else {
		NT_LOG(ERR, ETHDEV,
		       "FPGA profile (p_drv=%p) for adapter with PCI " PCIIDENT_PRINT_STR
		       " is not found\n",
		       p_drv, pci_addr.domain, pci_addr.bus, pci_addr.devid, pci_addr.function);
	}
	return fpga_profile;
}

static int string_to_u32(const char *key_str __rte_unused,
			 const char *value_str, void *extra_args)
{
	if (!value_str || !extra_args)
		return -1;
	const uint32_t value = strtol(value_str, NULL, 0);
	*(uint32_t *)extra_args = value;
	return 0;
}

struct port_link_speed {
	int port_id;
	int link_speed;
};

/* Parse <port>:<link speed Mbps>, e.g 1:10000 */
static int string_to_port_link_speed(const char *key_str __rte_unused,
				     const char *value_str, void *extra_args)
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

static int dpdk_stats_collect(struct pmd_internals *internals,
			      struct rte_eth_stats *stats)
{
	unsigned int i;
	struct drv_s *p_drv = internals->p_drv;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	const int if_index = internals->if_index;
	uint64_t rx_total = 0;
	uint64_t rx_total_b = 0;
	uint64_t tx_total = 0;
	uint64_t tx_total_b = 0;
	uint64_t tx_err_total = 0;

	if (!p_nthw_stat || !p_nt4ga_stat || !stats || if_index < 0 ||
			if_index > NUM_ADAPTER_PORTS_MAX) {
		NT_LOG(WRN, ETHDEV, "%s - error exit\n", __func__);
		return -1;
	}

	/*
	 * Pull the latest port statistic numbers (Rx/Tx pkts and bytes)
	 * Return values are in the "internals->rxq_scg[]" and "internals->txq_scg[]" arrays
	 */
	poll_statistics(internals);

	memset(stats, 0, sizeof(*stats));
	for (i = 0;
			i < RTE_ETHDEV_QUEUE_STAT_CNTRS && i < internals->nb_rx_queues;
			i++) {
		stats->q_ipackets[i] = internals->rxq_scg[i].rx_pkts;
		stats->q_ibytes[i] = internals->rxq_scg[i].rx_bytes;
		rx_total += stats->q_ipackets[i];
		rx_total_b += stats->q_ibytes[i];
	}

	for (i = 0;
			i < RTE_ETHDEV_QUEUE_STAT_CNTRS && i < internals->nb_tx_queues;
			i++) {
		stats->q_opackets[i] = internals->txq_scg[i].tx_pkts;
		stats->q_obytes[i] = internals->txq_scg[i].tx_bytes;
		stats->q_errors[i] = internals->txq_scg[i].err_pkts;
		tx_total += stats->q_opackets[i];
		tx_total_b += stats->q_obytes[i];
		tx_err_total += stats->q_errors[i];
	}

	stats->imissed = internals->rx_missed;
	stats->ipackets = rx_total;
	stats->ibytes = rx_total_b;
	stats->opackets = tx_total;
	stats->obytes = tx_total_b;
	stats->oerrors = tx_err_total;

	return 0;
}

static int dpdk_stats_reset(struct pmd_internals *internals,
			    struct ntdrv_4ga_s *p_nt_drv, int n_intf_no)
{
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	unsigned int i;

	if (!p_nthw_stat || !p_nt4ga_stat || n_intf_no < 0 ||
			n_intf_no > NUM_ADAPTER_PORTS_MAX)
		return -1;

	pthread_mutex_lock(&p_nt_drv->stat_lck);

	/* Rx */
	for (i = 0; i < internals->nb_rx_queues; i++) {
		internals->rxq_scg[i].rx_pkts = 0;
		internals->rxq_scg[i].rx_bytes = 0;
		internals->rxq_scg[i].err_pkts = 0;
	}

	internals->rx_missed = 0;

	/* Tx */
	for (i = 0; i < internals->nb_tx_queues; i++) {
		internals->txq_scg[i].tx_pkts = 0;
		internals->txq_scg[i].tx_bytes = 0;
		internals->txq_scg[i].err_pkts = 0;
	}

	p_nt4ga_stat->n_totals_reset_timestamp = time(NULL);

	pthread_mutex_unlock(&p_nt_drv->stat_lck);

	return 0;
}

/* NOTE: please note the difference between ETH_SPEED_NUM_xxx and ETH_LINK_SPEED_xxx */
static int nt_link_speed_to_eth_speed_num(enum nt_link_speed_e nt_link_speed)
{
	int eth_speed_num = ETH_SPEED_NUM_NONE;

	switch (nt_link_speed) {
	case NT_LINK_SPEED_10M:
		eth_speed_num = ETH_SPEED_NUM_10M;
		break;
	case NT_LINK_SPEED_100M:
		eth_speed_num = ETH_SPEED_NUM_100M;
		break;
	case NT_LINK_SPEED_1G:
		eth_speed_num = ETH_SPEED_NUM_1G;
		break;
	case NT_LINK_SPEED_10G:
		eth_speed_num = ETH_SPEED_NUM_10G;
		break;
	case NT_LINK_SPEED_25G:
		eth_speed_num = ETH_SPEED_NUM_25G;
		break;
	case NT_LINK_SPEED_40G:
		eth_speed_num = ETH_SPEED_NUM_40G;
		break;
	case NT_LINK_SPEED_50G:
		eth_speed_num = ETH_SPEED_NUM_50G;
		break;
	case NT_LINK_SPEED_100G:
		eth_speed_num = ETH_SPEED_NUM_100G;
		break;
	default:
		eth_speed_num = ETH_SPEED_NUM_NONE;
		break;
	}

	return eth_speed_num;
}

static int nt_link_duplex_to_eth_duplex(enum nt_link_duplex_e nt_link_duplex)
{
	int eth_link_duplex = 0;

	switch (nt_link_duplex) {
	case NT_LINK_DUPLEX_FULL:
		eth_link_duplex = ETH_LINK_FULL_DUPLEX;
		break;
	case NT_LINK_DUPLEX_HALF:
		eth_link_duplex = ETH_LINK_HALF_DUPLEX;
		break;
	case NT_LINK_DUPLEX_UNKNOWN: /* fall-through */
	default:
		break;
	}
	return eth_link_duplex;
}

static int eth_link_update(struct rte_eth_dev *eth_dev,
			   int wait_to_complete __rte_unused)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;

	if (eth_dev->data->dev_started) {
		if (internals->type == PORT_TYPE_VIRTUAL ||
				internals->type == PORT_TYPE_OVERRIDE) {
			eth_dev->data->dev_link.link_status =
				((internals->vport_comm ==
				  VIRT_PORT_NEGOTIATED_NONE) ?
				 ETH_LINK_DOWN :
				 ETH_LINK_UP);
			eth_dev->data->dev_link.link_speed = ETH_SPEED_NUM_NONE;
			eth_dev->data->dev_link.link_duplex =
				ETH_LINK_FULL_DUPLEX;
			return 0;
		}

		const bool port_link_status =
			nt4ga_port_get_link_status(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_status =
			port_link_status ? ETH_LINK_UP : ETH_LINK_DOWN;

		nt_link_speed_t port_link_speed =
			nt4ga_port_get_link_speed(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_speed =
			nt_link_speed_to_eth_speed_num(port_link_speed);

		nt_link_duplex_t nt_link_duplex =
			nt4ga_port_get_link_duplex(p_adapter_info, n_intf_no);
		eth_dev->data->dev_link.link_duplex =
			nt_link_duplex_to_eth_duplex(nt_link_duplex);
	} else {
		eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;
		eth_dev->data->dev_link.link_speed = ETH_SPEED_NUM_NONE;
		eth_dev->data->dev_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	}
	return 0;
}

static int eth_stats_get(struct rte_eth_dev *eth_dev,
			 struct rte_eth_stats *stats)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	dpdk_stats_collect(internals, stats);
	return 0;
}

static int eth_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;
	const int if_index = internals->if_index;

	dpdk_stats_reset(internals, p_nt_drv, if_index);
	return 0;
}

static uint32_t nt_link_speed_capa_to_eth_speed_capa(int nt_link_speed_capa)
{
	uint32_t eth_speed_capa = 0;

	if (nt_link_speed_capa & NT_LINK_SPEED_10M)
		eth_speed_capa |= ETH_LINK_SPEED_10M;
	if (nt_link_speed_capa & NT_LINK_SPEED_100M)
		eth_speed_capa |= ETH_LINK_SPEED_100M;
	if (nt_link_speed_capa & NT_LINK_SPEED_1G)
		eth_speed_capa |= ETH_LINK_SPEED_1G;
	if (nt_link_speed_capa & NT_LINK_SPEED_10G)
		eth_speed_capa |= ETH_LINK_SPEED_10G;
	if (nt_link_speed_capa & NT_LINK_SPEED_25G)
		eth_speed_capa |= ETH_LINK_SPEED_25G;
	if (nt_link_speed_capa & NT_LINK_SPEED_40G)
		eth_speed_capa |= ETH_LINK_SPEED_40G;
	if (nt_link_speed_capa & NT_LINK_SPEED_50G)
		eth_speed_capa |= ETH_LINK_SPEED_50G;
	if (nt_link_speed_capa & NT_LINK_SPEED_100G)
		eth_speed_capa |= ETH_LINK_SPEED_100G;

	return eth_speed_capa;
}

#define RTE_RSS_5TUPLE (ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP)

static int eth_dev_infos_get(struct rte_eth_dev *eth_dev,
			     struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;

	dev_info->if_index = internals->if_index;
	dev_info->driver_name = internals->name;
	dev_info->max_mac_addrs = NUM_MAC_ADDRS_PER_PORT;
	dev_info->max_rx_pktlen = HW_MAX_PKT_LEN;
	dev_info->max_mtu = MAX_MTU;
	if (p_adapter_info->fpga_info.profile == FPGA_INFO_PROFILE_INLINE)
		dev_info->min_mtu = MIN_MTU_INLINE;

	else
		dev_info->min_mtu = MIN_MTU;

	if (internals->p_drv) {
		dev_info->max_rx_queues = internals->nb_rx_queues;
		dev_info->max_tx_queues = internals->nb_tx_queues;

		dev_info->min_rx_bufsize = 64;

		const uint32_t nt_port_speed_capa =
			nt4ga_port_get_link_speed_capabilities(p_adapter_info,
							       n_intf_no);
		dev_info->speed_capa = nt_link_speed_capa_to_eth_speed_capa(nt_port_speed_capa);
	}

	dev_info->flow_type_rss_offloads =
		RTE_RSS_5TUPLE | RTE_ETH_RSS_C_VLAN |
		RTE_ETH_RSS_LEVEL_INNERMOST | RTE_ETH_RSS_L3_SRC_ONLY |
		RTE_ETH_RSS_LEVEL_OUTERMOST | RTE_ETH_RSS_L3_DST_ONLY;
	/*
	 * NT hashing algorithm doesn't use key, so it is just a fake key length to
	 * feet testpmd requirements.
	 */
	dev_info->hash_key_size = 1;

	return 0;
}

static __rte_always_inline int
copy_virtqueue_to_mbuf(struct rte_mbuf *mbuf, struct rte_mempool *mb_pool,
		       struct nthw_received_packets *hw_recv, int max_segs,
		       uint16_t data_len)
{
	int src_pkt = 0;
	/*
	 * 1. virtqueue packets may be segmented
	 * 2. the mbuf size may be too small and may need to be segmented
	 */
	char *data = (char *)hw_recv->addr + SG_HDR_SIZE;
	char *dst = (char *)mbuf->buf_addr + RTE_PKTMBUF_HEADROOM;

	/* set packet length */
	mbuf->pkt_len = data_len - SG_HDR_SIZE;

#ifdef RX_MERGE_SEGMENT_DEBUG
	void *dbg_src_start = hw_recv->addr;
	void *dbg_dst_start = dst;
#endif

	int remain = mbuf->pkt_len;
	/* First cpy_size is without header */
	int cpy_size = (data_len > SG_HW_RX_PKT_BUFFER_SIZE) ?
		       SG_HW_RX_PKT_BUFFER_SIZE - SG_HDR_SIZE :
		       remain;

	struct rte_mbuf *m = mbuf; /* if mbuf segmentation is needed */

	while (++src_pkt <= max_segs) {
		/* keep track of space in dst */
		int cpto_size = rte_pktmbuf_tailroom(m);

#ifdef RX_MERGE_SEGMENT_DEBUG
		printf("src copy size %i\n", cpy_size);
#endif

		if (cpy_size > cpto_size) {
			int new_cpy_size = cpto_size;

#ifdef RX_MERGE_SEGMENT_DEBUG
			printf("Seg %i: mbuf first cpy src off 0x%" PRIX64 ", dst off 0x%" PRIX64 ", size %i\n",
			       mbuf->nb_segs - 1,
			       (uint64_t)data - (uint64_t)dbg_src_start,
			       (uint64_t)dst - (uint64_t)dbg_dst_start,
			       new_cpy_size);
#endif
			rte_memcpy((void *)dst, (void *)data, new_cpy_size);
			m->data_len += new_cpy_size;
			remain -= new_cpy_size;
			cpy_size -= new_cpy_size;

			data += new_cpy_size;

			/*
			 * Loop if remaining data from this virtqueue seg cannot fit in one extra
			 * mbuf
			 */
			do {
				m->next = rte_pktmbuf_alloc(mb_pool);
				if (unlikely(!m->next))
					return -1;
				m = m->next;

				/* Headroom is not needed in chained mbufs */
				rte_pktmbuf_prepend(m, rte_pktmbuf_headroom(m));
				dst = (char *)m->buf_addr;
				m->data_len = 0;
				m->pkt_len = 0;

#ifdef RX_MERGE_SEGMENT_DEBUG
				dbg_dst_start = dst;
#endif
				cpto_size = rte_pktmbuf_tailroom(m);

				int actual_cpy_size = (cpy_size > cpto_size) ?
						      cpto_size :
						      cpy_size;
#ifdef RX_MERGE_SEGMENT_DEBUG
				printf("new dst mbuf seg - size %i\n",
				       cpto_size);
				printf("Seg %i: mbuf cpy src off 0x%" PRIX64 ", dst off 0x%" PRIX64 ", size %i\n",
				       mbuf->nb_segs,
				       (uint64_t)data - (uint64_t)dbg_src_start,
				       (uint64_t)dst - (uint64_t)dbg_dst_start,
				       actual_cpy_size);
#endif

				rte_memcpy((void *)dst, (void *)data,
					   actual_cpy_size);
				m->pkt_len += actual_cpy_size;
				m->data_len += actual_cpy_size;

				remain -= actual_cpy_size;
				cpy_size -= actual_cpy_size;

				data += actual_cpy_size;

				mbuf->nb_segs++;

			} while (cpy_size && remain);

		} else {
			/* all data from this virtqueue segment can fit in current mbuf */
#ifdef RX_MERGE_SEGMENT_DEBUG
			printf("Copy all into Seg %i: %i bytes, src off 0x%" PRIX64
			       ", dst off 0x%" PRIX64 "\n",
			       mbuf->nb_segs - 1, cpy_size,
			       (uint64_t)data - (uint64_t)dbg_src_start,
			       (uint64_t)dst - (uint64_t)dbg_dst_start);
#endif
			rte_memcpy((void *)dst, (void *)data, cpy_size);
			m->data_len += cpy_size;
			if (mbuf->nb_segs > 1)
				m->pkt_len += cpy_size;
			remain -= cpy_size;
		}

		/* packet complete - all data from current virtqueue packet has been copied */
		if (remain == 0)
			break;
		/* increment dst to data end */
		dst = rte_pktmbuf_mtod_offset(m, char *, m->data_len);
		/* prepare for next virtqueue segment */
		data = (char *)hw_recv[src_pkt]
		       .addr; /* following packets are full data */

#ifdef RX_MERGE_SEGMENT_DEBUG
		dbg_src_start = data;
#endif
		cpy_size = (remain > SG_HW_RX_PKT_BUFFER_SIZE) ?
			   SG_HW_RX_PKT_BUFFER_SIZE :
			   remain;
#ifdef RX_MERGE_SEGMENT_DEBUG
		printf("next src buf\n");
#endif
	};

	if (src_pkt > max_segs) {
		NT_LOG(ERR, ETHDEV,
		       "Did not receive correct number of segment for a whole packet");
		return -1;
	}

	return src_pkt;
}

static uint16_t eth_dev_rx_scg(void *queue, struct rte_mbuf **bufs,
			       uint16_t nb_pkts)
{
	unsigned int i;
	struct rte_mbuf *mbuf;
	struct ntnic_rx_queue *rx_q = queue;
	uint16_t num_rx = 0;

	struct nthw_received_packets hw_recv[MAX_RX_PACKETS];

	if (kill_pmd)
		return 0;

#ifdef DEBUG_PRINT_APPROX_CPU_LOAD
	dbg_print_approx_cpu_load_rx_called(rx_q->port);
#endif

	if (unlikely(nb_pkts == 0))
		return 0;

	if (nb_pkts > MAX_RX_PACKETS)
		nb_pkts = MAX_RX_PACKETS;

	uint16_t whole_pkts;
	uint16_t hw_recv_pkt_segs =
		nthw_get_rx_packets(rx_q->vq, nb_pkts, hw_recv, &whole_pkts);

	if (!hw_recv_pkt_segs) {
#ifdef DEBUG_PRINT_APPROX_CPU_LOAD
		dbg_print_approx_cpu_load_rx_done(rx_q->port, 0);
#endif

		return 0;
	}

#ifdef NT_DEBUG_STAT
	dbg_rx_queue(rx_q,
		     hw_recv_pkt_segs); /* _update debug statistics with new rx packet count */
#endif

	nb_pkts = whole_pkts;

#ifdef RX_MERGE_SEGMENT_DEBUG
	printf("\n---------- DPDK Rx ------------\n");
	printf("[Port %i] Pkts recv %i on hw queue index %i: tot segs %i, "
	       "vq buf %i, vq header size %i\n",
	       rx_q->port, nb_pkts, rx_q->queue.hw_id, hw_recv_pkt_segs,
	       SG_HW_RX_PKT_BUFFER_SIZE, SG_HDR_SIZE);
#endif

	int src_pkt = 0; /* from 0 to hw_recv_pkt_segs */

	for (i = 0; i < nb_pkts; i++) {
		bufs[i] = rte_pktmbuf_alloc(rx_q->mb_pool);
		if (!bufs[i]) {
			printf("ERROR - no more buffers mbuf in mempool\n");
			goto err_exit;
		}
		mbuf = bufs[i];

		struct _pkt_hdr_rx *phdr =
			(struct _pkt_hdr_rx *)hw_recv[src_pkt].addr;

#ifdef RX_MERGE_SEGMENT_DEBUG
		printf("\nRx pkt #%i: vq pkt len %i, segs %i -> mbuf size %i, headroom size %i\n",
		       i, phdr->cap_len - SG_HDR_SIZE,
		       (phdr->cap_len + SG_HW_RX_PKT_BUFFER_SIZE - 1) /
		       SG_HW_RX_PKT_BUFFER_SIZE,
		       rte_pktmbuf_tailroom(mbuf), rte_pktmbuf_headroom(mbuf));
#endif

#ifdef RX_SRC_DUMP_PKTS_DEBUG
		{
			int d, _segs = (phdr->cap_len +
					SG_HW_RX_PKT_BUFFER_SIZE - 1) /
				       SG_HW_RX_PKT_BUFFER_SIZE;
			int _size = phdr->cap_len;

			printf("Rx packet dump: pkt #%i hdr rx port %i, pkt len %i, segs %i\n",
			       i, phdr->port, phdr->cap_len - SG_HDR_SIZE,
			       _segs);
			for (d = 0; d < _segs; d++) {
				printf("Dump seg %i:\n", d);
				dump_packet_seg("Vq seg:", hw_recv[src_pkt + d].addr,
						_size > SG_HW_RX_PKT_BUFFER_SIZE ?
						SG_HW_RX_PKT_BUFFER_SIZE :
						_size);
				_size -= SG_HW_RX_PKT_BUFFER_SIZE;
			}
		}
#endif

		if (phdr->cap_len < SG_HDR_SIZE) {
			printf("Pkt len of zero received. No header!! - dropping packets\n");
			rte_pktmbuf_free(mbuf);
			goto err_exit;
		}

		{
			if (phdr->cap_len <= SG_HW_RX_PKT_BUFFER_SIZE &&
					(phdr->cap_len - SG_HDR_SIZE) <=
					rte_pktmbuf_tailroom(mbuf)) {
#ifdef RX_MERGE_SEGMENT_DEBUG
				printf("Simple copy vq -> mbuf %p size %i\n",
				       rte_pktmbuf_mtod(mbuf, void *),
				       phdr->cap_len);
#endif
				mbuf->data_len = phdr->cap_len - SG_HDR_SIZE;
				rte_memcpy(rte_pktmbuf_mtod(mbuf, char *),
					   (char *)hw_recv[src_pkt].addr +
					   SG_HDR_SIZE,
					   mbuf->data_len);

				mbuf->pkt_len = mbuf->data_len;
				src_pkt++;
			} else {
				int cpy_segs = copy_virtqueue_to_mbuf(mbuf, rx_q->mb_pool,
								      &hw_recv[src_pkt],
								      hw_recv_pkt_segs - src_pkt,
								      phdr->cap_len);
				if (cpy_segs < 0) {
					/* Error */
					rte_pktmbuf_free(mbuf);
					goto err_exit;
				}
				src_pkt += cpy_segs;
			}

#ifdef RX_DST_DUMP_PKTS_DEBUG
			{
				struct rte_mbuf *m = mbuf;

				printf("\nRx final mbuf:\n");
				for (int ii = 0; m && ii < m->nb_segs; ii++) {
					printf("  seg %i len %i\n", ii,
					       m->data_len);
					printf("  seg dump:\n");
					dump_packet_seg("mbuf seg:",
							rte_pktmbuf_mtod(m, uint8_t *),
							m->data_len);
					m = m->next;
				}
			}
#endif

			num_rx++;

			mbuf->ol_flags &=
				~(RTE_MBUF_F_RX_FDIR_ID | RTE_MBUF_F_RX_FDIR);
			mbuf->port = (uint16_t)-1;

			if (phdr->color_type == 0) {
				if (phdr->port >= VIRTUAL_TUNNEL_PORT_OFFSET &&
						((phdr->color >> 24) == 0x02)) {
					/* VNI in color of descriptor add port as well */
					mbuf->hash.fdir.hi =
						((uint32_t)phdr->color &
						 0xffffff) |
						((uint32_t)phdr->port
						 << 24);
					mbuf->hash.fdir.lo =
						(uint32_t)phdr->fid;
					mbuf->ol_flags |= RTE_MBUF_F_RX_FDIR_ID;

					NT_LOG(DBG, ETHDEV,
					       "POP'ed packet received that missed on inner match. color = %08x, port %i, tunnel-match flow stat id %i",
					       phdr->color, phdr->port,
					       phdr->fid);
				}

			} else {
				if (phdr->color) {
					mbuf->hash.fdir.hi =
						phdr->color &
						(NT_MAX_COLOR_FLOW_STATS - 1);
					mbuf->ol_flags |=
						RTE_MBUF_F_RX_FDIR_ID |
						RTE_MBUF_F_RX_FDIR;
				}
			}
		}
	}

err_exit:
	nthw_release_rx_packets(rx_q->vq, hw_recv_pkt_segs);

#ifdef DEBUG_PRINT_APPROX_CPU_LOAD
	dbg_print_approx_cpu_load_rx_done(rx_q->port, num_rx);
#endif

#ifdef RX_MERGE_SEGMENT_DEBUG
	/*
	 * When the application double frees a mbuf, it will become a doublet in the memory pool
	 * This is obvious a bug in application, but can be verified here to some extend at least
	 */
	uint64_t addr = (uint64_t)bufs[0]->buf_addr;

	for (int i = 1; i < num_rx; i++) {
		if (bufs[i]->buf_addr == addr) {
			printf("Duplicate packet addresses! num_rx %i\n",
			       num_rx);
			for (int ii = 0; ii < num_rx; ii++) {
				printf("bufs[%i]->buf_addr %p\n", ii,
				       bufs[ii]->buf_addr);
			}
		}
	}
#endif

	return num_rx;
}

int copy_mbuf_to_virtqueue(struct nthw_cvirtq_desc *cvq_desc,
			   uint16_t vq_descr_idx,
			   struct nthw_memory_descriptor *vq_bufs, int max_segs,
			   struct rte_mbuf *mbuf)
{
	/*
	 * 1. mbuf packet may be segmented
	 * 2. the virtqueue buffer size may be too small and may need to be segmented
	 */

	char *data = rte_pktmbuf_mtod(mbuf, char *);
	char *dst = (char *)vq_bufs[vq_descr_idx].virt_addr + SG_HDR_SIZE;

	int remain = mbuf->pkt_len;
	int cpy_size = mbuf->data_len;

#ifdef CPY_MBUF_TO_VQUEUE_DEBUG
	printf("src copy size %i\n", cpy_size);
#endif

	struct rte_mbuf *m = mbuf;
	int cpto_size = SG_HW_TX_PKT_BUFFER_SIZE - SG_HDR_SIZE;

	cvq_desc->b[vq_descr_idx].len = SG_HDR_SIZE;

	int cur_seg_num = 0; /* start from 0 */

	while (m) {
		/* Can all data in current src segment be in current dest segment */
		if (cpy_size > cpto_size) {
			int new_cpy_size = cpto_size;

#ifdef CPY_MBUF_TO_VQUEUE_DEBUG
			printf("Seg %i: virtq buf first cpy src offs %u, dst offs 0x%" PRIX64 ", size %i\n",
			       cur_seg_num,
			       (uint64_t)data - rte_pktmbuf_mtod(m, uint64_t),
			       (uint64_t)dst -
			       (uint64_t)vq_bufs[vq_descr_idx].virt_addr,
			       new_cpy_size);
#endif
			rte_memcpy((void *)dst, (void *)data, new_cpy_size);

			cvq_desc->b[vq_descr_idx].len += new_cpy_size;

			remain -= new_cpy_size;
			cpy_size -= new_cpy_size;

			data += new_cpy_size;

			/*
			 * Loop if remaining data from this virtqueue seg cannot fit in one extra
			 * mbuf
			 */
			do {
				vq_add_flags(cvq_desc, vq_descr_idx,
					     VIRTQ_DESC_F_NEXT);

				int next_vq_descr_idx =
					VIRTQ_DESCR_IDX_NEXT(vq_descr_idx);

				vq_set_next(cvq_desc, vq_descr_idx,
					    next_vq_descr_idx);

				vq_descr_idx = next_vq_descr_idx;

				vq_set_flags(cvq_desc, vq_descr_idx, 0);
				vq_set_next(cvq_desc, vq_descr_idx, 0);

				if (++cur_seg_num > max_segs)
					break;

				dst = (char *)vq_bufs[vq_descr_idx].virt_addr;
				cpto_size = SG_HW_TX_PKT_BUFFER_SIZE;

				int actual_cpy_size = (cpy_size > cpto_size) ?
						      cpto_size :
						      cpy_size;
#ifdef CPY_MBUF_TO_VQUEUE_DEBUG
				printf("Tx vq buf seg %i: virtq cpy %i - offset 0x%" PRIX64 "\n",
				       cur_seg_num, actual_cpy_size,
				       (uint64_t)dst -
				       (uint64_t)vq_bufs[vq_descr_idx]
				       .virt_addr);
#endif
				rte_memcpy((void *)dst, (void *)data,
					   actual_cpy_size);

				cvq_desc->b[vq_descr_idx].len = actual_cpy_size;

				remain -= actual_cpy_size;
				cpy_size -= actual_cpy_size;
				cpto_size -= actual_cpy_size;

				data += actual_cpy_size;

			} while (cpy_size && remain);

		} else {
			/* All data from this segment can fit in current virtqueue buffer */
#ifdef CPY_MBUF_TO_VQUEUE_DEBUG
			printf("Tx vq buf seg %i: Copy %i bytes - offset %u\n",
			       cur_seg_num, cpy_size,
			       (uint64_t)dst -
			       (uint64_t)vq_bufs[vq_descr_idx].virt_addr);
#endif

			rte_memcpy((void *)dst, (void *)data, cpy_size);

			cvq_desc->b[vq_descr_idx].len += cpy_size;

			remain -= cpy_size;
			cpto_size -= cpy_size;
		}

		/* Packet complete - all segments from current mbuf has been copied */
		if (remain == 0)
			break;
		/* increment dst to data end */
		dst = (char *)vq_bufs[vq_descr_idx].virt_addr +
		      cvq_desc->b[vq_descr_idx].len;

		m = m->next;
		if (!m) {
			NT_LOG(ERR, ETHDEV, "ERROR: invalid packet size\n");
			break;
		}

		/* Prepare for next mbuf segment */
		data = rte_pktmbuf_mtod(m, char *);
		cpy_size = m->data_len;
	};

	cur_seg_num++;
	if (cur_seg_num > max_segs) {
		NT_LOG(ERR, ETHDEV,
		       "Did not receive correct number of segment for a whole packet");
		return -1;
	}

	return cur_seg_num;
}

static uint16_t eth_dev_tx_scg(void *queue, struct rte_mbuf **bufs,
			       uint16_t nb_pkts)
{
	uint16_t pkt;
	uint16_t first_vq_descr_idx = 0;

	struct nthw_cvirtq_desc cvq_desc;

	struct nthw_memory_descriptor *vq_bufs;

	struct ntnic_tx_queue *tx_q = queue;

	int nb_segs = 0, i;
	int pkts_sent = 0;
	uint16_t nb_segs_arr[MAX_TX_PACKETS];

	if (kill_pmd)
		return 0;

	if (nb_pkts > MAX_TX_PACKETS)
		nb_pkts = MAX_TX_PACKETS;

#ifdef TX_CHAINING_DEBUG
	printf("\n---------- DPDK Tx ------------\n");
#endif

	/*
	 * count all segments needed to contain all packets in vq buffers
	 */
	for (i = 0; i < nb_pkts; i++) {
		if (bufs[i]->pkt_len < 60) {
			bufs[i]->pkt_len = 60;
			bufs[i]->data_len = 60;
		}

		/* build the num segments array for segmentation control and release function */
		int vq_segs = NUM_VQ_SEGS(bufs[i]->pkt_len);

		nb_segs_arr[i] = vq_segs;
		nb_segs += vq_segs;
	}
	if (!nb_segs)
		goto exit_out;

#ifdef TX_CHAINING_DEBUG
	printf("[Port %i] Mbufs for Tx: tot segs %i, packets %i, mbuf size %i, headroom size %i\n",
	       tx_q->port, nb_segs, nb_pkts,
	       bufs[0]->buf_len - rte_pktmbuf_headroom(bufs[0]),
	       rte_pktmbuf_headroom(bufs[0]));
#endif

	int got_nb_segs =
		nthw_get_tx_buffers(tx_q->vq, nb_segs, &first_vq_descr_idx,
				    &cvq_desc /*&vq_descr,*/, &vq_bufs);
	if (!got_nb_segs) {
#ifdef TX_CHAINING_DEBUG
		printf("Zero segments got - back pressure from HW\n");
#endif
		goto exit_out;
	}

	/*
	 * we may get less vq buffers than we have asked for
	 * calculate last whole packet that can fit into what
	 * we have got
	 */
	while (got_nb_segs < nb_segs) {
		if (!--nb_pkts)
			goto exit_out;
		nb_segs -= NUM_VQ_SEGS(bufs[nb_pkts]->pkt_len);
		if (nb_segs <= 0)
			goto exit_out;
	}

	/*
	 * nb_pkts & nb_segs, got it all, ready to copy
	 */
	int seg_idx = 0;
	int last_seg_idx = seg_idx;

	for (pkt = 0; pkt < nb_pkts; ++pkt) {
		uint16_t vq_descr_idx = VIRTQ_DESCR_IDX(seg_idx);

		vq_set_flags(&cvq_desc, vq_descr_idx, 0);
		vq_set_next(&cvq_desc, vq_descr_idx, 0);

		struct _pkt_hdr_tx *hdr_tx =
			(struct _pkt_hdr_tx *)vq_bufs[vq_descr_idx].virt_addr;
		/* Set the header to all zeros */
		memset(hdr_tx, 0, SG_HDR_SIZE);

		/*
		 * Set the NT DVIO0 header fields
		 *
		 * Applicable for Vswitch only.
		 * For other product types the header values are "don't care" and we leave them as
		 * all zeros.
		 */
		if (tx_q->profile == FPGA_INFO_PROFILE_VSWITCH) {
			hdr_tx->bypass_port = tx_q->target_id;

			/* set packet length */
			hdr_tx->cap_len = bufs[pkt]->pkt_len + SG_HDR_SIZE;
		}

#ifdef TX_CHAINING_DEBUG
		printf("\nTx pkt #%i: pkt segs %i, pkt len %i -> vq buf size %i, vq header size %i\n",
		       pkt, bufs[pkt]->nb_segs, bufs[pkt]->pkt_len,
		       SG_HW_TX_PKT_BUFFER_SIZE, SG_HDR_SIZE);

#ifdef TX_SRC_DUMP_PKTS_DEBUG
		{
			struct rte_mbuf *m = bufs[pkt];
			int ii;

			printf("Dump src mbuf:\n");
			for (ii = 0; ii < bufs[pkt]->nb_segs; ii++) {
				printf("  seg %i len %i\n", ii, m->data_len);
				printf("  seg dump:\n");
				dump_packet_seg("mbuf seg:",
						rte_pktmbuf_mtod(m, uint8_t *),
						m->data_len);
				m = m->next;
			}
		}
#endif

#endif

		if (bufs[pkt]->nb_segs == 1 && nb_segs_arr[pkt] == 1) {
#ifdef TX_CHAINING_DEBUG
			printf("Simple copy %i bytes - mbuf -> vq\n",
			       bufs[pkt]->pkt_len);
#endif
			rte_memcpy((void *)((char *)vq_bufs[vq_descr_idx].virt_addr +
				SG_HDR_SIZE),
				rte_pktmbuf_mtod(bufs[pkt], void *),
				bufs[pkt]->pkt_len);

			cvq_desc.b[vq_descr_idx].len =
				bufs[pkt]->pkt_len + SG_HDR_SIZE;

			seg_idx++;
		} else {
			int cpy_segs = copy_mbuf_to_virtqueue(&cvq_desc,
							      vq_descr_idx, vq_bufs,
							      nb_segs - last_seg_idx, bufs[pkt]);
			if (cpy_segs < 0)
				break;
			seg_idx += cpy_segs;
		}

#ifdef TX_DST_DUMP_PKTS_DEBUG
		int d, tot_size = 0;

		for (d = last_seg_idx; d < seg_idx; d++)
			tot_size += cvq_desc.b[VIRTQ_DESCR_IDX(d)].len;
		printf("\nDump final Tx vq pkt %i, size %i, tx port %i, bypass id %i, using hw queue index %i\n",
		       pkt, tot_size, tx_q->port, hdr_tx->bypass_port,
		       tx_q->queue.hw_id);
		for (d = last_seg_idx; d < seg_idx; d++) {
			char str[32];

			sprintf(str, "Vq seg %i:", d - last_seg_idx);
			dump_packet_seg(str,
					vq_bufs[VIRTQ_DESCR_IDX(d)].virt_addr,
					cvq_desc.b[VIRTQ_DESCR_IDX(d)].len);
		}
#endif

		last_seg_idx = seg_idx;
		rte_pktmbuf_free(bufs[pkt]);
		pkts_sent++;
	}

#ifdef TX_CHAINING_DEBUG
	printf("\nTx final vq setup:\n");
	for (int i = 0; i < nb_segs; i++) {
		int idx = VIRTQ_DESCR_IDX(i);

		if (cvq_desc.vq_type == SPLIT_RING) {
			printf("virtq descr %i, len %i, flags %04x, next %i\n",
			       idx, cvq_desc.b[idx].len, cvq_desc.s[idx].flags,
			       cvq_desc.s[idx].next);
		}
	}
#endif

exit_out:

	if (pkts_sent) {
#ifdef TX_CHAINING_DEBUG
		printf("Release virtq segs %i\n", nb_segs);
#endif
		nthw_release_tx_buffers(tx_q->vq, pkts_sent, nb_segs_arr);
	}
	return pkts_sent;
}

static int allocate_hw_virtio_queues(struct rte_eth_dev *eth_dev, int vf_num,
				     struct hwq_s *hwq, int num_descr,
				     int buf_size)
{
	int i, res;
	uint32_t size;
	uint64_t iova_addr;

	NT_LOG(DBG, ETHDEV,
	       "***** Configure IOMMU for HW queues on VF %i *****\n", vf_num);

	/* Just allocate 1MB to hold all combined descr rings */
	uint64_t tot_alloc_size = 0x100000 + buf_size * num_descr;

	void *virt = rte_malloc_socket("VirtQDescr", tot_alloc_size,
				       ALIGN_SIZE(tot_alloc_size),
				       eth_dev->data->numa_node);
	if (!virt)
		return -1;

	uint64_t gp_offset = (uint64_t)virt & ONE_G_MASK;
	rte_iova_t hpa = rte_malloc_virt2iova(virt);

	NT_LOG(DBG, ETHDEV,
	       "Allocated virtio descr rings : virt %p [0x%" PRIX64
	       "], hpa %p [0x%" PRIX64 "]\n",
	       virt, gp_offset, hpa, hpa & ONE_G_MASK);

	/*
	 * Same offset on both HPA and IOVA
	 * Make sure 1G boundary is never crossed
	 */
	if (((hpa & ONE_G_MASK) != gp_offset) ||
			(((uint64_t)virt + tot_alloc_size) & ~ONE_G_MASK) !=
			((uint64_t)virt & ~ONE_G_MASK)) {
		NT_LOG(ERR, ETHDEV,
		       "*********************************************************\n");
		NT_LOG(ERR, ETHDEV,
		       "ERROR, no optimal IOMMU mapping available hpa : %016lx (%016lx), gp_offset : %016lx size %u\n",
		       hpa, hpa & ONE_G_MASK, gp_offset, tot_alloc_size);
		NT_LOG(ERR, ETHDEV,
		       "*********************************************************\n");

		rte_free(virt);

		/* Just allocate 1MB to hold all combined descr rings */
		size = 0x100000;
		void *virt = rte_malloc_socket("VirtQDescr", size, 4096,
					       eth_dev->data->numa_node);
		if (!virt)
			return -1;

		res = nt_vfio_dma_map(vf_num, virt, &iova_addr, size);

		NT_LOG(DBG, ETHDEV, "VFIO MMAP res %i, vf_num %i\n", res,
		       vf_num);
		if (res != 0)
			return -1;

		hwq->vf_num = vf_num;
		hwq->virt_queues_ctrl.virt_addr = virt;
		hwq->virt_queues_ctrl.phys_addr = (void *)iova_addr;
		hwq->virt_queues_ctrl.len = size;

		NT_LOG(DBG, ETHDEV,
		       "Allocated for virtio descr rings combined 1MB : %p, IOVA %016lx\n",
		       virt, iova_addr);

		size = num_descr * sizeof(struct nthw_memory_descriptor);
		hwq->pkt_buffers = rte_zmalloc_socket("rx_pkt_buffers", size,
						      64, eth_dev->data->numa_node);
		if (!hwq->pkt_buffers) {
			NT_LOG(ERR, ETHDEV,
			       "Failed to allocated buffer array for hw-queue %p, "
			       "total size %i, elements %i\n",
			       hwq->pkt_buffers, size, num_descr);
			rte_free(virt);
			return -1;
		}

		size = buf_size * num_descr;
		void *virt_addr = rte_malloc_socket("pkt_buffer_pkts", size,
						    4096,
						    eth_dev->data->numa_node);
		if (!virt_addr) {
			NT_LOG(ERR, ETHDEV,
			       "Failed allocate packet buffers for hw-queue %p, "
			       "buf size %i, elements %i\n",
			       hwq->pkt_buffers, buf_size, num_descr);
			rte_free(hwq->pkt_buffers);
			rte_free(virt);
			return -1;
		}

		res = nt_vfio_dma_map(vf_num, virt_addr, &iova_addr, size);

		NT_LOG(DBG, ETHDEV,
		       "VFIO MMAP res %i, virt %p, iova %016lx, vf_num %i, num "
		       "pkt bufs %i, tot size %i\n",
		       res, virt_addr, iova_addr, vf_num, num_descr, size);

		if (res != 0)
			return -1;

		for (i = 0; i < num_descr; i++) {
			hwq->pkt_buffers[i].virt_addr =
				(void *)((char *)virt_addr +
					 ((uint64_t)(i) * buf_size));
			hwq->pkt_buffers[i].phys_addr =
				(void *)(iova_addr + ((uint64_t)(i) * buf_size));
			hwq->pkt_buffers[i].len = buf_size;
		}

		return 0;
	} /* End of: no optimal IOMMU mapping available */

	res = nt_vfio_dma_map(vf_num, virt, &iova_addr, ONE_G_SIZE);
	if (res != 0) {
		NT_LOG(ERR, ETHDEV, "VFIO MMAP FAILED! res %i, vf_num %i\n",
		       res, vf_num);
		return -1;
	}

	hwq->vf_num = vf_num;
	hwq->virt_queues_ctrl.virt_addr = virt;
	hwq->virt_queues_ctrl.phys_addr = (void *)(iova_addr);
	hwq->virt_queues_ctrl.len = 0x100000;
	iova_addr += 0x100000;

	NT_LOG(DBG, ETHDEV,
	       "VFIO MMAP: virt_addr=%" PRIX64 " phys_addr=%" PRIX64
	       " size=%" PRIX64 " hpa=%" PRIX64 "\n",
	       hwq->virt_queues_ctrl.virt_addr, hwq->virt_queues_ctrl.phys_addr,
	       hwq->virt_queues_ctrl.len,
	       rte_malloc_virt2iova(hwq->virt_queues_ctrl.virt_addr));

	size = num_descr * sizeof(struct nthw_memory_descriptor);
	hwq->pkt_buffers = rte_zmalloc_socket("rx_pkt_buffers", size, 64,
					      eth_dev->data->numa_node);
	if (!hwq->pkt_buffers) {
		NT_LOG(ERR, ETHDEV,
		       "Failed to allocated buffer array for hw-queue %p, total size %i, elements %i\n",
		       hwq->pkt_buffers, size, num_descr);
		rte_free(virt);
		return -1;
	}

	void *virt_addr = (void *)((uint64_t)virt + 0x100000);

	for (i = 0; i < num_descr; i++) {
		hwq->pkt_buffers[i].virt_addr =
			(void *)((char *)virt_addr + ((uint64_t)(i) * buf_size));
		hwq->pkt_buffers[i].phys_addr =
			(void *)(iova_addr + ((uint64_t)(i) * buf_size));
		hwq->pkt_buffers[i].len = buf_size;
	}
	return 0;
}

static void release_hw_virtio_queues(struct hwq_s *hwq)
{
	if (!hwq || hwq->vf_num == 0)
		return;
	hwq->vf_num = 0;
}

static int deallocate_hw_virtio_queues(struct hwq_s *hwq)
{
	int vf_num = hwq->vf_num;

	void *virt = hwq->virt_queues_ctrl.virt_addr;

	int res = nt_vfio_dma_unmap(vf_num, hwq->virt_queues_ctrl.virt_addr,
				    (uint64_t)hwq->virt_queues_ctrl.phys_addr,
				    ONE_G_SIZE);
	if (res != 0) {
		NT_LOG(ERR, ETHDEV, "VFIO UNMMAP FAILED! res %i, vf_num %i\n",
		       res, vf_num);
		return -1;
	}

	release_hw_virtio_queues(hwq);
	rte_free(hwq->pkt_buffers);
	rte_free(virt);
	return 0;
}

static void eth_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ntnic_tx_queue *tx_q = &internals->txq_scg[queue_id];

	deallocate_hw_virtio_queues(&tx_q->hwq);
	NT_LOG(DBG, ETHDEV, "NTNIC: %s\n", __func__);
}

static void eth_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ntnic_rx_queue *rx_q = &internals->rxq_scg[queue_id];

	deallocate_hw_virtio_queues(&rx_q->hwq);
	NT_LOG(DBG, ETHDEV, "NTNIC: %s\n", __func__);
}

static int num_queues_allocated;

/* Returns num queue starting at returned queue num or -1 on fail */
static int allocate_queue(int num)
{
	int next_free = num_queues_allocated;

	NT_LOG(DBG, ETHDEV,
	       "%s: num_queues_allocated=%u, New queues=%u, Max queues=%u\n",
	       __func__, num_queues_allocated, num, MAX_TOTAL_QUEUES);
	if (num_queues_allocated + num > MAX_TOTAL_QUEUES)
		return -1;
	num_queues_allocated += num;
	return next_free;
}

static int
eth_rx_scg_queue_setup(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id,
		       uint16_t nb_rx_desc __rte_unused,
		       unsigned int socket_id __rte_unused,
		       const struct rte_eth_rxconf *rx_conf __rte_unused,
		       struct rte_mempool *mb_pool)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	struct rte_pktmbuf_pool_private *mbp_priv;
	struct pmd_internals *internals = eth_dev->data->dev_private;
	struct ntnic_rx_queue *rx_q = &internals->rxq_scg[rx_queue_id];
	struct drv_s *p_drv = internals->p_drv;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;

	if (internals->type == PORT_TYPE_OVERRIDE) {
		rx_q->mb_pool = mb_pool;
		eth_dev->data->rx_queues[rx_queue_id] = rx_q;
		mbp_priv = rte_mempool_get_priv(rx_q->mb_pool);
		rx_q->buf_size = (uint16_t)(mbp_priv->mbuf_data_room_size -
					    RTE_PKTMBUF_HEADROOM);
		rx_q->enabled = 1;
		return 0;
	}

	NT_LOG(DBG, ETHDEV,
	       "(%i) NTNIC RX OVS-SW queue setup: queue id %i, hw queue index %i\n",
	       internals->port, rx_queue_id, rx_q->queue.hw_id);

	rx_q->mb_pool = mb_pool;

	eth_dev->data->rx_queues[rx_queue_id] = rx_q;

	mbp_priv = rte_mempool_get_priv(rx_q->mb_pool);
	rx_q->buf_size = (uint16_t)(mbp_priv->mbuf_data_room_size -
				    RTE_PKTMBUF_HEADROOM);
	rx_q->enabled = 1;

	if (allocate_hw_virtio_queues(eth_dev, EXCEPTION_PATH_HID, &rx_q->hwq,
				      SG_NB_HW_RX_DESCRIPTORS,
				      SG_HW_RX_PKT_BUFFER_SIZE) < 0)
		return -1;

	rx_q->nb_hw_rx_descr = SG_NB_HW_RX_DESCRIPTORS;

	rx_q->profile = p_drv->ntdrv.adapter_info.fpga_info.profile;

	rx_q->vq = nthw_setup_managed_rx_virt_queue(p_nt_drv->adapter_info.fpga_info.mp_nthw_dbs,
		rx_q->queue.hw_id, /* index */
		rx_q->nb_hw_rx_descr, EXCEPTION_PATH_HID, /* host_id */
		1, /* header NT DVIO header for exception path */
		&rx_q->hwq.virt_queues_ctrl, rx_q->hwq.pkt_buffers, SPLIT_RING, -1);

	NT_LOG(DBG, ETHDEV, "(%i) NTNIC RX OVS-SW queues successfully setup\n",
	       internals->port);

	return 0;
}

static int
eth_tx_scg_queue_setup(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id,
		       uint16_t nb_tx_desc __rte_unused,
		       unsigned int socket_id __rte_unused,
		       const struct rte_eth_txconf *tx_conf __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	struct pmd_internals *internals = eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;
	struct ntnic_tx_queue *tx_q = &internals->txq_scg[tx_queue_id];

	if (internals->type == PORT_TYPE_OVERRIDE) {
		eth_dev->data->tx_queues[tx_queue_id] = tx_q;
		return 0;
	}

	NT_LOG(DBG, ETHDEV,
	       "(%i) NTNIC TX OVS-SW queue setup: queue id %i, hw queue index %i\n",
	       tx_q->port, tx_queue_id, tx_q->queue.hw_id);

	if (tx_queue_id > internals->nb_tx_queues) {
		printf("Error invalid tx queue id\n");
		return -1;
	}

	eth_dev->data->tx_queues[tx_queue_id] = tx_q;

	/* Calculate target ID for HW  - to be used in NTDVIO0 header bypass_port */
	if (tx_q->rss_target_id >= 0) {
		/* bypass to a multiqueue port - qsl-hsh index */
		tx_q->target_id = tx_q->rss_target_id + 0x90;
	} else {
		if (internals->vpq[tx_queue_id].hw_id > -1) {
			/* virtual port - queue index */
			tx_q->target_id = internals->vpq[tx_queue_id].hw_id;
		} else {
			/* Phy port - phy port identifier */
			if (lag_active) {
				/* If in LAG mode use bypass 0x90 mode */
				tx_q->target_id = 0x90;
			} else {
				/* output/bypass to MAC */
				tx_q->target_id = (int)(tx_q->port + 0x80);
			}
		}
	}

	if (allocate_hw_virtio_queues(eth_dev, EXCEPTION_PATH_HID, &tx_q->hwq,
				      SG_NB_HW_TX_DESCRIPTORS,
				      SG_HW_TX_PKT_BUFFER_SIZE) < 0)
		return -1;

	tx_q->nb_hw_tx_descr = SG_NB_HW_TX_DESCRIPTORS;

	tx_q->profile = p_drv->ntdrv.adapter_info.fpga_info.profile;

	uint32_t port, header;

	if (tx_q->profile == FPGA_INFO_PROFILE_VSWITCH) {
		/* transmit port - not used in vswitch enabled mode - using bypass */
		port = 0;
		header = 1; /* header type DVIO0 Always for exception path */
	} else {
		port = tx_q->port; /* transmit port */
		header = 0; /* header type VirtIO-Net */
	}
	/*
	 * in_port - in vswitch mode has to move tx port from OVS excep. Away
	 * from VM tx port, because of QoS is matched by port id!
	 */
	tx_q->vq = nthw_setup_managed_tx_virt_queue(p_nt_drv->adapter_info.fpga_info.mp_nthw_dbs,
		tx_q->queue.hw_id, /* index */
		tx_q->nb_hw_tx_descr, /* queue size */
		EXCEPTION_PATH_HID, /* host_id always VF4 */
		port,
		tx_q->port +
		128,
		header, &tx_q->hwq.virt_queues_ctrl, tx_q->hwq.pkt_buffers,
		SPLIT_RING, -1, IN_ORDER);

	tx_q->enabled = 1;
	for (uint32_t i = 0; i < internals->vpq_nb_vq; i++) {
		nthw_epp_set_queue_to_vport(p_nt_drv->adapter_info.fpga_info.mp_nthw_epp,
					    internals->vpq[i].hw_id, tx_q->port);
	}

	NT_LOG(DBG, ETHDEV, "(%i) NTNIC TX OVS-SW queues successfully setup\n",
	       internals->port);

	if (internals->type == PORT_TYPE_PHYSICAL) {
		struct adapter_info_s *p_adapter_info =
				&internals->p_drv->ntdrv.adapter_info;
		NT_LOG(DBG, ETHDEV, "Port %i is ready for data. Enable port\n",
		       internals->if_index);
		nt4ga_port_set_adm_state(p_adapter_info, internals->if_index,
					 true);
		if (lag_active && internals->if_index == 0) {
			/*
			 * Special case for link aggregation where the second phy interface (port 1)
			 * is "hidden" from DPDK and therefore doesn't get enabled through normal
			 * interface probing
			 */
			NT_LOG(DBG, ETHDEV, "LAG: Enable port %i\n",
			       internals->if_index + 1);
			nt4ga_port_set_adm_state(p_adapter_info,
						 internals->if_index + 1, true);
		}
	}

	return 0;
}

static int dev_set_mtu_inline(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)dev->data->dev_private;
	struct flow_eth_dev *flw_dev = internals->flw_dev;
	int ret = -1;

	if (internals->type == PORT_TYPE_PHYSICAL && mtu >= MIN_MTU_INLINE &&
			mtu <= MAX_MTU)
		ret = flow_set_mtu_inline(flw_dev, internals->port, mtu);
	return ret ? -EINVAL : 0;
}

static int dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	/*struct ntnic_tx_queue *tx_q = internals->txq; */
	struct drv_s *p_drv = internals->p_drv;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;
	fpga_info_t *fpga_info = &p_nt_drv->adapter_info.fpga_info;
	int retval = EINVAL;

	if (mtu < MIN_MTU || mtu > MAX_MTU)
		return -EINVAL;

	if (internals->type == PORT_TYPE_VIRTUAL) {
		/* set MTU on exception to MAX_MTU */
		retval = nthw_epp_set_mtu(fpga_info->mp_nthw_epp,
			internals->rxq_scg[0]
			.queue
			.hw_id, /* exception tx queue hw_id to OVS */
			MAX_MTU, /* max number of bytes allowed for a given port. */
			internals->type); /* port type */

		if (retval)
			return retval;

		uint i;

		for (i = 0; i < internals->vpq_nb_vq; i++) {
			retval = nthw_epp_set_mtu(fpga_info->mp_nthw_epp,
				internals->vpq[i].hw_id, /* tx queue hw_id */
				mtu, /* max number of bytes allowed for a given port. */
				internals->type); /* port type */
			if (retval)
				return retval;

			NT_LOG(DBG, ETHDEV, "SET MTU SIZE %d queue hw_id %d\n",
			       mtu, internals->vpq[i].hw_id);
		}
	} else if (internals->type == PORT_TYPE_PHYSICAL) {
		/* set MTU on exception to MAX_MTU */
		retval = nthw_epp_set_mtu(fpga_info->mp_nthw_epp,
			internals->rxq_scg[0]
			.queue
			.hw_id, /* exception tx queue hw_id to OVS */
			MAX_MTU, /* max number of bytes allowed for a given port. */
			PORT_TYPE_VIRTUAL); /* port type */
		if (retval)
			return retval;

		retval = nthw_epp_set_mtu(fpga_info->mp_nthw_epp,
			internals->port, /* port number */
			mtu, /* max number of bytes allowed for a given port. */
			internals->type); /* port type */

		NT_LOG(DBG, ETHDEV, "SET MTU SIZE %d port %d\n", mtu,
		       internals->port);
	} else {
		NT_LOG(DBG, ETHDEV,
		       "COULD NOT SET MTU SIZE %d port %d type %d\n", mtu,
		       internals->port, internals->type);
		retval = -EINVAL;
	}
	return retval;
}

static int eth_rx_queue_start(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	eth_dev->data->rx_queue_state[rx_queue_id] =
		RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int eth_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	eth_dev->data->rx_queue_state[rx_queue_id] =
		RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static int eth_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	eth_dev->data->tx_queue_state[rx_queue_id] =
		RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int eth_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	NT_LOG(DBG, ETHDEV, "%s: [%s:%u]\n", __func__, __func__, __LINE__);
	eth_dev->data->tx_queue_state[rx_queue_id] =
		RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static void eth_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct rte_ether_addr *const eth_addrs = dev->data->mac_addrs;

	assert(index < NUM_MAC_ADDRS_PER_PORT);

	if (index >= NUM_MAC_ADDRS_PER_PORT) {
		const struct pmd_internals *const internals =
				dev->data->dev_private;
		NT_LOG(ERR, ETHDEV,
		       "%s: [%s:%i]: Port %i: illegal index %u (>= %u)\n",
		       __FILE__, __func__, __LINE__, internals->if_index, index,
		       NUM_MAC_ADDRS_PER_PORT);
		return;
	}
	(void)memset(&eth_addrs[index], 0, sizeof(eth_addrs[index]));
}

static int eth_mac_addr_add(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mac_addr, uint32_t index,
			    uint32_t vmdq __rte_unused)
{
	struct rte_ether_addr *const eth_addrs = dev->data->mac_addrs;

	assert(index < NUM_MAC_ADDRS_PER_PORT);

	if (index >= NUM_MAC_ADDRS_PER_PORT) {
		const struct pmd_internals *const internals =
				dev->data->dev_private;
		NT_LOG(ERR, ETHDEV,
		       "%s: [%s:%i]: Port %i: illegal index %u (>= %u)\n",
		       __FILE__, __func__, __LINE__, internals->if_index, index,
		       NUM_MAC_ADDRS_PER_PORT);
		return -1;
	}

	eth_addrs[index] = *mac_addr;

	return 0;
}

static int eth_mac_addr_set(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mac_addr)
{
	struct rte_ether_addr *const eth_addrs = dev->data->mac_addrs;

	eth_addrs[0U] = *mac_addr;

	return 0;
}

static int eth_set_mc_addr_list(struct rte_eth_dev *dev,
				struct rte_ether_addr *mc_addr_set,
				uint32_t nb_mc_addr)
{
	struct pmd_internals *const internals = dev->data->dev_private;
	struct rte_ether_addr *const mc_addrs = internals->mc_addrs;
	size_t i;

	if (nb_mc_addr >= NUM_MULTICAST_ADDRS_PER_PORT) {
		NT_LOG(ERR, ETHDEV,
		       "%s: [%s:%i]: Port %i: too many multicast addresses %u (>= %u)\n",
		       __FILE__, __func__, __LINE__, internals->if_index,
		       nb_mc_addr, NUM_MULTICAST_ADDRS_PER_PORT);
		return -1;
	}

	for (i = 0U; i < NUM_MULTICAST_ADDRS_PER_PORT; i++) {
		if (i < nb_mc_addr)
			mc_addrs[i] = mc_addr_set[i];

		else
			(void)memset(&mc_addrs[i], 0, sizeof(mc_addrs[i]));
	}

	return 0;
}

static int eth_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] Called for eth_dev %p\n", __func__,
	       __func__, __LINE__, eth_dev);

	p_drv->probe_finished = 1;

	/* The device is ALWAYS running promiscuous mode. */
	eth_dev->data->promiscuous ^= ~eth_dev->data->promiscuous;
	return 0;
}

static int eth_dev_start(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] - Port %u, %u\n", __func__, __func__,
	       __LINE__, internals->n_intf_no, internals->if_index);

	if (internals->type == PORT_TYPE_VIRTUAL ||
			internals->type == PORT_TYPE_OVERRIDE) {
		eth_dev->data->dev_link.link_status = ETH_LINK_UP;
	} else {
		/*
		 * wait for link on port
		 * If application starts sending too soon before FPGA port is ready, garbage is
		 * produced
		 */
		int loop = 0;

		while (nt4ga_port_get_link_status(p_adapter_info, n_intf_no) ==
				ETH_LINK_DOWN) {
			/* break out after 5 sec */
			if (++loop >= 50) {
				NT_LOG(DBG, ETHDEV,
				       "%s: TIMEOUT No link on port %i (5sec timeout)\n",
				       __func__, internals->n_intf_no);
				break;
			}
			usleep(100000);
		}
		assert(internals->n_intf_no ==
		       internals->if_index); /* Sanity check */
		if (internals->lpbk_mode) {
			if (internals->lpbk_mode & 1 << 0) {
				nt4ga_port_set_loopback_mode(p_adapter_info,
							     n_intf_no,
							     NT_LINK_LOOPBACK_HOST);
			}
			if (internals->lpbk_mode & 1 << 1) {
				nt4ga_port_set_loopback_mode(p_adapter_info,
							     n_intf_no,
							     NT_LINK_LOOPBACK_LINE);
			}
		}
	}
	return 0;
}

static int eth_dev_stop(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	const int n_intf_no = internals->if_index;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] - Port %u, %u, type %u\n", __func__,
	       __func__, __LINE__, internals->n_intf_no, internals->if_index,
	       internals->type);

	if (internals->type != PORT_TYPE_VIRTUAL) {
		struct ntnic_rx_queue *rx_q = internals->rxq_scg;
		struct ntnic_tx_queue *tx_q = internals->txq_scg;

		uint q;

		for (q = 0; q < internals->nb_rx_queues; q++)
			nthw_release_managed_rx_virt_queue(rx_q[q].vq);

		for (q = 0; q < internals->nb_tx_queues; q++)
			nthw_release_managed_tx_virt_queue(tx_q[q].vq);

		nt4ga_port_set_adm_state(p_adapter_info, n_intf_no, 0);
		nt4ga_port_set_link_status(p_adapter_info, n_intf_no, 0);
		nt4ga_port_set_link_speed(p_adapter_info, n_intf_no,
					  NT_LINK_SPEED_UNKNOWN);
		nt4ga_port_set_loopback_mode(p_adapter_info, n_intf_no,
					     NT_LINK_LOOPBACK_OFF);
	}

	eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;
	return 0;
}

static int eth_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct pmd_internals *const internals = dev->data->dev_private;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;
	const int port = internals->if_index;

	if (internals->type == PORT_TYPE_VIRTUAL ||
			internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	assert(port >= 0 && port < NUM_ADAPTER_PORTS_MAX);
	assert(port == internals->n_intf_no);

	nt4ga_port_set_adm_state(p_adapter_info, port, true);

	return 0;
}

static int eth_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct pmd_internals *const internals = dev->data->dev_private;
	struct adapter_info_s *p_adapter_info =
			&internals->p_drv->ntdrv.adapter_info;
	const int port = internals->if_index;

	if (internals->type == PORT_TYPE_VIRTUAL ||
			internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	assert(port >= 0 && port < NUM_ADAPTER_PORTS_MAX);
	assert(port == internals->n_intf_no);

	nt4ga_port_set_link_status(p_adapter_info, port, false);

	return 0;
}

static int eth_dev_close(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	fpga_info_t *fpga_info = &p_nt_drv->adapter_info.fpga_info;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	(void)pci_dev; /* UNUSED */

	NT_LOG(DBG, ETHDEV, "%s: enter [%s:%u]\n", __func__, __func__,
	       __LINE__);

	internals->p_drv = NULL;

	/* LAG cleanup */
	if (internals->lag_config) {
		if (internals->lag_config->lag_tid) {
			internals->lag_config->lag_thread_active = 0;
			pthread_join(internals->lag_config->lag_tid, NULL);
		}
		lag_active = 0;
		rte_free(internals->lag_config);
	}

	/* free */
	rte_free(internals);
	internals = NULL;

	eth_dev->data->dev_private = NULL;
	eth_dev->data->mac_addrs = NULL;

	/* release */
	rte_eth_dev_release_port(eth_dev);

	NT_LOG(DBG, ETHDEV, "%s: %d [%s:%u]\n", __func__,
	       p_drv->n_eth_dev_init_count, __func__, __LINE__);
	p_drv->n_eth_dev_init_count--;

	/*
	 * rte_pci_dev has no private member for p_drv
	 * wait until all rte_eth_dev's are closed - then close adapters via p_drv
	 */
	if (!p_drv->n_eth_dev_init_count && p_drv) {
		NT_LOG(DBG, ETHDEV, "%s: %d [%s:%u]\n", __func__,
		       p_drv->n_eth_dev_init_count, __func__, __LINE__);
		p_drv->ntdrv.b_shutdown = true;
		void *p_ret_val = NULL;

		pthread_join(p_nt_drv->stat_thread, &p_ret_val);
		if (fpga_info->profile == FPGA_INFO_PROFILE_INLINE) {
			p_ret_val = NULL;
			pthread_join(p_nt_drv->flm_thread, &p_ret_val);
		}
		nt4ga_adapter_deinit(&p_nt_drv->adapter_info);
		rte_free(p_drv);
	}
	NT_LOG(DBG, ETHDEV, "%s: leave [%s:%u]\n", __func__, __func__,
	       __LINE__);
	return 0;
}

static int eth_fw_version_get(struct rte_eth_dev *eth_dev, char *fw_version,
			      size_t fw_size)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;

	if (internals->type == PORT_TYPE_VIRTUAL ||
			internals->type == PORT_TYPE_OVERRIDE)
		return 0;

	fpga_info_t *fpga_info = &internals->p_drv->ntdrv.adapter_info.fpga_info;
	const int length =
		snprintf(fw_version, fw_size, "%03d-%04d-%02d-%02d",
			 fpga_info->n_fpga_type_id, fpga_info->n_fpga_prod_id,
			 fpga_info->n_fpga_ver_id, fpga_info->n_fpga_rev_id);
	if ((size_t)length < fw_size) {
		/* We have space for the version string */
		return 0;
	}
	/* We do not have space for the version string -return the needed space */
	return length + 1;
}

static int eth_xstats_get(struct rte_eth_dev *eth_dev,
			  struct rte_eth_xstat *stats, unsigned int n)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	int if_index = internals->if_index;
	int nb_xstats;

	pthread_mutex_lock(&p_nt_drv->stat_lck);
	nb_xstats = nthw_xstats_get(p_nt4ga_stat, stats, n,
				    p_nthw_stat->mb_is_vswitch, if_index);
	pthread_mutex_unlock(&p_nt_drv->stat_lck);
	return nb_xstats;
}

static int eth_xstats_get_by_id(struct rte_eth_dev *eth_dev,
				const uint64_t *ids, uint64_t *values,
				unsigned int n)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	int if_index = internals->if_index;
	int nb_xstats;

	pthread_mutex_lock(&p_nt_drv->stat_lck);
	nb_xstats = nthw_xstats_get_by_id(p_nt4ga_stat, ids, values, n,
					  p_nthw_stat->mb_is_vswitch, if_index);
	pthread_mutex_unlock(&p_nt_drv->stat_lck);
	return nb_xstats;
}

static int eth_xstats_reset(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	int if_index = internals->if_index;

	pthread_mutex_lock(&p_nt_drv->stat_lck);
	nthw_xstats_reset(p_nt4ga_stat, p_nthw_stat->mb_is_vswitch, if_index);
	pthread_mutex_unlock(&p_nt_drv->stat_lck);
	return dpdk_stats_reset(internals, p_nt_drv, if_index);
}

static int eth_xstats_get_names(struct rte_eth_dev *eth_dev __rte_unused,
				struct rte_eth_xstat_name *xstats_names,
				unsigned int size)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;

	return nthw_xstats_get_names(p_nt4ga_stat, xstats_names, size,
				     p_nthw_stat->mb_is_vswitch);
}

static int eth_xstats_get_names_by_id(struct rte_eth_dev *eth_dev,
				      const uint64_t *ids,
				      struct rte_eth_xstat_name *xstats_names,
				      unsigned int size)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct drv_s *p_drv = internals->p_drv;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;

	return nthw_xstats_get_names_by_id(p_nt4ga_stat, xstats_names, ids, size,
					   p_nthw_stat->mb_is_vswitch);
}

static int _dev_flow_ops_get(struct rte_eth_dev *dev __rte_unused,
			     const struct rte_flow_ops **ops)
{
	*ops = &_dev_flow_ops;
	return 0;
}

static int promiscuous_enable(struct rte_eth_dev __rte_unused * dev)
{
	NT_LOG(DBG, NTHW, "The device always run promiscuous mode.");
	return 0;
}

static int eth_dev_rss_hash_update(struct rte_eth_dev *eth_dev,
				   struct rte_eth_rss_conf *rss_conf)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct flow_eth_dev *fedev = internals->flw_dev;
	struct flow_nic_dev *ndev = fedev->ndev;
	const int hsh_idx =
		0; /* hsh index 0 means the default receipt in HSH module */
	int res = flow_nic_set_hasher_fields(ndev, hsh_idx,
					     nt_rss_hash_field_from_dpdk(rss_conf->rss_hf));
	res |= hw_mod_hsh_rcp_flush(&ndev->be, hsh_idx, 1);
	return res;
}

static int rss_hash_conf_get(struct rte_eth_dev *eth_dev,
			     struct rte_eth_rss_conf *rss_conf)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)eth_dev->data->dev_private;
	struct flow_eth_dev *fedev = internals->flw_dev;
	struct flow_nic_dev *ndev = fedev->ndev;

	rss_conf->rss_key = NULL;
	rss_conf->rss_key_len = 0;
	rss_conf->rss_hf |=
		dpdk_rss_hash_define_from_nt_rss(ndev->rss_hash_config);
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
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
	.dev_infos_get = eth_dev_infos_get,
	.fw_version_get = eth_fw_version_get,
	.rx_queue_setup = eth_rx_scg_queue_setup,
	.rx_queue_start = eth_rx_queue_start,
	.rx_queue_stop = eth_rx_queue_stop,
	.rx_queue_release = eth_rx_queue_release,
	.tx_queue_setup = eth_tx_scg_queue_setup,
	.tx_queue_start = eth_tx_queue_start,
	.tx_queue_stop = eth_tx_queue_stop,
	.tx_queue_release = eth_tx_queue_release,
	.mac_addr_remove = eth_mac_addr_remove,
	.mac_addr_add = eth_mac_addr_add,
	.mac_addr_set = eth_mac_addr_set,
	.set_mc_addr_list = eth_set_mc_addr_list,
	.xstats_get = eth_xstats_get,
	.xstats_get_names = eth_xstats_get_names,
	.xstats_reset = eth_xstats_reset,
	.xstats_get_by_id = eth_xstats_get_by_id,
	.xstats_get_names_by_id = eth_xstats_get_names_by_id,
	.mtu_set = NULL,
	.mtr_ops_get = eth_mtr_ops_get,
	.flow_ops_get = _dev_flow_ops_get,
	.promiscuous_disable = NULL,
	.promiscuous_enable = promiscuous_enable,
	.rss_hash_update = eth_dev_rss_hash_update,
	.rss_hash_conf_get = rss_hash_conf_get,
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

/*
 * Adapter flm stat thread
 */
static void *adapter_flm_thread_fn(void *context)
{
	struct drv_s *p_drv = context;
	struct ntdrv_4ga_s *p_nt_drv = &p_drv->ntdrv;
	struct adapter_info_s *p_adapter_info = &p_nt_drv->adapter_info;
	struct nt4ga_filter_s *p_nt4ga_filter = &p_adapter_info->nt4ga_filter;
	struct flow_nic_dev *p_flow_nic_dev = p_nt4ga_filter->mp_flow_device;

	NT_LOG(DBG, ETHDEV, "%s: %s: waiting for port configuration\n",
	       p_adapter_info->mp_adapter_id_str, __func__);

	while (p_flow_nic_dev->eth_base == NULL)
		usleep(1000000);
	struct flow_eth_dev *dev = p_flow_nic_dev->eth_base;

	NT_LOG(DBG, ETHDEV, "%s: %s: begin\n", p_adapter_info->mp_adapter_id_str,
	       __func__);

	while (!p_drv->ntdrv.b_shutdown) {
		if (flm_mtr_update_stats(dev) == 0)
			usleep(10);
	}

	NT_LOG(DBG, ETHDEV, "%s: %s: end\n", p_adapter_info->mp_adapter_id_str,
	       __func__);

	return NULL;
}

/*
 * Adapter stat thread
 */
static void *adapter_stat_thread_fn(void *context)
{
	struct drv_s *p_drv = context;
	ntdrv_4ga_t *p_nt_drv = &p_drv->ntdrv;
	nt4ga_stat_t *p_nt4ga_stat = &p_nt_drv->adapter_info.nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;

	const char *const p_adapter_id_str _unused =
		p_nt_drv->adapter_info.mp_adapter_id_str;

	NT_LOG(DBG, ETHDEV, "%s: %s: begin\n", p_adapter_id_str, __func__);

	assert(p_nthw_stat);

	while (!p_drv->ntdrv.b_shutdown) {
		usleep(100 * 100);

		nthw_stat_trigger(p_nthw_stat);

		uint32_t loop = 0;

		while ((!p_drv->ntdrv.b_shutdown) &&
				(*p_nthw_stat->mp_timestamp == (uint64_t)-1)) {
			usleep(1 * 100);

			if (nt_log_is_debug(NT_LOG_MODULE_ETHDEV) &&
					(++loop & 0x3fff) == 0) {
				uint32_t sf_ram_of =
					nthw_rmc_get_status_sf_ram_of(p_nt4ga_stat->mp_nthw_rmc);
				uint32_t descr_fifo_of =
				nthw_rmc_get_status_descr_fifo_of(p_nt4ga_stat->mp_nthw_rmc);

				uint32_t dbg_merge =
					nthw_rmc_get_dbg_merge(p_nt4ga_stat->mp_nthw_rmc);
				uint32_t mac_if_err =
					nthw_rmc_get_mac_if_err(p_nt4ga_stat->mp_nthw_rmc);

				NT_LOG(ERR, ETHDEV, "Statistics DMA frozen\n");
				NT_LOG(ERR, ETHDEV,
				       "SF RAM Overflow     : %08x\n",
				       sf_ram_of);
				NT_LOG(ERR, ETHDEV,
				       "Descr Fifo Overflow : %08x\n",
				       descr_fifo_of);
				NT_LOG(ERR, ETHDEV,
				       "DBG Merge           : %08x\n",
				       dbg_merge);
				NT_LOG(ERR, ETHDEV,
				       "MAC If Errors       : %08x\n",
				       mac_if_err);
			}
		}

		/* Check then collect */
		{
			pthread_mutex_lock(&p_nt_drv->stat_lck);
			nt4ga_stat_collect(&p_nt_drv->adapter_info, p_nt4ga_stat);
			pthread_mutex_unlock(&p_nt_drv->stat_lck);
		}
	}

	NT_LOG(DBG, ETHDEV, "%s: %s: end\n", p_adapter_id_str, __func__);

	return NULL;
}

static struct {
	struct rte_pci_device *vpf_dev;
	struct rte_eth_devargs eth_da;
	int portqueues[MAX_FPGA_VIRTUAL_PORTS_SUPPORTED];
	uint16_t pf_backer_port_id;
} rep;

static int nthw_pci_dev_init(struct rte_pci_device *pci_dev)
{
	int res;
	struct drv_s *p_drv;
	ntdrv_4ga_t *p_nt_drv;
	fpga_info_t *fpga_info;

	hw_info_t *p_hw_info _unused;
	uint32_t n_port_mask = -1; /* All ports enabled by default */
	uint32_t nb_rx_queues = 1;
	uint32_t nb_tx_queues = 1;
	uint32_t exception_path = 0;
	struct flow_queue_id_s queue_ids[FLOW_MAX_QUEUES];
	lag_config_t *lag_config = NULL;
	int n_phy_ports;
	struct port_link_speed pls_mbps[NUM_ADAPTER_PORTS_MAX] = {{ 0 }};
	int num_port_speeds = 0;
	enum flow_eth_dev_profile profile;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] enter\n", __func__, __FILE__, __LINE__);
	NT_LOG(DBG, ETHDEV, "Dev %s PF #%i Init : %02x:%02x:%i\n",
	       pci_dev->name, pci_dev->addr.function, pci_dev->addr.bus,
	       pci_dev->addr.devid, pci_dev->addr.function);

	/*
	 * Process options/arguments
	 */
	if (pci_dev->device.devargs && pci_dev->device.devargs->args) {
		int kvargs_count;
		struct rte_kvargs *kvlist = rte_kvargs_parse(pci_dev->device.devargs->args,
							     valid_arguments);
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

				printf("NTNIC supported arguments:\n\n");
				for (i = 0; i < RTE_DIM(valid_arguments); i++) {
					if (valid_arguments[i] == NULL)
						break;
					printf("  %s\n", valid_arguments[i]);
				}
				printf("\n");
				exit(0);
			}
		}

		/*
		 * Argument: supported-fpgas=list|verbose
		 * NOTE: this argument/option check should be the first as it will stop
		 * execution after producing its output
		 */
		{
			const char *val_str;

			val_str = rte_kvargs_get(kvlist,
						 ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG);
			if (val_str) {
				int detail_level = 0;
				nt_fpga_mgr_t *p_fpga_mgr = NULL;

				if (strcmp(val_str, "list") == 0) {
					detail_level = 0;
				} else if (strcmp(val_str, "verbose") == 0) {
					detail_level = 1;
				} else {
					NT_LOG(ERR, ETHDEV,
					       "%s: argument '%s': '%s': unsupported value\n",
					       __func__,
					       ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG,
					       val_str);
					exit(1);
				}
				/* Produce fpgamgr output and exit hard */
				p_fpga_mgr = fpga_mgr_new();
				if (p_fpga_mgr) {
					fpga_mgr_init(p_fpga_mgr);
					fpga_mgr_show(p_fpga_mgr, stdout,
						     detail_level);
					fpga_mgr_delete(p_fpga_mgr);
					p_fpga_mgr = NULL;
				} else {
					NT_LOG(ERR, ETHDEV,
					       "%s: %s cannot complete\n",
					       __func__,
					       ETH_DEV_NTNIC_SUPPORTED_FPGAS_ARG);
					exit(1);
				}
				exit(0);
			}
		}

		/* link_speed options/argument only applicable for physical ports. */
		num_port_speeds =
			rte_kvargs_count(kvlist, ETH_DEV_NTHW_LINK_SPEED_ARG);
		if (num_port_speeds) {
			assert(num_port_speeds <= NUM_ADAPTER_PORTS_MAX);
			void *pls_mbps_ptr = &pls_mbps[0];

			res = rte_kvargs_process(kvlist,
						 ETH_DEV_NTHW_LINK_SPEED_ARG,
						 &string_to_port_link_speed,
						 &pls_mbps_ptr);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with port link speed command "
				       "line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			for (int i = 0; i < num_port_speeds; ++i) {
				int pid = pls_mbps[i].port_id;

				int lspeed _unused = pls_mbps[i].link_speed;

				NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%d.%d\n",
				       __func__, ETH_DEV_NTHW_LINK_SPEED_ARG,
				       pid, lspeed);
				if (pls_mbps[i].port_id >=
						NUM_ADAPTER_PORTS_MAX) {
					NT_LOG(ERR, ETHDEV,
					       "%s: problem with port link speed command line "
					       "arguments: port id should be 0 to %d, got %d\n",
					       __func__, NUM_ADAPTER_PORTS_MAX,
					       pid);
					return -1;
				}
			}
		}

		/*
		 * portmask option/argument
		 * It is intentional that portmask is only used to decide if DPDK eth_dev
		 * should be created for testing we would still keep the nthw subsystems
		 * running for all interfaces
		 */
		kvargs_count =
			rte_kvargs_count(kvlist, ETH_DEV_NTHW_PORTMASK_ARG);
		if (kvargs_count) {
			assert(kvargs_count == 1);
			res = rte_kvargs_process(kvlist,
						 ETH_DEV_NTHW_PORTMASK_ARG,
						 &string_to_u32, &n_port_mask);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with command line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%u\n", __func__,
			       ETH_DEV_NTHW_PORTMASK_ARG, n_port_mask);
		}

		/*
		 * rxq option/argument
		 * The number of rxq (hostbuffers) allocated in memory.
		 * Default is 32 RX Hostbuffers
		 */
		kvargs_count =
			rte_kvargs_count(kvlist, ETH_DEV_NTHW_RXQUEUES_ARG);
		if (kvargs_count) {
			assert(kvargs_count == 1);
			res = rte_kvargs_process(kvlist,
						 ETH_DEV_NTHW_RXQUEUES_ARG,
						 &string_to_u32, &nb_rx_queues);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with command line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%u\n", __func__,
			       ETH_DEV_NTHW_RXQUEUES_ARG, nb_rx_queues);
		}

		/*
		 * txq option/argument
		 * The number of txq (hostbuffers) allocated in memory.
		 * Default is 32 TX Hostbuffers
		 */
		kvargs_count =
			rte_kvargs_count(kvlist, ETH_DEV_NTHW_TXQUEUES_ARG);
		if (kvargs_count) {
			assert(kvargs_count == 1);
			res = rte_kvargs_process(kvlist,
						 ETH_DEV_NTHW_TXQUEUES_ARG,
						 &string_to_u32, &nb_tx_queues);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with command line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%u\n", __func__,
			       ETH_DEV_NTHW_TXQUEUES_ARG, nb_tx_queues);
		}

		kvargs_count = rte_kvargs_count(kvlist, ETH_NTNIC_LAG_MODE_ARG);
		if (kvargs_count) {
			lag_config = (lag_config_t *)rte_zmalloc(NULL, sizeof(lag_config_t), 0);
			if (lag_config == NULL) {
				NT_LOG(ERR, ETHDEV,
				       "Failed to alloc lag_config data\n");
				return -1;
			}
			assert(kvargs_count == 1);
			res = rte_kvargs_process(kvlist, ETH_NTNIC_LAG_MODE_ARG,
						 &string_to_u32,
						 &lag_config->mode);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with command line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%u\n", __func__,
			       ETH_NTNIC_LAG_MODE_ARG, nb_tx_queues);
			lag_active = 1;
		}

		kvargs_count = rte_kvargs_count(kvlist,
						ETH_DEV_NTHW_EXCEPTION_PATH_ARG);
		if (kvargs_count) {
			assert(kvargs_count == 1);
			res = rte_kvargs_process(kvlist,
						 ETH_DEV_NTHW_EXCEPTION_PATH_ARG,
						 &string_to_u32, &exception_path);
			if (res < 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: problem with command line arguments: res=%d\n",
				       __func__, res);
				return -1;
			}
			NT_LOG(DBG, ETHDEV, "%s: devargs: %s=%u\n", __func__,
			       ETH_DEV_NTHW_EXCEPTION_PATH_ARG, exception_path);
		}

		if (lag_active && lag_config) {
			switch (lag_config->mode) {
			case BONDING_MODE_ACTIVE_BACKUP:
				NT_LOG(DBG, ETHDEV,
				       "Active / Backup LAG mode\n");
				kvargs_count = rte_kvargs_count(kvlist,
								ETH_NTNIC_LAG_PRIMARY_ARG);
				if (kvargs_count) {
					assert(kvargs_count == 1);
					res = rte_kvargs_process(kvlist,
								 ETH_NTNIC_LAG_PRIMARY_ARG,
								 &string_to_u32,
								 &lag_config->primary_port);
					if (res < 0) {
						NT_LOG(ERR, ETHDEV,
						       "%s: problem with command line "
						       "arguments: res=%d\n",
						       __func__, res);
						return -1;
					}
					NT_LOG(DBG, ETHDEV,
					       "%s: devargs: %s=%u\n", __func__,
					       ETH_NTNIC_LAG_MODE_ARG,
					       nb_tx_queues);
				} else {
					NT_LOG(ERR, ETHDEV,
					       "LAG must define a primary port\n");
					return -1;
				}

				kvargs_count = rte_kvargs_count(kvlist,
								ETH_NTNIC_LAG_BACKUP_ARG);
				if (kvargs_count) {
					assert(kvargs_count == 1);
					res = rte_kvargs_process(kvlist,
								 ETH_NTNIC_LAG_BACKUP_ARG,
								 &string_to_u32,
								 &lag_config->backup_port);
					if (res != 0) {
						NT_LOG(ERR, ETHDEV,
						       "%s: problem with command line "
						       "arguments: res=%d\n",
						       __func__, res);
						return -1;
					}
					NT_LOG(DBG, ETHDEV,
					       "%s: devargs: %s=%u\n", __func__,
					       ETH_NTNIC_LAG_MODE_ARG,
					       nb_tx_queues);
				} else {
					NT_LOG(ERR, ETHDEV,
					       "LAG must define a backup port\n");
					return -1;
				}
				break;

			case BONDING_MODE_8023AD:
				NT_LOG(DBG, ETHDEV,
				       "Active / Active LAG mode\n");
				lag_config->primary_port = 0;
				lag_config->backup_port = 0;
				break;

			default:
				NT_LOG(ERR, ETHDEV, "Unsupported LAG mode\n");
				return -1;
			}
		}

		rte_kvargs_free(kvlist);
	}

	/* parse representor args */
	if (setup_virtual_pf_representor_base(pci_dev) == -1) {
		NT_LOG(ERR, ETHDEV,
		       "%s: setup_virtual_pf_representor_base error %d (%s:%u)\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), -1, __func__,
		       __LINE__);
		return -1;
	}

	/* alloc */
	p_drv = rte_zmalloc_socket(pci_dev->name, sizeof(struct drv_s),
				  RTE_CACHE_LINE_SIZE,
				  pci_dev->device.numa_node);
	if (!p_drv) {
		NT_LOG(ERR, ETHDEV, "%s: error %d (%s:%u)\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), -1, __func__,
		       __LINE__);
		return -1;
	}

	/* Setup VFIO context */
	int vfio = nt_vfio_setup(pci_dev);

	if (vfio < 0) {
		NT_LOG(ERR, ETHDEV, "%s: vfio_setup error %d (%s:%u)\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), -1, __func__,
		       __LINE__);
		rte_free(p_drv);
		return -1;
	}

	p_drv->probe_finished = 0;
	/* context */
	p_nt_drv = &p_drv->ntdrv;
	fpga_info = &p_nt_drv->adapter_info.fpga_info;
	p_hw_info = &p_nt_drv->adapter_info.hw_info;

	p_drv->p_dev = pci_dev;

	/* Set context for NtDrv */
	p_nt_drv->pciident =
		BDF_TO_PCIIDENT(pci_dev->addr.domain, pci_dev->addr.bus,
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
	p_nt_drv->adapter_info.hw_info.pci_sub_vendor_id =
		pci_dev->id.subsystem_vendor_id;
	p_nt_drv->adapter_info.hw_info.pci_sub_device_id =
		pci_dev->id.subsystem_device_id;

	NT_LOG(DBG, ETHDEV,
	       "%s: " PCIIDENT_PRINT_STR " %04X:%04X: %04X:%04X:\n",
	       p_nt_drv->adapter_info.mp_adapter_id_str,
	       PCIIDENT_TO_DOMAIN(p_nt_drv->pciident),
	       PCIIDENT_TO_BUSNR(p_nt_drv->pciident),
	       PCIIDENT_TO_DEVNR(p_nt_drv->pciident),
	       PCIIDENT_TO_FUNCNR(p_nt_drv->pciident),
	       p_nt_drv->adapter_info.hw_info.pci_vendor_id,
	       p_nt_drv->adapter_info.hw_info.pci_device_id,
	       p_nt_drv->adapter_info.hw_info.pci_sub_vendor_id,
	       p_nt_drv->adapter_info.hw_info.pci_sub_device_id);

	p_nt_drv->b_shutdown = false;
	p_nt_drv->adapter_info.pb_shutdown = &p_nt_drv->b_shutdown;

	for (int i = 0; i < num_port_speeds; ++i) {
		struct adapter_info_s *p_adapter_info = &p_nt_drv->adapter_info;
		nt_link_speed_t link_speed =
			convert_link_speed(pls_mbps[i].link_speed);
		nt4ga_port_set_link_speed(p_adapter_info, i, link_speed);
	}

	/* store context */
	store_pdrv(p_drv);

	/* initialize nt4ga nthw fpga module instance in drv */
	int err = nt4ga_adapter_init(&p_nt_drv->adapter_info);

	if (err != 0) {
		NT_LOG(ERR, ETHDEV,
		       "%s: Cannot initialize the adapter instance\n",
		       p_nt_drv->adapter_info.mp_adapter_id_str);
		return -1;
	}

	if (fpga_info->mp_nthw_epp != NULL)
		nthw_eth_dev_ops.mtu_set = dev_set_mtu;

	/* Initialize the queue system */
	if (err == 0) {
		err = nthw_virt_queue_init(fpga_info);
		if (err != 0) {
			NT_LOG(ERR, ETHDEV,
			       "%s: Cannot initialize scatter-gather queues\n",
			       p_nt_drv->adapter_info.mp_adapter_id_str);
		} else {
			NT_LOG(DBG, ETHDEV,
			       "%s: Initialized scatter-gather queues\n",
			       p_nt_drv->adapter_info.mp_adapter_id_str);
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
		       (pci_dev->name[0] ? pci_dev->name : "NA"), __func__,
		       __LINE__);
		return -1;
	}

	if (err == 0) {
		/* mp_adapter_id_str is initialized after nt4ga_adapter_init(p_nt_drv) */
		const char *const p_adapter_id_str _unused =
			p_nt_drv->adapter_info.mp_adapter_id_str;
		NT_LOG(DBG, ETHDEV,
		       "%s: %s: AdapterPCI=" PCIIDENT_PRINT_STR
		       " Hw=0x%02X_rev%d PhyPorts=%d\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), p_adapter_id_str,
		       PCIIDENT_TO_DOMAIN(p_nt_drv->adapter_info.fpga_info.pciident),
		       PCIIDENT_TO_BUSNR(p_nt_drv->adapter_info.fpga_info.pciident),
		       PCIIDENT_TO_DEVNR(p_nt_drv->adapter_info.fpga_info.pciident),
		       PCIIDENT_TO_FUNCNR(p_nt_drv->adapter_info.fpga_info.pciident),
		       p_hw_info->hw_platform_id, fpga_info->nthw_hw_info.hw_id,
		       fpga_info->n_phy_ports);
	} else {
		NT_LOG(ERR, ETHDEV, "%s: error=%d [%s:%u]\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), err, __func__,
		       __LINE__);
		return -1;
	}

	pthread_mutex_init(&p_nt_drv->stat_lck, NULL);
	res = rte_ctrl_thread_create(&p_nt_drv->stat_thread, "nt4ga_stat_thr",
				     NULL, adapter_stat_thread_fn,
				     (void *)p_drv);
	if (res) {
		NT_LOG(ERR, ETHDEV, "%s: error=%d [%s:%u]\n",
		       (pci_dev->name[0] ? pci_dev->name : "NA"), res, __func__,
		       __LINE__);
		return -1;
	}

	if (fpga_info->profile == FPGA_INFO_PROFILE_INLINE) {
		res = rte_ctrl_thread_create(&p_nt_drv->flm_thread,
					     "nt_flm_stat_thr", NULL,
					     adapter_flm_thread_fn,
					     (void *)p_drv);
		if (res) {
			NT_LOG(ERR, ETHDEV, "%s: error=%d [%s:%u]\n",
			       (pci_dev->name[0] ? pci_dev->name : "NA"), res,
			       __func__, __LINE__);
			return -1;
		}
	}

	if (lag_config) {
		/* LAG is activated, so only use port 0 */
		n_phy_ports = 1;
	} else {
		n_phy_ports = fpga_info->n_phy_ports;
	}
	for (int n_intf_no = 0; n_intf_no < n_phy_ports; n_intf_no++) {
		const char *const p_port_id_str _unused =
			p_nt_drv->adapter_info.mp_port_id_str[n_intf_no];
		struct pmd_internals *internals = NULL;
		struct rte_eth_dev *eth_dev;
		char name[32];
		int i;

		if ((1 << n_intf_no) & ~n_port_mask) {
			NT_LOG(DBG, ETHDEV,
			       "%s: %s: interface #%d: skipping due to portmask 0x%02X\n",
			       __func__, p_port_id_str, n_intf_no, n_port_mask);
			continue;
		}

		snprintf(name, sizeof(name), "ntnic%d", n_intf_no);
		NT_LOG(DBG, ETHDEV, "%s: %s: interface #%d: %s: '%s'\n",
		       __func__, p_port_id_str, n_intf_no,
		       (pci_dev->name[0] ? pci_dev->name : "NA"), name);

		internals = rte_zmalloc_socket(name,
					       sizeof(struct pmd_internals),
					       RTE_CACHE_LINE_SIZE,
					       pci_dev->device.numa_node);
		if (!internals) {
			NT_LOG(ERR, ETHDEV, "%s: %s: error=%d [%s:%u]\n",
			       (pci_dev->name[0] ? pci_dev->name : "NA"), name,
			       -1, __func__, __LINE__);
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

		int max_num_queues = (nb_rx_queues > nb_tx_queues) ?
				     nb_rx_queues :
				     nb_tx_queues;
		int start_queue = allocate_queue(max_num_queues);

		if (start_queue < 0)
			return -1;

		for (i = 0; i < (int)max_num_queues; i++) {
			queue_ids[i].id    = i;
			queue_ids[i].hw_id = start_queue + i;

			internals->rxq_scg[i].queue = queue_ids[i];
			/* use same index in Rx and Tx rings */
			internals->txq_scg[i].queue = queue_ids[i];
			internals->rxq_scg[i].enabled = 0;
			internals->txq_scg[i].type = internals->type;
			internals->rxq_scg[i].type = internals->type;
			internals->rxq_scg[i].port = internals->port;
		}

		/* no tx queues - tx data goes out on phy */
		internals->vpq_nb_vq = 0;

		for (i = 0; i < (int)nb_tx_queues; i++) {
			internals->txq_scg[i].port = internals->port;
			internals->txq_scg[i].enabled = 0;
		}

		/* Set MAC address (but only if the MAC address is permitted) */
		if (n_intf_no < fpga_info->nthw_hw_info.vpd_info.mn_mac_addr_count) {
			const uint64_t mac =
				fpga_info->nthw_hw_info.vpd_info.mn_mac_addr_value +
				n_intf_no;
			internals->eth_addrs[0].addr_bytes[0] = (mac >> 40) &
								0xFFu;
			internals->eth_addrs[0].addr_bytes[1] = (mac >> 32) &
								0xFFu;
			internals->eth_addrs[0].addr_bytes[2] = (mac >> 24) &
								0xFFu;
			internals->eth_addrs[0].addr_bytes[3] = (mac >> 16) &
								0xFFu;
			internals->eth_addrs[0].addr_bytes[4] = (mac >> 8) &
								0xFFu;
			internals->eth_addrs[0].addr_bytes[5] = (mac >> 0) &
								0xFFu;
		}

		eth_dev = rte_eth_dev_allocate(name);
		if (!eth_dev) {
			NT_LOG(ERR, ETHDEV, "%s: %s: error=%d [%s:%u]\n",
			       (pci_dev->name[0] ? pci_dev->name : "NA"), name,
			       -1, __func__, __LINE__);
			return -1;
		}

		internals->flw_dev = flow_get_eth_dev(0, n_intf_no,
						      eth_dev->data->port_id,
						      nb_rx_queues,
						      queue_ids,
						      &internals->txq_scg[0].rss_target_id,
						      profile, exception_path);
		if (!internals->flw_dev) {
			NT_LOG(ERR, VDPA,
			       "Error creating port. Resource exhaustion in HW\n");
			return -1;
		}

		NT_LOG(DBG, ETHDEV,
		       "%s: [%s:%u] eth_dev %p, port_id %u, if_index %u\n",
		       __func__, __func__, __LINE__, eth_dev,
		       eth_dev->data->port_id, n_intf_no);

		/* connect structs */
		internals->p_drv = p_drv;
		eth_dev->data->dev_private = internals;
		eth_dev->data->mac_addrs = internals->eth_addrs;

		internals->port_id = eth_dev->data->port_id;

		/*
		 * if representor ports defined on this PF set the assigned port_id as the
		 * backer_port_id for the VFs
		 */
		if (rep.vpf_dev == pci_dev)
			rep.pf_backer_port_id = eth_dev->data->port_id;
		NT_LOG(DBG, ETHDEV,
		       "%s: [%s:%u] Setting up RX functions for SCG\n",
		       __func__, __func__, __LINE__);
		eth_dev->rx_pkt_burst = eth_dev_rx_scg;
		eth_dev->tx_pkt_burst = eth_dev_tx_scg;
		eth_dev->tx_pkt_prepare = NULL;

		struct rte_eth_link pmd_link;

		pmd_link.link_speed = ETH_SPEED_NUM_NONE;
		pmd_link.link_duplex = ETH_LINK_FULL_DUPLEX;
		pmd_link.link_status = ETH_LINK_DOWN;
		pmd_link.link_autoneg = ETH_LINK_AUTONEG;

		eth_dev->device = &pci_dev->device;
		eth_dev->data->dev_link = pmd_link;
		eth_dev->data->numa_node = pci_dev->device.numa_node;
		eth_dev->dev_ops = &nthw_eth_dev_ops;
		eth_dev->state = RTE_ETH_DEV_ATTACHED;

		rte_eth_copy_pci_info(eth_dev, pci_dev);
		eth_dev_pci_specific_init(eth_dev,
					  pci_dev); /* performs rte_eth_copy_pci_info() */

		p_drv->n_eth_dev_init_count++;

		if (lag_config) {
			internals->lag_config = lag_config;
			lag_config->internals = internals;

			/* Always merge port 0 and port 1 on a LAG bond */
			lag_set_port_group(0, (uint32_t)0x01);
			lag_config->lag_thread_active = 1;
			pthread_create(&lag_config->lag_tid, NULL,
				       lag_management, lag_config);
		}

		if (fpga_info->profile == FPGA_INFO_PROFILE_INLINE &&
				internals->flw_dev->ndev->be.tpe.ver >= 2) {
			assert(nthw_eth_dev_ops.mtu_set ==
			       dev_set_mtu_inline ||
			       nthw_eth_dev_ops.mtu_set == NULL);
			nthw_eth_dev_ops.mtu_set = dev_set_mtu_inline;
			dev_set_mtu_inline(eth_dev, MTUINITVAL);
			NT_LOG(DBG, ETHDEV,
			       "%s INLINE MTU supported, tpe version %d\n",
			       __func__, internals->flw_dev->ndev->be.tpe.ver);
		} else {
			NT_LOG(DBG, ETHDEV, "INLINE MTU not supported");
		}
	}

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] leave\n", __func__, __FILE__, __LINE__);

#ifdef NT_TOOLS
	/*
	 * If NtConnect interface must be started for external tools
	 */
	ntconn_adap_register(p_drv);
	ntconn_stat_register(p_drv);

	/* Determine CPU used by the DPDK */
	cpu_set_t cpuset;
	unsigned int lcore_id;

	CPU_ZERO(&cpuset);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_has_role(lcore_id, ROLE_OFF))
			continue;
		rte_cpuset_t lcore_cpuset = rte_lcore_cpuset(lcore_id);

		RTE_CPU_OR(&cpuset, &cpuset, &lcore_cpuset);
	}
	/* Set available CPU for ntconnect */
	RTE_CPU_NOT(&cpuset, &cpuset);

	ntconn_flow_register(p_drv);
	ntconn_meter_register(p_drv);
#ifdef NTCONNECT_TEST
	ntconn_test_register(p_drv);
#endif
	ntconnect_init(NTCONNECT_SOCKET, cpuset);
#endif

	return 0;
}

static int nthw_pci_dev_deinit(struct rte_eth_dev *eth_dev __rte_unused)
{
	int i;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] start\n", __func__, __FILE__, __LINE__);

	struct pmd_internals *internals = pmd_intern_base;

	sleep(1); /* let running threads end Rx and Tx activity */

	while (internals) {
		for (i = internals->nb_tx_queues - 1; i >= 0; i--) {
			nthw_release_managed_tx_virt_queue(internals->txq_scg[i].vq);
			release_hw_virtio_queues(&internals->txq_scg[i].hwq);
		}

		for (i = internals->nb_rx_queues - 1; i >= 0; i--) {
			nthw_release_managed_rx_virt_queue(internals->rxq_scg[i].vq);
			release_hw_virtio_queues(&internals->rxq_scg[i].hwq);
		}
		internals = internals->next;
	}

	for (i = 0; i < MAX_REL_VQS; i++) {
		if (rel_virt_queue[i].vq != NULL) {
			if (rel_virt_queue[i].rx) {
				if (rel_virt_queue[i].managed)
					nthw_release_managed_rx_virt_queue(rel_virt_queue[i].vq);
				else
					nthw_release_rx_virt_queue(rel_virt_queue[i].vq);
			} else {
				if (rel_virt_queue[i].managed)
					nthw_release_managed_tx_virt_queue(rel_virt_queue[i].vq);
				else
					nthw_release_tx_virt_queue(rel_virt_queue[i].vq);
			}
			rel_virt_queue[i].vq = NULL;
		}
	}

	nt_vfio_remove(EXCEPTION_PATH_HID);

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

static void *shutdown_thread(void *arg __rte_unused)
{
	struct rte_eth_dev dummy;

	while (!kill_pmd)
		usleep(100000);

	NT_LOG(DBG, ETHDEV, "%s: Shutting down because of ctrl+C\n", __func__);
	nthw_pci_dev_deinit(&dummy);

	signal(SIGINT, previous_handler);
	raise(SIGINT);

	return NULL;
}

static int init_shutdown(void)
{
	NT_LOG(DBG, ETHDEV, "%s: Starting shutdown handler\n", __func__);
	kill_pmd = 0;
	previous_handler = signal(SIGINT, signal_handler_func_int);
	pthread_create(&shutdown_tid, NULL, shutdown_thread, NULL);

	/*
	 * 1 time calculation of 1 sec stat update rtc cycles to prevent stat poll
	 * flooding by OVS from multiple virtual port threads - no need to be precise
	 */
	uint64_t now_rtc = rte_get_tsc_cycles();

	usleep(10000);
	rte_tsc_freq = 100 * (rte_get_tsc_cycles() - now_rtc);

	return 0;
}

static int nthw_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			  struct rte_pci_device *pci_dev)
{
	int res;

	NT_LOG(DBG, ETHDEV, "%s: [%s:%u] start\n", __func__, __FILE__, __LINE__);

#if defined(DEBUG)
	NT_LOG(DBG, NTHW, "Testing NTHW %u [%s:%u]\n",
	       nt_log_module_logtype[NT_LOG_MODULE_INDEX(NT_LOG_MODULE_NTHW)],
	       __func__, __LINE__);
#endif

	NT_LOG(DBG, ETHDEV, "%s: pcidev: name: '%s'\n", __func__,
	       pci_dev->name);
	NT_LOG(DBG, ETHDEV, "%s: devargs: name: '%s'\n", __func__,
	       pci_dev->device.name);
	if (pci_dev->device.devargs) {
		NT_LOG(DBG, ETHDEV, "%s: devargs: args: '%s'\n", __func__,
		       (pci_dev->device.devargs->args ?
			pci_dev->device.devargs->args :
			"NULL"));
		NT_LOG(DBG, ETHDEV, "%s: devargs: data: '%s'\n", __func__,
		       (pci_dev->device.devargs->data ?
			pci_dev->device.devargs->data :
			"NULL"));
	}

	const int n_rte_has_pci = rte_eal_has_pci();

	NT_LOG(DBG, ETHDEV, "has_pci=%d\n", n_rte_has_pci);
	if (n_rte_has_pci == 0) {
		NT_LOG(ERR, ETHDEV, "has_pci=%d: this PMD needs hugepages\n",
		       n_rte_has_pci);
		return -1;
	}

	const int n_rte_vfio_no_io_mmu_enabled = rte_vfio_noiommu_is_enabled();

	NT_LOG(DBG, ETHDEV, "vfio_no_iommu_enabled=%d\n",
	       n_rte_vfio_no_io_mmu_enabled);
	if (n_rte_vfio_no_io_mmu_enabled) {
		NT_LOG(ERR, ETHDEV,
		       "vfio_no_iommu_enabled=%d: this PMD needs VFIO IOMMU\n",
		       n_rte_vfio_no_io_mmu_enabled);
		return -1;
	}

	const enum rte_iova_mode n_rte_io_va_mode = rte_eal_iova_mode();

	NT_LOG(DBG, ETHDEV, "iova mode=%d\n", n_rte_io_va_mode);
	if (n_rte_io_va_mode != RTE_IOVA_PA) {
		NT_LOG(WRN, ETHDEV,
		       "iova mode (%d) should be PA for performance reasons\n",
		       n_rte_io_va_mode);
	}

	const int n_rte_has_huge_pages = rte_eal_has_hugepages();

	NT_LOG(DBG, ETHDEV, "has_hugepages=%d\n", n_rte_has_huge_pages);
	if (n_rte_has_huge_pages == 0) {
		NT_LOG(ERR, ETHDEV,
		       "has_hugepages=%d: this PMD needs hugepages\n",
		       n_rte_has_huge_pages);
		return -1;
	}

	NT_LOG(DBG, ETHDEV,
	       "busid=" PCI_PRI_FMT
	       " pciid=%04x:%04x_%04x:%04x locstr=%s @ numanode=%d: drv=%s drvalias=%s\n",
	       pci_dev->addr.domain, pci_dev->addr.bus, pci_dev->addr.devid,
	       pci_dev->addr.function, pci_dev->id.vendor_id,
	       pci_dev->id.device_id, pci_dev->id.subsystem_vendor_id,
	       pci_dev->id.subsystem_device_id,
	       pci_dev->name[0] ? pci_dev->name : "NA", /* locstr */
	       pci_dev->device.numa_node,
	       pci_dev->driver->driver.name ? pci_dev->driver->driver.name :
	       "NA",
	       pci_dev->driver->driver.alias ? pci_dev->driver->driver.alias :
	       "NA");

	if (pci_dev->id.vendor_id == NT_HW_PCI_VENDOR_ID) {
		if (pci_dev->id.device_id == NT_HW_PCI_DEVICE_ID_NT200A01 ||
				pci_dev->id.device_id == NT_HW_PCI_DEVICE_ID_NT50B01) {
			if (pci_dev->id.subsystem_device_id != 0x01) {
				NT_LOG(DBG, ETHDEV,
				       "%s: PCIe bifurcation - secondary endpoint "
				       "found - leaving probe\n",
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

__rte_format_printf(3, 0)
static int nt_log_log_impl(enum nt_log_level level, uint32_t module,
			   const char *format, va_list args)
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

	rte_module =
		(module >= NT_LOG_MODULE_GENERAL &&
		 module < NT_LOG_MODULE_END) ?
		(uint32_t)nt_log_module_logtype[NT_LOG_MODULE_INDEX(module)] : module;

	return (int)rte_vlog(rte_level, rte_module, format, args);
}

static int nt_log_is_debug_impl(uint32_t module)
{
	if (module < NT_LOG_MODULE_GENERAL || module >= NT_LOG_MODULE_END)
		return -1;
	int index = NT_LOG_MODULE_INDEX(module);

	return rte_log_get_level(nt_log_module_logtype[index]) == RTE_LOG_DEBUG;
}

RTE_INIT(ntnic_rte_init); /* must go before function */

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

/*
 * VF and VDPA code
 */
int register_release_virtqueue_info(struct nthw_virt_queue *vq, int rx,
				    int managed)
{
	int i;

	for (i = 0; i < MAX_REL_VQS; i++) {
		if (rel_virt_queue[i].vq == NULL) {
			rel_virt_queue[i].vq = vq;
			rel_virt_queue[i].rx = rx;
			rel_virt_queue[i].managed = managed;
			return 0;
		}
	}
	return -1;
}

int de_register_release_virtqueue_info(struct nthw_virt_queue *vq)
{
	int i;

	for (i = 0; i < MAX_REL_VQS; i++) {
		if (rel_virt_queue[i].vq == vq) {
			rel_virt_queue[i].vq = NULL;
			return 0;
		}
	}
	return -1;
}

struct pmd_internals *vp_vhid_instance_ready(int vhid)
{
	struct pmd_internals *intern = pmd_intern_base;

	while (intern) {
		if (intern->vhid == vhid)
			return intern;
		intern = intern->next;
	}
	return NULL;
}

struct pmd_internals *vp_path_instance_ready(const char *path)
{
	struct pmd_internals *intern = pmd_intern_base;

	while (intern) {
		printf("Searching for path: \"%s\" == \"%s\" (%d)\n",
		       intern->vhost_path, path,
		       strcmp(intern->vhost_path, path));
		if (strcmp(intern->vhost_path, path) == 0)
			return intern;
		intern = intern->next;
	}
	return NULL;
}

static void read_port_queues_mapping(char *str, int *portq)
{
	int len;
	char *tok;

	while (*str != '[' && *str != '\0')
		str++;

	if (*str == '\0')
		return;
	str++;
	len = strlen(str);
	char *str_e = &str[len];

	while (*str_e != ']' && str_e != str)
		str_e--;
	if (*str_e != ']')
		return;
	*str_e = '\0';

	tok = strtok(str, ",;");
	while (tok) {
		char *ch = strchr(tok, ':');

		if (ch) {
			*ch = '\0';
			int port = atoi(tok);
			int nvq = atoi(ch + 1);

			if (port >= 0 &&
					port < MAX_FPGA_VIRTUAL_PORTS_SUPPORTED &&
					nvq > 0 && nvq < MAX_QUEUES)
				portq[port] = nvq;
		}

		tok = strtok(NULL, ",;");
	}
}

int setup_virtual_pf_representor_base(struct rte_pci_device *dev)
{
	struct rte_eth_devargs eth_da;

	eth_da.nb_representor_ports = 0U;
	if (dev->device.devargs && dev->device.devargs->args) {
		char *ch = strstr(dev->device.devargs->args, "portqueues");

		if (ch) {
			read_port_queues_mapping(ch, rep.portqueues);
			/*
			 * Remove this extension. DPDK cannot read representor=[x] if added
			 * parameter to the end
			 */
			 *ch = '\0';
		}

		int err = rte_eth_devargs_parse(dev->device.devargs->args,
						&eth_da);
		if (err) {
			rte_errno = -err;
			NT_LOG(ERR, VDPA,
			       "failed to process device arguments: %s",
			       strerror(rte_errno));
			return -1;
		}

		if (eth_da.nb_representor_ports) {
			rep.vpf_dev = dev;
			rep.eth_da = eth_da;
		}
	}
	/* Will be set later when assigned to this PF */
	rep.pf_backer_port_id = RTE_MAX_ETHPORTS;
	return eth_da.nb_representor_ports;
}

static inline struct rte_eth_dev *
rte_eth_vdev_allocate(struct rte_pci_device *dev, const char *name,
		       size_t private_data_size, int *n_vq)
{
	static int next_rep_p;
	struct rte_eth_dev *eth_dev = NULL;

	eth_dev = rte_eth_dev_allocate(name);
	if (!eth_dev)
		return NULL;

	NT_LOG(DBG, VDPA, "%s: [%s:%u] eth_dev %p, port_id %u\n", __func__,
	       __func__, __LINE__, eth_dev, eth_dev->data->port_id);

	if (private_data_size) {
		eth_dev->data->dev_private = rte_zmalloc_socket(name, private_data_size,
								RTE_CACHE_LINE_SIZE,
								dev->device.numa_node);
		if (!eth_dev->data->dev_private) {
			rte_eth_dev_release_port(eth_dev);
			return NULL;
		}
	}

	eth_dev->intr_handle = NULL;
	eth_dev->data->numa_node = dev->device.numa_node;
	eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;

	if (rep.vpf_dev && rep.eth_da.nb_representor_ports > next_rep_p) {
		eth_dev->data->representor_id =
			rep.eth_da.representor_ports[next_rep_p++];
		eth_dev->device = &rep.vpf_dev->device;
		eth_dev->data->backer_port_id = rep.pf_backer_port_id;
	} else {
		eth_dev->data->representor_id = nt_vfio_vf_num(dev);
		eth_dev->device = &dev->device;
	}

	if (rep.portqueues[eth_dev->data->representor_id])
		*n_vq = rep.portqueues[eth_dev->data->representor_id];

	else
		*n_vq = 1;
	return eth_dev;
}

static inline const char *
rte_vdev_device_name(const struct rte_pci_device *dev)
{
	if (dev && dev->device.name)
		return dev->device.name;
	return NULL;
}

static const char *const valid_args[] = {
#define VP_VLAN_ID "vlan"
	VP_VLAN_ID,
#define VP_SEPARATE_SOCKET "sep"
	VP_SEPARATE_SOCKET, NULL
};

static int rte_pmd_vp_init_internals(struct rte_pci_device *vdev,
				     struct rte_eth_dev **eth_dev)
{
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev_data *data = NULL;
	int i;
	struct rte_eth_link pmd_link;
	int numa_node = vdev->device.numa_node;
	const char *name;
	int n_vq;
	int num_queues;
	uint8_t port;
	uint32_t vlan = 0;
	uint32_t separate_socket = 0;

	enum fpga_info_profile fpga_profile =
		get_fpga_profile_from_pci(vdev->addr);

	name = rte_vdev_device_name(vdev);

	/*
	 * Now do all data allocation - for eth_dev structure
	 * and internal (private) data
	 */

	if (vdev && vdev->device.devargs) {
		struct rte_kvargs *kvlist = NULL;

		kvlist = rte_kvargs_parse(vdev->device.devargs->args,
					  valid_args);
		if (!kvlist) {
			NT_LOG(ERR, VDPA, "error when parsing param");
			goto error;
		}

		if (rte_kvargs_count(kvlist, VP_VLAN_ID) == 1) {
			if (rte_kvargs_process(kvlist, VP_VLAN_ID,
					       &string_to_u32, &vlan) < 0) {
				NT_LOG(ERR, VDPA, "error to parse %s",
				       VP_VLAN_ID);
				goto error;
			}
		}

		if (rte_kvargs_count(kvlist, VP_SEPARATE_SOCKET) == 1) {
			if (rte_kvargs_process(kvlist, VP_SEPARATE_SOCKET,
					       &string_to_u32,
					       &separate_socket) < 0) {
				NT_LOG(ERR, VDPA, "error to parse %s",
				       VP_SEPARATE_SOCKET);
				goto error;
			}
		}
	}

	n_vq = 0;
	*eth_dev =
		rte_eth_vdev_allocate(vdev, name, sizeof(*internals), &n_vq);
	if (*eth_dev == NULL)
		goto error;

	data = rte_zmalloc_socket(name, sizeof(*data), 0, numa_node);
	if (data == NULL)
		goto error;

	NT_LOG(DBG, VDPA, "%s: [%s:%u] eth_dev %p, port_id %u, if_index %u\n",
	       __func__, __func__, __LINE__, *eth_dev,
	       (*eth_dev)->data->port_id, (*eth_dev)->data->representor_id);

	port = (*eth_dev)->data->representor_id;

	if (port < MAX_NTNIC_PORTS || port >= VIRTUAL_TUNNEL_PORT_OFFSET) {
		NT_LOG(ERR, VDPA,
		       "(%i) Creating ntvp-backend ethdev on numa socket %i has invalid representor port\n",
		       port, numa_node);
		return -1;
	}
	NT_LOG(DBG, VDPA,
	       "(%i) Creating ntnic-backend ethdev on numa socket %i\n", port,
	       numa_node);

	/* Build up private dev data */
	internals = (*eth_dev)->data->dev_private;
	internals->pci_dev = vdev;
	if (fpga_profile == FPGA_INFO_PROFILE_VSWITCH) {
		internals->type = PORT_TYPE_VIRTUAL;
		internals->nb_rx_queues = 1;
		internals->nb_tx_queues = 1;
	} else {
		internals->type = PORT_TYPE_OVERRIDE;
		internals->nb_rx_queues = n_vq;
		internals->nb_tx_queues = n_vq;
	}
	internals->p_drv = get_pdrv_from_pci(vdev->addr);

	if (n_vq > MAX_QUEUES) {
		NT_LOG(ERR, VDPA,
		       "Error creating virtual port. Too many rx or tx queues. Max is %i\n",
		       MAX_QUEUES);
		goto error;
	}

	if (n_vq > FLOW_MAX_QUEUES) {
		NT_LOG(ERR, VDPA,
		       "Error creating virtual port. Too many rx or tx queues for NIC. Max reported %i\n",
		       FLOW_MAX_QUEUES);
		goto error;
	}

	/* Initialize HB output dest to none */
	for (i = 0; i < MAX_QUEUES; i++)
		internals->vpq[i].hw_id = -1;

	internals->vhid = -1;
	internals->port = port;
	internals->if_index = port;
	internals->port_id = (*eth_dev)->data->port_id;
	internals->vlan = vlan;

	/*
	 * Create first time all queues in HW
	 */
	struct flow_queue_id_s queue_ids[FLOW_MAX_QUEUES + 1];

	if (fpga_profile == FPGA_INFO_PROFILE_VSWITCH)
		num_queues = n_vq + 1; /* add 1: 0th for exception */
	else
		num_queues = n_vq;

	int start_queue = allocate_queue(num_queues);

	if (start_queue < 0) {
		NT_LOG(ERR, VDPA,
		       "Error creating virtual port. Too many rx queues. Could not allocate %i\n",
		       num_queues);
		goto error;
	}

	int vhid = -1;

	for (i = 0; i < num_queues; i++) {
		queue_ids[i].id    = i; /* 0th is exception queue */
		queue_ids[i].hw_id = start_queue + i;
	}

	if (fpga_profile == FPGA_INFO_PROFILE_VSWITCH) {
		internals->txq_scg[0].rss_target_id = -1;
		internals->flw_dev = flow_get_eth_dev(0, internals->port,
						      internals->port_id, num_queues,
						      queue_ids,
						      &internals->txq_scg[0].rss_target_id,
						      FLOW_ETH_DEV_PROFILE_VSWITCH, 0);
	} else {
		uint16_t in_port = internals->port & 1;
		char name[RTE_ETH_NAME_MAX_LEN];
		struct pmd_internals *main_internals;
		struct rte_eth_dev *eth_dev;
		int i;
		int status;

		/* Get name of in_port */
		status = rte_eth_dev_get_name_by_port(in_port, name);
		if (status != 0) {
			NT_LOG(ERR, VDPA, "Name of port not found");
			goto error;
		}
		NT_LOG(DBG, VDPA, "Name of port %u = %s\n", in_port, name);

		/* Get ether device for in_port */
		eth_dev = rte_eth_dev_get_by_name(name);
		if (eth_dev == NULL) {
			NT_LOG(ERR, VDPA, "Failed to get eth device");
			goto error;
		}

		/* Get internals for in_port */
		main_internals =
			(struct pmd_internals *)eth_dev->data->dev_private;
		NT_LOG(DBG, VDPA, "internals port   %u\n\n",
		       main_internals->port);
		if (main_internals->port != in_port) {
			NT_LOG(ERR, VDPA, "Port did not match");
			goto error;
		}

		/* Get flow device for in_port */
		internals->flw_dev = main_internals->flw_dev;

		for (i = 0; i < num_queues && i < MAX_QUEUES; i++) {
			NT_LOG(DBG, VDPA, "Queue:            %u\n",
			       queue_ids[i].id);
			NT_LOG(DBG, VDPA, "HW ID:            %u\n",
			       queue_ids[i].hw_id);
			if (flow_eth_dev_add_queue(main_internals->flw_dev,
						   &queue_ids[i])) {
				NT_LOG(ERR, VDPA, "Could not add queue");
				goto error;
			}
		}
	}

	if (!internals->flw_dev) {
		NT_LOG(ERR, VDPA,
		       "Error creating virtual port. Resource exhaustion in HW\n");
		goto error;
	}

	char path[128];

	if (!separate_socket) {
		sprintf(path, "%sstdvio%i", DVIO_VHOST_DIR_NAME, port);
	} else {
		sprintf(path, "%sstdvio%i/stdvio%i", DVIO_VHOST_DIR_NAME, port,
			port);
	}

	internals->vpq_nb_vq = n_vq;
	if (fpga_profile == FPGA_INFO_PROFILE_VSWITCH) {
		if (nthw_vdpa_init(vdev, (*eth_dev)->device->name, path,
				   queue_ids[1].hw_id, n_vq, n_vq,
				   internals->port, &vhid)) {
			NT_LOG(ERR, VDPA,
			       "*********** ERROR *********** vDPA RELAY INIT\n");
			goto error;
		}
		for (i = 0; i < n_vq; i++) {
			internals->vpq[i] =
				queue_ids[i + 1]; /* queue 0 is for exception */
		}
	} else {
		if (nthw_vdpa_init(vdev, (*eth_dev)->device->name, path,
				   queue_ids[0].hw_id, n_vq, n_vq,
				   internals->port, &vhid)) {
			NT_LOG(ERR, VDPA,
			       "*********** ERROR *********** vDPA RELAY INIT\n");
			goto error;
		}
		for (i = 0; i < n_vq; i++)
			internals->vpq[i] = queue_ids[i];
	}

	/*
	 * Exception queue for OVS SW path
	 */
	internals->rxq_scg[0].queue = queue_ids[0];
	internals->txq_scg[0].queue =
		queue_ids[0]; /* use same index in Rx and Tx rings */
	internals->rxq_scg[0].enabled = 0;
	internals->txq_scg[0].port = port;

	internals->txq_scg[0].type = internals->type;
	internals->rxq_scg[0].type = internals->type;
	internals->rxq_scg[0].port = internals->port;

	/* Setup pmd_link info */
	pmd_link.link_speed = ETH_SPEED_NUM_NONE;
	pmd_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	pmd_link.link_status = ETH_LINK_DOWN;

	rte_memcpy(data, (*eth_dev)->data, sizeof(*data));
	data->dev_private = internals;
	data->port_id = (*eth_dev)->data->port_id;

	data->nb_rx_queues = 1; /* this is exception */
	data->nb_tx_queues = 1;

	data->dev_link = pmd_link;
	data->mac_addrs = &eth_addr_vp[port - MAX_NTNIC_PORTS];
	data->numa_node = numa_node;

	(*eth_dev)->data = data;
	(*eth_dev)->dev_ops = &nthw_eth_dev_ops;

	if (pmd_intern_base) {
		struct pmd_internals *intern = pmd_intern_base;

		while (intern->next)
			intern = intern->next;
		intern->next = internals;
	} else {
		pmd_intern_base = internals;
	}
	internals->next = NULL;

	__atomic_store_n(&internals->vhid, vhid, __ATOMIC_RELAXED);

	LIST_INIT(&internals->mtr_profiles);
	LIST_INIT(&internals->mtrs);
	return 0;

error:
	if (data)
		rte_free(data);
	if (internals)
		rte_free(internals);
	return -1;
}

/*
 * PORT_TYPE_OVERRIDE cannot receive data through SCG as the queues
 * are going to VF/vDPA
 */
static uint16_t eth_dev_rx_scg_dummy(void *queue __rte_unused,
				     struct rte_mbuf **bufs __rte_unused,
				     uint16_t nb_pkts __rte_unused)
{
	return 0;
}

/*
 * PORT_TYPE_OVERRIDE cannot transmit data through SCG as the queues
 * are coming from VF/vDPA
 */
static uint16_t eth_dev_tx_scg_dummy(void *queue __rte_unused,
				     struct rte_mbuf **bufs __rte_unused,
				     uint16_t nb_pkts __rte_unused)
{
	return 0;
}

int nthw_create_vf_interface_dpdk(struct rte_pci_device *pci_dev)
{
	struct pmd_internals *internals;
	struct rte_eth_dev *eth_dev;

	/* Create virtual function DPDK PCI devices.*/
	if (rte_pmd_vp_init_internals(pci_dev, &eth_dev) < 0)
		return -1;

	internals = (struct pmd_internals *)eth_dev->data->dev_private;

	if (internals->type == PORT_TYPE_OVERRIDE) {
		eth_dev->rx_pkt_burst = eth_dev_rx_scg_dummy;
		eth_dev->tx_pkt_burst = eth_dev_tx_scg_dummy;
	} else {
		eth_dev->rx_pkt_burst = eth_dev_rx_scg;
		eth_dev->tx_pkt_burst = eth_dev_tx_scg;
	}

	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}

int nthw_remove_vf_interface_dpdk(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev = NULL;

	NT_LOG(DBG, VDPA, "Closing ntvp pmd on numa socket %u\n",
	       rte_socket_id());

	if (!pci_dev)
		return -1;

	/* Clean up all vDPA devices */
	nthw_vdpa_close();

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(pci_dev));
	if (eth_dev == NULL)
		return -1;

	rte_free(eth_dev->data->dev_private);
	rte_free(eth_dev->data);

	rte_eth_dev_release_port(eth_dev);

	return 0;
}

/*
 * LAG
 */

#define LAG_PORT0_ONLY (100)
#define LAG_BALANCED_50_50 (50)
#define LAG_PORT1_ONLY (0)

#define LAG_NO_TX (0)
#define LAG_PORT0_INDEX (1)
#define LAG_PORT1_INDEX (2)
#define LAG_HASH_INDEX (3)

static int lag_nop(lag_config_t *config __rte_unused)
{
	return 0;
}

static int lag_balance(lag_config_t *config __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "AA LAG: balanced output\n");
	return lag_set_config(0, FLOW_LAG_SET_BALANCE, 0, LAG_BALANCED_50_50);
}

static int lag_port0_active(lag_config_t *config __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "AA LAG: port 0 output only\n");
	return lag_set_config(0, FLOW_LAG_SET_BALANCE, 0, LAG_PORT0_ONLY);
}

static int lag_port1_active(lag_config_t *config __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "AA LAG: port 1 output only\n");
	return lag_set_config(0, FLOW_LAG_SET_BALANCE, 0, LAG_PORT1_ONLY);
}

static int lag_notx(lag_config_t *config __rte_unused)
{
	NT_LOG(DBG, ETHDEV, "AA LAG: no link\n");

	int retval = 0;

	retval +=
		lag_set_config(0, FLOW_LAG_SET_ALL, LAG_PORT0_INDEX, LAG_NO_TX);
	retval +=
		lag_set_config(0, FLOW_LAG_SET_ALL, LAG_HASH_INDEX, LAG_NO_TX);
	return retval;
}

static bool lag_get_link_status(lag_config_t *lag_config, uint8_t port)
{
	struct adapter_info_s *p_adapter_info =
			&lag_config->internals->p_drv->ntdrv.adapter_info;
	const bool link_up = nt4ga_port_get_link_status(p_adapter_info, port);

	NT_LOG(DBG, ETHDEV, "port %d status: %d\n", port, link_up);
	return link_up;
}

static int lag_get_status(lag_config_t *config)
{
	uint8_t port0 = lag_get_link_status(config, 0);

	uint8_t port1 = lag_get_link_status(config, 1);

	uint8_t status = (port1 << 1 | port0);
	return status;
}

static int lag_activate_primary(lag_config_t *config)
{
	int retval;

	uint8_t port_0_distribution;
	uint8_t blocked_port;

	if (config->primary_port == 0) {
		/* If port 0 is the active primary, then it take 100% of the hash distribution. */
		port_0_distribution = 100;
		blocked_port = LAG_PORT1_INDEX;
	} else {
		/* If port 1 is the active primary, then port 0 take 0% of the hash distribution. */
		port_0_distribution = 0;
		blocked_port = LAG_PORT0_INDEX;
	}

	retval =
		lag_set_config(0, FLOW_LAG_SET_BALANCE, 0, port_0_distribution);

	/* Block Rx on the backup port */
	retval += lag_set_port_block(0, blocked_port);

	return retval;
}

static int lag_activate_backup(lag_config_t *config)
{
	int retval;

	uint8_t port_0_distribution;
	uint8_t blocked_port;

	if (config->backup_port == 0) {
		/* If port 0 is the active backup, then it take 100% of the hash distribution. */
		port_0_distribution = 100;
		blocked_port = LAG_PORT1_INDEX;
	} else {
		/* If port 1 is the active backup, then port 0 take 0% of the hash distribution. */
		port_0_distribution = 0;
		blocked_port = LAG_PORT0_INDEX;
	}

	/* Tx only on the backup port */
	retval =
		lag_set_config(0, FLOW_LAG_SET_BALANCE, 0, port_0_distribution);

	/* Block Rx on the primary port */
	retval += lag_set_port_block(0, blocked_port);

	return retval;
}

static int lag_active_backup(lag_config_t *config)
{
	uint8_t backup_port_active = 0;

	/* Initialize with the primary port active */
	lag_activate_primary(config);

	while (config->lag_thread_active) {
		usleep(500 *
		       1000); /* 500 ms sleep between testing the link status. */

		bool primary_port_status =
			lag_get_link_status(config, config->primary_port);

		if (!primary_port_status) {
			bool backup_port_status =
				lag_get_link_status(config, config->backup_port);
			/* If the backup port has been activated, no need to do more. */
			if (backup_port_active)
				continue;

			/* If the backup port is up, flip to it. */
			if (backup_port_status) {
				NT_LOG(DBG, ETHDEV,
				       "LAG: primary port down => swapping to backup port\n");
				lag_activate_backup(config);
				backup_port_active = 1;
			}
		} else {
			/* If using the backup port and primary come back. */
			if (backup_port_active) {
				NT_LOG(DBG, ETHDEV,
				       "LAG: primary port restored => swapping to primary port\n");
				lag_activate_primary(config);
				backup_port_active = 0;
			} /* Backup is active, while primary is restored. */
		} /* Primary port status */
	}

	return 0;
}

typedef int (*lag_aa_action)(lag_config_t *config);

/* port 0 is LSB and port 1 is MSB */
enum lag_state_e {
	P0DOWN_P1DOWN = 0b00,
	P0UP_P1DOWN = 0b01,
	P0DOWN_P1UP = 0b10,
	P0UP_P1UP = 0b11
};

struct lag_action_s {
	enum lag_state_e src_state;
	enum lag_state_e dst_state;
	lag_aa_action action;
};

struct lag_action_s actions[] = {
	/* No action in same state */
	{ P0UP_P1UP, P0UP_P1UP, lag_nop },
	{ P0UP_P1DOWN, P0UP_P1DOWN, lag_nop },
	{ P0DOWN_P1UP, P0DOWN_P1UP, lag_nop },
	{ P0DOWN_P1DOWN, P0DOWN_P1DOWN, lag_nop },

	/* UU start */
	{ P0UP_P1UP, P0UP_P1DOWN, lag_port0_active },
	{ P0UP_P1UP, P0DOWN_P1UP, lag_port1_active },
	{ P0UP_P1UP, P0DOWN_P1DOWN, lag_notx },

	/* UD start */
	{ P0UP_P1DOWN, P0DOWN_P1DOWN, lag_notx },
	{ P0UP_P1DOWN, P0DOWN_P1UP, lag_port1_active },
	{ P0UP_P1DOWN, P0UP_P1UP, lag_balance },

	/* DU start */
	{ P0DOWN_P1UP, P0DOWN_P1DOWN, lag_notx },
	{ P0DOWN_P1UP, P0UP_P1DOWN, lag_port0_active },
	{ P0DOWN_P1UP, P0UP_P1UP, lag_balance },

	/* DD start */
	{ P0DOWN_P1DOWN, P0DOWN_P1UP, lag_port1_active },
	{ P0DOWN_P1DOWN, P0UP_P1DOWN, lag_port0_active },
	{ P0DOWN_P1DOWN, P0UP_P1UP, lag_balance },
};

static lag_aa_action lookup_action(enum lag_state_e current_state,
				   enum lag_state_e new_state)
{
	uint32_t i;

	for (i = 0; i < sizeof(actions) / sizeof(struct lag_action_s); i++) {
		if (actions[i].src_state == current_state &&
				actions[i].dst_state == new_state)
			return actions[i].action;
	}
	return NULL;
}

static int lag_active_active(lag_config_t *config)
{
	enum lag_state_e ports_status;

	/* Set the initial state to 50/50% */
	enum lag_state_e current_state = P0UP_P1UP;

	lag_balance(config);
	/* No ports are blocked in active/active */
	lag_set_port_block(0, 0);

	lag_aa_action action;

	while (config->lag_thread_active) {
		/* 500 ms sleep between testing the link status. */
		usleep(500 * 1000);

		ports_status = lag_get_status(config);

		action = lookup_action(current_state, ports_status);
		action(config);

		current_state = ports_status;
	}

	return 0;
}

static void *lag_management(void *arg)
{
	lag_config_t *config = (lag_config_t *)arg;

	switch (config->mode) {
	case BONDING_MODE_ACTIVE_BACKUP:
		lag_active_backup(config);
		break;

	case BONDING_MODE_8023AD:
		lag_active_active(config);
		break;

	default:
		fprintf(stderr, "Unsupported NTbond mode\n");
		return NULL;
	}

	return NULL;
}
