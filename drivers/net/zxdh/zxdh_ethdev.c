/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_interrupts.h>
#include <eal_interrupts.h>
#include <ethdev_pci.h>
#include <rte_kvargs.h>
#include <rte_hexdump.h>

struct zxdh_hw_internal zxdh_hw_internal[RTE_MAX_ETHPORTS];
struct zxdh_shared_data *zxdh_shared_data;
const char *MZ_ZXDH_PMD_SHARED_DATA = "zxdh_pmd_shared_data";
rte_spinlock_t zxdh_shared_data_lock = RTE_SPINLOCK_INITIALIZER;
struct zxdh_dtb_shared_data g_dtb_data = {0};

#define ZXDH_PMD_DEFAULT_HOST_FEATURES   \
	(1ULL << ZXDH_NET_F_MRG_RXBUF | \
	 1ULL << ZXDH_NET_F_STATUS    | \
	 1ULL << ZXDH_NET_F_MQ        | \
	 1ULL << ZXDH_F_ANY_LAYOUT    | \
	 1ULL << ZXDH_F_VERSION_1   | \
	 1ULL << ZXDH_F_RING_PACKED | \
	 1ULL << ZXDH_F_IN_ORDER    | \
	 1ULL << ZXDH_F_ORDER_PLATFORM | \
	 1ULL << ZXDH_F_NOTIFICATION_DATA |\
	 1ULL << ZXDH_NET_F_MAC | \
	 1ULL << ZXDH_NET_F_CSUM |\
	 1ULL << ZXDH_NET_F_GUEST_CSUM |\
	 1ULL << ZXDH_NET_F_GUEST_TSO4 |\
	 1ULL << ZXDH_NET_F_GUEST_TSO6 |\
	 1ULL << ZXDH_NET_F_HOST_TSO4 |\
	 1ULL << ZXDH_NET_F_HOST_TSO6 |\
	 1ULL << ZXDH_NET_F_GUEST_UFO |\
	 1ULL << ZXDH_NET_F_HOST_UFO)

#define ZXDH_PMD_DEFAULT_GUEST_FEATURES   \
	(1ULL << ZXDH_NET_F_MRG_RXBUF | \
	 1ULL << ZXDH_NET_F_STATUS    | \
	 1ULL << ZXDH_NET_F_MQ        | \
	 1ULL << ZXDH_F_ANY_LAYOUT    | \
	 1ULL << ZXDH_F_VERSION_1     | \
	 1ULL << ZXDH_F_RING_PACKED   | \
	 1ULL << ZXDH_F_IN_ORDER      | \
	 1ULL << ZXDH_F_NOTIFICATION_DATA | \
	 1ULL << ZXDH_NET_F_MAC)

#define ZXDH_RX_QUEUES_MAX  128U
#define ZXDH_TX_QUEUES_MAX  128U

static unsigned int
log2above(unsigned int v)
{
	unsigned int l;
	unsigned int r;

	for (l = 0, r = 0; (v >> 1); ++l, v >>= 1)
		r |= (v & 1);
	return l + r;
}

static uint16_t zxdh_queue_desc_pre_setup(uint16_t desc)
{
	uint32_t nb_desc = desc;

	if (desc < ZXDH_MIN_QUEUE_DEPTH) {
		PMD_RX_LOG(WARNING,
			"nb_desc(%u) increased number of descriptors to the min queue depth (%u)",
			desc, ZXDH_MIN_QUEUE_DEPTH);
		return ZXDH_MIN_QUEUE_DEPTH;
	}

	if (desc > ZXDH_MAX_QUEUE_DEPTH) {
		PMD_RX_LOG(WARNING,
			"nb_desc(%u) can't be greater than max_rxds (%d), turn to max queue depth",
			desc, ZXDH_MAX_QUEUE_DEPTH);
		return ZXDH_MAX_QUEUE_DEPTH;
	}

	if (!rte_is_power_of_2(desc)) {
		nb_desc = 1 << log2above(desc);
		if (nb_desc > ZXDH_MAX_QUEUE_DEPTH)
			nb_desc = ZXDH_MAX_QUEUE_DEPTH;

		PMD_RX_LOG(WARNING,
			"nb_desc(%u) increased number of descriptors to the next power of two (%d)",
			desc, nb_desc);
	}

	return nb_desc;
}

static int32_t hw_q_depth_handler(const char *key __rte_unused,
				const char *value, void *ret_val)
{
	uint16_t val = 0;
	struct zxdh_hw *hw = ret_val;

	val = strtoul(value, NULL, 0);
	uint16_t q_depth = zxdh_queue_desc_pre_setup(val);

	hw->q_depth = q_depth;
	return 0;
}

static int32_t zxdh_dev_devargs_parse(struct rte_devargs *devargs, struct zxdh_hw *hw)
{
	struct rte_kvargs *kvlist = NULL;
	int32_t ret = 0;

	if (devargs == NULL)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL) {
		PMD_INIT_LOG(ERR, "error when parsing param");
		return 0;
	}

	ret = rte_kvargs_process(kvlist, "q_depth", hw_q_depth_handler, hw);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "Failed to parse q_depth");
		goto exit;
	}
	if (!hw->q_depth)
		hw->q_depth = ZXDH_MIN_QUEUE_DEPTH;

exit:
	rte_kvargs_free(kvlist);
	return ret;
}

static int zxdh_init_shared_data(void)
{
	const struct rte_memzone *mz;
	int ret = 0;

	rte_spinlock_lock(&zxdh_shared_data_lock);
	if (zxdh_shared_data == NULL) {
		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			/* Allocate shared memory. */
			mz = rte_memzone_reserve(MZ_ZXDH_PMD_SHARED_DATA,
					sizeof(*zxdh_shared_data), SOCKET_ID_ANY, 0);
			if (mz == NULL) {
				PMD_INIT_LOG(ERR, "Cannot allocate zxdh shared data");
				ret = -rte_errno;
				goto error;
			}
			zxdh_shared_data = mz->addr;
			memset(zxdh_shared_data, 0, sizeof(*zxdh_shared_data));
			rte_spinlock_init(&zxdh_shared_data->lock);
		} else { /* Lookup allocated shared memory. */
			mz = rte_memzone_lookup(MZ_ZXDH_PMD_SHARED_DATA);
			if (mz == NULL) {
				PMD_INIT_LOG(ERR, "Cannot attach zxdh shared data");
				ret = -rte_errno;
				goto error;
			}
			zxdh_shared_data = mz->addr;
		}
	}

error:
	rte_spinlock_unlock(&zxdh_shared_data_lock);
	return ret;
}

static int zxdh_init_once(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_LOG(DEBUG, "port 0x%x init...", eth_dev->data->port_id);
	if (zxdh_init_shared_data())
		return -rte_errno;

	struct zxdh_shared_data *sd = zxdh_shared_data;
	int ret = 0;

	rte_spinlock_lock(&sd->lock);
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		if (!sd->init_done) {
			++sd->secondary_cnt;
			sd->init_done = true;
		}
		goto out;
	}

	sd->dev_refcnt++;
out:
	rte_spinlock_unlock(&sd->lock);
	return ret;
}

static int32_t zxdh_get_pci_dev_config(struct zxdh_hw *hw)
{
	hw->host_features = zxdh_vtpci_get_features(hw);
	hw->host_features = ZXDH_PMD_DEFAULT_HOST_FEATURES;

	uint64_t guest_features = (uint64_t)ZXDH_PMD_DEFAULT_GUEST_FEATURES;
	uint64_t nego_features = guest_features & hw->host_features;

	hw->guest_features = nego_features;

	if (hw->guest_features & (1ULL << ZXDH_NET_F_MAC)) {
		zxdh_vtpci_read_dev_config(hw, offsetof(struct zxdh_net_config, mac),
				&hw->mac_addr, RTE_ETHER_ADDR_LEN);
		PMD_INIT_LOG(DEBUG, "get dev mac: %02X:%02X:%02X:%02X:%02X:%02X",
				hw->mac_addr[0], hw->mac_addr[1],
				hw->mac_addr[2], hw->mac_addr[3],
				hw->mac_addr[4], hw->mac_addr[5]);
	} else {
		rte_eth_random_addr(&hw->mac_addr[0]);
		PMD_INIT_LOG(DEBUG, "random dev mac: %02X:%02X:%02X:%02X:%02X:%02X",
				hw->mac_addr[0], hw->mac_addr[1],
				hw->mac_addr[2], hw->mac_addr[3],
				hw->mac_addr[4], hw->mac_addr[5]);
	}
	uint32_t max_queue_pairs;

	zxdh_vtpci_read_dev_config(hw, offsetof(struct zxdh_net_config, max_virtqueue_pairs),
			&max_queue_pairs, sizeof(max_queue_pairs));
	PMD_INIT_LOG(DEBUG, "get max queue pairs %u", max_queue_pairs);
	if (max_queue_pairs == 0)
		hw->max_queue_pairs = ZXDH_RX_QUEUES_MAX;
	else
		hw->max_queue_pairs = RTE_MIN(ZXDH_RX_QUEUES_MAX, max_queue_pairs);

	PMD_INIT_LOG(DEBUG, "set max queue pairs %d", hw->max_queue_pairs);

	hw->weak_barriers = !vtpci_with_feature(hw, ZXDH_F_ORDER_PLATFORM);
	return 0;
}

static void zxdh_dev_free_mbufs(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = hw->queue_num;
	uint32_t i, mbuf_num = 0;

	const char *type __rte_unused;
	struct virtqueue *vq = NULL;
	struct rte_mbuf *buf = NULL;
	int32_t queue_type = 0;

	if (hw->vqs == NULL)
		return;

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (!vq)
			continue;

		queue_type = get_queue_type(i);
		if (queue_type == VTNET_RQ)
			type = "rxq";
		else if (queue_type == VTNET_TQ)
			type = "txq";
		else
			continue;

		PMD_INIT_LOG(DEBUG, "Before freeing %s[%d] used and unused buf", type, i);

		while ((buf = zxdh_virtqueue_detach_unused(vq)) != NULL) {
			rte_pktmbuf_free(buf);
			mbuf_num++;
		}

		PMD_INIT_LOG(DEBUG, "After freeing %s[%d] used and unused buf", type, i);
	}

	PMD_INIT_LOG(DEBUG, "%d mbufs freed", mbuf_num);
}

static int32_t zxdh_init_device(struct rte_eth_dev *eth_dev)
{
	struct zxdh_hw *hw = eth_dev->data->dev_private;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	int ret = zxdh_read_pci_caps(pci_dev, hw);

	if (ret) {
		PMD_INIT_LOG(ERR, "port 0x%x pci caps read failed .", hw->vport.vport);
		goto err;
	}
	zxdh_hw_internal[hw->port_id].vtpci_ops = &zxdh_modern_ops;
	zxdh_vtpci_reset(hw);
	zxdh_get_pci_dev_config(hw);
	if (hw->vqs) { /* not reachable? */
		zxdh_dev_free_mbufs(eth_dev);
		ret = zxdh_free_queues(eth_dev);
		if (ret < 0) {
			PMD_INIT_LOG(ERR, "port 0x%x free queue failed.", hw->vport.vport);
			goto err;
		}
	}
	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	hw->speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	hw->duplex = RTE_ETH_LINK_FULL_DUPLEX;

	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac_addr, &eth_dev->data->mac_addrs[0]);
	PMD_INIT_LOG(DEBUG, "PORT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		eth_dev->data->mac_addrs->addr_bytes[0],
		eth_dev->data->mac_addrs->addr_bytes[1],
		eth_dev->data->mac_addrs->addr_bytes[2],
		eth_dev->data->mac_addrs->addr_bytes[3],
		eth_dev->data->mac_addrs->addr_bytes[4],
		eth_dev->data->mac_addrs->addr_bytes[5]);
	/* If host does not support both status and MSI-X then disable LSC */
	if (vtpci_with_feature(hw, ZXDH_NET_F_STATUS) && (hw->use_msix != ZXDH_MSIX_NONE)) {
		eth_dev->data->dev_flags |= RTE_ETH_DEV_INTR_LSC;
		PMD_INIT_LOG(DEBUG, "LSC enable");
	} else {
		eth_dev->data->dev_flags &= ~RTE_ETH_DEV_INTR_LSC;
	}
	return 0;

err:
	PMD_INIT_LOG(ERR, "port %d init device failed", eth_dev->data->port_id);
	return ret;
}


static void zxdh_queues_unbind_intr(struct rte_eth_dev *dev)
{
	PMD_INIT_LOG(INFO, "queue/interrupt unbinding");
	struct zxdh_hw *hw = dev->data->dev_private;
	int32_t i;

	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		VTPCI_OPS(hw)->set_queue_irq(hw, hw->vqs[i * 2], ZXDH_MSI_NO_VECTOR);
		VTPCI_OPS(hw)->set_queue_irq(hw, hw->vqs[i * 2 + 1], ZXDH_MSI_NO_VECTOR);
	}
}

static int32_t zxdh_intr_unmask(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (rte_intr_ack(dev->intr_handle) < 0)
		return -1;

	hw->use_msix = zxdh_vtpci_msix_detect(RTE_ETH_DEV_TO_PCI(dev));

	return 0;
}


static void zxdh_devconf_intr_handler(void *param)
{
	struct rte_eth_dev *dev = param;
	struct zxdh_hw *hw = dev->data->dev_private;
	uint16_t status = 0;
	/* Read interrupt status which clears interrupt */
	uint8_t isr = zxdh_vtpci_isr(hw);

	if (zxdh_intr_unmask(dev) < 0)
		PMD_DRV_LOG(ERR, "interrupt enable failed");
	if (isr & ZXDH_PCI_ISR_CONFIG) {
		/** todo provided later
		 * if (zxdh_dev_link_update(dev, 0) == 0)
		 * rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
		 */

		if (vtpci_with_feature(hw, ZXDH_NET_F_STATUS)) {
			zxdh_vtpci_read_dev_config(hw, offsetof(struct zxdh_net_config, status),
					&status, sizeof(status));
			if (status & ZXDH_NET_S_ANNOUNCE)
				zxdh_notify_peers(dev);
		}
	}
}

/* Interrupt handler triggered by NIC for handling specific interrupt. */
static void zxdh_frompfvf_intr_handler(void *param)
{
	struct rte_eth_dev *dev = param;
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t virt_addr = 0;

	virt_addr = (uint64_t)(hw->bar_addr[ZXDH_BAR0_INDEX] + ZXDH_MSG_CHAN_PFVFSHARE_OFFSET);
	if (hw->is_pf) {
		PMD_INIT_LOG(INFO, "zxdh_pf2vf_intr_handler  PF ");
		zxdh_bar_irq_recv(MSG_CHAN_END_VF, MSG_CHAN_END_PF, virt_addr, dev);
	} else {
		PMD_INIT_LOG(INFO, "zxdh_pf2vf_intr_handler  VF ");
		zxdh_bar_irq_recv(MSG_CHAN_END_PF, MSG_CHAN_END_VF, virt_addr, dev);
	}
}

/* Interrupt handler triggered by NIC for handling specific interrupt. */
static void zxdh_fromriscv_intr_handler(void *param)
{
	struct rte_eth_dev *dev = param;
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t virt_addr = 0;

	virt_addr = (uint64_t)(hw->bar_addr[ZXDH_BAR0_INDEX] + ZXDH_CTRLCH_OFFSET);
	if (hw->is_pf) {
		PMD_INIT_LOG(INFO, "zxdh_risc2pf_intr_handler  PF ");
		zxdh_bar_irq_recv(MSG_CHAN_END_RISC, MSG_CHAN_END_PF, virt_addr, dev);
	} else {
		PMD_INIT_LOG(INFO, "zxdh_riscvf_intr_handler  VF ");
		zxdh_bar_irq_recv(MSG_CHAN_END_RISC, MSG_CHAN_END_VF, virt_addr, dev);
	}
}

static void zxdh_intr_cb_unreg(struct rte_eth_dev *dev)
{
	PMD_INIT_LOG(ERR, "");
	if (dev->data->dev_flags & RTE_ETH_DEV_INTR_LSC)
		rte_intr_callback_unregister(dev->intr_handle, zxdh_devconf_intr_handler, dev);

	struct zxdh_hw *hw = dev->data->dev_private;

	/* register callback to update dev config intr */
	rte_intr_callback_unregister(dev->intr_handle, zxdh_devconf_intr_handler, dev);
	/* Register rsic_v to pf interrupt callback */
	struct rte_intr_handle *tmp = hw->risc_intr +
			(MSIX_FROM_PFVF - ZXDH_MSIX_INTR_MSG_VEC_BASE);

	rte_intr_callback_unregister(tmp, zxdh_frompfvf_intr_handler, dev);
	tmp = hw->risc_intr + (MSIX_FROM_RISCV - ZXDH_MSIX_INTR_MSG_VEC_BASE);
	rte_intr_callback_unregister(tmp, zxdh_fromriscv_intr_handler, dev);
}

static int32_t zxdh_intr_disable(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (!hw->intr_enabled)
		return 0;

	zxdh_intr_cb_unreg(dev);
	if (rte_intr_disable(dev->intr_handle) < 0)
		return -1;

	hw->intr_enabled = 0;
	return 0;
}

static int32_t zxdh_intr_release(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (dev->data->dev_flags & RTE_ETH_DEV_INTR_LSC)
		VTPCI_OPS(hw)->set_config_irq(hw, ZXDH_MSI_NO_VECTOR);

	zxdh_queues_unbind_intr(dev);
	zxdh_intr_disable(dev);

	rte_intr_efd_disable(dev->intr_handle);
	rte_intr_vec_list_free(dev->intr_handle);
	rte_free(hw->risc_intr);
	hw->risc_intr = NULL;
	rte_free(hw->dtb_intr);
	hw->dtb_intr = NULL;
	return 0;
}

static int32_t zxdh_setup_risc_interrupts(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint8_t i;

	if (!hw->risc_intr) {
		PMD_INIT_LOG(ERR, " to allocate risc_intr");
		hw->risc_intr = rte_zmalloc("risc_intr",
			ZXDH_MSIX_INTR_MSG_VEC_NUM * sizeof(struct rte_intr_handle), 0);
		if (hw->risc_intr == NULL) {
			PMD_INIT_LOG(ERR, "Failed to allocate risc_intr");
			return -ENOMEM;
		}
	}

	for (i = 0; i < ZXDH_MSIX_INTR_MSG_VEC_NUM; i++) {
		if (dev->intr_handle->efds[i] < 0) {
			PMD_INIT_LOG(ERR, "[%u]risc interrupt fd is invalid", i);
			rte_free(hw->risc_intr);
			hw->risc_intr = NULL;
			return -1;
		}

		struct rte_intr_handle *intr_handle = hw->risc_intr + i;

		intr_handle->fd = dev->intr_handle->efds[i];
		intr_handle->type = dev->intr_handle->type;
	}

	return 0;
}

static int32_t zxdh_setup_dtb_interrupts(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (!hw->dtb_intr) {
		hw->dtb_intr = rte_zmalloc("dtb_intr", sizeof(struct rte_intr_handle), 0);
		if (hw->dtb_intr == NULL) {
			PMD_INIT_LOG(ERR, "Failed to allocate dtb_intr");
			return -ENOMEM;
		}
	}

	if (dev->intr_handle->efds[ZXDH_MSIX_INTR_DTB_VEC - 1] < 0) {
		PMD_INIT_LOG(ERR, "[%d]dtb interrupt fd is invalid", ZXDH_MSIX_INTR_DTB_VEC - 1);
		rte_free(hw->dtb_intr);
		hw->dtb_intr = NULL;
		return -1;
	}
	hw->dtb_intr->fd = dev->intr_handle->efds[ZXDH_MSIX_INTR_DTB_VEC - 1];
	hw->dtb_intr->type = dev->intr_handle->type;
	return 0;
}

static int32_t zxdh_queues_bind_intr(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	int32_t i;
	uint16_t vec;

	if (!dev->data->dev_conf.intr_conf.rxq) {
		PMD_INIT_LOG(INFO, "queue/interrupt mask, nb_rx_queues %u",
				dev->data->nb_rx_queues);
		for (i = 0; i < dev->data->nb_rx_queues; ++i) {
			vec = VTPCI_OPS(hw)->set_queue_irq(hw,
					hw->vqs[i * 2], ZXDH_MSI_NO_VECTOR);
			PMD_INIT_LOG(INFO, "vq%d irq set 0x%x, get 0x%x",
					i * 2, ZXDH_MSI_NO_VECTOR, vec);
		}
	} else {
		PMD_INIT_LOG(DEBUG, "queue/interrupt binding, nb_rx_queues %u",
				dev->data->nb_rx_queues);
		for (i = 0; i < dev->data->nb_rx_queues; ++i) {
			vec = VTPCI_OPS(hw)->set_queue_irq(hw,
					hw->vqs[i * 2], i + ZXDH_QUE_INTR_VEC_BASE);
			PMD_INIT_LOG(INFO, "vq%d irq set %d, get %d",
					i * 2, i + ZXDH_QUE_INTR_VEC_BASE, vec);
		}
	}
	/* mask all txq intr */
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		vec = VTPCI_OPS(hw)->set_queue_irq(hw,
				hw->vqs[(i * 2) + 1], ZXDH_MSI_NO_VECTOR);
		PMD_INIT_LOG(INFO, "vq%d irq set 0x%x, get 0x%x",
				(i * 2) + 1, ZXDH_MSI_NO_VECTOR, vec);
	}
	return 0;
}

int32_t zxdh_dev_pause(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	rte_spinlock_lock(&hw->state_lock);

	if (hw->started == 0) {
		/* Device is just stopped. */
		rte_spinlock_unlock(&hw->state_lock);
		return -1;
	}
	hw->started = 0;
	hw->admin_status = 0;
	/*
	 * Prevent the worker threads from touching queues to avoid contention,
	 * 1 ms should be enough for the ongoing Tx function to finish.
	 */
	rte_delay_ms(1);
	return 0;
}

/*
 * Recover hw state to let the worker threads continue.
 */
void zxdh_dev_resume(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	hw->started = 1;
	hw->admin_status = 1;
	rte_spinlock_unlock(&hw->state_lock);
}

/*
 * Should be called only after device is paused.
 */
int32_t zxdh_inject_pkts(struct rte_eth_dev *dev, struct rte_mbuf **tx_pkts, int32_t nb_pkts)
{
	struct zxdh_hw	*hw   = dev->data->dev_private;
	struct virtnet_tx *txvq = dev->data->tx_queues[0];
	int32_t ret = 0;

	hw->inject_pkts = tx_pkts;
	ret = dev->tx_pkt_burst(txvq, tx_pkts, nb_pkts);
	hw->inject_pkts = NULL;

	return ret;
}

void zxdh_notify_peers(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct virtnet_rx *rxvq = NULL;
	struct rte_mbuf *rarp_mbuf = NULL;

	if (!dev->data->rx_queues)
		return;

	rxvq = dev->data->rx_queues[0];
	if (!rxvq)
		return;

	rarp_mbuf = rte_net_make_rarp_packet(rxvq->mpool, (struct rte_ether_addr *)hw->mac_addr);
	if (rarp_mbuf == NULL) {
		PMD_DRV_LOG(ERR, "failed to make RARP packet.");
		return;
	}

	/* If virtio port just stopped, no need to send RARP */
	if (zxdh_dev_pause(dev) < 0) {
		rte_pktmbuf_free(rarp_mbuf);
		return;
	}

	zxdh_inject_pkts(dev, &rarp_mbuf, 1);
	zxdh_dev_resume(dev);
}

static void zxdh_intr_cb_reg(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (dev->data->dev_flags & RTE_ETH_DEV_INTR_LSC)
		rte_intr_callback_unregister(dev->intr_handle, zxdh_devconf_intr_handler, dev);

	/* register callback to update dev config intr */
	rte_intr_callback_register(dev->intr_handle, zxdh_devconf_intr_handler, dev);
	/* Register rsic_v to pf interrupt callback */
	struct rte_intr_handle *tmp = hw->risc_intr +
			(MSIX_FROM_PFVF - ZXDH_MSIX_INTR_MSG_VEC_BASE);

	rte_intr_callback_register(tmp, zxdh_frompfvf_intr_handler, dev);

	tmp = hw->risc_intr + (MSIX_FROM_RISCV - ZXDH_MSIX_INTR_MSG_VEC_BASE);
	rte_intr_callback_register(tmp, zxdh_fromriscv_intr_handler, dev);
}

static int32_t zxdh_intr_enable(struct rte_eth_dev *dev)
{
	int ret = 0;
	struct zxdh_hw *hw = dev->data->dev_private;

	if (!hw->intr_enabled) {
		zxdh_intr_cb_reg(dev);
		ret = rte_intr_enable(dev->intr_handle);
		if (unlikely(ret))
			PMD_INIT_LOG(ERR, "Failed to enable %s intr", dev->data->name);

		hw->intr_enabled = 1;
	}
	return ret;
}

static int32_t zxdh_configure_intr(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	int32_t ret = 0;

	if (!rte_intr_cap_multiple(dev->intr_handle)) {
		PMD_INIT_LOG(ERR, "Multiple intr vector not supported");
		return -ENOTSUP;
	}
	zxdh_intr_release(dev);
	uint8_t nb_efd = ZXDH_MSIX_INTR_DTB_VEC_NUM + ZXDH_MSIX_INTR_MSG_VEC_NUM;

	if (dev->data->dev_conf.intr_conf.rxq)
		nb_efd += dev->data->nb_rx_queues;

	if (rte_intr_efd_enable(dev->intr_handle, nb_efd)) {
		PMD_INIT_LOG(ERR, "Fail to create eventfd");
		return -1;
	}

	if (rte_intr_vec_list_alloc(dev->intr_handle, "intr_vec",
					hw->max_queue_pairs + ZXDH_INTR_NONQUE_NUM)) {
		PMD_INIT_LOG(ERR, "Failed to allocate %u rxq vectors",
					hw->max_queue_pairs + ZXDH_INTR_NONQUE_NUM);
		return -ENOMEM;
	}
	PMD_INIT_LOG(INFO, "allocate %u rxq vectors", dev->intr_handle->vec_list_size);
	if (zxdh_setup_risc_interrupts(dev) != 0) {
		PMD_INIT_LOG(ERR, "Error setting up rsic_v interrupts!");
		ret = -1;
		goto free_intr_vec;
	}
	if (zxdh_setup_dtb_interrupts(dev) != 0) {
		PMD_INIT_LOG(ERR, "Error setting up dtb interrupts!");
		ret = -1;
		goto free_intr_vec;
	}

	if (zxdh_queues_bind_intr(dev) < 0) {
		PMD_INIT_LOG(ERR, "Failed to bind queue/interrupt");
		ret = -1;
		goto free_intr_vec;
	}
	/** DO NOT try to remove this! This function will enable msix,
	 * or QEMU will encounter SIGSEGV when DRIVER_OK is sent.
	 * And for legacy devices, this should be done before queue/vec
	 * binding to change the config size from 20 to 24, or
	 * ZXDH_MSI_QUEUE_VECTOR (22) will be ignored.
	 **/
	if (zxdh_intr_enable(dev) < 0) {
		PMD_DRV_LOG(ERR, "interrupt enable failed");
		ret = -1;
		goto free_intr_vec;
	}
	return 0;

free_intr_vec:
	zxdh_intr_release(dev);
	return ret;
}

/* dev_ops for zxdh, bare necessities for basic operation */
static const struct eth_dev_ops zxdh_eth_dev_ops = {
	.dev_configure			 = NULL,
	.dev_start				 = NULL,
	.dev_stop				 = NULL,
	.dev_close				 = NULL,

	.rx_queue_setup			 = NULL,
	.rx_queue_intr_enable	 = NULL,
	.rx_queue_intr_disable	 = NULL,

	.tx_queue_setup			 = NULL,
};


static int32_t set_rxtx_funcs(struct rte_eth_dev *eth_dev)
{
	/** todo later
	 * eth_dev->tx_pkt_prepare = zxdh_xmit_pkts_prepare;
	 */

	struct zxdh_hw *hw = eth_dev->data->dev_private;

	if (!vtpci_packed_queue(hw)) {
		PMD_INIT_LOG(ERR, " port %u not support packed queue", eth_dev->data->port_id);
		return -1;
	}
	if (!vtpci_with_feature(hw, ZXDH_NET_F_MRG_RXBUF)) {
		PMD_INIT_LOG(ERR, " port %u not support rx mergeable", eth_dev->data->port_id);
		return -1;
	}
	/** todo later provided rx/tx
	 * eth_dev->tx_pkt_burst = &zxdh_xmit_pkts_packed;
	 * eth_dev->rx_pkt_burst = &zxdh_recv_mergeable_pkts_packed;
	 */

	return 0;
}

static void zxdh_msg_cb_reg(struct zxdh_hw *hw)
{
	if (hw->is_pf)
		zxdh_bar_chan_msg_recv_register(MODULE_BAR_MSG_TO_PF, pf_recv_bar_msg);
	else
		zxdh_bar_chan_msg_recv_register(MODULE_BAR_MSG_TO_VF, vf_recv_bar_msg);
}

static void zxdh_priv_res_init(struct zxdh_hw *hw)
{
	hw->vlan_fiter = (uint64_t *)rte_malloc("vlan_filter", 64 * sizeof(uint64_t), 1);
	memset(hw->vlan_fiter, 0, 64 * sizeof(uint64_t));
	if (hw->is_pf)
		hw->vfinfo = rte_zmalloc("vfinfo", ZXDH_MAX_VF * sizeof(struct vfinfo), 4);
	else
		hw->vfinfo = NULL;
}

static void set_vfs_pcieid(struct zxdh_hw *hw)
{
	if (hw->pfinfo.vf_nums > ZXDH_MAX_VF) {
		PMD_DRV_LOG(ERR, "vf nums %u out of range", hw->pfinfo.vf_nums);
		return;
	}
	if (hw->vfinfo == NULL) {
		PMD_DRV_LOG(ERR, " vfinfo uninited");
		return;
	}

	PMD_DRV_LOG(INFO, "vf nums %d", hw->pfinfo.vf_nums);
	int vf_idx;

	for (vf_idx = 0; vf_idx < hw->pfinfo.vf_nums; vf_idx++)
		hw->vfinfo[vf_idx].pcieid = VF_PCIE_ID(hw->pcie_id, vf_idx);
}


static void zxdh_sriovinfo_init(struct zxdh_hw *hw)
{
	hw->pfinfo.pcieid = PF_PCIE_ID(hw->pcie_id);

	if (hw->is_pf)
		set_vfs_pcieid(hw);
}

static int zxdh_tbl_entry_offline_destroy(struct zxdh_hw *hw)
{
	int ret = 0;
	uint32_t sdt_no;

	if (!g_dtb_data.init_done)
		return ret;

	if (hw->is_pf) {
		sdt_no = MK_SDT_NO(L2_ENTRY, hw->hash_search_index);
		ret = dpp_dtb_hash_offline_delete(0, g_dtb_data.queueid, sdt_no, 0);
		PMD_DRV_LOG(DEBUG, "%d dpp_dtb_hash_offline_delete sdt_no %d",
				hw->port_id, sdt_no);
		if (ret)
			PMD_DRV_LOG(ERR, "%d dpp_dtb_hash_offline_delete sdt_no %d failed",
					hw->port_id, sdt_no);

		sdt_no = MK_SDT_NO(MC, hw->hash_search_index);
		ret = dpp_dtb_hash_offline_delete(0, g_dtb_data.queueid, sdt_no, 0);
		PMD_DRV_LOG(DEBUG, "%d dpp_dtb_hash_offline_delete sdt_no %d",
				hw->port_id, sdt_no);
		if (ret)
			PMD_DRV_LOG(ERR, "%d dpp_dtb_hash_offline_delete sdt_no %d failed",
				hw->port_id, sdt_no);
	}
	return ret;
}

static inline int zxdh_dtb_dump_res_init(struct zxdh_hw *hw __rte_unused,
			DPP_DEV_INIT_CTRL_T *dpp_ctrl)
{
	int ret = 0;
	int i;

	struct zxdh_dtb_bulk_dump_info dtb_dump_baseres[] = {
	/* eram */
	{"zxdh_sdt_vport_att_table", ZXDH_TBL_ERAM_DUMP_SIZE, ZXDH_SDT_VPORT_ATT_TABLE, NULL},
	{"zxdh_sdt_panel_att_table", ZXDH_TBL_ERAM_DUMP_SIZE, ZXDH_SDT_PANEL_ATT_TABLE, NULL},
	{"zxdh_sdt_rss_att_table", ZXDH_TBL_ERAM_DUMP_SIZE, ZXDH_SDT_RSS_ATT_TABLE, NULL},
	{"zxdh_sdt_vlan_att_table", ZXDH_TBL_ERAM_DUMP_SIZE, ZXDH_SDT_VLAN_ATT_TABLE, NULL},
	/* hash */
	{"zxdh_sdt_l2_entry_table0", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_L2_ENTRY_TABLE0, NULL},
	{"zxdh_sdt_l2_entry_table1", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_L2_ENTRY_TABLE1, NULL},
	{"zxdh_sdt_l2_entry_table2", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_L2_ENTRY_TABLE2, NULL},
	{"zxdh_sdt_l2_entry_table3", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_L2_ENTRY_TABLE3, NULL},
	{"zxdh_sdt_mc_table0", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_MC_TABLE0, NULL},
	{"zxdh_sdt_mc_table1", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_MC_TABLE1, NULL},
	{"zxdh_sdt_mc_table2", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_MC_TABLE2, NULL},
	{"zxdh_sdt_mc_table3", ZXDH_TBL_ZCAM_DUMP_SIZE, ZXDH_SDT_MC_TABLE3, NULL},
	};
	for (i = 0; i < (int)RTE_DIM(dtb_dump_baseres); i++) {
		struct zxdh_dtb_bulk_dump_info *p = dtb_dump_baseres + i;
		const struct rte_memzone *generic_dump_mz = rte_memzone_reserve_aligned(p->mz_name,
					p->mz_size, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);

		if (generic_dump_mz == NULL) {
			PMD_DRV_LOG(ERR,
				"Cannot alloc mem for dtb tbl bulk dump, mz_name is %s, mz_size is %u",
				p->mz_name, p->mz_size);
			ret = -ENOMEM;
			return ret;
		}
		p->mz = generic_dump_mz;
		dpp_ctrl->dump_addr_info[i].vir_addr = generic_dump_mz->addr_64;
		dpp_ctrl->dump_addr_info[i].phy_addr = generic_dump_mz->iova;
		dpp_ctrl->dump_addr_info[i].sdt_no   = p->sdt_no;
		dpp_ctrl->dump_addr_info[i].size     = p->mz_size;

		g_dtb_data.dtb_table_bulk_dump_mz[dpp_ctrl->dump_sdt_num] = generic_dump_mz;
		dpp_ctrl->dump_sdt_num++;
	}
	return ret;
}

static void dtb_data_res_free(struct zxdh_hw *hw)
{
	struct rte_eth_dev *dev = hw->eth_dev;

	if ((g_dtb_data.init_done) && (g_dtb_data.bind_device == dev))  {
		PMD_DRV_LOG(INFO, "%s g_dtb_data free queue %d",
				dev->data->name, g_dtb_data.queueid);

		int ret = 0;

		ret = dpp_np_online_uninstall(0, dev->data->name, g_dtb_data.queueid);
		if (ret)
			PMD_DRV_LOG(ERR, "%s dpp_np_online_uninstall failed", dev->data->name);

		if (g_dtb_data.dtb_table_conf_mz) {
			rte_memzone_free(g_dtb_data.dtb_table_conf_mz);
			PMD_DRV_LOG(INFO, "%s free  dtb_table_conf_mz  ", dev->data->name);
			g_dtb_data.dtb_table_conf_mz = NULL;
		}
		if (g_dtb_data.dtb_table_dump_mz) {
			PMD_DRV_LOG(INFO, "%s free  dtb_table_dump_mz  ", dev->data->name);
			rte_memzone_free(g_dtb_data.dtb_table_dump_mz);
			g_dtb_data.dtb_table_dump_mz = NULL;
		}
		int i;

		for (i = 0; i < ZXDH_MAX_BASE_DTB_TABLE_COUNT; i++) {
			if (g_dtb_data.dtb_table_bulk_dump_mz[i]) {
				rte_memzone_free(g_dtb_data.dtb_table_bulk_dump_mz[i]);
				PMD_DRV_LOG(INFO, "%s free dtb_table_bulk_dump_mz[%d]",
						dev->data->name, i);
				g_dtb_data.dtb_table_bulk_dump_mz[i] = NULL;
			}
		}
		g_dtb_data.init_done = 0;
		g_dtb_data.bind_device = NULL;
	}
	if (zxdh_shared_data != NULL)
		zxdh_shared_data->npsdk_init_done = 0;
}

static inline int npsdk_dtb_res_init(struct rte_eth_dev *dev)
{
	int ret = 0;
	struct zxdh_hw *hw = dev->data->dev_private;

	if (g_dtb_data.init_done) {
		PMD_INIT_LOG(DEBUG, "DTB res already init done, dev %s no need init",
			dev->device->name);
		return 0;
	}
	g_dtb_data.queueid = INVALID_DTBQUE;
	g_dtb_data.bind_device = dev;
	g_dtb_data.dev_refcnt++;
	g_dtb_data.init_done = 1;
	/* */
	DPP_DEV_INIT_CTRL_T *dpp_ctrl = malloc(sizeof(*dpp_ctrl) +
			sizeof(DPP_DTB_ADDR_INFO_T) * 256);

	if (dpp_ctrl == NULL) {
		PMD_INIT_LOG(ERR, "dev %s annot allocate memory for dpp_ctrl", dev->device->name);
		ret = -ENOMEM;
		goto free_res;
	}
	memset(dpp_ctrl, 0, sizeof(*dpp_ctrl) + sizeof(DPP_DTB_ADDR_INFO_T) * 256);

	dpp_ctrl->queue_id = 0xff;
	dpp_ctrl->vport	 = hw->vport.vport;
	dpp_ctrl->vector = ZXDH_MSIX_INTR_DTB_VEC;
	strcpy((char *)dpp_ctrl->port_name, dev->device->name);
	dpp_ctrl->pcie_vir_addr = (uint32_t)hw->bar_addr[0];

	struct bar_offset_params param = {0};
	struct bar_offset_res  res = {0};

	param.pcie_id = hw->pcie_id;
	param.virt_addr = hw->bar_addr[0] + ZXDH_CTRLCH_OFFSET;
	param.type = URI_NP;

	ret = zxdh_get_bar_offset(&param, &res);
	if (ret) {
		PMD_INIT_LOG(ERR, "dev %s get npbar offset failed", dev->device->name);
		goto free_res;
	}
	dpp_ctrl->np_bar_len = res.bar_length;
	dpp_ctrl->np_bar_offset = res.bar_offset;
	if (!g_dtb_data.dtb_table_conf_mz) {
		const struct rte_memzone *conf_mz = rte_memzone_reserve_aligned("zxdh_dtb_table_conf_mz",
				ZXDH_DTB_TABLE_CONF_SIZE, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);

		if (conf_mz == NULL) {
			PMD_INIT_LOG(ERR,
				"dev %s annot allocate memory for dtb table conf",
				dev->device->name);
			ret = -ENOMEM;
			goto free_res;
		}
		dpp_ctrl->down_vir_addr = conf_mz->addr_64;
		dpp_ctrl->down_phy_addr = conf_mz->iova;
		g_dtb_data.dtb_table_conf_mz = conf_mz;
	}
	/* */
	if (!g_dtb_data.dtb_table_dump_mz) {
		const struct rte_memzone *dump_mz = rte_memzone_reserve_aligned("zxdh_dtb_table_dump_mz",
				ZXDH_DTB_TABLE_DUMP_SIZE, SOCKET_ID_ANY, 0, RTE_CACHE_LINE_SIZE);

		if (dump_mz == NULL) {
			PMD_INIT_LOG(ERR,
				"dev %s Cannot allocate memory for dtb table dump",
				dev->device->name);
			ret = -ENOMEM;
			goto free_res;
		}
		dpp_ctrl->dump_vir_addr = dump_mz->addr_64;
		dpp_ctrl->dump_phy_addr = dump_mz->iova;
		g_dtb_data.dtb_table_dump_mz = dump_mz;
	}
	/* init bulk dump */
	zxdh_dtb_dump_res_init(hw, dpp_ctrl);

	ret = dpp_host_np_init(0, dpp_ctrl);
	if (ret) {
		PMD_INIT_LOG(ERR, "dev %s dpp host np init failed .ret %d", dev->device->name, ret);
		goto free_res;
	}

	PMD_INIT_LOG(INFO, "dev %s dpp host np init ok.dtb queue %d",
		dev->device->name, dpp_ctrl->queue_id);
	g_dtb_data.queueid = dpp_ctrl->queue_id;
	free(dpp_ctrl);
	return 0;

free_res:
	dtb_data_res_free(hw);
	free(dpp_ctrl);
	return -ret;
}

static int32_t dpp_res_uni_init(uint32_t type)
{
	uint32_t ret = 0;
	uint32_t dev_id = 0;
	DPP_APT_HASH_RES_INIT_T HashResInit = {0};
	DPP_APT_ERAM_RES_INIT_T EramResInit = {0};
	DPP_APT_STAT_RES_INIT_T StatResInit = {0};

	memset(&HashResInit, 0x0, sizeof(DPP_APT_HASH_RES_INIT_T));
	memset(&EramResInit, 0x0, sizeof(DPP_APT_ERAM_RES_INIT_T));
	memset(&StatResInit, 0x0, sizeof(DPP_APT_STAT_RES_INIT_T));

	ret = dpp_apt_hash_res_get(type, &HashResInit);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s hash_res_get failed!", __func__);
		return -1;
	}
	ret = dpp_apt_eram_res_get(type, &EramResInit);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s eram_res_get failed!", __func__);
		return -1;
	}
	ret = dpp_apt_stat_res_get(type, &StatResInit);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s stat_res_get failed!", __func__);
		return -1;
	}
	ret = dpp_apt_hash_global_res_init(dev_id);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s hash_global_res_init failed!", __func__);
		return -1;
	}

	ret = dpp_apt_hash_func_res_init(dev_id, HashResInit.func_num, HashResInit.func_res);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s hash_func_res_init failed!", __func__);
		return -1;
	}

	ret = dpp_apt_hash_bulk_res_init(dev_id, HashResInit.bulk_num, HashResInit.bulk_res);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s hash_bulk_res_init failed!", __func__);
		return -1;
	}
	ret = dpp_apt_hash_tbl_res_init(dev_id, HashResInit.tbl_num, HashResInit.tbl_res);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s hash_tbl_res_init failed!", __func__);
		return -1;
	}
	ret = dpp_apt_eram_res_init(dev_id, EramResInit.tbl_num, EramResInit.eram_res);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s eram_res_init failed!", __func__);
		return -1;
	}
	ret = dpp_stat_ppu_eram_baddr_set(dev_id, StatResInit.eram_baddr);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s stat_ppu_eram_baddr_set failed!", __func__);
		return -1;
	}
	ret = dpp_stat_ppu_eram_depth_set(dev_id, StatResInit.eram_depth); /* unit: 128bits */
	if (ret) {
		PMD_DRV_LOG(ERR, "%s stat_ppu_eram_depth_set failed!", __func__);
		return -1;
	}
	ret = dpp_se_cmmu_smmu1_cfg_set(dev_id, StatResInit.ddr_baddr);
	if (ret) {
		PMD_DRV_LOG(ERR, "%s dpp_se_cmmu_smmu1_cfg_set failed!", __func__);
		return -1;
	}
	ret = dpp_stat_ppu_ddr_baddr_set(dev_id, StatResInit.ppu_ddr_offset); /* unit: 128bits */
	if (ret) {
		PMD_DRV_LOG(ERR, "%s stat_ppu_ddr_baddr_set failed!", __func__);
		return -1;
	}

	return 0;
}

static inline int npsdk_apt_res_init(struct rte_eth_dev *dev __rte_unused)
{
	int32_t ret = 0;

	ret = dpp_res_uni_init(SE_NIC_RES_TYPE);
	if (ret) {
		PMD_INIT_LOG(ERR, "init stand dpp res failed");
		return -1;
	}

	return ret;
}
static int zxdh_np_init(struct rte_eth_dev *eth_dev)
{
	uint32_t ret = 0;
	struct zxdh_hw *hw = eth_dev->data->dev_private;

	if ((zxdh_shared_data != NULL) && zxdh_shared_data->npsdk_init_done) {
		g_dtb_data.dev_refcnt++;
		zxdh_tbl_entry_offline_destroy(hw);
		PMD_DRV_LOG(DEBUG, "no need to init dtb  dtb chanenl %d devref %d",
				g_dtb_data.queueid, g_dtb_data.dev_refcnt);
		return 0;
	}

	if (hw->is_pf) {
		ret = npsdk_dtb_res_init(eth_dev);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpp apt init failed, ret:%d ", ret);
			return -ret;
		}

		ret = npsdk_apt_res_init(eth_dev);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpp apt init failed, ret:%d ", ret);
			return -ret;
		}
	}
	if (zxdh_shared_data != NULL)
		zxdh_shared_data->npsdk_init_done = 1;

	return 0;
}

static void zxdh_priv_res_free(struct zxdh_hw *priv)
{
	rte_free(priv->vlan_fiter);
	priv->vlan_fiter = NULL;
	rte_free(priv->vfinfo);
	priv->vfinfo = NULL;
}

static int zxdh_tbl_entry_destroy(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint32_t sdt_no;
	int ret = 0;

	if (!g_dtb_data.init_done)
		return ret;

	if (hw->is_pf) {
		sdt_no = MK_SDT_NO(L2_ENTRY, hw->hash_search_index);
		ret = dpp_dtb_hash_online_delete(0, g_dtb_data.queueid, sdt_no);
		if (ret) {
			PMD_DRV_LOG(ERR, "%s dpp_dtb_hash_online_delete sdt_no %d failed ",
				dev->data->name, sdt_no);
			return -1;
		}

		sdt_no = MK_SDT_NO(MC, hw->hash_search_index);
		ret = dpp_dtb_hash_online_delete(0, g_dtb_data.queueid, sdt_no);
		if (ret) {
			PMD_DRV_LOG(ERR, "%s dpp_dtb_hash_online_delete sdt_no %d failed ",
				dev->data->name, sdt_no);
			return -1;
		}
	}
	return ret;
}

static void zxdh_np_destroy(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	int ret;

	ret = zxdh_tbl_entry_destroy(dev);
	if (ret)
		return;

	if ((!g_dtb_data.init_done) && (!g_dtb_data.dev_refcnt))
		return;

	if (--g_dtb_data.dev_refcnt == 0)
		dtb_data_res_free(hw);

	PMD_DRV_LOG(DEBUG, "g_dtb_data dev_refcnt %d", g_dtb_data.dev_refcnt);
}

static int32_t zxdh_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	int32_t ret;

	eth_dev->dev_ops = &zxdh_eth_dev_ops;

	/**
	 * Primary process does the whole initialization,
	 * for secondaryprocesses, we just select the same Rx and Tx function as primary.
	 */
	struct zxdh_hw *hw = eth_dev->data->dev_private;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		VTPCI_OPS(hw) = &zxdh_modern_ops;
		set_rxtx_funcs(eth_dev);
		return 0;
	}
	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("zxdh_mac",
			ZXDH_MAX_MAC_ADDRS * RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes store MAC addresses",
				ZXDH_MAX_MAC_ADDRS * RTE_ETHER_ADDR_LEN);
		return -ENOMEM;
	}
	memset(hw, 0, sizeof(*hw));
	ret = zxdh_dev_devargs_parse(eth_dev->device->devargs, hw);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "dev args parse failed");
		return -EINVAL;
	}

	hw->bar_addr[0] = (uint64_t)pci_dev->mem_resource[0].addr;
	if (hw->bar_addr[0] == 0) {
		PMD_INIT_LOG(ERR, "Bad mem resource.");
		return -EIO;
	}
	hw->device_id = pci_dev->id.device_id;
	hw->port_id = eth_dev->data->port_id;
	hw->eth_dev = eth_dev;
	hw->speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	hw->duplex = RTE_ETH_LINK_FULL_DUPLEX;
	hw->is_pf = 0;

	rte_spinlock_init(&hw->state_lock);
	if (pci_dev->id.device_id == ZXDH_E310_PF_DEVICEID ||
		pci_dev->id.device_id == ZXDH_E312_PF_DEVICEID) {
		hw->is_pf = 1;
		hw->pfinfo.vf_nums = pci_dev->max_vfs;
	}

	/* reset device and get dev config*/
	ret = zxdh_init_once(eth_dev);
	if (ret != 0)
		goto err_zxdh_init;

	ret = zxdh_init_device(eth_dev);
	if (ret < 0)
		goto err_zxdh_init;

	ret = zxdh_np_init(eth_dev);
	if (ret)
		goto err_zxdh_init;

	zxdh_priv_res_init(hw);
	zxdh_sriovinfo_init(hw);
	zxdh_msg_cb_reg(hw);
	zxdh_configure_intr(eth_dev);
	return 0;

err_zxdh_init:
	zxdh_intr_release(eth_dev);
	zxdh_np_destroy(eth_dev);
	zxdh_bar_msg_chan_exit();
	zxdh_priv_res_free(hw);
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	return ret;
}

int32_t zxdh_eth_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
						sizeof(struct zxdh_hw),
						zxdh_eth_dev_init);
}


static int32_t zxdh_eth_dev_uninit(struct rte_eth_dev *eth_dev __rte_unused)
{
	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return 0;
	/** todo later
	 * zxdh_dev_close(eth_dev);
	 */
	return 0;
}

int32_t zxdh_eth_pci_remove(struct rte_pci_device *pci_dev)
{
	int32_t ret = rte_eth_dev_pci_generic_remove(pci_dev, zxdh_eth_dev_uninit);

	if (ret == -ENODEV) { /* Port has already been released by close. */
		ret = 0;
	}
	return ret;
}

static const struct rte_pci_id pci_id_zxdh_map[] = {
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_ZTE, ZXDH_E310_PF_DEVICEID)},
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_ZTE, ZXDH_E310_VF_DEVICEID)},
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_ZTE, ZXDH_E312_PF_DEVICEID)},
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_ZTE, ZXDH_E312_VF_DEVICEID)},
	{.vendor_id = 0, /* sentinel */ },
};
static struct rte_pci_driver zxdh_pmd = {
	.driver = {.name = "net_zxdh", },
	.id_table = pci_id_zxdh_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = zxdh_eth_pci_probe,
	.remove = zxdh_eth_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_zxdh, zxdh_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_zxdh, pci_id_zxdh_map);
RTE_PMD_REGISTER_KMOD_DEP(net_zxdh, "* vfio-pci");
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_driver, driver, NOTICE);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_rx, rx, DEBUG);
RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_tx, tx, DEBUG);

RTE_LOG_REGISTER_SUFFIX(zxdh_logtype_msg, msg, NOTICE);
RTE_PMD_REGISTER_PARAM_STRING(net_zxdh,
	"q_depth=<int>");

