/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <stdbool.h>
#include <rte_random.h>
#include <dpaax_iova_table.h>
#include "enetc_logs.h"
#include "enetc.h"

#define ENETC_CRC_TABLE_SIZE		256
#define ENETC_POLY			0x1021
#define ENETC_CRC_INIT			0xffff
#define ENETC_BYTE_SIZE			8
#define ENETC_MSB_BIT			0x8000

uint16_t enetc_crc_table[ENETC_CRC_TABLE_SIZE];
bool enetc_crc_gen;

static void
enetc_gen_crc_table(void)
{
	uint16_t crc = 0;
	uint16_t c;

	for (int i = 0; i < ENETC_CRC_TABLE_SIZE; i++) {
		crc = 0;
		c = i << ENETC_BYTE_SIZE;
		for (int j = 0; j < ENETC_BYTE_SIZE; j++) {
			if ((crc ^ c) & ENETC_MSB_BIT)
				crc = (crc << 1) ^ ENETC_POLY;
			else
				crc = crc << 1;
			c = c << 1;
		}

		enetc_crc_table[i] = crc;
	}

	enetc_crc_gen = true;
}

static uint16_t
enetc_crc_calc(uint16_t crc, const uint8_t *buffer, size_t len)
{
	uint8_t data;

	while (len--) {
		data = *buffer;
		crc = (crc << 8) ^ enetc_crc_table[((crc >> 8) ^ data) & 0xff];
		buffer++;
	}
	return crc;
}

int
enetc4_vf_dev_stop(struct rte_eth_dev *dev __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static int
enetc4_vf_dev_start(struct rte_eth_dev *dev __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	return 0;
}

static int
enetc4_vf_stats_get(struct rte_eth_dev *dev,
		    struct rte_eth_stats *stats)
{
	struct enetc_eth_hw *hw =
		ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_bdr *rx_ring;
	uint8_t i;

	PMD_INIT_FUNC_TRACE();
	stats->ipackets = enetc4_rd(enetc_hw, ENETC4_SIRFRM0);
	stats->opackets = enetc4_rd(enetc_hw, ENETC4_SITFRM0);
	stats->ibytes = enetc4_rd(enetc_hw, ENETC4_SIROCT0);
	stats->obytes = enetc4_rd(enetc_hw, ENETC4_SITOCT0);
	stats->oerrors = enetc4_rd(enetc_hw, ENETC4_SITDFCR);
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rx_ring = dev->data->rx_queues[i];
		stats->ierrors += rx_ring->ierrors;
	}
	return 0;
}


static void
enetc_msg_vf_fill_common_hdr(struct enetc_msg_swbd *msg,
					uint8_t class_id, uint8_t cmd_id, uint8_t proto_ver,
					uint8_t len, uint8_t cookie)
{
	struct enetc_msg_cmd_header *hdr = msg->vaddr;

	hdr->class_id = class_id;
	hdr->cmd_id = cmd_id;
	hdr->proto_ver = proto_ver;
	hdr->len = len;
	hdr->cookie = cookie;
	/* Incrementing msg 2 bytes ahead as the first two bytes are for CRC */
	hdr->csum = rte_cpu_to_be_16(enetc_crc_calc(ENETC_CRC_INIT,
				(uint8_t *)msg->vaddr + sizeof(uint16_t),
				msg->size - sizeof(uint16_t)));

	dcbf(hdr);
}

/* Messaging */
static void
enetc4_msg_vsi_write_msg(struct enetc_hw *hw,
		struct enetc_msg_swbd *msg)
{
	uint32_t val;

	val = enetc_vsi_set_msize(msg->size) | lower_32_bits(msg->dma);
	enetc_wr(hw, ENETC4_VSIMSGSNDAR1, upper_32_bits(msg->dma));
	enetc_wr(hw, ENETC4_VSIMSGSNDAR0, val);
}

static void
enetc4_msg_vsi_reply_msg(struct enetc_hw *enetc_hw, struct enetc_psi_reply_msg *reply_msg)
{
	int vsimsgsr;
	int8_t class_id = 0;
	uint8_t status = 0;

	vsimsgsr = enetc_rd(enetc_hw, ENETC4_VSIMSGSR);

	/* Extracting 8 bits of message result in class_id */
	class_id |= ((ENETC_SIMSGSR_GET_MC(vsimsgsr) >> 8) & 0xff);

	/* Extracting 4 bits of message result in status */
	status |= ((ENETC_SIMSGSR_GET_MC(vsimsgsr) >> 4) & 0xf);

	reply_msg->class_id = class_id;
	reply_msg->status = status;
}

static int
enetc4_msg_vsi_send(struct enetc_hw *enetc_hw, struct enetc_msg_swbd *msg)
{
	int timeout = ENETC4_DEF_VSI_WAIT_TIMEOUT_UPDATE;
	int delay_us = ENETC4_DEF_VSI_WAIT_DELAY_UPDATE;
	uint8_t class_id = 0;
	int err = 0;
	int vsimsgsr;

	enetc4_msg_vsi_write_msg(enetc_hw, msg);

	do {
		vsimsgsr = enetc_rd(enetc_hw, ENETC4_VSIMSGSR);
		if (!(vsimsgsr & ENETC4_VSIMSGSR_MB))
			break;
		rte_delay_us(delay_us);
	} while (--timeout);

	if (!timeout) {
		ENETC_PMD_ERR("Message not processed by PSI");
		return -ETIMEDOUT;
	}
	/* check for message delivery error */
	if (vsimsgsr & ENETC4_VSIMSGSR_MS) {
		ENETC_PMD_ERR("Transfer error when copying the data");
		return -EIO;
	}

	class_id |= ((ENETC_SIMSGSR_GET_MC(vsimsgsr) >> 8) & 0xff);

	/* Check the user-defined completion status. */
	if (class_id != ENETC_MSG_CLASS_ID_CMD_SUCCESS) {
		switch (class_id) {
		case ENETC_MSG_CLASS_ID_PERMISSION_DENY:
			ENETC_PMD_ERR("Permission denied");
			err = -EACCES;
			break;
		case ENETC_MSG_CLASS_ID_CMD_NOT_SUPPORT:
			ENETC_PMD_ERR("Command not supported");
			err = -EOPNOTSUPP;
			break;
		case ENETC_MSG_CLASS_ID_PSI_BUSY:
			ENETC_PMD_ERR("PSI Busy");
			err = -EBUSY;
			break;
		case ENETC_MSG_CLASS_ID_CMD_TIMEOUT:
			ENETC_PMD_ERR("Command timeout");
			err = -ETIME;
			break;
		case ENETC_MSG_CLASS_ID_CRC_ERROR:
			ENETC_PMD_ERR("CRC error");
			err = -EIO;
			break;
		case ENETC_MSG_CLASS_ID_PROTO_NOT_SUPPORT:
			ENETC_PMD_ERR("Protocol Version not supported");
			err = -EOPNOTSUPP;
			break;
		case ENETC_MSG_CLASS_ID_INVALID_MSG_LEN:
			ENETC_PMD_ERR("Invalid message length");
			err = -EINVAL;
			break;
		case ENETC_CLASS_ID_MAC_FILTER:
			break;
		default:
			err = -EIO;
		}
	}

	return err;
}

static int
enetc4_vf_set_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_cmd_set_primary_mac *cmd;
	struct enetc_msg_swbd *msg;
	struct enetc_psi_reply_msg *reply_msg;
	int msg_size;
	int err = 0;

	PMD_INIT_FUNC_TRACE();
	reply_msg = rte_zmalloc(NULL, sizeof(*reply_msg), RTE_CACHE_LINE_SIZE);
	if (!reply_msg) {
		ENETC_PMD_ERR("Failed to alloc memory for reply_msg");
		return -ENOMEM;
	}

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		rte_free(reply_msg);
		return err;
	}

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_cmd_set_primary_mac),
				ENETC_VSI_PSI_MSG_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		rte_free(reply_msg);
		return -ENOMEM;
	}

	msg->dma = rte_mem_virt2iova((const void *)msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_cmd_set_primary_mac *)msg->vaddr;

	cmd->count = 0;
	memcpy(&cmd->addr.addr_bytes, addr, sizeof(struct rte_ether_addr));

	enetc_msg_vf_fill_common_hdr(msg, ENETC_CLASS_ID_MAC_FILTER,
					ENETC_CMD_ID_SET_PRIMARY_MAC, 0, 0, 0);

	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if (err) {
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

	enetc4_msg_vsi_reply_msg(enetc_hw, reply_msg);

	if (reply_msg->class_id == ENETC_CLASS_ID_MAC_FILTER) {
		switch (reply_msg->status) {
		case ENETC_INVALID_MAC_ADDR:
			ENETC_PMD_ERR("Invalid MAC address");
			err = -EINVAL;
			break;
		case ENETC_DUPLICATE_MAC_ADDR:
			ENETC_PMD_ERR("Duplicate MAC address");
			err = -EINVAL;
			break;
		default:
			err = -EINVAL;
			break;
		}
	}

	if (err) {
		ENETC_PMD_ERR("VSI command execute error!");
		goto end;
	}

	rte_ether_addr_copy((struct rte_ether_addr *)&cmd->addr,
			&dev->data->mac_addrs[0]);

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(reply_msg);
	rte_free(msg);
	return err;
}

static int
enetc4_vf_promisc_send_message(struct rte_eth_dev *dev, bool promisc_en)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_cmd_set_promisc *cmd;
	struct enetc_msg_swbd *msg;
	int msg_size;
	int err = 0;

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		return err;
	}

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_cmd_set_promisc), ENETC_VSI_PSI_MSG_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		return -ENOMEM;
	}

	msg->dma = rte_mem_virt2iova((const void *)msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_cmd_set_promisc *)msg->vaddr;

	/* op_type is based on the result of message format
	 *    7  6      1       0
	      type   promisc  flush
	 */

	if (promisc_en)
		cmd->op_type = ENETC_PROMISC_ENABLE;
	else
		cmd->op_type = ENETC_PROMISC_DISABLE;

	enetc_msg_vf_fill_common_hdr(msg, ENETC_CLASS_ID_MAC_FILTER,
				ENETC_CMD_ID_SET_MAC_PROMISCUOUS, 0, 0, 0);

	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if (err) {
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(msg);
	return err;
}

static int
enetc4_vf_allmulti_send_message(struct rte_eth_dev *dev, bool mc_promisc)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_cmd_set_promisc *cmd;
	struct enetc_msg_swbd *msg;
	int msg_size;
	int err = 0;

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		return err;
	}

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_cmd_set_promisc),
				ENETC_VSI_PSI_MSG_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		return -ENOMEM;
	}

	msg->dma = rte_mem_virt2iova((const void *)msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_cmd_set_promisc *)msg->vaddr;

	/* op_type is based on the result of message format
	 *    7  6      1       0
	      type   promisc  flush
	 */

	if (mc_promisc)
		cmd->op_type = ENETC_ALLMULTI_PROMISC_EN;
	else
		cmd->op_type = ENETC_ALLMULTI_PROMISC_DIS;

	enetc_msg_vf_fill_common_hdr(msg, ENETC_CLASS_ID_MAC_FILTER,
				ENETC_CMD_ID_SET_MAC_PROMISCUOUS, 0, 0, 0);

	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if (err) {
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(msg);
	return err;
}


static int
enetc4_vf_multicast_enable(struct rte_eth_dev *dev)
{
	int err;

	PMD_INIT_FUNC_TRACE();
	err = enetc4_vf_allmulti_send_message(dev, true);
	if (err) {
		ENETC_PMD_ERR("Failed to enable multicast promiscuous mode");
		return err;
	}

	return 0;
}

static int
enetc4_vf_multicast_disable(struct rte_eth_dev *dev)
{
	int err;

	PMD_INIT_FUNC_TRACE();
	err = enetc4_vf_allmulti_send_message(dev, false);
	if (err) {
		ENETC_PMD_ERR("Failed to disable multicast promiscuous mode");
		return err;
	}

	return 0;
}

static int
enetc4_vf_promisc_enable(struct rte_eth_dev *dev)
{
	int err;

	PMD_INIT_FUNC_TRACE();
	err = enetc4_vf_promisc_send_message(dev, true);
	if (err) {
		ENETC_PMD_ERR("Failed to enable promiscuous mode");
		return err;
	}

	return 0;
}

static int
enetc4_vf_promisc_disable(struct rte_eth_dev *dev)
{
	int err;

	PMD_INIT_FUNC_TRACE();
	err = enetc4_vf_promisc_send_message(dev, false);
	if (err) {
		ENETC_PMD_ERR("Failed to disable promiscuous mode");
		return err;
	}

	return 0;
}

static int
enetc4_vf_vlan_promisc(struct rte_eth_dev *dev, bool promisc_en)
{
	struct enetc_eth_hw *hw = ENETC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct enetc_hw *enetc_hw = &hw->hw;
	struct enetc_msg_cmd_set_vlan_promisc *cmd;
	struct enetc_msg_swbd *msg;
	int msg_size;
	int err = 0;

	msg = rte_zmalloc(NULL, sizeof(*msg), RTE_CACHE_LINE_SIZE);
	if (!msg) {
		ENETC_PMD_ERR("Failed to alloc msg");
		err = -ENOMEM;
		return err;
	}

	msg_size = RTE_ALIGN(sizeof(struct enetc_msg_cmd_set_vlan_promisc),
				ENETC_VSI_PSI_MSG_SIZE);
	msg->vaddr = rte_zmalloc(NULL, msg_size, 0);
	if (!msg->vaddr) {
		ENETC_PMD_ERR("Failed to alloc memory for msg");
		rte_free(msg);
		return -ENOMEM;
	}
	msg->dma = rte_mem_virt2iova((const void *)msg->vaddr);
	msg->size = msg_size;

	cmd = (struct enetc_msg_cmd_set_vlan_promisc *)msg->vaddr;
	/* op is based on the result of message format
	 *	   1	  0
	 *	promisc	flush
	 */

	if (promisc_en)
		cmd->op = ENETC_PROMISC_VLAN_ENABLE;
	else
		cmd->op = ENETC_PROMISC_VLAN_DISABLE;

	enetc_msg_vf_fill_common_hdr(msg, ENETC_CLASS_ID_VLAN_FILTER,
				ENETC_CMD_ID_SET_VLAN_PROMISCUOUS, 0, 0, 0);

	/* send the command and wait */
	err = enetc4_msg_vsi_send(enetc_hw, msg);
	if (err) {
		ENETC_PMD_ERR("VSI message send error");
		goto end;
	}

end:
	/* free memory no longer required */
	rte_free(msg->vaddr);
	rte_free(msg);
	return err;
}

static int enetc4_vf_vlan_offload_set(struct rte_eth_dev *dev, int mask __rte_unused)
{
	int err = 0;

	PMD_INIT_FUNC_TRACE();

	if (dev->data->dev_conf.rxmode.offloads) {
		ENETC_PMD_DEBUG("VLAN filter table entry inserted:"
					"Disabling VLAN promisc mode");
		err = enetc4_vf_vlan_promisc(dev, false);
		if (err) {
			ENETC_PMD_ERR("Added VLAN filter table entry:"
					"Failed to disable promiscuous mode");
			return err;
		}
	} else {
		ENETC_PMD_DEBUG("Enabling VLAN promisc mode");
		err = enetc4_vf_vlan_promisc(dev, true);
		if (err) {
			ENETC_PMD_ERR("Vlan filter table empty:"
					"Failed to enable promiscuous mode");
			return err;
		}
	}

	return 0;
}

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_vf_id_enetc4_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_NXP, ENETC4_DEV_ID_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

/* Features supported by this driver */
static const struct eth_dev_ops enetc4_vf_ops = {
	.dev_configure        = enetc4_dev_configure,
	.dev_start            = enetc4_vf_dev_start,
	.dev_stop             = enetc4_vf_dev_stop,
	.dev_close            = enetc4_dev_close,
	.dev_infos_get        = enetc4_dev_infos_get,
	.stats_get            = enetc4_vf_stats_get,
	.mac_addr_set         = enetc4_vf_set_mac_addr,
	.promiscuous_enable   = enetc4_vf_promisc_enable,
	.promiscuous_disable  = enetc4_vf_promisc_disable,
	.allmulticast_enable  = enetc4_vf_multicast_enable,
	.allmulticast_disable = enetc4_vf_multicast_disable,
	.vlan_offload_set     = enetc4_vf_vlan_offload_set,
	.rx_queue_setup       = enetc4_rx_queue_setup,
	.rx_queue_start       = enetc4_rx_queue_start,
	.rx_queue_stop        = enetc4_rx_queue_stop,
	.rx_queue_release     = enetc4_rx_queue_release,
	.tx_queue_setup       = enetc4_tx_queue_setup,
	.tx_queue_start       = enetc4_tx_queue_start,
	.tx_queue_stop        = enetc4_tx_queue_stop,
	.tx_queue_release     = enetc4_tx_queue_release,
	.dev_supported_ptypes_get = enetc4_supported_ptypes_get,
};

static int
enetc4_vf_mac_init(struct enetc_eth_hw *hw, struct rte_eth_dev *eth_dev)
{
	uint32_t *mac = (uint32_t *)hw->mac.addr;
	struct enetc_hw *enetc_hw = &hw->hw;
	uint32_t high_mac = 0;
	uint16_t low_mac = 0;
	char vf_eth_name[ENETC_ETH_NAMESIZE];

	PMD_INIT_FUNC_TRACE();

	/* Enabling Station Interface */
	enetc4_wr(enetc_hw, ENETC_SIMR, ENETC_SIMR_EN);
	*mac = (uint32_t)enetc_rd(enetc_hw, ENETC_SIPMAR0);
	high_mac = (uint32_t)*mac;
	mac++;
	*mac = (uint16_t)enetc_rd(enetc_hw, ENETC_SIPMAR1);
	low_mac = (uint16_t)*mac;

	if ((high_mac | low_mac) == 0) {
		char *first_byte;
		ENETC_PMD_NOTICE("MAC is not available for this SI, "
				 "set random MAC");
		mac = (uint32_t *)hw->mac.addr;
		*mac = (uint32_t)rte_rand();
		first_byte = (char *)mac;
		*first_byte &= 0xfe;    /* clear multicast bit */
		*first_byte |= 0x02;    /* set local assignment bit (IEEE802) */
		enetc4_port_wr(enetc_hw, ENETC4_PMAR0, *mac);
		mac++;
		*mac = (uint16_t)rte_rand();
		enetc4_port_wr(enetc_hw, ENETC4_PMAR1, *mac);
		print_ethaddr("New address: ",
			(const struct rte_ether_addr *)hw->mac.addr);
	}

	/* Allocate memory for storing MAC addresses */
	snprintf(vf_eth_name, sizeof(vf_eth_name), "enetc4_vf_eth_%d", eth_dev->data->port_id);
	eth_dev->data->mac_addrs = rte_zmalloc(vf_eth_name,
					RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		ENETC_PMD_ERR("Failed to allocate %d bytes needed to "
			      "store MAC addresses",
			      RTE_ETHER_ADDR_LEN * 1);
		return -ENOMEM;
	}

	if (!enetc_crc_gen)
		enetc_gen_crc_table();

	/* Copy the permanent MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.addr,
			     &eth_dev->data->mac_addrs[0]);

	return 0;
}

static int
enetc4_vf_dev_init(struct rte_eth_dev *eth_dev)
{
	struct enetc_eth_hw *hw =
			    ENETC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	int error = 0;
	uint32_t si_cap;
	struct enetc_hw *enetc_hw = &hw->hw;

	PMD_INIT_FUNC_TRACE();
	eth_dev->dev_ops = &enetc4_vf_ops;
	enetc4_dev_hw_init(eth_dev);

	si_cap = enetc_rd(enetc_hw, ENETC_SICAPR0);
	hw->max_tx_queues = si_cap & ENETC_SICAPR0_BDR_MASK;
	hw->max_rx_queues = (si_cap >> 16) & ENETC_SICAPR0_BDR_MASK;

	ENETC_PMD_DEBUG("Max RX queues = %d Max TX queues = %d",
			hw->max_rx_queues, hw->max_tx_queues);
	error = enetc4_vf_mac_init(hw, eth_dev);
	if (error != 0) {
		ENETC_PMD_ERR("MAC initialization failed!!");
		return -1;
	}

	if (rte_eal_iova_mode() == RTE_IOVA_PA)
		dpaax_iova_table_populate();

	ENETC_PMD_DEBUG("port_id %d vendorID=0x%x deviceID=0x%x",
			eth_dev->data->port_id, pci_dev->id.vendor_id,
			pci_dev->id.device_id);
	return 0;
}

static int
enetc4_vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct enetc_eth_adapter),
					     enetc4_vf_dev_init);
}

static struct rte_pci_driver rte_enetc4_vf_pmd = {
	.id_table = pci_vf_id_enetc4_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = enetc4_vf_pci_probe,
	.remove = enetc4_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_enetc4_vf, rte_enetc4_vf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_enetc4_vf, pci_vf_id_enetc4_map);
RTE_PMD_REGISTER_KMOD_DEP(net_enetc4_vf, "* uio_pci_generic");
RTE_LOG_REGISTER_DEFAULT(enetc4_vf_logtype_pmd, NOTICE);
