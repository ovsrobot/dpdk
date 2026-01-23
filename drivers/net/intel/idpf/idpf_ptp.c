/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Intel Corporation
 */

#include "idpf_ptp.h"
#include <base/virtchnl2.h>
#include "idpf_common_virtchnl.h"

/**
 * idpf_ptp_get_access - Determine the access type of the PTP features
 * @adapter: Driver specific private structure
 * @direct: Capability that indicates the direct access
 * @mailbox: Capability that indicates the mailbox access
 *
 * Return: the type of supported access for the PTP feature.
 */
static enum idpf_ptp_access
idpf_ptp_get_access(const struct idpf_adapter *adapter, u32 direct, u32 mailbox)
{
	if (adapter->ptp->caps & direct)
		return IDPF_PTP_DIRECT;
	else if (adapter->ptp->caps & mailbox)
		return IDPF_PTP_MAILBOX;
	else
		return IDPF_PTP_NONE;
}

/**
 * idpf_ptp_get_features_access - Determine the access type of PTP features
 * @adapter: Driver specific private structure
 *
 * Fulfill the adapter structure with type of the supported PTP features
 * access.
 */
static void idpf_ptp_get_features_access(const struct idpf_adapter *adapter)
{
	struct idpf_ptp *ptp = adapter->ptp;
	u32 direct, mailbox;

	/* Get the device clock time */
	direct = VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME;
	mailbox = VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME_MB;
	ptp->get_dev_clk_time_access = (uint8_t)idpf_ptp_get_access(adapter,
							 direct,
							 mailbox);

	/* Get the cross timestamp */
	direct = VIRTCHNL2_CAP_PTP_GET_CROSS_TIME;
	mailbox = VIRTCHNL2_CAP_PTP_GET_CROSS_TIME_MB;
	ptp->get_cross_tstamp_access = (uint8_t)idpf_ptp_get_access(adapter,
							 direct,
							 mailbox);

	/* Set the device clock time */
	direct = VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME;
	mailbox = VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME_MB;
	ptp->set_dev_clk_time_access = (uint8_t)idpf_ptp_get_access(adapter,
							 direct,
							 mailbox);

	/* Adjust the device clock time */
	direct = VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK;
	mailbox = VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK_MB;
	ptp->adj_dev_clk_time_access = (uint8_t)idpf_ptp_get_access(adapter,
							 direct,
							 mailbox);

	/* Tx timestamping */
	direct = VIRTCHNL2_CAP_PTP_TX_TSTAMPS;
	mailbox = VIRTCHNL2_CAP_PTP_TX_TSTAMPS_MB;
	ptp->tx_tstamp_access = (uint8_t)idpf_ptp_get_access(adapter,
							 direct,
							 mailbox);
}

/**
 * idpf_ptp_get_caps - Send virtchnl get ptp capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl get PTP capabilities message.
 *
 * Return: 0 on success, -errno on failure.
 */
int idpf_ptp_get_caps(struct idpf_adapter *adapter)
{
	struct virtchnl2_ptp_cross_time_reg_offsets cross_tstamp_offsets;
	struct virtchnl2_ptp_clk_adj_reg_offsets clk_adj_offsets;
	struct virtchnl2_ptp_get_caps send_ptp_caps_msg = { };
	struct virtchnl2_ptp_clk_reg_offsets clock_offsets;
	struct virtchnl2_ptp_get_caps *recv_ptp_caps_msg;
	struct idpf_cmd_info args = { };
	struct idpf_ptp_secondary_mbx *scnd_mbx;
	struct idpf_ptp *ptp = adapter->ptp;
	struct idpf_hw *hw = &adapter->hw;
	enum idpf_ptp_access access_type;
	int err;
	u32 temp_offset;

	send_ptp_caps_msg.caps = CPU_TO_LE32(VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME |
					     VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME_MB |
					     VIRTCHNL2_CAP_PTP_GET_CROSS_TIME |
					     VIRTCHNL2_CAP_PTP_GET_CROSS_TIME_MB |
					     VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME |
					     VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME_MB |
					     VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK |
					     VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK_MB |
					     VIRTCHNL2_CAP_PTP_TX_TSTAMPS |
					     VIRTCHNL2_CAP_PTP_TX_TSTAMPS_MB);

	args.ops = VIRTCHNL2_OP_PTP_GET_CAPS;
	args.in_args = (uint8_t *)&send_ptp_caps_msg;
	args.in_args_size = sizeof(send_ptp_caps_msg);

	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(*recv_ptp_caps_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	recv_ptp_caps_msg = (struct virtchnl2_ptp_get_caps *)args.out_buffer;
	ptp->caps = LE32_TO_CPU(recv_ptp_caps_msg->caps);
	ptp->base_incval = LE64_TO_CPU(recv_ptp_caps_msg->base_incval);
	ptp->max_adj = LE32_TO_CPU(recv_ptp_caps_msg->max_adj);

	scnd_mbx = &ptp->secondary_mbx;
	scnd_mbx->peer_mbx_q_id = LE16_TO_CPU(recv_ptp_caps_msg->peer_mbx_q_id);

	/* if the ptp_mb_q_id holds invalid value (0xffff), the secondary
	 * mailbox is not supported.
	 */
	scnd_mbx->valid = scnd_mbx->peer_mbx_q_id != 0xffff;
	if (scnd_mbx->valid)
		scnd_mbx->peer_id = recv_ptp_caps_msg->peer_id;

	/* Determine the access type for the PTP features */
	idpf_ptp_get_features_access(adapter);

	access_type = (enum idpf_ptp_access)ptp->get_dev_clk_time_access;
	if (access_type != IDPF_PTP_DIRECT)
		goto cross_tstamp;

	clock_offsets = recv_ptp_caps_msg->clk_offsets;

	temp_offset = LE32_TO_CPU(clock_offsets.dev_clk_ns_l);
	ptp->dev_clk_regs.dev_clk_ns_l = IDPF_PCI_REG_ADDR(hw,
							   temp_offset);
	temp_offset = LE32_TO_CPU(clock_offsets.dev_clk_ns_h);
	ptp->dev_clk_regs.dev_clk_ns_h = IDPF_PCI_REG_ADDR(hw,
							   temp_offset);
	temp_offset = LE32_TO_CPU(clock_offsets.phy_clk_ns_l);
	ptp->dev_clk_regs.phy_clk_ns_l = IDPF_PCI_REG_ADDR(hw,
				  temp_offset);
	temp_offset = LE32_TO_CPU(clock_offsets.phy_clk_ns_h);
	ptp->dev_clk_regs.phy_clk_ns_h = IDPF_PCI_REG_ADDR(hw,
				  temp_offset);
	temp_offset = LE32_TO_CPU(clock_offsets.cmd_sync_trigger);
	ptp->dev_clk_regs.cmd_sync = IDPF_PCI_REG_ADDR(hw, temp_offset);

cross_tstamp:
	access_type = (enum idpf_ptp_access)ptp->get_cross_tstamp_access;
	if (access_type != IDPF_PTP_DIRECT)
		goto discipline_clock;

	cross_tstamp_offsets = recv_ptp_caps_msg->cross_time_offsets;

	temp_offset = LE32_TO_CPU(cross_tstamp_offsets.sys_time_ns_l);
	ptp->dev_clk_regs.sys_time_ns_l = IDPF_PCI_REG_ADDR(hw,
					temp_offset);
	temp_offset = LE32_TO_CPU(cross_tstamp_offsets.sys_time_ns_h);
	ptp->dev_clk_regs.sys_time_ns_h = IDPF_PCI_REG_ADDR(hw,
					temp_offset);
	temp_offset = LE32_TO_CPU(cross_tstamp_offsets.cmd_sync_trigger);
	ptp->dev_clk_regs.cmd_sync = IDPF_PCI_REG_ADDR(hw, temp_offset);

discipline_clock:
	access_type = (enum idpf_ptp_access)ptp->adj_dev_clk_time_access;
	if (access_type != IDPF_PTP_DIRECT)
		return err;

	clk_adj_offsets = recv_ptp_caps_msg->clk_adj_offsets;

	/* Device clock offsets */
	temp_offset = LE32_TO_CPU(clk_adj_offsets.dev_clk_cmd_type);
	ptp->dev_clk_regs.cmd = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.dev_clk_incval_l);
	ptp->dev_clk_regs.incval_l = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.dev_clk_incval_h);
	ptp->dev_clk_regs.incval_h = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.dev_clk_shadj_l);
	ptp->dev_clk_regs.shadj_l = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.dev_clk_shadj_h);
	ptp->dev_clk_regs.shadj_h = IDPF_PCI_REG_ADDR(hw, temp_offset);

	/* PHY clock offsets */
	temp_offset = LE32_TO_CPU(clk_adj_offsets.phy_clk_cmd_type);
	ptp->dev_clk_regs.phy_cmd = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.phy_clk_incval_l);
	ptp->dev_clk_regs.phy_incval_l = IDPF_PCI_REG_ADDR(hw,
				  temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.phy_clk_incval_h);
	ptp->dev_clk_regs.phy_incval_h = IDPF_PCI_REG_ADDR(hw,
				  temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.phy_clk_shadj_l);
	ptp->dev_clk_regs.phy_shadj_l = IDPF_PCI_REG_ADDR(hw, temp_offset);
	temp_offset = LE32_TO_CPU(clk_adj_offsets.phy_clk_shadj_h);
	ptp->dev_clk_regs.phy_shadj_h = IDPF_PCI_REG_ADDR(hw, temp_offset);

	return err;
}

/**
 * idpf_ptp_enable_shtime - Enable shadow time and execute a command
 * @adapter: Driver specific private structure
 */
static void idpf_ptp_enable_shtime(struct idpf_adapter *adapter)
{
	uint32_t shtime_enable, exec_cmd;

	/* Get offsets */
	shtime_enable = adapter->ptp->cmd.shtime_enable_mask;
	exec_cmd = adapter->ptp->cmd.exec_cmd_mask;

	/* Set the shtime en and the sync field */
	IDPF_PCI_REG_WRITE(adapter->ptp->dev_clk_regs.cmd_sync, shtime_enable);
	IDPF_PCI_REG_WRITE(adapter->ptp->dev_clk_regs.cmd_sync, exec_cmd | shtime_enable);
}

/**
 * idpf_ptp_get_dev_clk_time - Send virtchnl get device clk time message
 * @adapter: Driver specific private structure
 * @dev_clk_time: Pointer to the device clock structure where the value is set
 *
 * Send virtchnl get time message to get the time of the clock.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_get_dev_clk_time(struct idpf_adapter *adapter,
			      struct idpf_ptp_dev_timers *dev_clk_time)
{
	struct virtchnl2_ptp_get_dev_clk_time get_dev_clk_time_msg = { };
	struct idpf_cmd_info args = { };
	int err;
	u64 dev_time;

	args.ops = VIRTCHNL2_OP_PTP_GET_DEV_CLK_TIME;
	args.in_args = (uint8_t *)&get_dev_clk_time_msg;
	args.in_args_size = sizeof(get_dev_clk_time_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(get_dev_clk_time_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	get_dev_clk_time_msg = *(struct virtchnl2_ptp_get_dev_clk_time *)args.out_buffer;
	dev_time = LE64_TO_CPU(get_dev_clk_time_msg.dev_time_ns);
	dev_clk_time->dev_clk_time_ns = dev_time;

	return err;
}

/**
 * idpf_ptp_get_cross_time - Send virtchnl get cross time message
 * @adapter: Driver specific private structure
 * @cross_time: Pointer to the device clock structure where the value is set
 *
 * Send virtchnl get cross time message to get the time of the clock and the
 * system time.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_get_cross_time(struct idpf_adapter *adapter,
			    struct idpf_ptp_dev_timers *cross_time)
{
	struct virtchnl2_ptp_get_cross_time cross_time_msg = { };
	struct idpf_cmd_info args = { };
	int err;

	args.ops = VIRTCHNL2_OP_PTP_GET_CROSS_TIME;
	args.in_args = (uint8_t *)&cross_time_msg;
	args.in_args_size = sizeof(cross_time_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(cross_time_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	cross_time_msg = *(struct virtchnl2_ptp_get_cross_time *)args.out_buffer;
	cross_time->dev_clk_time_ns = LE64_TO_CPU(cross_time_msg.dev_time_ns);
	cross_time->sys_time_ns = LE64_TO_CPU(cross_time_msg.sys_time_ns);

	return err;
}

/**
 * idpf_ptp_set_dev_clk_time - Send virtchnl set device time message
 * @adapter: Driver specific private structure
 * @time: New time value
 *
 * Send virtchnl set time message to set the time of the clock.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_set_dev_clk_time(struct idpf_adapter *adapter, u64 time)
{
	struct virtchnl2_ptp_set_dev_clk_time set_dev_clk_time_msg = { };
	struct idpf_cmd_info args = { };
	int err;

	set_dev_clk_time_msg.dev_time_ns = CPU_TO_LE64(time);

	args.ops = VIRTCHNL2_OP_PTP_SET_DEV_CLK_TIME;
	args.in_args = (uint8_t *)&set_dev_clk_time_msg;
	args.in_args_size = sizeof(set_dev_clk_time_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(set_dev_clk_time_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	return err;
}

/**
 * idpf_ptp_adj_dev_clk_time - Send virtchnl adj device clock time message
 * @adapter: Driver specific private structure
 * @delta: Offset in nanoseconds to adjust the time by
 *
 * Send virtchnl adj time message to adjust the clock by the indicated delta.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_adj_dev_clk_time(struct idpf_adapter *adapter, int64_t delta)
{
	struct virtchnl2_ptp_adj_dev_clk_time adj_dev_clk_time_msg = { };
	struct idpf_cmd_info args = { };
	int err;

	adj_dev_clk_time_msg.delta = CPU_TO_LE64(delta);

	args.ops = VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_TIME;
	args.in_args = (uint8_t *)&adj_dev_clk_time_msg;
	args.in_args_size = sizeof(adj_dev_clk_time_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(adj_dev_clk_time_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	return err;
}

/**
 * idpf_ptp_adj_dev_clk_fine - Send virtchnl adj time message
 * @adapter: Driver specific private structure
 * @incval: Source timer increment value per clock cycle
 *
 * Send virtchnl adj fine message to adjust the frequency of the clock by
 * incval.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_adj_dev_clk_fine(struct idpf_adapter *adapter, u64 incval)
{
	struct virtchnl2_ptp_adj_dev_clk_fine adj_dev_clk_fine_msg = { };
	struct idpf_cmd_info args = { };
	int err;

	adj_dev_clk_fine_msg.incval = CPU_TO_LE64(incval);

	args.ops = VIRTCHNL2_OP_PTP_ADJ_DEV_CLK_FINE;
	args.in_args = (uint8_t *)&adj_dev_clk_fine_msg;
	args.in_args_size = sizeof(adj_dev_clk_fine_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = sizeof(adj_dev_clk_fine_msg);

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err < 0)
		return err;

	return err;
}

/**
 * idpf_ptp_get_vport_tstamps_caps - Send virtchnl to get tstamps caps for vport
 * @vport: Virtual port structure
 *
 * Send virtchnl get vport tstamps caps message to receive the set of tstamp
 * capabilities per vport.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_get_vport_tstamps_caps(struct idpf_vport *vport)
{
	struct virtchnl2_ptp_get_vport_tx_tstamp_caps send_tx_tstamp_caps = { };
	struct virtchnl2_ptp_get_vport_tx_tstamp_caps *rcv_tx_tstamp_caps;
	struct virtchnl2_ptp_tx_tstamp_latch_caps tx_tstamp_latch_caps;
	enum idpf_ptp_access tstamp_access, get_dev_clk_access;
	struct idpf_ptp_vport_tx_tstamp_caps *tstamp_caps;
	struct idpf_ptp *ptp = vport->adapter->ptp;
	struct idpf_cmd_info args = { };
	int err;
	u16 num_latches, i;
	u32 size;

	if (ptp == NULL)
		return -EOPNOTSUPP;

	tstamp_access = (enum idpf_ptp_access)ptp->tx_tstamp_access;
	get_dev_clk_access = (enum idpf_ptp_access)ptp->get_dev_clk_time_access;
	if (tstamp_access == IDPF_PTP_NONE ||
	    get_dev_clk_access == IDPF_PTP_NONE)
		return -EOPNOTSUPP;

	send_tx_tstamp_caps.vport_id = CPU_TO_LE32(vport->vport_id);

	args.ops = VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP_CAPS;
	args.in_args = (uint8_t *)&send_tx_tstamp_caps;
	args.in_args_size = sizeof(send_tx_tstamp_caps);
	args.out_size = IDPF_CTLQ_MAX_BUF_LEN;
	args.out_buffer = vport->adapter->mbx_resp;

	err = idpf_vc_cmd_execute(vport->adapter, &args);
	if (err < 0)
		return err;

	rcv_tx_tstamp_caps = (struct virtchnl2_ptp_get_vport_tx_tstamp_caps *)
			     args.out_buffer;
	num_latches = LE16_TO_CPU(rcv_tx_tstamp_caps->num_latches);
	size = sizeof(struct idpf_ptp_vport_tx_tstamp_caps) +
	       sizeof(struct idpf_ptp_tx_tstamp) * num_latches;
	tstamp_caps = rte_zmalloc(NULL, size, 0);
	if (tstamp_caps == NULL)
		return -ENOMEM;

	tstamp_caps->access = true;
	tstamp_caps->num_entries = num_latches;

	tstamp_caps->tstamp_ns_lo_bit = rcv_tx_tstamp_caps->tstamp_ns_lo_bit;

	for (i = 0; i < tstamp_caps->num_entries; i++) {
		__le32 offset_l, offset_h;

		tx_tstamp_latch_caps = rcv_tx_tstamp_caps->tstamp_latches[i];

		if (tstamp_access == IDPF_PTP_DIRECT) {
			offset_l = tx_tstamp_latch_caps.tx_latch_reg_offset_l;
			offset_h = tx_tstamp_latch_caps.tx_latch_reg_offset_h;
			tstamp_caps->tx_tstamp[i].tx_latch_reg_offset_l = LE32_TO_CPU(offset_l);
			tstamp_caps->tx_tstamp[i].tx_latch_reg_offset_h = LE32_TO_CPU(offset_h);
		}
		tstamp_caps->tx_tstamp[i].idx = tx_tstamp_latch_caps.index;
	}

	tstamp_caps->latched_idx = -1;
	vport->tx_tstamp_caps = tstamp_caps;

	return err;
}

/**
 * idpf_ptp_get_tstamp_value - Get the Tx timestamp value and provide it
 *			       back to the skb.
 * @vport: Virtual port structure
 * @tstamp_latch: Tx timestamp latch structure fulfilled by the Control Plane
 * @tx_tstamp: Tx timestamp structure to be fulfilled with the timestamp value
 *
 * Read the value of the Tx timestamp for a given latch received from the
 * Control Plane.
 *
 * Return: 0 on success, -errno otherwise.
 */
static int
idpf_ptp_get_tstamp_value(struct idpf_vport *vport,
			  struct virtchnl2_ptp_tx_tstamp_latch *tstamp_latch,
			  struct idpf_ptp_tx_tstamp *tx_tstamp)
{
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	u8 tstamp_ns_lo_bit;

	tx_tstamp_caps = vport->tx_tstamp_caps;
	tstamp_ns_lo_bit = tx_tstamp_caps->tstamp_ns_lo_bit;

	tx_tstamp->tstamp = LE64_TO_CPU(tstamp_latch->tstamp);
	tx_tstamp->tstamp >>= tstamp_ns_lo_bit;

	return 0;
}

/**
 * idpf_ptp_get_tx_tstamp - Send virtchnl get Tx timestamp latches message
 * @vport: Virtual port structure
 *
 * Send virtchnl get Tx tstamp message to read the value of the HW timestamp.
 * The message contains a list of indexes set in the Tx descriptors.
 *
 * Return: 0 on success, -errno otherwise.
 */
int idpf_ptp_get_tx_tstamp(struct idpf_vport *vport)
{
	struct virtchnl2_ptp_get_vport_tx_tstamp_latches *send_tx_tstamp_msg;
	struct virtchnl2_ptp_get_vport_tx_tstamp_latches *recv_tx_tstamp_msg;
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	struct virtchnl2_ptp_tx_tstamp_latch tstamp_latch;
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp;
	struct idpf_cmd_info args = { };
	int size, msg_size;
	u32 vport_id;
	u16 num_latches, id;
	int err;

	tx_tstamp_caps = vport->tx_tstamp_caps;
	ptp_tx_tstamp = tx_tstamp_caps->tx_tstamp;

	size = sizeof(struct virtchnl2_ptp_get_vport_tx_tstamp_latches) +
	      sizeof(struct virtchnl2_ptp_tx_tstamp_latch) *
	      tx_tstamp_caps->num_entries;
	send_tx_tstamp_msg = rte_zmalloc(NULL, size, 0);
	if (send_tx_tstamp_msg == NULL)
		return -ENOMEM;

	for (id = 0; id < tx_tstamp_caps->num_entries; id++,
		ptp_tx_tstamp++)
		send_tx_tstamp_msg->tstamp_latches[id].index =
										ptp_tx_tstamp->idx;
	send_tx_tstamp_msg->get_devtime_with_txtstmp = 1;

	msg_size = sizeof(struct virtchnl2_ptp_get_vport_tx_tstamp_latches) +
		   sizeof(struct virtchnl2_ptp_tx_tstamp_latch) * id;
	send_tx_tstamp_msg->vport_id = CPU_TO_LE32(vport->vport_id);
	send_tx_tstamp_msg->num_latches = CPU_TO_LE16(id);

	args.ops = VIRTCHNL2_OP_PTP_GET_VPORT_TX_TSTAMP;
	args.in_args = (uint8_t *)send_tx_tstamp_msg;
	args.in_args_size = msg_size;
	args.out_size = msg_size;
	args.out_buffer = vport->adapter->mbx_resp;

	err = idpf_vc_cmd_execute(vport->adapter, &args);
	rte_free(send_tx_tstamp_msg);
	if (err < 0)
		return err;

	recv_tx_tstamp_msg = (struct virtchnl2_ptp_get_vport_tx_tstamp_latches *)
			     args.out_buffer;
	vport_id = LE32_TO_CPU(recv_tx_tstamp_msg->vport_id);
	if (vport->vport_id != vport_id)
		return -EINVAL;

	num_latches = LE16_TO_CPU(recv_tx_tstamp_msg->num_latches);

	ptp_tx_tstamp = tx_tstamp_caps->tx_tstamp;
	for (id = 0; id < num_latches; id++, ptp_tx_tstamp++) {
		tstamp_latch = recv_tx_tstamp_msg->tstamp_latches[id];

		if (!tstamp_latch.valid)
			continue;

		err = idpf_ptp_get_tstamp_value(vport, &tstamp_latch,
						ptp_tx_tstamp);
		if (err == 0) {
			tx_tstamp_caps->latched_idx = id;
			vport->adapter->time_hw = recv_tx_tstamp_msg->device_time;
		}
		break;
	}
	return err;
}

/**
 * idpf_ptp_read_src_clk_reg_direct - Read directly the main timer value
 * @adapter: Driver specific private structure
 *
 * Return: the device clock time.
 */
static u64 idpf_ptp_read_src_clk_reg_direct(struct idpf_adapter *adapter)
{
	struct idpf_ptp *ptp = adapter->ptp;
	u32 hi, lo;

	idpf_ptp_enable_shtime(adapter);

	lo = IDPF_PCI_REG(ptp->dev_clk_regs.dev_clk_ns_l);
	hi = IDPF_PCI_REG(ptp->dev_clk_regs.dev_clk_ns_h);

	return ((u64)hi << 32) | lo;
}

/**
 * idpf_ptp_read_src_clk_reg_mailbox - Read the main timer value through mailbox
 * @adapter: Driver specific private structure
 * @src_clk: Returned main timer value in nanoseconds unit
 *
 * Return: 0 on success, -errno otherwise.
 */
static int idpf_ptp_read_src_clk_reg_mailbox(struct idpf_adapter *adapter,
					     u64 *src_clk)
{
	struct idpf_ptp_dev_timers clk_time;
	int err;

	err = idpf_ptp_get_dev_clk_time(adapter, &clk_time);
	if (err)
		return err;

	*src_clk = clk_time.dev_clk_time_ns;

	return 0;
}

/**
 * idpf_ptp_read_src_clk_reg - Read the main timer value
 * @adapter: Driver specific private structure
 * @src_clk: Returned main timer value in nanoseconds unit
 *
 * Return: the device clock time on success, -errno otherwise.
 */
int idpf_ptp_read_src_clk_reg(struct idpf_adapter *adapter, u64 *src_clk)
{
	if (adapter->ptp == NULL)
		return 0;
	switch ((enum idpf_ptp_access)adapter->ptp->get_dev_clk_time_access) {
	case IDPF_PTP_NONE:
		return -EOPNOTSUPP;
	case IDPF_PTP_MAILBOX:
		return idpf_ptp_read_src_clk_reg_mailbox(adapter, src_clk);
	case IDPF_PTP_DIRECT:
		*src_clk = idpf_ptp_read_src_clk_reg_direct(adapter);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
