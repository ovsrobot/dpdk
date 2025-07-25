/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include "sxevf.h"
#include "sxevf_msg.h"
#include "sxevf_hw.h"
#include "sxe_errno.h"
#include "sxe_logs.h"

#define SXEVF_PFMSG_MASK	0xFF00
#define SXEVF_DEFAULT_TC_NUM		1

void sxevf_mbx_init(struct sxevf_hw *hw)
{
	hw->mbx.msg_len = SXEVF_MBX_MSG_NUM;

	hw->mbx.stats.rcv_msgs = 0;
	hw->mbx.stats.send_msgs = 0;
	hw->mbx.stats.acks = 0;
	hw->mbx.stats.reqs = 0;
	hw->mbx.stats.rsts = 0;

	hw->mbx.retry = 0;
	hw->mbx.interval = SXEVF_MBX_RETRY_INTERVAL;

	hw->mbx.api_version = SXEVF_MBX_API_10;
}

static u32 sxevf_mbx_reg_read(struct sxevf_hw *hw)
{
	u32 value = sxevf_mailbox_read(hw);

	value |= hw->mbx.reg_value;

	hw->mbx.reg_value |= value & SXE_VFMAILBOX_RC_BIT;

	return value;
}

static bool sxevf_mbx_bit_check(struct sxevf_hw *hw, u32 mask)
{
	bool ret = false;
	u32 value = sxevf_mbx_reg_read(hw);

	if (value & mask)
		ret = true;

	hw->mbx.reg_value &= ~mask;

	return ret;
}

static bool sxevf_pf_msg_check(struct sxevf_hw *hw)
{
	bool ret = false;

	if (sxevf_mbx_bit_check(hw, SXE_VFMAILBOX_PFSTS)) {
		hw->mbx.stats.reqs++;
		ret = true;
	}

	return ret;
}

static bool sxevf_pf_ack_check(struct sxevf_hw *hw)
{
	bool ret = false;

	if (sxevf_mbx_bit_check(hw, SXE_VFMAILBOX_PFACK)) {
		hw->mbx.stats.acks++;
		ret = true;
	}

	return ret;
}

bool sxevf_pf_rst_check(struct sxevf_hw *hw)
{
	bool ret = false;

	if (!sxevf_mbx_bit_check(hw, (SXE_VFMAILBOX_RSTI |
					  SXE_VFMAILBOX_RSTD))) {
		hw->mbx.stats.rsts++;
		ret = true;
	}

	return ret;
}

static s32 sxevf_mailbox_lock(struct sxevf_hw *hw)
{
	u32 mailbox;
	u32 retry = SXEVF_MBX_RETRY_COUNT;
	s32 ret = -SXEVF_ERR_MBX_LOCK_FAIL;

	while (retry--) {
		mailbox = sxevf_mbx_reg_read(hw);
		mailbox |= SXE_VFMAILBOX_VFU;
		sxevf_mailbox_write(hw, mailbox);

		if (sxevf_mbx_reg_read(hw) & SXE_VFMAILBOX_VFU) {
			ret = 0;
			break;
		}

		sxe_udelay(hw->mbx.interval);
	}

	return ret;
}

static void sxevf_mailbox_unlock(struct sxevf_hw *hw)
{
	u32 mailbox;

	mailbox = sxevf_mbx_reg_read(hw);
	mailbox &= ~SXE_VFMAILBOX_VFU;
	sxevf_mailbox_write(hw, mailbox);
}

static bool sxevf_msg_poll(struct sxevf_hw *hw)
{
	struct sxevf_mbx_info *mbx = &hw->mbx;
	u32 retry = mbx->retry;
	bool ret = true;
	struct sxevf_adapter *adapter = hw->adapter;

	while (!sxevf_pf_msg_check(hw) && retry) {
		retry--;
		sxe_udelay(mbx->interval);
	}

	if (!retry) {
		LOG_ERROR_BDF("retry:%d send msg to pf done, but don't check pf reply.",
			  mbx->retry);
		mbx->retry = 0;
		ret = false;
	}

	return ret;
}

static bool sxevf_ack_poll(struct sxevf_hw *hw)
{
	struct sxevf_mbx_info *mbx = &hw->mbx;
	u32 retry = mbx->retry;
	bool ret = true;
	struct sxevf_adapter *adapter = hw->adapter;

	while (!sxevf_pf_ack_check(hw) && retry) {
		retry--;
		sxe_udelay(mbx->interval);
	}

	if (!retry) {
		LOG_ERROR_BDF("send msg to pf, retry:%d but don't check pf ack, "
			  "init mbx retry to 0.",
			  mbx->retry);
		mbx->retry = 0;
		ret = false;
	}

	return ret;
}

static void sxevf_pf_msg_and_ack_clear(struct sxevf_hw *hw)
{
	struct sxevf_adapter *adapter = hw->adapter;

	LOG_INFO_BDF("clear pending pf msg and ack.");

	sxevf_pf_msg_check(hw);
	sxevf_pf_ack_check(hw);
}

static s32 sxevf_send_msg_to_pf(struct sxevf_hw *hw, u32 *msg, u16 msg_len)
{
	struct sxevf_mbx_info *mbx = &hw->mbx;
	s32 ret = 0;
	u16 i;
	u32 old;
	struct sxevf_adapter *adapter = hw->adapter;

	if (!mbx->retry) {
		ret = -SXEVF_ERR_NOT_READY;
		LOG_ERROR_BDF("msg:0x%x len:%d send fail due to timeout.(err:%d)",
			  msg[0], msg_len, ret);
		goto l_out;
	}

	if (msg_len > mbx->msg_len) {
		ret = -EINVAL;
		LOG_ERROR_BDF("vf msg:0x%x len:%d exceed limit:%d "
			  "send fail.(err:%d)",
			  msg[0], msg_len, mbx->msg_len, ret);
		goto l_out;
	}

	ret = sxevf_mailbox_lock(hw);
	if (ret) {
		LOG_ERROR_BDF("msg:0x%x len:%d send lock mailbox fail.(err:%d)",
			   msg[0], msg_len, ret);
		goto l_out;
	}

	sxevf_pf_msg_and_ack_clear(hw);

	old = sxevf_msg_read(hw, 0);
	msg[0] |= (old & SXEVF_PFMSG_MASK);

	for (i = 0; i < msg_len; i++)
		sxevf_msg_write(hw, i, msg[i]);

	sxevf_pf_req_irq_trigger(hw);

	hw->mbx.stats.send_msgs++;

	if (!sxevf_ack_poll(hw)) {
		ret = -SXEVF_ERR_POLL_ACK_FAIL;
		LOG_ERROR_BDF("msg:0x%x len:%d send done, but don't poll ack.",
			   msg[0], msg_len);
		goto l_out;
	}

	LOG_INFO_BDF("vf send msg:0x%x len:%d to pf and polled pf ack done."
		 "stats send_msg:%d ack:%d.",
		 msg[0], msg_len,
		 mbx->stats.send_msgs, mbx->stats.acks);

l_out:
	return ret;
}

s32 sxevf_mbx_msg_rcv(struct sxevf_hw *hw, u32 *msg, u16 msg_len)
{
	u32 i;
	u16 msg_entry;
	s32 ret = 0;
	struct sxevf_mbx_info *mbx = &hw->mbx;
	struct sxevf_adapter *adapter = hw->adapter;

	msg_entry = (msg_len > mbx->msg_len) ? mbx->msg_len : msg_len;

	ret = sxevf_mailbox_lock(hw);
	if (ret) {
		LOG_ERROR_BDF("size:%d rcv lock mailbox fail.(err:%d)",
			   msg_entry, ret);
		goto l_end;
	}

	for (i = 0; i < msg_entry; i++)
		msg[i] = sxevf_msg_read(hw, i);

	msg[0] &= ~SXEVF_PFMSG_MASK;

	sxevf_pf_ack_irq_trigger(hw);

	mbx->stats.rcv_msgs++;
l_end:
	return ret;
}

s32 sxevf_ctrl_msg_rcv(struct sxevf_hw *hw, u32 *msg, u16 msg_len)
{
	u16 i;
	u16 msg_entry;
	s32 ret = 0;
	struct sxevf_mbx_info *mbx = &hw->mbx;
	struct sxevf_adapter *adapter = hw->adapter;

	msg_entry = (msg_len > mbx->msg_len) ? mbx->msg_len : msg_len;

	ret = sxevf_mailbox_lock(hw);
	if (ret) {
		LOG_ERROR_BDF("size:%d rcv lock mailbox fail.(err:%d)",
			   msg_entry, ret);
		goto l_end;
	}

	for (i = 0; i < msg_entry; i++)
		msg[i] = sxevf_msg_read(hw, i);

	sxevf_mailbox_unlock(hw);

	LOG_INFO_BDF("rcv pf mailbox msg:0x%x.", *msg);

	mbx->stats.rcv_msgs++;
l_end:
	return ret;
}

s32 sxevf_ctrl_msg_rcv_and_clear(struct sxevf_hw *hw, u32 *msg, u16 msg_len)
{
	u16 i;
	u16 msg_entry;
	s32 ret = 0;
	u32 clear;
	struct sxevf_mbx_info *mbx = &hw->mbx;
	struct sxevf_adapter *adapter = hw->adapter;

	msg_entry = (msg_len > mbx->msg_len) ? mbx->msg_len : msg_len;

	ret = sxevf_mailbox_lock(hw);
	if (ret) {
		LOG_ERROR_BDF("size:%d rcv lock mailbox fail.(err:%d)",
			   msg_entry, ret);
		goto l_end;
	}

	for (i = 0; i < msg_entry; i++)
		msg[i] = sxevf_msg_read(hw, i);

	clear = msg[0] & (~SXEVF_PFMSG_MASK);
	sxevf_msg_write(hw, 0, clear);

	sxevf_mailbox_unlock(hw);

	LOG_INFO_BDF("rcv pf mailbox msg:0x%x.", *msg);

	mbx->stats.rcv_msgs++;
l_end:
	return ret;
}

static s32 sxevf_rcv_msg_from_pf(struct sxevf_hw *hw, u32 *msg, u16 msg_len)
{
	s32 ret;
	struct sxevf_adapter *adapter = hw->adapter;

	if (!sxevf_msg_poll(hw)) {
		ret = -SXEVF_ERR_POLL_MSG_FAIL;
		LOG_ERROR_BDF("retry:%d don't poll pf msg.", hw->mbx.retry);
		goto l_out;
	}

	ret = sxevf_mbx_msg_rcv(hw, msg, msg_len);
	if (ret < 0) {
		LOG_ERROR_BDF("retry:%d read msg fail.", hw->mbx.retry);
		goto l_out;
	}

	LOG_INFO_BDF("vf polled pf msg:0x%x and rcv pf msg done. "
		"stats req:%d rcv_msg:%d",
		 msg[0], hw->mbx.stats.reqs, hw->mbx.stats.rcv_msgs);

l_out:
	return ret;
}

s32 sxevf_send_and_rcv_msg(struct sxevf_hw *hw, u32 *msg, u8 msg_len)
{
	s32 ret;
	u16 msg_type = msg[0] & 0xFF;
	struct sxevf_adapter *adapter = hw->adapter;

	ret = sxevf_send_msg_to_pf(hw, msg, msg_len);
	if (ret) {
		LOG_ERROR_BDF("msg:0x%x len:%u msg send fail.(err:%d).",
			   msg[0], msg_len, ret);
		goto l_out;
	}

	if (msg_type == SXEVF_RESET)
		mdelay(10);

	ret = sxevf_rcv_msg_from_pf(hw, msg, msg_len);
	if (ret) {
		LOG_ERROR_BDF("msg:0x%x len:%u rcv fail.(err:%d).",
			   msg[0], msg_len, ret);
		goto l_out;
	}

	LOG_INFO_BDF("send and rcv msg:0x%x len:%u success.", msg[0], msg_len);

l_out:
	return ret;
}

void sxevf_mbx_api_version_init(struct sxevf_adapter *adapter)
{
	s32 ret;
	struct sxevf_hw *hw = &adapter->hw;
	static const int api[] = {
		SXEVF_MBX_API_13,
		SXEVF_MBX_API_12,
		SXEVF_MBX_API_11,
		SXEVF_MBX_API_10,
		SXEVF_MBX_API_NR
	};
	u32 idx = 0;
	struct sxevf_mbx_api_msg msg;

	while (api[idx] != SXEVF_MBX_API_NR) {
		msg.msg_type = SXEVF_API_NEGOTIATE;
		msg.api_version = api[idx];

		ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg, SXEVF_MSG_NUM(sizeof(msg)));
		if (!ret && (msg.msg_type == (SXEVF_API_NEGOTIATE | SXEVF_MSGTYPE_ACK))) {
			hw->mbx.api_version = api[idx];
			break;
		}
		idx++;
	}

	LOG_INFO_BDF("mailbox api version:%u", hw->mbx.api_version);
}

s32 sxevf_ring_info_get(struct sxevf_adapter *adapter,
			u8 *tc_num, u8 *default_tc)
{
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_ring_info_msg req = {};
	s32 ret;

	req.msg_type = SXEVF_RING_INFO_GET;
	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&req,
					 SXEVF_MSG_NUM(sizeof(req)));
	if (ret) {
		LOG_ERROR_BDF("msg:0x%x send or rcv reply failed.(err:%d)",
			   req.msg_type, ret);
		goto l_out;
	}

	if (req.msg_type != (SXEVF_MSGTYPE_ACK | SXEVF_RING_INFO_GET)) {
		ret = -SXEVF_ERR_REPLY_INVALID;
		LOG_WARN_BDF("msg:0x%x not expected.(err:%d)", req.msg_type, ret);
		goto l_out;
	}

	LOG_DEBUG_BDF("original ring info from pf, max_tx_num:%u max_rx_num:%u "
		 "tc_num:%u default_tc:%u.",
		 req.max_tx_num, req.max_rx_num, req.tc_num, req.default_tc);

	if (req.max_tx_num == 0 ||
		req.max_tx_num > SXEVF_TXRX_RING_NUM_MAX) {
		req.max_tx_num = SXEVF_TXRX_RING_NUM_MAX;
	}

	if (req.max_rx_num == 0 ||
		req.max_rx_num > SXEVF_TXRX_RING_NUM_MAX) {
		req.max_rx_num = SXEVF_TXRX_RING_NUM_MAX;
	}

	if (req.tc_num > req.max_rx_num)
		req.tc_num = SXEVF_DEFAULT_TC_NUM;

	*tc_num = req.tc_num;

	if (req.default_tc > req.max_tx_num)
		req.default_tc = 0;

	*default_tc = req.default_tc;

	adapter->max_rx_queue = req.max_rx_num;
	adapter->max_tx_queue = req.max_tx_num;

	LOG_INFO_BDF("ring info max_tx_num:%u max_rx_num:%u "
		 "tc_num:%u default_tc:%u.",
		 req.max_tx_num, req.max_rx_num, req.tc_num, req.default_tc);

l_out:
	return ret;
}

s32 sxevf_rss_hash_config_get(struct sxevf_adapter *adapter,
			struct rte_eth_rss_conf *rss_conf)
{
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_rss_hash_msg msg = {};
	s32 ret;

	msg.msg_type = SXEVF_RSS_CONF_GET;
	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg,
					 SXEVF_MSG_NUM(sizeof(msg)));
	if (ret) {
		LOG_ERROR_BDF("msg:0x%x send or rcv reply failed.(err:%d)",
			   msg.msg_type, ret);
		goto l_out;
	}

	if (msg.msg_type != (SXEVF_MSGTYPE_ACK | SXEVF_RSS_CONF_GET)) {
		ret = -SXEVF_ERR_REPLY_INVALID;
		LOG_WARN_BDF("msg:0x%x not expected.(err:%d)", msg.msg_type, ret);
		goto l_out;
	}

	rss_conf->rss_key = msg.hash_key;
	rss_conf->rss_hf = msg.rss_hf;

	LOG_INFO_BDF("rss hash conf get success, msg:0x%x rss_key:%s rss_func:%" SXE_PRID64 ". ",
		 msg.msg_type, msg.hash_key, msg.rss_hf);

l_out:
	return ret;
}

s32 sxevf_mac_addr_set(struct sxevf_hw *hw, u8 *uc_addr)
{
	s32 ret;
	struct sxevf_uc_addr_msg msg = {};
	struct sxevf_adapter *adapter = hw->adapter;

	msg.msg_type = SXEVF_DEV_MAC_ADDR_SET;
	memcpy(msg.uc_addr, uc_addr, SXEVF_MAC_ADDR_LEN);

	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg, SXEVF_MSG_NUM(sizeof(msg)));
	if (!ret && (msg.msg_type ==
		   (SXEVF_DEV_MAC_ADDR_SET | SXEVF_MSGTYPE_NACK))) {
		ret = -EPERM;
		LOG_ERROR_BDF("msg:0x%x uc addr:%pM replyed nack.",
			   msg.msg_type, uc_addr);
		goto l_out;
	}

	if (ret) {
		LOG_ERROR_BDF("msg:0x%x uc addr:%pM set fail.(err:%d)",
			   msg.msg_type, uc_addr, ret);
		ret = -EPERM;
		goto l_out;
	}

	LOG_INFO_BDF("msg:0x%x uc addr:%pM set success.", msg.msg_type, uc_addr);

l_out:
	return ret;
}

s32 sxevf_rx_max_frame_set(struct sxevf_hw *hw, u32 mtu)
{
	struct sxevf_max_frame_msg msg = {};
	s32 ret;
	struct sxevf_adapter *adapter = hw->adapter;

	msg.msg_type = SXEVF_LPE_SET;
	msg.max_frame = mtu;

	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg,
						 SXEVF_MSG_NUM(sizeof(msg)));
	if (ret || ((msg.msg_type & SXEVF_LPE_SET) &&
			(msg.msg_type & SXEVF_MSGTYPE_NACK))) {
		ret = ret ? ret : -SXEVF_ERR_MSG_HANDLE_ERR;
	}

	LOG_INFO_BDF("msg_type:0x%x max_frame:0x%x (ret:%d)",
		   msg.msg_type, msg.max_frame, ret);

	return ret;
}

s32 sxevf_vlan_id_set(struct sxevf_hw *hw, u32 vlan_id,
						 bool vlan_on)
{
	struct sxevf_vlan_filter_msg msg = {};
	s32 ret;
	struct sxevf_adapter *adapter = hw->adapter;

	msg.msg_type = SXEVF_VLAN_SET;
	msg.vlan_id = vlan_id;
	msg.msg_type |= vlan_on << SXEVF_MSGINFO_SHIFT;

	LOG_INFO_BDF("update vlan[%u], vlan on = %s", vlan_id, vlan_on ? "yes" : "no");
	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg,
						 SXEVF_MSG_NUM(sizeof(msg)));
	LOG_INFO_BDF("update vlan[%u] ret = %d", vlan_id, ret);

	msg.msg_type &= ~(0xFF << SXEVF_MSGINFO_SHIFT);

	if (ret || (msg.msg_type != (SXEVF_VLAN_SET | SXEVF_MSGTYPE_ACK)))
		ret = ret ? ret : -SXEVF_ERR_MSG_HANDLE_ERR;

	return ret;
}

s32 sxevf_cast_mode_set(struct sxevf_hw *hw, enum sxevf_cast_mode mode)
{
	struct sxevf_cast_mode_msg msg = {};
	s32 ret;
	struct sxevf_adapter *adapter = hw->adapter;

	msg.msg_type = SXEVF_CAST_MODE_SET;
	msg.cast_mode = mode;

	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg, SXEVF_MSG_NUM(sizeof(msg)));
	if (ret || (msg.msg_type != (SXEVF_CAST_MODE_SET | SXEVF_MSGTYPE_ACK)))
		ret = ret ? ret : -SXEVF_ERR_MSG_HANDLE_ERR;

	LOG_INFO_BDF("msg_type:0x%x mode:0x%x msg result:0x%x.(ret:%d)",
		   msg.msg_type, mode, msg.msg_type, ret);

	return ret;
}

s32 sxevf_uc_addr_add(struct sxevf_hw *hw, u32 index, u8 *mac_addr)
{
	s32 ret = 0;
	struct sxevf_adapter *adapter = hw->adapter;
	struct sxevf_uc_sync_msg msg = {};
	u32 check;
	u32 result;

	msg.msg_type = SXEVF_UC_ADDR_SYNC;
	msg.index = index;
	check = *(u32 *)&msg;

	if (mac_addr)
		memcpy((u8 *)&msg.addr, mac_addr, SXEVF_MAC_ADDR_LEN);

	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg, SXEVF_MSG_NUM(sizeof(msg)));
	result = *(u32 *)&msg;

	if (ret || (result != (check | SXEVF_MSGTYPE_ACK)))
		ret = ret ? ret : -SXEVF_ERR_MSG_HANDLE_ERR;

	LOG_INFO_BDF("msg_type:0x%x index:%d addr:%pM sync done "
		 " result:0x%x msg.(ret:%d)",
		 msg.msg_type, index, mac_addr, result, ret);

	return ret;
}

#endif
