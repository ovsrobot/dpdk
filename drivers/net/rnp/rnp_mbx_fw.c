#include <stdio.h>
#include <error.h>

#include <rte_version.h>
#include <ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_alarm.h>

#include "rnp.h"
#include "rnp_mbx.h"
#include "rnp_mbx_fw.h"
#include "rnp_logs.h"

static int
rnp_fw_send_cmd_wait(struct rte_eth_dev *dev, struct mbx_fw_cmd_req *req,
		     struct mbx_fw_cmd_reply *reply)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	int err;

	rte_spinlock_lock(&hw->fw_lock);

	err = ops->write_posted(dev, (u32 *)req,
			(req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		RNP_PMD_LOG(ERR, "%s: write_posted failed! err:0x%x\n",
				__func__, err);
		rte_spinlock_unlock(&hw->fw_lock);
		return err;
	}

	err = ops->read_posted(dev, (u32 *)reply, sizeof(*reply) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);
	if (err) {
		RNP_PMD_LOG(ERR,
				"%s: read_posted failed! err:0x%x. "
				"req-op:0x%x\n",
				__func__,
				err,
				req->opcode);
		goto err_quit;
	}

	if (reply->error_code) {
		RNP_PMD_LOG(ERR,
				"%s: reply err:0x%x. req-op:0x%x\n",
				__func__,
				reply->error_code,
				req->opcode);
		err = -reply->error_code;
		goto err_quit;
	}

	return 0;
err_quit:
	RNP_PMD_LOG(ERR,
			"%s:PF[%d]: req:%08x_%08x_%08x_%08x "
			"reply:%08x_%08x_%08x_%08x\n",
			__func__,
			hw->function,
			((int *)req)[0],
			((int *)req)[1],
			((int *)req)[2],
			((int *)req)[3],
			((int *)reply)[0],
			((int *)reply)[1],
			((int *)reply)[2],
			((int *)reply)[3]);

	return err;
}

static int rnp_mbx_fw_post_req(struct rte_eth_dev *dev,
			       struct mbx_fw_cmd_req *req,
			       struct mbx_req_cookie *cookie)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	int err = 0;
	int timeout_cnt;
#define WAIT_MS 10

	cookie->done = 0;

	rte_spinlock_lock(&hw->fw_lock);

	/* down_interruptible(&pf_cpu_lock); */
	err = ops->write(hw, (u32 *)req,
			(req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		RNP_PMD_LOG(ERR, "rnp_write_mbx failed!\n");
		goto quit;
	}

	timeout_cnt = cookie->timeout_ms / WAIT_MS;
	while (timeout_cnt > 0) {
		rte_delay_ms(WAIT_MS);
		timeout_cnt--;
		if (cookie->done)
			break;
	}

quit:
	rte_spinlock_unlock(&hw->fw_lock);
	return err;
}

static int rnp_fw_get_capablity(struct rte_eth_dev *dev,
				struct phy_abilities *abil)
{
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_phy_abalities_req(&req, &req);

	err = rnp_fw_send_cmd_wait(dev, &req, &reply);
	if (err)
		return err;

	memcpy(abil, &reply.phy_abilities, sizeof(*abil));

	return 0;
}

#define RNP_MBX_API_MAX_RETRY (10)
int rnp_mbx_get_capability(struct rte_eth_dev *dev,
			   int *lane_mask,
			   int *nic_mode)
{
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct phy_abilities ablity;
	uint16_t temp_lmask;
	uint16_t lane_bit = 0;
	uint16_t retry = 0;
	int lane_cnt = 0;
	uint8_t lane_idx;
	int err = -EIO;
	uint8_t idx;

	memset(&ablity, 0, sizeof(ablity));

	/* enable CM3CPU to PF MBX IRQ */
	do {
		err = rnp_fw_get_capablity(dev, &ablity);
		if (retry > RNP_MBX_API_MAX_RETRY)
			break;
		retry++;
	} while (err);
	if (!err) {
		hw->lane_mask = ablity.lane_mask;
		hw->nic_mode = ablity.nic_mode;
		hw->pfvfnum = ablity.pfnum;
		hw->fw_version = ablity.fw_version;
		hw->axi_mhz = ablity.axi_mhz;
		hw->fw_uid = ablity.fw_uid;
		if (ablity.phy_type == PHY_TYPE_SGMII) {
			hw->is_sgmii = 1;
			hw->sgmii_phy_id = ablity.phy_id;
		}

		if (ablity.ext_ablity != 0xffffffff && ablity.e.valid) {
			hw->ncsi_en = (ablity.e.ncsi_en == 1);
			hw->ncsi_rar_entries = 1;
		}

		if (hw->nic_mode == RNP_SINGLE_10G &&
				hw->fw_version >= 0x00050201 &&
				ablity.speed == RTE_ETH_SPEED_NUM_10G) {
			hw->force_speed_stat = FORCE_SPEED_STAT_DISABLED;
			hw->force_10g_1g_speed_ablity = 1;
		}

		if (lane_mask)
			*lane_mask = hw->lane_mask;
		if (nic_mode)
			*nic_mode = hw->nic_mode;

		lane_cnt = __builtin_popcount(hw->lane_mask);
		temp_lmask = hw->lane_mask;
		for (idx = 0; idx < lane_cnt; idx++) {
			hw->phy_port_ids[idx] = ablity.port_ids[idx];
			lane_bit = ffs(temp_lmask) - 1;
			lane_idx = ablity.port_ids[idx] % lane_cnt;
			hw->lane_of_port[lane_idx] = lane_bit;
			temp_lmask &= ~BIT(lane_bit);
		}
		hw->max_port_num = lane_cnt;
	}

	RNP_PMD_LOG(INFO,
			"%s: nic-mode:%d lane_cnt:%d lane_mask:0x%x "
			"pfvfnum:0x%x, fw_version:0x%08x, ports:%d-%d-%d-%d ncsi:en:%d\n",
			__func__,
			hw->nic_mode,
			lane_cnt,
			hw->lane_mask,
			hw->pfvfnum,
			ablity.fw_version,
			ablity.port_ids[0],
			ablity.port_ids[1],
			ablity.port_ids[2],
			ablity.port_ids[3],
			hw->ncsi_en);

	if (lane_cnt <= 0 || lane_cnt > 4)
		return -EIO;

	return err;
}

int rnp_mbx_link_event_enable(struct rte_eth_dev *dev, int enable)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err, v;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	rte_spinlock_lock(&hw->fw_lock);
	if (enable) {
		v = rnp_rd_reg(hw->link_sync);
		v &= ~RNP_FIRMWARE_SYNC_MASK;
		v |= RNP_FIRMWARE_SYNC_MAGIC;
		rnp_wr_reg(hw->link_sync, v);
	} else {
		rnp_wr_reg(hw->link_sync, 0);
	}
	rte_spinlock_unlock(&hw->fw_lock);

	build_link_set_event_mask(&req, BIT(EVT_LINK_UP),
			(enable & 1) << EVT_LINK_UP, &req);

	rte_spinlock_lock(&hw->fw_lock);
	err = ops->write_posted(dev, (u32 *)&req,
			(req.datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	rte_spinlock_unlock(&hw->fw_lock);

	rte_delay_ms(200);

	return err;
}

int rnp_mbx_fw_reset_phy(struct rte_eth_dev *dev)
{
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct mbx_fw_cmd_reply reply;
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (hw->mbx.irq_enabled) {
		cookie = rnp_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		build_reset_phy_req(&req, cookie);
		return rnp_mbx_fw_post_req(dev, &req, cookie);
	}
	build_reset_phy_req(&req, &req);

	return rnp_fw_send_cmd_wait(dev, &req, &reply);
}
