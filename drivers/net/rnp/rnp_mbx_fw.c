#include <linux/wait.h>
#include <stdio.h>

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

static int
rnp_mbx_write_posted_locked(struct rte_eth_dev *dev, struct mbx_fw_cmd_req *req)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	int err = 0;

	rte_spinlock_lock(&hw->fw_lock);

	err = ops->write_posted(dev, (u32 *)req,
			(req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		RNP_PMD_LOG(ERR, "%s failed!\n", __func__);
		goto quit;
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

int
rnp_fw_get_macaddr(struct rte_eth_dev *dev,
		   int pfvfnum,
		   u8 *mac_addr,
		   int nr_lane)
{
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	struct mac_addr *mac;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	if (!mac_addr)
		return -EINVAL;

	if (hw->mbx.irq_enabled) {
		cookie = rnp_memzone_reserve(hw->cookie_p_name, 0);
		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		mac = (struct mac_addr *)cookie->priv;
		build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, cookie);
		err = rnp_mbx_fw_post_req(dev, &req, cookie);
		if (err)
			goto quit;

		if ((1 << nr_lane) & mac->lanes) {
			memcpy(mac_addr, mac->addrs[nr_lane].mac, 6);
			err = 0;
		} else {
			err = -ENODATA;
		}
quit:
		return err;
	}
	build_get_macaddress_req(&req, 1 << nr_lane, pfvfnum, &req);
	err = rnp_fw_send_cmd_wait(dev, &req, &reply);
	if (err) {
		RNP_PMD_LOG(ERR, "%s: failed. err:%d\n", __func__, err);
		return err;
	}

	if ((1 << nr_lane) & reply.mac_addr.lanes) {
		memcpy(mac_addr, reply.mac_addr.addrs[nr_lane].mac, 6);
		return 0;
	}

	return -ENODATA;
}

int rnp_mbx_get_lane_stat(struct rte_eth_dev *dev)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);
	struct rnp_phy_meta *phy_meta = &port->attr.phy_meta;
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct lane_stat_data *lane_stat;
	int nr_lane = port->attr.nr_lane;
	struct mbx_req_cookie *cookie;
	struct mbx_fw_cmd_reply reply;
	struct mbx_fw_cmd_req req;
	int err = 0;

	memset(&req, 0, sizeof(req));

	if (hw->mbx.irq_enabled) {
		cookie = rnp_memzone_reserve(hw->cookie_p_name, 0);

		if (!cookie)
			return -ENOMEM;
		memset(cookie->priv, 0, cookie->priv_len);
		lane_stat = (struct lane_stat_data *)cookie->priv;
		build_get_lane_status_req(&req, nr_lane, cookie);
		err = rnp_mbx_fw_post_req(dev, &req, cookie);
		if (err)
			goto quit;
	} else {
		memset(&reply, 0, sizeof(reply));
		build_get_lane_status_req(&req, nr_lane, &req);
		err = rnp_fw_send_cmd_wait(dev, &req, &reply);
		if (err)
			goto quit;
		lane_stat = (struct lane_stat_data *)reply.data;
	}

	phy_meta->supported_link = lane_stat->supported_link;
	phy_meta->is_backplane = lane_stat->is_backplane;
	phy_meta->phy_identifier = lane_stat->phy_addr;
	phy_meta->link_autoneg = lane_stat->autoneg;
	phy_meta->link_duplex = lane_stat->duplex;
	phy_meta->phy_type = lane_stat->phy_type;
	phy_meta->is_sgmii = lane_stat->is_sgmii;
	phy_meta->fec = lane_stat->fec;

	if (phy_meta->is_sgmii) {
		phy_meta->media_type = RNP_MEDIA_TYPE_COPPER;
		phy_meta->supported_link |=
			RNP_SPEED_CAP_100M_HALF | RNP_SPEED_CAP_10M_HALF;
	} else if (phy_meta->is_backplane) {
		phy_meta->media_type = RNP_MEDIA_TYPE_BACKPLANE;
	} else {
		phy_meta->media_type = RNP_MEDIA_TYPE_FIBER;
	}

	return 0;
quit:
	return err;
}

static int rnp_maintain_req(struct rte_eth_dev *dev,
		int cmd,
		int arg0,
		int req_data_bytes,
		int reply_bytes,
		phys_addr_t dma_phy_addr)
{
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_req req;
	int err;

	if (!hw->mbx.irq_enabled)
		return -EIO;
	cookie = rnp_memzone_reserve(hw->cookie_p_name, 0);
	if (!cookie)
		return -ENOMEM;
	memset(&req, 0, sizeof(req));
	cookie->timeout_ms = 60 * 1000; /* 60s */

	build_maintain_req(&req,
			cookie,
			cmd,
			arg0,
			req_data_bytes,
			reply_bytes,
			dma_phy_addr & 0xffffffff,
			(dma_phy_addr >> 32) & 0xffffffff);

	err = rnp_mbx_fw_post_req(dev, &req, cookie);

	return (err) ? -EIO : 0;
}

int rnp_fw_update(struct rnp_eth_adapter *adapter)
{
	const struct rte_memzone *rz = NULL;
	struct maintain_req *mt;
	FILE *file;
	int fsz;
#define MAX_FW_BIN_SZ (552 * 1024)
#define FW_256KB          (256 * 1024)

	RNP_PMD_LOG(INFO, "%s: %s\n", __func__, adapter->fw_path);

	file = fopen(adapter->fw_path, "rb");
	if (!file) {
		RNP_PMD_LOG(ERR,
				"RNP: [%s] %s can't open for read\n",
				__func__,
				adapter->fw_path);
		return -ENOENT;
	}
	/* get dma */
	rz = rte_memzone_reserve("fw_update", MAX_FW_BIN_SZ, SOCKET_ID_ANY, 4);
	if (rz == NULL) {
		RNP_PMD_LOG(ERR, "RNP: [%s] not memory:%d\n", __func__,
				MAX_FW_BIN_SZ);
		return -EFBIG;
	}
	memset(rz->addr, 0xff, rz->len);
	mt = (struct maintain_req *)rz->addr;

	/* read data */
	fsz = fread(mt->data, 1, rz->len, file);
	if (fsz <= 0) {
		RNP_PMD_LOG(INFO, "RNP: [%s] read failed! err:%d\n",
				__func__, fsz);
		return -EIO;
	}
	fclose(file);

	if (fsz > ((256 + 4) * 1024)) {
		printf("fw length:%d is two big. not supported!\n", fsz);
		return -EINVAL;
	}
	RNP_PMD_LOG(NOTICE, "RNP: fw update ...\n");
	fflush(stdout);

	/* ==== update fw */
	mt->magic       = MAINTAIN_MAGIC;
	mt->cmd         = MT_WRITE_FLASH;
	mt->arg0        = 1;
	mt->req_data_bytes = (fsz > FW_256KB) ? FW_256KB : fsz;
	mt->reply_bytes = 0;

	if (rnp_maintain_req(adapter->eth_dev, mt->cmd, mt->arg0,
				mt->req_data_bytes, mt->reply_bytes, rz->iova))
		RNP_PMD_LOG(ERR, "maintain request failed!\n");
	else
		RNP_PMD_LOG(INFO, "maintail request done!\n");

	/* ==== update cfg */
	if (fsz > FW_256KB) {
		mt->magic       = MAINTAIN_MAGIC;
		mt->cmd         = MT_WRITE_FLASH;
		mt->arg0        = 2;
		mt->req_data_bytes = 4096;
		mt->reply_bytes    = 0;
		memcpy(mt->data, mt->data + FW_256KB, mt->req_data_bytes);

		if (rnp_maintain_req(adapter->eth_dev,
					mt->cmd, mt->arg0, mt->req_data_bytes,
					mt->reply_bytes, rz->iova))
			RNP_PMD_LOG(ERR, "maintain request failed!\n");
		else
			RNP_PMD_LOG(INFO, "maintail request done!\n");
	}

	RNP_PMD_LOG(NOTICE, "done\n");
	fflush(stdout);

	rte_memzone_free(rz);

	exit(0);

	return 0;
}

static int rnp_mbx_set_dump(struct rte_eth_dev *dev, int flag)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);
	struct mbx_fw_cmd_req req;
	int err;

	memset(&req, 0, sizeof(req));
	build_set_dump(&req, port->attr.nr_lane, flag);

	err = rnp_mbx_write_posted_locked(dev, &req);

	return err;
}

int rnp_hw_set_fw_10g_1g_auto_detch(struct rte_eth_dev *dev, int enable)
{
	return rnp_mbx_set_dump(dev, 0x01140000 | (enable & 1));
}

int rnp_hw_set_fw_force_speed_1g(struct rte_eth_dev *dev, int enable)
{
	return rnp_mbx_set_dump(dev, 0x01150000 | (enable & 1));
}
