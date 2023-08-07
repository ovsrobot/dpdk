#include <rte_cycles.h>
#include <rte_log.h>

#include "rnp.h"
#include "rnp_hw.h"
#include "rnp_mbx.h"
#include "rnp_mbx_fw.h"
#include "rnp_logs.h"

#define RNP_MAX_VF_FUNCTIONS	(64)
/* == VEC == */
#define VF2PF_MBOX_VEC(VF)	(0xa5100 + 4 * (VF))
#define CPU2PF_MBOX_VEC		(0xa5300)

/* == PF <--> VF mailbox ==== */
#define SHARE_MEM_BYTES		(64) /* 64bytes */
/* for PF1 rtl will remap 6000 to 0xb000 */
#define PF_VF_SHM(vf)		((0xa6000) + (64 * (vf)))
#define PF2VF_COUNTER(vf)	(PF_VF_SHM(vf) + 0)
#define VF2PF_COUNTER(vf)	(PF_VF_SHM(vf) + 4)
#define PF_VF_SHM_DATA(vf)	(PF_VF_SHM(vf) + 8)
#define PF2VF_MBOX_CTRL(vf)	((0xa7100) + (4 * (vf)))
#define PF_VF_MBOX_MASK_LO	((0xa7200))
#define PF_VF_MBOX_MASK_HI	((0xa7300))

/* === CPU <--> PF === */
#define CPU_PF_SHM		(0xaa000)
#define CPU2PF_COUNTER		(CPU_PF_SHM + 0)
#define PF2CPU_COUNTER		(CPU_PF_SHM + 4)
#define CPU_PF_SHM_DATA		(CPU_PF_SHM + 8)
#define PF2CPU_MBOX_CTRL	(0xaa100)
#define CPU_PF_MBOX_MASK	(0xaa300)

/* === CPU <--> VF === */
#define CPU_VF_SHM(vf)		(0xa8000 + (64 * (vf)))
#define CPU2VF_COUNTER(vf)	(CPU_VF_SHM(vf) + 0)
#define VF2CPU_COUNTER(vf)	(CPU_VF_SHM(vf) + 4)
#define CPU_VF_SHM_DATA(vf)	(CPU_VF_SHM(vf) + 8)
#define VF2CPU_MBOX_CTRL(vf)	(0xa9000 + 64 * (vf))
#define CPU_VF_MBOX_MASK_LO(vf) (0xa9200 + 64 * (vf))
#define CPU_VF_MBOX_MASK_HI(vf) (0xa9300 + 64 * (vf))

#define MBOX_CTRL_REQ		(1 << 0)  /* WO */
/* VF:WR, PF:RO */
#define MBOX_CTRL_PF_HOLD_SHM	(1 << 3)  /* VF:RO, PF:WR */

#define MBOX_IRQ_EN		(0)
#define MBOX_IRQ_DISABLE	(1)

/****************************PF MBX OPS************************************/
static inline u16 rnp_mbx_get_req(struct rnp_hw *hw, int reg)
{
	rte_mb();
	return mbx_rd32(hw, reg) & 0xffff;
}

static inline u16 rnp_mbx_get_ack(struct rnp_hw *hw, int reg)
{
	rte_mb();
	return (mbx_rd32(hw, reg) >> 16) & 0xffff;
}

static inline void rnp_mbx_inc_pf_req(struct rnp_hw *hw, enum MBX_ID mbx_id)
{
	int reg = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_COUNTER : PF2VF_COUNTER(mbx_id);
	u32 v = mbx_rd32(hw, reg);
	u16 req;

	req = (v & 0xffff);
	req++;
	v &= ~(0x0000ffff);
	v |= req;

	rte_mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	/* hw->mbx.stats.msgs_tx++; */
}

static inline void rnp_mbx_inc_pf_ack(struct rnp_hw *hw, enum MBX_ID mbx_id)
{
	int reg = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_COUNTER : PF2VF_COUNTER(mbx_id);
	u32 v = mbx_rd32(hw, reg);
	u16 ack;

	ack = (v >> 16) & 0xffff;
	ack++;
	v &= ~(0xffff0000);
	v |= (ack << 16);

	rte_mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	/* hw->mbx.stats.msgs_rx++; */
}

/**
 *  rnp_poll_for_msg - Wait for message notification
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification
 **/
static int32_t rnp_poll_for_msg(struct rte_eth_dev *dev, enum MBX_ID mbx_id)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct rnp_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !ops->check_for_msg)
		goto out;

	while (countdown && ops->check_for_msg(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		rte_delay_us_block(mbx->usec_delay);
	}

out:
	return countdown ? 0 : -ETIMEDOUT;
}

/**
 *  rnp_poll_for_ack - Wait for message acknowledgment
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message acknowledgment
 **/
static int32_t rnp_poll_for_ack(struct rte_eth_dev *dev, enum MBX_ID mbx_id)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct rnp_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !ops->check_for_ack)
		goto out;

	while (countdown && ops->check_for_ack(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		rte_delay_us_block(mbx->usec_delay);
	}

out:
	return countdown ? 0 : -ETIMEDOUT;
}

/**
 *  rnp_read_posted_mbx - Wait for message notification and receive message
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification and
 *  copied it into the receive buffer.
 **/
static int32_t
rnp_read_posted_mbx_pf(struct rte_eth_dev *dev, u32 *msg, u16 size,
		       enum MBX_ID mbx_id)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct rnp_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;
	int32_t ret_val = -ETIMEDOUT;

	if (!ops->read || !countdown)
		return -EOPNOTSUPP;

	ret_val = rnp_poll_for_msg(dev, mbx_id);

	/* if ack received read message, otherwise we timed out */
	if (!ret_val)
		return ops->read(hw, msg, size, mbx_id);
	return ret_val;
}

/**
 *  rnp_write_posted_mbx - Write a message to the mailbox, wait for ack
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer and
 *  received an ack to that message within delay * timeout period
 **/
static int32_t
rnp_write_posted_mbx_pf(struct rte_eth_dev *dev, u32 *msg, u16 size,
			enum MBX_ID mbx_id)
{
	const struct rnp_mbx_api *ops = RNP_DEV_TO_MBX_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	struct rnp_mbx_info *mbx = &hw->mbx;
	int32_t ret_val = -ETIMEDOUT;

	/* exit if either we can't write or there isn't a defined timeout */
	if (!ops->write || !mbx->timeout)
		goto out;

	/* send msg and hold buffer lock */
	if (ops->write)
		ret_val = ops->write(hw, msg, size, mbx_id);

	/* if msg sent wait until we receive an ack */
	if (!ret_val)
		ret_val = rnp_poll_for_ack(dev, mbx_id);
out:
	return ret_val;
}

/**
 *  rnp_check_for_msg_pf - checks to see if the VF has sent mail
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static int32_t rnp_check_for_msg_pf(struct rnp_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIMEDOUT;

	if (mbx_id == MBX_CM3CPU) {
		if (rnp_mbx_get_req(hw, CPU2PF_COUNTER) != hw->mbx.cpu_req) {
			ret_val = 0;
			/* hw->mbx.stats.reqs++; */
		}
	} else {
		if (rnp_mbx_get_req(hw, VF2PF_COUNTER(mbx_id)) !=
				hw->mbx.vf_req[mbx_id]) {
			ret_val = 0;
			/* hw->mbx.stats.reqs++; */
		}
	}

	return ret_val;
}

/**
 *  rnp_check_for_ack_pf - checks to see if the VF has ACKed
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static int32_t rnp_check_for_ack_pf(struct rnp_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIMEDOUT;

	if (mbx_id == MBX_CM3CPU) {
		if (rnp_mbx_get_ack(hw, CPU2PF_COUNTER) != hw->mbx.cpu_ack) {
			ret_val = 0;
			/* hw->mbx.stats.acks++; */
		}
	} else {
		if (rnp_mbx_get_ack(hw, VF2PF_COUNTER(mbx_id)) != hw->mbx.vf_ack[mbx_id]) {
			ret_val = 0;
			/* hw->mbx.stats.acks++; */
		}
	}

	return ret_val;
}

/**
 *  rnp_obtain_mbx_lock_pf - obtain mailbox lock
 *  @hw: pointer to the HW structure
 *  @mbx_id: the VF index or CPU
 *
 *  return SUCCESS if we obtained the mailbox lock
 **/
static int32_t rnp_obtain_mbx_lock_pf(struct rnp_hw *hw, enum MBX_ID mbx_id)
{
	int32_t ret_val = -ETIMEDOUT;
	int try_cnt = 5000;  /* 500ms */
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);

	while (try_cnt-- > 0) {
		/* Take ownership of the buffer */
		mbx_wr32(hw, CTRL_REG, MBOX_CTRL_PF_HOLD_SHM);

		/* reserve mailbox for cm3 use */
		if (mbx_rd32(hw, CTRL_REG) & MBOX_CTRL_PF_HOLD_SHM)
			return 0;
		rte_delay_us_block(100);
	}

	RNP_PMD_LOG(WARNING, "%s: failed to get:%d lock\n",
			__func__, mbx_id);
	return ret_val;
}

/**
 *  rnp_write_mbx_pf - Places a message in the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: the VF index
 *
 *  returns SUCCESS if it successfully copied message into the buffer
 **/
static int32_t rnp_write_mbx_pf(struct rnp_hw *hw, u32 *msg,
				u16 size, enum MBX_ID mbx_id)
{
	u32 DATA_REG = (mbx_id == MBX_CM3CPU) ?
		CPU_PF_SHM_DATA : PF_VF_SHM_DATA(mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);
	int32_t ret_val = 0;
	u32 stat __rte_unused;
	u16 i;

	if (size > RNP_VFMAILBOX_SIZE) {
		RNP_PMD_LOG(ERR, "%s: size:%d should <%d\n", __func__,
				size, RNP_VFMAILBOX_SIZE);
		return -EINVAL;
	}

	/* lock the mailbox to prevent pf/vf/cpu race condition */
	ret_val = rnp_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val) {
		RNP_PMD_LOG(WARNING, "PF[%d] Can't Get Mbx-Lock Try Again\n",
				hw->function);
		return ret_val;
	}

	/* copy the caller specified message to the mailbox memory buffer */
	for (i = 0; i < size; i++) {
#ifdef MBX_WR_DEBUG
		mbx_pwr32(hw, DATA_REG + i * 4, msg[i]);
#else
		mbx_wr32(hw, DATA_REG + i * 4, msg[i]);
#endif
	}

	/* flush msg and acks as we are overwriting the message buffer */
	if (mbx_id == MBX_CM3CPU)
		hw->mbx.cpu_ack = rnp_mbx_get_ack(hw, CPU2PF_COUNTER);
	else
		hw->mbx.vf_ack[mbx_id] = rnp_mbx_get_ack(hw, VF2PF_COUNTER(mbx_id));

	rnp_mbx_inc_pf_req(hw, mbx_id);
	rte_mb();

	rte_delay_us(300);

	/* Interrupt VF/CM3 to tell it a message
	 * has been sent and release buffer
	 */
	mbx_wr32(hw, CTRL_REG, MBOX_CTRL_REQ);

	return 0;
}

/**
 *  rnp_read_mbx_pf - Read a message from the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @vf_number: the VF index
 *
 *  This function copies a message from the mailbox buffer to the caller's
 *  memory buffer.  The presumption is that the caller knows that there was
 *  a message due to a VF/CPU request so no polling for message is needed.
 **/
static int32_t rnp_read_mbx_pf(struct rnp_hw *hw, u32 *msg,
			       u16 size, enum MBX_ID mbx_id)
{
	u32 BUF_REG  = (mbx_id == MBX_CM3CPU) ?
		CPU_PF_SHM_DATA : PF_VF_SHM_DATA(mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
		PF2CPU_MBOX_CTRL : PF2VF_MBOX_CTRL(mbx_id);
	int32_t ret_val = -EIO;
	u32 stat __rte_unused, i;
	if (size > RNP_VFMAILBOX_SIZE) {
		RNP_PMD_LOG(ERR, "%s: size:%d should <%d\n", __func__,
				size, RNP_VFMAILBOX_SIZE);
		return -EINVAL;
	}
	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = rnp_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val)
		goto out_no_read;

	/* copy the message from the mailbox memory buffer */
	for (i = 0; i < size; i++) {
#ifdef MBX_RD_DEBUG
		msg[i] = mbx_prd32(hw, BUF_REG + 4 * i);
#else
		msg[i] = mbx_rd32(hw, BUF_REG + 4 * i);
#endif
	}
	mbx_wr32(hw, BUF_REG, 0);

	/* update req. used by rnpvf_check_for_msg_vf  */
	if (mbx_id == MBX_CM3CPU)
		hw->mbx.cpu_req = rnp_mbx_get_req(hw, CPU2PF_COUNTER);
	else
		hw->mbx.vf_req[mbx_id] = rnp_mbx_get_req(hw, VF2PF_COUNTER(mbx_id));

	/* this ack maybe too earier? */
	/* Acknowledge receipt and release mailbox, then we're done */
	rnp_mbx_inc_pf_ack(hw, mbx_id);

	rte_mb();

	/* free ownership of the buffer */
	mbx_wr32(hw, CTRL_REG, 0);

out_no_read:

	return ret_val;
}

static void rnp_mbx_reset_pf(struct rnp_hw *hw)
{
	int v;

	/* reset pf->cm3 status */
	v = mbx_rd32(hw, CPU2PF_COUNTER);
	hw->mbx.cpu_req = v & 0xffff;
	hw->mbx.cpu_ack = (v >> 16) & 0xffff;
	/* release   pf->cm3 buffer lock */
	mbx_wr32(hw, PF2CPU_MBOX_CTRL, 0);

	rte_mb();
	/* enable irq to fw */
	mbx_wr32(hw, CPU_PF_MBOX_MASK, 0);
}

static int get_pfvfnum(struct rnp_hw *hw)
{
	uint32_t addr_mask;
	uint32_t offset;
	uint32_t val;
#define RNP_PF_NUM_REG       (0x75f000)
#define RNP_PFVF_SHIFT       (4)
#define RNP_PF_SHIFT         (6)
#define RNP_PF_BIT_MASK      BIT(6)
	addr_mask = hw->iobar0_len - 1;
	offset = RNP_PF_NUM_REG & addr_mask;
	val = rnp_io_rd(hw->iobar0, offset);

	return val >> RNP_PFVF_SHIFT;
}

const struct rnp_mbx_api rnp_mbx_pf_ops = {
	.read           = rnp_read_mbx_pf,
	.write          = rnp_write_mbx_pf,
	.read_posted    = rnp_read_posted_mbx_pf,
	.write_posted   = rnp_write_posted_mbx_pf,
	.check_for_msg  = rnp_check_for_msg_pf,
	.check_for_ack  = rnp_check_for_ack_pf,
};

void *rnp_memzone_reserve(const char *name, unsigned int size)
{
#define NO_FLAGS 0
	const struct rte_memzone *mz = NULL;

	if (name) {
		if (size) {
			mz = rte_memzone_reserve(name, size,
					rte_socket_id(), NO_FLAGS);
			if (mz)
				memset(mz->addr, 0, size);
		} else {
			mz = rte_memzone_lookup(name);
		}
		return mz ? mz->addr : NULL;
	}
	return NULL;
}

void rnp_init_mbx_ops_pf(struct rnp_hw *hw)
{
	struct rnp_eth_adapter *adapter = hw->back;
	struct rnp_mbx_info *mbx = &hw->mbx;
	struct mbx_req_cookie *cookie;
	uint32_t vf_isolat_off;

	mbx->size       = RNP_VFMAILBOX_SIZE;
	mbx->usec_delay = RNP_MBX_DELAY_US;
	mbx->timeout    = (RNP_MBX_TIMEOUT_SECONDS * 1000 * 1000) /
		mbx->usec_delay;
	if (hw->device_id == RNP_DEV_ID_N10G) {
		vf_isolat_off = RNP_VF_ISOLATE_CTRL &
			(hw->iobar0_len - 1);
		rnp_io_wr(hw->iobar0, vf_isolat_off, 0);
	}
	mbx->sriov_st = 0;
	hw->pf_vf_num = get_pfvfnum(hw);
	mbx->vf_num = UINT16_MAX;
	mbx->pf_num = (hw->pf_vf_num & RNP_PF_BIT_MASK) >> RNP_PF_SHIFT;
	hw->function = mbx->pf_num;
	/* Retrieving and storing the HW base address of device */
	rnp_reg_offset_init(hw);
	snprintf(hw->cookie_p_name, RTE_MEMZONE_NAMESIZE, "mbx_req_cookie%d_%d",
			hw->function, adapter->eth_dev->data->port_id);
	hw->cookie_pool = rnp_memzone_reserve(hw->cookie_p_name,
			sizeof(struct mbx_req_cookie));

	cookie = (struct mbx_req_cookie *)hw->cookie_pool;
	if (cookie) {
		cookie->timeout_ms = 1000;
		cookie->magic = COOKIE_MAGIC;
		cookie->priv_len = RNP_MAX_SHARE_MEM;
	}

	rnp_mbx_reset_pf(hw);
}
