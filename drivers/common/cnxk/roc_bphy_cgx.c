/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <pthread.h>

#include "roc_api.h"
#include "roc_priv.h"

#define CGX_CMRX_CONFIG		       0x00
#define CGX_CMRX_CONFIG_DATA_PKT_RX_EN BIT_ULL(54)
#define CGX_CMRX_CONFIG_DATA_PKT_TX_EN BIT_ULL(53)
#define CGX_CMRX_INT		       0x40
#define CGX_CMRX_INT_OVERFLW	       BIT_ULL(1)
/*
 * CN10K stores number of lmacs in 4 bit filed
 * in contraty to CN9K which uses only 3 bits.
 *
 * In theory masks should differ yet on CN9K
 * bits beyond specified range contain zeros.
 *
 * Hence common longer mask may be used.
 */
#define CGX_CMRX_RX_LMACS	0x128
#define CGX_CMRX_RX_LMACS_LMACS GENMASK_ULL(3, 0)
#define CGX_CMRX_SCRATCH0	0x1050
#define CGX_CMRX_SCRATCH1	0x1058

static uint64_t
roc_bphy_cgx_read(struct roc_bphy_cgx *roc_cgx, uint64_t lmac, uint64_t offset)
{
	int shift = roc_model_is_cn10k() ? 20 : 18;
	uint64_t base = (uint64_t)roc_cgx->bar0_va;

	return plt_read64(base + (lmac << shift) + offset);
}

static void
roc_bphy_cgx_write(struct roc_bphy_cgx *roc_cgx, uint64_t lmac, uint64_t offset,
		   uint64_t value)
{
	int shift = roc_model_is_cn10k() ? 20 : 18;
	uint64_t base = (uint64_t)roc_cgx->bar0_va;

	plt_write64(value, base + (lmac << shift) + offset);
}

static void
roc_bphy_cgx_ack(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
		 uint64_t *scr0)
{
	uint64_t val;

	/* clear interrupt */
	val = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_INT);
	val |= FIELD_PREP(CGX_CMRX_INT_OVERFLW, 1);
	roc_bphy_cgx_write(roc_cgx, lmac, CGX_CMRX_INT, val);

	/* ack fw response */
	*scr0 &= ~SCR0_ETH_EVT_STS_S_ACK;
	roc_bphy_cgx_write(roc_cgx, lmac, CGX_CMRX_SCRATCH0, *scr0);
}

static int
roc_bphy_cgx_wait_for_ownership(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	uint64_t scr0, scr1;
	int tries = 5000;

	do {
		scr0 = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_SCRATCH0);
		scr1 = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_SCRATCH1);

		if (FIELD_GET(SCR1_OWN_STATUS, scr1) == ETH_OWN_NON_SECURE_SW &&
		    FIELD_GET(SCR0_ETH_EVT_STS_S_ACK, scr0) == 0)
			break;

		/* clear async events if any */
		if (FIELD_GET(SCR0_ETH_EVT_STS_S_EVT_TYPE, scr0) == ETH_EVT_ASYNC &&
		    FIELD_GET(SCR0_ETH_EVT_STS_S_ACK, scr0))
			roc_bphy_cgx_ack(roc_cgx, lmac, &scr0);

		plt_delay_ms(1);
	} while (--tries);

	return tries ? 0 : -ETIMEDOUT;
}

static int
roc_bphy_cgx_wait_for_ack(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	uint64_t scr0, scr1;
	int tries = 5000;

	do {
		scr0 = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_SCRATCH0);
		scr1 = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_SCRATCH1);

		if (FIELD_GET(SCR1_OWN_STATUS, scr1) == ETH_OWN_NON_SECURE_SW &&
		    FIELD_GET(SCR0_ETH_EVT_STS_S_ACK, scr0))
			break;

		plt_delay_ms(1);
	} while (--tries);

	return tries ? 0 : -ETIMEDOUT;
}

static int
roc_bphy_cgx_intf_req(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
		      uint64_t scr1, uint64_t *scr0)
{
	uint8_t cmd_id = FIELD_GET(SCR1_ETH_CMD_ID, scr1);
	int ret;

	pthread_mutex_lock(&roc_cgx->lock);

	/* wait for ownership */
	ret = roc_bphy_cgx_wait_for_ownership(roc_cgx, lmac);
	if (ret) {
		plt_err("timed out waiting for ownership");
		goto out;
	}

	/* write command */
	scr1 |= FIELD_PREP(SCR1_OWN_STATUS, ETH_OWN_FIRMWARE);
	roc_bphy_cgx_write(roc_cgx, lmac, CGX_CMRX_SCRATCH1, scr1);

	/* wait for command ack */
	ret = roc_bphy_cgx_wait_for_ack(roc_cgx, lmac);
	if (ret) {
		plt_err("timed out waiting for response");
		goto out;
	}

	if (cmd_id == ETH_CMD_INTF_SHUTDOWN)
		goto out;

	*scr0 = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_SCRATCH0);

	if (FIELD_GET(SCR0_ETH_EVT_STS_S_EVT_TYPE, *scr0) != ETH_EVT_CMD_RESP) {
		plt_err("received async event instead of cmd resp event");
		ret = -EIO;
		goto out;
	}

	if (FIELD_GET(SCR0_ETH_EVT_STS_S_ID, *scr0) != cmd_id) {
		plt_err("received resp for cmd %d expected for cmd %d",
			(int)FIELD_GET(SCR0_ETH_EVT_STS_S_ID, *scr0), cmd_id);
		ret = -EIO;
		goto out;
	}

	if (FIELD_GET(SCR0_ETH_EVT_STS_S_STAT, *scr0) != ETH_STAT_SUCCESS) {
		plt_err("cmd %d failed on cgx%u lmac%u with errcode %d", cmd_id,
			roc_cgx->id, lmac,
			(int)FIELD_GET(SCR0_ETH_LNK_STS_S_ERR_TYPE, *scr0));
		ret = -EIO;
	}

out:
	roc_bphy_cgx_ack(roc_cgx, lmac, scr0);

	pthread_mutex_unlock(&roc_cgx->lock);

	return ret;
}

static unsigned int
roc_bphy_cgx_dev_id(struct roc_bphy_cgx *roc_cgx)
{
	uint64_t cgx_id = roc_model_is_cn10k() ? GENMASK_ULL(26, 24) :
						 GENMASK_ULL(25, 24);

	return FIELD_GET(cgx_id, roc_cgx->bar0_pa);
}

int
roc_bphy_cgx_dev_init(struct roc_bphy_cgx *roc_cgx)
{
	uint64_t val;
	int ret;

	if (!roc_cgx || !roc_cgx->bar0_va || !roc_cgx->bar0_pa)
		return -EINVAL;

	ret = pthread_mutex_init(&roc_cgx->lock, NULL);
	if (ret)
		return ret;

	val = roc_bphy_cgx_read(roc_cgx, 0, CGX_CMRX_RX_LMACS);
	val = FIELD_GET(CGX_CMRX_RX_LMACS_LMACS, val);
	if (roc_model_is_cn9k())
		val = GENMASK_ULL(val - 1, 0);
	roc_cgx->lmac_bmap = val;
	roc_cgx->id = roc_bphy_cgx_dev_id(roc_cgx);

	return 0;
}

int
roc_bphy_cgx_dev_fini(struct roc_bphy_cgx *roc_cgx)
{
	if (!roc_cgx)
		return -EINVAL;

	pthread_mutex_destroy(&roc_cgx->lock);

	return 0;
}

static bool
roc_bphy_cgx_lmac_exists(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return (lmac < MAX_LMACS_PER_CGX) &&
	       (roc_cgx->lmac_bmap & BIT_ULL(lmac));
}

static int
roc_bphy_cgx_start_stop_rxtx(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			     bool start)
{
	uint64_t val;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	pthread_mutex_lock(&roc_cgx->lock);
	val = roc_bphy_cgx_read(roc_cgx, lmac, CGX_CMRX_CONFIG);
	val &= ~(CGX_CMRX_CONFIG_DATA_PKT_RX_EN |
		 CGX_CMRX_CONFIG_DATA_PKT_TX_EN);

	if (start)
		val |= FIELD_PREP(CGX_CMRX_CONFIG_DATA_PKT_RX_EN, 1) |
		       FIELD_PREP(CGX_CMRX_CONFIG_DATA_PKT_TX_EN, 1);

	roc_bphy_cgx_write(roc_cgx, lmac, CGX_CMRX_CONFIG, val);
	pthread_mutex_unlock(&roc_cgx->lock);

	return 0;
}

static int
roc_bphy_cgx_intlbk_ena_dis(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			    bool enable)
{
	uint64_t scr1, scr0;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	scr1 = FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_INTERNAL_LBK) |
	       FIELD_PREP(SCR1_ETH_CTL_ARGS_ENABLE, enable);

	return roc_bphy_cgx_intf_req(roc_cgx, lmac, scr1, &scr0);
}

static int
roc_bphy_cgx_ptp_rx_ena_dis(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			    bool enable)
{
	uint64_t scr1, scr0;

	if (roc_model_is_cn10k())
		return -ENOTSUP;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	scr1 = FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_SET_PTP_MODE) |
	       FIELD_PREP(SCR1_ETH_CTL_ARGS_ENABLE, enable);

	return roc_bphy_cgx_intf_req(roc_cgx, lmac, scr1, &scr0);
}

int
roc_bphy_cgx_start_rxtx(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_start_stop_rxtx(roc_cgx, lmac, true);
}

int
roc_bphy_cgx_stop_rxtx(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_start_stop_rxtx(roc_cgx, lmac, false);
}

int
roc_bphy_cgx_set_link_state(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			    bool state)
{
	uint64_t scr1, scr0;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	scr1 = state ? FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_LINK_BRING_UP) :
		       FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_LINK_BRING_DOWN);

	return roc_bphy_cgx_intf_req(roc_cgx, lmac, scr1, &scr0);
}

int
roc_bphy_cgx_get_linkinfo(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			  struct roc_bphy_cgx_link_info *info)
{
	uint64_t scr1, scr0;
	int ret;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	if (!info)
		return -EINVAL;

	scr1 = FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_GET_LINK_STS);
	ret = roc_bphy_cgx_intf_req(roc_cgx, lmac, scr1, &scr0);
	if (ret)
		return ret;

	info->link_up = FIELD_GET(SCR0_ETH_LNK_STS_S_LINK_UP, scr0);
	info->full_duplex = FIELD_GET(SCR0_ETH_LNK_STS_S_FULL_DUPLEX, scr0);
	info->speed = FIELD_GET(SCR0_ETH_LNK_STS_S_SPEED, scr0);
	info->an = FIELD_GET(SCR0_ETH_LNK_STS_S_AN, scr0);
	info->fec = FIELD_GET(SCR0_ETH_LNK_STS_S_FEC, scr0);
	info->mode = FIELD_GET(SCR0_ETH_LNK_STS_S_MODE, scr0);

	return 0;
}

int
roc_bphy_cgx_set_link_mode(struct roc_bphy_cgx *roc_cgx, unsigned int lmac,
			   struct roc_bphy_cgx_link_mode *mode)
{
	uint64_t scr1, scr0;

	if (roc_model_is_cn10k())
		return -ENOTSUP;

	if (!roc_cgx)
		return -EINVAL;

	if (!roc_bphy_cgx_lmac_exists(roc_cgx, lmac))
		return -EINVAL;

	if (!mode)
		return -EINVAL;

	scr1 = FIELD_PREP(SCR1_ETH_CMD_ID, ETH_CMD_MODE_CHANGE) |
	       FIELD_PREP(SCR1_ETH_MODE_CHANGE_ARGS_SPEED, mode->speed) |
	       FIELD_PREP(SCR1_ETH_MODE_CHANGE_ARGS_DUPLEX, mode->full_duplex) |
	       FIELD_PREP(SCR1_ETH_MODE_CHANGE_ARGS_AN, mode->an) |
	       FIELD_PREP(SCR1_ETH_MODE_CHANGE_ARGS_PORT, mode->port) |
	       FIELD_PREP(SCR1_ETH_MODE_CHANGE_ARGS_MODE, BIT_ULL(mode->mode));

	return roc_bphy_cgx_intf_req(roc_cgx, lmac, scr1, &scr0);
}

int
roc_bphy_cgx_intlbk_enable(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_intlbk_ena_dis(roc_cgx, lmac, true);
}

int
roc_bphy_cgx_intlbk_disable(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_intlbk_ena_dis(roc_cgx, lmac, false);
}

int
roc_bphy_cgx_ptp_rx_enable(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_ptp_rx_ena_dis(roc_cgx, lmac, true);
}

int
roc_bphy_cgx_ptp_rx_disable(struct roc_bphy_cgx *roc_cgx, unsigned int lmac)
{
	return roc_bphy_cgx_ptp_rx_ena_dis(roc_cgx, lmac, false);
}
