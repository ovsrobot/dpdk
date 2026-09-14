/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <inttypes.h>
#include <math.h>

#include <rte_kvargs.h>

#include "cnxk_ethdev.h"

struct sdp_channel {
	bool is_sdp_mask_set;
	uint16_t channel;
	uint16_t mask;
};

struct flow_pre_l2_size_info {
	uint8_t pre_l2_size_off;
	uint8_t pre_l2_size_off_mask;
	uint8_t pre_l2_size_shift_dir;
};

static int
parse_outb_nb_crypto_qs(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	if (rte_kvargs_to_uint(value, 1, 64, &val) < 0)
		return -EINVAL;

	*(uint16_t *)extra_args = val;

	return 0;
}

static int
parse_rxc_step(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	if (rte_kvargs_to_uint(value, 0, ROC_NIX_INL_REAS_STEP_MAX, &val) < 0)
		return -EINVAL;

	*(uint32_t *)extra_args = val;

	return 0;
}

static int
parse_flow_max_priority(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	if (rte_kvargs_to_uint(value, 1, ROC_NPC_MAX_MCAM_PRIORITY, &val) < 0)
		return -EINVAL;

	*(uint16_t *)extra_args = val;

	return 0;
}

static int
parse_flow_prealloc_size(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	/* Limit the prealloc size to 32 */
	if (rte_kvargs_to_uint(value, 1, 32, &val) < 0)
		return -EINVAL;

	*(uint16_t *)extra_args = val;

	return 0;
}

static int
parse_reta_size(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	if (rte_kvargs_to_uint(value, 0, UINT32_MAX, &val) < 0)
		return -EINVAL;

	if (val <= RTE_ETH_RSS_RETA_SIZE_64)
		val = ROC_NIX_RSS_RETA_SZ_64;
	else if (val > RTE_ETH_RSS_RETA_SIZE_64 && val <= RTE_ETH_RSS_RETA_SIZE_128)
		val = ROC_NIX_RSS_RETA_SZ_128;
	else if (val > RTE_ETH_RSS_RETA_SIZE_128 && val <= RTE_ETH_RSS_RETA_SIZE_256)
		val = ROC_NIX_RSS_RETA_SZ_256;
	else
		val = ROC_NIX_RSS_RETA_SZ_64;

	*(uint16_t *)extra_args = val;

	return 0;
}

static int
parse_pre_l2_hdr_info(const char *key, const char *value, void *extra_args)
{
	struct flow_pre_l2_size_info *info =
		(struct flow_pre_l2_size_info *)extra_args;
	char *tok1 = NULL, *tok2 = NULL;
	uint16_t off, off_mask, dir;

	RTE_SET_USED(key);
	off = strtol(value, &tok1, 16);
	tok1++;
	off_mask = strtol(tok1, &tok2, 16);
	tok2++;
	dir = strtol(tok2, 0, 16);
	if (off >= 256 || off_mask < 1 || off_mask >= 256 || dir > 1)
		return -EINVAL;
	info->pre_l2_size_off = off;
	info->pre_l2_size_off_mask = off_mask;
	info->pre_l2_size_shift_dir = dir;

	return 0;
}

static int
parse_switch_header_type(const char *key, const char *value, void *extra_args)
{
	RTE_SET_USED(key);

	if (strcmp(value, "higig2") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_HIGIG;

	if (strcmp(value, "dsa") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_EDSA;

	if (strcmp(value, "chlen90b") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_LEN_90B;

	if (strcmp(value, "exdsa") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_EXDSA;

	if (strcmp(value, "vlan_exdsa") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_VLAN_EXDSA;

	if (strcmp(value, "pre_l2") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_PRE_L2;

	if (strcmp(value, "skip_size") == 0)
		*(uint16_t *)extra_args = ROC_PRIV_FLAGS_SKIP_SIZE;

	return 0;
}

static int
parse_skip_size_info(const char *key, const char *value, void *extra_args)
{
	uint64_t val;

	RTE_SET_USED(key);

	if (rte_kvargs_to_uint(value, 0, 255, &val) < 0)
		return -EINVAL;

	*(uint16_t *)extra_args = val;

	return 0;
}

static int
parse_sdp_channel_mask(const char *key, const char *value, void *extra_args)
{
	RTE_SET_USED(key);
	uint16_t chan = 0, mask = 0;
	char *next = 0;

	/* next will point to the separator '/' */
	chan = strtol(value, &next, 16);
	mask = strtol(++next, 0, 16);

	if (chan > GENMASK(11, 0) || mask > GENMASK(11, 0))
		return -EINVAL;

	((struct sdp_channel *)extra_args)->channel = chan;
	((struct sdp_channel *)extra_args)->mask = mask;
	((struct sdp_channel *)extra_args)->is_sdp_mask_set = true;

	return 0;
}

#define CNXK_RSS_RETA_SIZE	"reta_size"
#define CNXK_SCL_ENABLE		"scalar_enable"
#define CNXK_TX_COMPL_ENA       "tx_compl_ena"
#define CNXK_MAX_SQB_COUNT	"max_sqb_count"
#define CNXK_FLOW_PREALLOC_SIZE "flow_prealloc_size"
#define CNXK_FLOW_MAX_PRIORITY	"flow_max_priority"
#define CNXK_SWITCH_HEADER_TYPE "switch_header"
#define CNXK_RSS_TAG_AS_XOR	"tag_as_xor"
#define CNXK_LOCK_RX_CTX	"lock_rx_ctx"
#define CNXK_IPSEC_IN_MIN_SPI	"ipsec_in_min_spi"
#define CNXK_IPSEC_IN_MAX_SPI	"ipsec_in_max_spi"
#define CNXK_IPSEC_OUT_MAX_SA	"ipsec_out_max_sa"
#define CNXK_OUTB_NB_DESC	"outb_nb_desc"
#define CNXK_NO_INL_DEV		"no_inl_dev"
#define CNXK_OUTB_NB_CRYPTO_QS	"outb_nb_crypto_qs"
#define CNXK_SDP_CHANNEL_MASK	"sdp_channel_mask"
#define CNXK_FLOW_PRE_L2_INFO	"flow_pre_l2_info"
#define CNXK_CUSTOM_SA_ACT	"custom_sa_act"
#define CNXK_SQB_SLACK		"sqb_slack"
#define CNXK_NIX_META_BUF_SZ	"meta_buf_sz"
#define CNXK_FLOW_AGING_POLL_FREQ	"aging_poll_freq"
#define CNXK_NIX_RX_INJ_ENABLE	"rx_inj_ena"
#define CNXK_CUSTOM_META_AURA_DIS "custom_meta_aura_dis"
#define CNXK_CUSTOM_INB_SA	  "custom_inb_sa"
#define CNXK_FORCE_TAIL_DROP	  "force_tail_drop"
#define CNXK_DIS_XQE_DROP	  "disable_xqe_drop"
#define CNXK_RXC_STEP		  "rxc_step"
#define CNXK_SKIP_SIZE_INFO	  "skip_size_info"

int
cnxk_ethdev_parse_devargs(struct rte_devargs *devargs, struct cnxk_eth_dev *dev)
{
	uint16_t aging_thread_poll_freq = ROC_NPC_AGE_POLL_FREQ_MIN;
	uint16_t reta_sz = ROC_NIX_RSS_RETA_SZ_64;
	uint16_t sqb_count = CNXK_NIX_TX_MAX_SQB;
	struct flow_pre_l2_size_info pre_l2_info;
	uint32_t ipsec_in_max_spi = BIT(8) - 1;
	uint16_t sqb_slack = ROC_NIX_SQB_SLACK;
	uint32_t ipsec_out_max_sa = BIT(12);
	bool custom_meta_aura_dis = false;
	uint16_t flow_prealloc_size = 1;
	uint16_t switch_header_type = 0;
	uint16_t skip_size_info = 0;
	uint16_t flow_max_priority = 3;
	uint16_t outb_nb_crypto_qs = 1;
	uint32_t ipsec_in_min_spi = 0;
	uint16_t outb_nb_desc = 8200;
	struct sdp_channel sdp_chan;
	bool rss_tag_as_xor = false;
	bool force_tail_drop = false;
	bool scalar_enable = false;
	bool tx_compl_ena = false;
	bool custom_sa_act = false;
	bool custom_inb_sa = false;
	struct rte_kvargs *kvlist;
	bool dis_xqe_drop = false;
	uint32_t meta_buf_sz = 0;
	bool lock_rx_ctx = false;
	bool rx_inj_ena = false;
	bool no_inl_dev = false;
	uint32_t rxc_step = 0;
	int ret;

	memset(&sdp_chan, 0, sizeof(sdp_chan));
	memset(&pre_l2_info, 0, sizeof(struct flow_pre_l2_size_info));

	if (devargs == NULL)
		goto null_devargs;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		goto exit;

	ret = 0;
	ret |= rte_kvargs_process(kvlist, CNXK_RSS_RETA_SIZE, &parse_reta_size,
				  &reta_sz);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_SCL_ENABLE, rte_kvargs_handle_bool,
				  &scalar_enable);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_TX_COMPL_ENA, rte_kvargs_handle_bool,
				  &tx_compl_ena);
	ret |= rte_kvargs_process(kvlist, CNXK_MAX_SQB_COUNT, rte_kvargs_handle_u16,
				  &sqb_count);
	ret |= rte_kvargs_process(kvlist, CNXK_FLOW_PREALLOC_SIZE,
				  &parse_flow_prealloc_size, &flow_prealloc_size);
	ret |= rte_kvargs_process(kvlist, CNXK_FLOW_MAX_PRIORITY,
				  &parse_flow_max_priority, &flow_max_priority);
	ret |= rte_kvargs_process(kvlist, CNXK_SWITCH_HEADER_TYPE,
				  &parse_switch_header_type, &switch_header_type);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_RSS_TAG_AS_XOR, rte_kvargs_handle_bool,
				  &rss_tag_as_xor);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_LOCK_RX_CTX, rte_kvargs_handle_bool, &lock_rx_ctx);
	ret |= rte_kvargs_process(kvlist, CNXK_IPSEC_IN_MIN_SPI,
				  rte_kvargs_handle_u32, &ipsec_in_min_spi);
	ret |= rte_kvargs_process(kvlist, CNXK_IPSEC_IN_MAX_SPI,
				  rte_kvargs_handle_u32, &ipsec_in_max_spi);
	ret |= rte_kvargs_process(kvlist, CNXK_IPSEC_OUT_MAX_SA,
				  rte_kvargs_handle_u32, &ipsec_out_max_sa);
	ret |= rte_kvargs_process(kvlist, CNXK_OUTB_NB_DESC, rte_kvargs_handle_u16,
				  &outb_nb_desc);
	ret |= rte_kvargs_process(kvlist, CNXK_OUTB_NB_CRYPTO_QS,
				  &parse_outb_nb_crypto_qs, &outb_nb_crypto_qs);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_NO_INL_DEV, rte_kvargs_handle_bool, &no_inl_dev);
	ret |= rte_kvargs_process(kvlist, CNXK_SDP_CHANNEL_MASK,
				  &parse_sdp_channel_mask, &sdp_chan);
	ret |= rte_kvargs_process(kvlist, CNXK_FLOW_PRE_L2_INFO,
				  &parse_pre_l2_hdr_info, &pre_l2_info);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_CUSTOM_SA_ACT, rte_kvargs_handle_bool,
				  &custom_sa_act);
	ret |= rte_kvargs_process(kvlist, CNXK_SQB_SLACK, rte_kvargs_handle_u16,
				  &sqb_slack);
	ret |= rte_kvargs_process(kvlist, CNXK_NIX_META_BUF_SZ, rte_kvargs_handle_u32, &meta_buf_sz);
	ret |= rte_kvargs_process(kvlist, CNXK_FLOW_AGING_POLL_FREQ, rte_kvargs_handle_u16,
				  &aging_thread_poll_freq);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_NIX_RX_INJ_ENABLE, rte_kvargs_handle_bool, &rx_inj_ena);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_CUSTOM_META_AURA_DIS, rte_kvargs_handle_bool,
				  &custom_meta_aura_dis);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_CUSTOM_INB_SA, rte_kvargs_handle_bool, &custom_inb_sa);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_FORCE_TAIL_DROP, rte_kvargs_handle_bool,
				  &force_tail_drop);
	ret |= rte_kvargs_process_opt(kvlist, CNXK_DIS_XQE_DROP, rte_kvargs_handle_bool, &dis_xqe_drop);
	ret |= rte_kvargs_process(kvlist, CNXK_RXC_STEP, &parse_rxc_step, &rxc_step);
	ret |= rte_kvargs_process(kvlist, CNXK_SKIP_SIZE_INFO, &parse_skip_size_info,
				  &skip_size_info);
	rte_kvargs_free(kvlist);

	if (ret != 0)
		goto exit;

null_devargs:
	dev->scalar_ena = scalar_enable;
	dev->tx_compl_ena = tx_compl_ena;
	dev->inb.no_inl_dev = no_inl_dev;
	dev->inb.min_spi = ipsec_in_min_spi;
	dev->inb.max_spi = ipsec_in_max_spi;
	dev->inb.custom_meta_aura_dis = custom_meta_aura_dis;
	dev->outb.max_sa = ipsec_out_max_sa;
	dev->outb.nb_desc = outb_nb_desc;
	dev->outb.nb_crypto_qs = outb_nb_crypto_qs;
	dev->nix.ipsec_out_max_sa = ipsec_out_max_sa;
	dev->nix.rss_tag_as_xor = rss_tag_as_xor;
	dev->nix.max_sqb_count = sqb_count;
	dev->nix.reta_sz = reta_sz;
	dev->nix.lock_rx_ctx = lock_rx_ctx;
	dev->nix.custom_sa_action = custom_sa_act;
	dev->nix.sqb_slack = sqb_slack;
	dev->nix.custom_inb_sa = custom_inb_sa;

	if (roc_feature_nix_has_own_meta_aura())
		dev->nix.meta_buf_sz = meta_buf_sz;

	dev->npc.flow_prealloc_size = flow_prealloc_size;

	if (roc_model_is_cn20k())
		dev->npc.flow_max_priority = ROC_NPC_MAX_MCAM_PRIORITY;
	else
		dev->npc.flow_max_priority = flow_max_priority;

	dev->npc.switch_header_type = switch_header_type;
	dev->npc.skip_size = skip_size_info;
	dev->npc.sdp_channel = sdp_chan.channel;
	dev->npc.sdp_channel_mask = sdp_chan.mask;
	dev->npc.is_sdp_mask_set = sdp_chan.is_sdp_mask_set;
	dev->npc.pre_l2_size_offset = pre_l2_info.pre_l2_size_off;
	dev->npc.pre_l2_size_offset_mask = pre_l2_info.pre_l2_size_off_mask;
	dev->npc.pre_l2_size_shift_dir = pre_l2_info.pre_l2_size_shift_dir;
	dev->npc.flow_age.aging_poll_freq = aging_thread_poll_freq;
	if (roc_feature_nix_has_rx_inject())
		dev->nix.rx_inj_ena = rx_inj_ena;
	dev->nix.force_tail_drop = force_tail_drop;
	dev->nix.dis_xqe_drop = dis_xqe_drop;
	dev->nix.rxc_step = rxc_step;
	return 0;
exit:
	return -EINVAL;
}

RTE_PMD_REGISTER_PARAM_STRING(net_cnxk,
			      CNXK_RSS_RETA_SIZE "=<64|128|256>"
			      CNXK_SCL_ENABLE "=1"
			      CNXK_TX_COMPL_ENA "=1"
			      CNXK_MAX_SQB_COUNT "=<8-512>"
			      CNXK_FLOW_PREALLOC_SIZE "=<1-32>"
			      CNXK_FLOW_MAX_PRIORITY "=<1-32>"
			      CNXK_SWITCH_HEADER_TYPE "=<higig2|dsa|chlen90b|skip_size>"
			      CNXK_RSS_TAG_AS_XOR "=1"
			      CNXK_IPSEC_IN_MAX_SPI "=<1-65535>"
			      CNXK_OUTB_NB_DESC "=<1-65535>"
			      CNXK_FLOW_PRE_L2_INFO "=<0-255>/<1-255>/<0-1>"
			      CNXK_OUTB_NB_CRYPTO_QS "=<1-64>"
			      CNXK_NO_INL_DEV "=0"
			      CNXK_SDP_CHANNEL_MASK "=<1-4095>/<1-4095>"
			      CNXK_CUSTOM_SA_ACT "=1"
			      CNXK_SQB_SLACK "=<12-512>"
			      CNXK_FLOW_AGING_POLL_FREQ "=<10-65535>"
			      CNXK_NIX_RX_INJ_ENABLE "=1"
			      CNXK_CUSTOM_META_AURA_DIS "=1"
			      CNXK_FORCE_TAIL_DROP "=1"
			      CNXK_DIS_XQE_DROP "=1"
			      CNXK_RXC_STEP "=<0-1048575>"
			      CNXK_SKIP_SIZE_INFO "=<0x0-0xff>");
