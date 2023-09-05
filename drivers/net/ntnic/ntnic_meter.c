/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>

#include <rte_common.h>
#include <rte_meter.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>

#include "ntdrv_4ga.h"
#include "nthw_fpga.h"
#include "ntnic_ethdev.h"
#include "ntnic_meter.h"
#include "ntlog.h"

/*
 *******************************************************************************
 * Vswitch metering
 *******************************************************************************
 */

static const uint32_t highest_bit_mask = (~(~0u >> 1));

static struct nt_mtr_profile *
nt_mtr_profile_find(struct pmd_internals *dev_priv, uint32_t meter_profile_id)
{
	struct nt_mtr_profile *profile = NULL;

	LIST_FOREACH(profile, &dev_priv->mtr_profiles, next)
	if (profile->profile_id == meter_profile_id)
		break;

	return profile;
}

static int eth_meter_profile_add(struct rte_eth_dev *dev,
				 uint32_t meter_profile_id,
				 struct rte_mtr_meter_profile *profile,
				 struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	const bool is_egress = meter_profile_id & highest_bit_mask;

	if (dev_priv->type == PORT_TYPE_VIRTUAL || is_egress) {
		struct nt_mtr_profile *prof;

		prof = nt_mtr_profile_find(dev_priv, meter_profile_id);
		if (prof)
			return -rte_mtr_error_set(error, EEXIST,
						  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
						  NULL,
						  "Profile id already exists\n");

		prof = rte_zmalloc(NULL, sizeof(*prof), 0);
		if (!prof) {
			return -rte_mtr_error_set(error,
						  ENOMEM, RTE_MTR_ERROR_TYPE_UNSPECIFIED,
						  NULL, NULL);
		}

		prof->profile_id = meter_profile_id;
		memcpy(&prof->profile, profile,
		       sizeof(struct rte_mtr_meter_profile));

		LIST_INSERT_HEAD(&dev_priv->mtr_profiles, prof, next);

		return 0;
	}
	/* Ingress is not possible yet on phy ports */
	return -rte_mtr_error_set(error, EINVAL,
		RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
		"Traffic ingress metering/policing is not supported on physical ports\n");
}

static int eth_meter_profile_delete(struct rte_eth_dev *dev,
				    uint32_t meter_profile_id,
				    struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;
	struct nt_mtr_profile *profile;

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	profile = nt_mtr_profile_find(dev_priv, meter_profile_id);
	if (!profile)
		return -rte_mtr_error_set(error, ENODEV,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile id does not exist\n");

	LIST_REMOVE(profile, next);
	rte_free(profile);
	return 0;
}

static struct nt_mtr *nt_mtr_find(struct pmd_internals *dev_priv,
				  uint32_t mtr_id)
{
	struct nt_mtr *mtr = NULL;

	LIST_FOREACH(mtr, &dev_priv->mtrs, next)
	if (mtr->mtr_id == mtr_id)
		break;

	return mtr;
}

struct qos_integer_fractional {
	uint32_t integer;
	uint32_t fractional; /* 1/1024 */
};

/*
 * Converts byte/s to byte/period if form of integer + 1/1024*fractional
 * the period depends on the clock friquency and other parameters which
 * being combined give multiplier. The resulting formula is:
 *     f[bytes/period] = x[byte/s] * period_ps / 10^-12
 */
static struct qos_integer_fractional
byte_per_second_to_qo_s_ri(uint64_t byte_per_second, uint64_t period_ps)
{
	struct qos_integer_fractional res;
	const uint64_t dividend = byte_per_second * period_ps;
	const uint64_t divisor = 1000000000000ull; /*10^12 pico second*/

	res.integer = dividend / divisor;
	const uint64_t reminder = dividend % divisor;

	res.fractional = 1024ull * reminder / divisor;
	return res;
}

static struct qos_integer_fractional
byte_per_second_to_physical_qo_s_ri(uint64_t byte_per_second)
{
	return byte_per_second_to_qo_s_ri(byte_per_second, 8 * 3333ul);
}

static struct qos_integer_fractional
byte_per_second_to_virtual_qo_s_ri(uint64_t byte_per_second)
{
	return byte_per_second_to_qo_s_ri(byte_per_second, 512 * 3333ul);
}

static int eth_meter_enable(struct rte_eth_dev *dev, uint32_t mtr_id,
			    struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;
	int res;
	static int ingress_initial;

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	nthw_dbs_t *p_nthw_dbs =
		dev_priv->p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_dbs;
	nthw_epp_t *p_nthw_epp =
		dev_priv->p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_epp;

	/*
	 *  FPGA is based on FRC 4115 so CIR,EIR and CBS/EBS are used
	 *   rfc4115.cir = rfc2697.cir
	 *   rfc4115.eir = rfc2697.cir
	 *   rfc4115.cbs = rfc2697.cbs
	 *   rfc4115.ebs = rfc2697.ebs
	 */
	struct nt_mtr *mtr = nt_mtr_find(dev_priv, mtr_id);

	if (!mtr) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id not found\n");
	}

	if (!mtr->profile) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id not found\n");
	}

	const uint32_t profile_id = mtr->profile->profile_id;
	const bool is_egress = profile_id & highest_bit_mask;
	uint32_t burst = mtr->profile->profile.srtcm_rfc2697.cbs;

	if (is_egress) {
		const bool is_virtual = (dev_priv->type == PORT_TYPE_VIRTUAL);
		struct qos_integer_fractional cir = { 0 };

		if (is_virtual) {
			cir =
			byte_per_second_to_virtual_qo_s_ri(mtr->profile->profile.srtcm_rfc2697.cir);
			if (cir.integer == 0 && cir.fractional == 0)
				cir.fractional = 1;
			res = nthw_epp_set_vport_qos(p_nthw_epp, dev_priv->port,
						  cir.integer, cir.fractional,
						  burst);
		} else {
			cir =
				byte_per_second_to_physical_qo_s_ri(mtr->profile->profile
								    .srtcm_rfc2697.cir);
			if (cir.integer == 0 && cir.fractional == 0)
				cir.fractional = 1;
			res = nthw_epp_set_txp_qos(p_nthw_epp, dev_priv->port,
						cir.integer, cir.fractional,
						burst);
		}
		if (res) {
			return -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED,
				NULL,
				"Applying meter profile for setting egress policy failed\n");
		}
	} else {
		if (!ingress_initial) {
			/*
			 * based on a 250Mhz FPGA
			 * _update refresh rate interval calculation:
			 * multiplier / (divider * 4ns)
			 * 1 / (2000 * 4ns) = 8,000*10-6 => refresh rate interval = 8000ns
			 *
			 * results in resolution of IR is 1Mbps
			 */
			res = nthw_set_tx_qos_rate_global(p_nthw_dbs, 1, 2000);

			if (res) {
				return -rte_mtr_error_set(error, EINVAL,
					RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					"Applying meter profile for setting ingress "
					"global QoS rate failed\n");
			}
			ingress_initial = 1;
		}

		if (mtr->profile->profile.srtcm_rfc2697.cbs >= (1 << 27)) {
			/* max burst 1,074Mb (27 bits) */
			mtr->profile->profile.srtcm_rfc2697.cbs = (1 << 27) - 1;
		}
		/* IR - fill x bytes each 8000ns -> 1B/8000ns => 1000Kbps => 125000Bps / x */
		res = nthw_set_tx_qos_config(p_nthw_dbs, dev_priv->port, /* vport */
					     1, /* enable */
					     mtr->profile->profile.srtcm_rfc2697.cir /
					     125000,
					     mtr->profile->profile.srtcm_rfc2697
					     .cbs); /* BS - burst size in Bytes */
		if (res) {
			return -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED,
				NULL, "Applying meter profile failed\n");
		}
	}
	return 0;
}

static void disable(struct pmd_internals *dev_priv)
{
	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	nthw_dbs_t *p_nthw_dbs =
		dev_priv->p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_dbs;
	nthw_set_tx_qos_config(p_nthw_dbs, dev_priv->port, /* vport */
			       0, /* disable */
			       0, /* IR */
			       0); /* BS */
}

static int eth_meter_disable(struct rte_eth_dev *dev, uint32_t mtr_id,
			     struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;
	struct nt_mtr *mtr = nt_mtr_find(dev_priv, mtr_id);

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	nthw_epp_t *p_nthw_epp =
		dev_priv->p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_epp;

	if (!mtr) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id not found\n");
	}

	const bool is_egress = mtr_id & highest_bit_mask;

	if (is_egress) {
		const bool is_virtual = (dev_priv->type == PORT_TYPE_VIRTUAL);

		if (is_virtual)
			nthw_epp_set_vport_qos(p_nthw_epp, dev_priv->port, 0, 0, 0);
		else
			nthw_epp_set_txp_qos(p_nthw_epp, dev_priv->port, 0, 0, 0);
	} else {
		disable(dev_priv);
	}
	return 0;
}

/* MTR object create */
static int eth_mtr_create(struct rte_eth_dev *dev, uint32_t mtr_id,
			  struct rte_mtr_params *params, int shared,
			  struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;
	struct nt_mtr *mtr = NULL;
	struct nt_mtr_profile *profile;

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	const bool is_egress = mtr_id & highest_bit_mask;

	if (dev_priv->type == PORT_TYPE_PHYSICAL && !is_egress) {
		NT_LOG(ERR, NTHW,
		       "ERROR try to create ingress meter object on a phy port. Not supported\n");

		return -rte_mtr_error_set(error, EINVAL, RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
			"Traffic ingress metering/policing is not supported on physical ports\n");
	}

	mtr = nt_mtr_find(dev_priv, mtr_id);
	if (mtr)
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id already exists\n");

	profile = nt_mtr_profile_find(dev_priv, params->meter_profile_id);
	if (!profile) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile id does not exist\n");
	}

	mtr = rte_zmalloc(NULL, sizeof(struct nt_mtr), 0);
	if (!mtr)
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  NULL);

	mtr->shared = shared;
	mtr->mtr_id = mtr_id;
	mtr->profile = profile;
	LIST_INSERT_HEAD(&dev_priv->mtrs, mtr, next);

	if (params->meter_enable)
		return eth_meter_enable(dev, mtr_id, error);

	return 0;
}

/* MTR object destroy */
static int eth_mtr_destroy(struct rte_eth_dev *dev, uint32_t mtr_id,
			   struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;
	struct nt_mtr *mtr;

	NT_LOG(DBG, NTHW, "%s: [%s:%u] adapter: " PCIIDENT_PRINT_STR "\n",
	       __func__, __func__, __LINE__,
	       PCIIDENT_TO_DOMAIN(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_BUSNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_DEVNR(dev_priv->p_drv->ntdrv.pciident),
	       PCIIDENT_TO_FUNCNR(dev_priv->p_drv->ntdrv.pciident));

	nthw_epp_t *p_nthw_epp =
		dev_priv->p_drv->ntdrv.adapter_info.fpga_info.mp_nthw_epp;

	mtr = nt_mtr_find(dev_priv, mtr_id);
	if (!mtr)
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id does not exist\n");

	const bool is_egress = mtr_id & highest_bit_mask;

	if (is_egress) {
		const bool is_virtual = (dev_priv->type == PORT_TYPE_VIRTUAL);

		if (is_virtual)
			nthw_epp_set_vport_qos(p_nthw_epp, dev_priv->port, 0, 0, 0);
		else
			nthw_epp_set_txp_qos(p_nthw_epp, dev_priv->port, 0, 0, 0);
	} else {
		disable(dev_priv);
	}
	LIST_REMOVE(mtr, next);
	rte_free(mtr);
	return 0;
}

/*
 *******************************************************************************
 * Inline FLM metering
 *******************************************************************************
 */

static int eth_mtr_capabilities_get_inline(struct rte_eth_dev *dev,
		struct rte_mtr_capabilities *cap,
		struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (!flow_mtr_supported(dev_priv->flw_dev)) {
		return -rte_mtr_error_set(error, EINVAL,
			RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
			"Ethernet device does not support metering\n");
	}

	memset(cap, 0x0, sizeof(struct rte_mtr_capabilities));

	/* MBR records use 28-bit integers */
	cap->n_max = flow_mtr_meters_supported();
	cap->n_shared_max = cap->n_max;

	cap->identical = 0;
	cap->shared_identical = 0;

	cap->shared_n_flows_per_mtr_max = UINT32_MAX;

	/* Limited by number of MBR record ids per FLM learn record */
	cap->chaining_n_mtrs_per_flow_max = 4;

	cap->chaining_use_prev_mtr_color_supported = 0;
	cap->chaining_use_prev_mtr_color_enforced = 0;

	cap->meter_rate_max = (uint64_t)(0xfff << 0xf) * 1099;

	cap->stats_mask = RTE_MTR_STATS_N_PKTS_GREEN |
			  RTE_MTR_STATS_N_BYTES_GREEN;

	/* Only color-blind mode is supported */
	cap->color_aware_srtcm_rfc2697_supported = 0;
	cap->color_aware_trtcm_rfc2698_supported = 0;
	cap->color_aware_trtcm_rfc4115_supported = 0;

	/* Focused on RFC2698 for now */
	cap->meter_srtcm_rfc2697_n_max = 0;
	cap->meter_trtcm_rfc2698_n_max = cap->n_max;
	cap->meter_trtcm_rfc4115_n_max = 0;

	cap->meter_policy_n_max = flow_mtr_meter_policy_n_max();

	/* Byte mode is supported */
	cap->srtcm_rfc2697_byte_mode_supported = 0;
	cap->trtcm_rfc2698_byte_mode_supported = 1;
	cap->trtcm_rfc4115_byte_mode_supported = 0;

	/* Packet mode not supported */
	cap->srtcm_rfc2697_packet_mode_supported = 0;
	cap->trtcm_rfc2698_packet_mode_supported = 0;
	cap->trtcm_rfc4115_packet_mode_supported = 0;

	return 0;
}

static int
eth_mtr_meter_profile_add_inline(struct rte_eth_dev *dev,
				 uint32_t meter_profile_id,
				 struct rte_mtr_meter_profile *profile,
				 struct rte_mtr_error *error __rte_unused)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (meter_profile_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile id out of range\n");

	if (profile->packet_mode != 0) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_PACKET_MODE, NULL,
					  "Profile packet mode not supported\n");
	}

	if (profile->alg == RTE_MTR_SRTCM_RFC2697) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE,
					  NULL, "RFC 2697 not supported\n");
	}

	if (profile->alg == RTE_MTR_TRTCM_RFC4115) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE,
					  NULL, "RFC 4115 not supported\n");
	}

	if (profile->trtcm_rfc2698.cir != profile->trtcm_rfc2698.pir ||
			profile->trtcm_rfc2698.cbs != profile->trtcm_rfc2698.pbs) {
		return -rte_mtr_error_set(error, EINVAL, RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
					  "Profile committed and peak rates must be equal\n");
	}

	int res = flow_mtr_set_profile(dev_priv->flw_dev, meter_profile_id,
				       profile->trtcm_rfc2698.cir,
				       profile->trtcm_rfc2698.cbs, 0, 0);

	if (res) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE,
					  NULL,
					  "Profile could not be added.\n");
	}

	return 0;
}

static int
eth_mtr_meter_profile_delete_inline(struct rte_eth_dev *dev __rte_unused,
				    uint32_t meter_profile_id __rte_unused,
				    struct rte_mtr_error *error __rte_unused)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (meter_profile_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile id out of range\n");

	flow_mtr_set_profile(dev_priv->flw_dev, meter_profile_id, 0, 0, 0, 0);

	return 0;
}

static int
eth_mtr_meter_policy_add_inline(struct rte_eth_dev *dev, uint32_t policy_id,
				struct rte_mtr_meter_policy_params *policy,
				struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (policy_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "Policy id out of range\n");

	const struct rte_flow_action *actions =
			policy->actions[RTE_COLOR_GREEN];
	int green_action_supported =
		(actions[0].type == RTE_FLOW_ACTION_TYPE_END) ||
		(actions[0].type == RTE_FLOW_ACTION_TYPE_VOID &&
		 actions[1].type == RTE_FLOW_ACTION_TYPE_END) ||
		(actions[0].type == RTE_FLOW_ACTION_TYPE_PASSTHRU &&
		 actions[1].type == RTE_FLOW_ACTION_TYPE_END);

	actions = policy->actions[RTE_COLOR_YELLOW];
	int yellow_action_supported =
		actions[0].type == RTE_FLOW_ACTION_TYPE_DROP &&
		actions[1].type == RTE_FLOW_ACTION_TYPE_END;

	actions = policy->actions[RTE_COLOR_RED];
	int red_action_supported = actions[0].type ==
				   RTE_FLOW_ACTION_TYPE_DROP &&
				   actions[1].type == RTE_FLOW_ACTION_TYPE_END;

	if (green_action_supported == 0 || yellow_action_supported == 0 ||
			red_action_supported == 0) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_POLICY, NULL,
					  "Unsupported meter policy actions\n");
	}

	if (flow_mtr_set_policy(dev_priv->flw_dev, policy_id, 1)) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_POLICY, NULL,
					  "Policy could not be added\n");
	}

	return 0;
}

static int
eth_mtr_meter_policy_delete_inline(struct rte_eth_dev *dev __rte_unused,
				   uint32_t policy_id __rte_unused,
				   struct rte_mtr_error *error __rte_unused)
{
	if (policy_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "Policy id out of range\n");

	return 0;
}

static int eth_mtr_create_inline(struct rte_eth_dev *dev, uint32_t mtr_id,
				 struct rte_mtr_params *params, int shared,
				 struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (params->use_prev_mtr_color != 0 || params->dscp_table != NULL) {
		return -rte_mtr_error_set(error, EINVAL, RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Only color blind mode is supported\n");
	}

	uint64_t allowed_stats_mask = RTE_MTR_STATS_N_PKTS_GREEN |
				      RTE_MTR_STATS_N_BYTES_GREEN;
	if ((params->stats_mask & ~allowed_stats_mask) != 0) {
		return -rte_mtr_error_set(error, EINVAL, RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Requested color stats not supported\n");
	}

	if (params->meter_enable == 0) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Disabled meters not supported\n");
	}

	if (shared == 0) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Only shared mtrs are supported\n");
	}

	if (params->meter_profile_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile id out of range\n");

	if (params->meter_policy_id >= flow_mtr_meter_policy_n_max())
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "Policy id out of range\n");

	if (mtr_id >= flow_mtr_meters_supported()) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "MTR id is out of range\n");
	}

	int res = flow_mtr_create_meter(dev_priv->flw_dev, mtr_id,
					params->meter_profile_id,
					params->meter_policy_id,
					params->stats_mask);

	if (res) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  "Failed to offload to hardware\n");
	}

	return 0;
}

static int eth_mtr_destroy_inline(struct rte_eth_dev *dev, uint32_t mtr_id,
				  struct rte_mtr_error *error __rte_unused)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (mtr_id >= flow_mtr_meters_supported()) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "MTR id is out of range\n");
	}

	if (flow_mtr_destroy_meter(dev_priv->flw_dev, mtr_id)) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  "Failed to offload to hardware\n");
	}

	return 0;
}

static int eth_mtr_stats_adjust_inline(struct rte_eth_dev *dev, uint32_t mtr_id,
				       uint64_t adjust_value,
				       struct rte_mtr_error *error)
{
	const uint64_t adjust_bit = 1ULL << 63;
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (mtr_id >= flow_mtr_meters_supported()) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "MTR id is out of range\n");
	}

	if ((adjust_value & adjust_bit) == 0) {
		return -rte_mtr_error_set(error, EINVAL, RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
			"To adjust a MTR bucket value, bit 63 of \"stats_mask\" must be 1\n");
	}

	adjust_value &= adjust_bit - 1;

	if (adjust_value > (uint64_t)UINT32_MAX) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Adjust value is out of range\n");
	}

	if (flm_mtr_adjust_stats(dev_priv->flw_dev, mtr_id,
				 (uint32_t)adjust_value)) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  "Failed to adjust offloaded MTR\n");
	}

	return 0;
}

static int eth_mtr_stats_read_inline(struct rte_eth_dev *dev, uint32_t mtr_id,
				     struct rte_mtr_stats *stats,
				     uint64_t *stats_mask, int clear,
				     struct rte_mtr_error *error)
{
	struct pmd_internals *dev_priv = dev->data->dev_private;

	if (mtr_id >= flow_mtr_meters_supported()) {
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "MTR id is out of range\n");
	}

	memset(stats, 0x0, sizeof(struct rte_mtr_stats));
	flm_mtr_read_stats(dev_priv->flw_dev, mtr_id, stats_mask,
			   &stats->n_pkts[RTE_COLOR_GREEN],
			   &stats->n_bytes[RTE_COLOR_GREEN], clear);

	return 0;
}

/*
 *******************************************************************************
 * Ops setup
 *******************************************************************************
 */

static const struct rte_mtr_ops mtr_ops_vswitch = {
	.meter_profile_add = eth_meter_profile_add,
	.meter_profile_delete = eth_meter_profile_delete,
	.create = eth_mtr_create,
	.destroy = eth_mtr_destroy,
	.meter_enable = eth_meter_enable,
	.meter_disable = eth_meter_disable,
};

static const struct rte_mtr_ops mtr_ops_inline = {
	.capabilities_get = eth_mtr_capabilities_get_inline,
	.meter_profile_add = eth_mtr_meter_profile_add_inline,
	.meter_profile_delete = eth_mtr_meter_profile_delete_inline,
	.create = eth_mtr_create_inline,
	.destroy = eth_mtr_destroy_inline,
	.meter_policy_add = eth_mtr_meter_policy_add_inline,
	.meter_policy_delete = eth_mtr_meter_policy_delete_inline,
	.stats_update = eth_mtr_stats_adjust_inline,
	.stats_read = eth_mtr_stats_read_inline,
};

int eth_mtr_ops_get(struct rte_eth_dev *dev, void *ops)
{
	struct pmd_internals *internals =
		(struct pmd_internals *)dev->data->dev_private;
	ntdrv_4ga_t *p_nt_drv = &internals->p_drv->ntdrv;
	enum fpga_info_profile profile = p_nt_drv->adapter_info.fpga_info.profile;

	switch (profile) {
	case FPGA_INFO_PROFILE_VSWITCH:
		*(const struct rte_mtr_ops **)ops = &mtr_ops_vswitch;
		break;
	case FPGA_INFO_PROFILE_INLINE:
		*(const struct rte_mtr_ops **)ops = &mtr_ops_inline;
		break;
	case FPGA_INFO_PROFILE_UNKNOWN:
	/* fallthrough */
	case FPGA_INFO_PROFILE_CAPTURE:
	/* fallthrough */
	default:
		NT_LOG(ERR, NTHW,
		       "" PCIIDENT_PRINT_STR
		       ": fpga profile not supported [%s:%u]\n",
		       PCIIDENT_TO_DOMAIN(p_nt_drv->pciident),
		       PCIIDENT_TO_BUSNR(p_nt_drv->pciident),
		       PCIIDENT_TO_DEVNR(p_nt_drv->pciident),
		       PCIIDENT_TO_FUNCNR(p_nt_drv->pciident),
		       __func__, __LINE__);
		return -1;
	}

	return 0;
}
