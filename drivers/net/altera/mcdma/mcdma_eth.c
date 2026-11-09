/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#include <stdlib.h>
#include <string.h>

#include <ethdev_pci.h>
#include <rte_kvargs.h>

#include "mcdma_eth.h"

RTE_LOG_REGISTER_SUFFIX(mcdma_logtype_driver, driver, NOTICE);

size_t config_csr_offsets[MCDMA_MAX_CONFIGS] = {
	0, 0x100000, 0x200000, 0x300000, 0x380000,
};

void *mcdma_get_csraddr(void *base, unsigned int idx)
{
	if (idx >= MCDMA_MAX_CONFIGS)
		return NULL;

	return (uint8_t *)base + config_csr_offsets[idx];
}

#define MCDMA_ARGS_CFG_BAM_BAR		"config_bam_bar"
#define MCDMA_ARGS_VF_WEIGHTS		"vf_weights"
#define MCDMA_ARGS_PF_IDX		"pf_index"
#define MCDMA_ARGS_PARENT_PF_IDX	"parent_pf_idx"

#define NUM_VF_WEIGHT			16
#define VF_WEIGHT_LO			1
#define VF_WEIGHT_HI			8

static const char *const mcdma_kvargs_keys[] = {
	MCDMA_ARGS_CFG_BAM_BAR,
	MCDMA_ARGS_VF_WEIGHTS,
	MCDMA_ARGS_PF_IDX,
	MCDMA_ARGS_PARENT_PF_IDX,
	NULL,
};

static int vf_weight_parse_handler(__rte_unused const char *key,
				   const char *value, void *data)
{
	int *weights = data;
	char *token, *str, *tofree;
	int i = 0;

	str = strdup(value);
	tofree = str;
	if (!str) {
		PMD_DRV_LOG(ERR, "failed to parse vf_weights: out of memory");
		return -ENOMEM;
	}

	while ((token = strsep(&str, ",")) != NULL) {
		uint8_t weight_val = atoi(token);
		if (weight_val < VF_WEIGHT_LO || weight_val > VF_WEIGHT_HI) {
			PMD_DRV_LOG(WARNING,
				    "weight value not in range; defaulting to %d",
				    VF_WEIGHT_LO);
			weight_val = VF_WEIGHT_LO;
		}

		if (i >= NUM_VF_WEIGHT) {
			free(tofree);
			PMD_DRV_LOG(ERR, "vf_weights expects %d values, got more",
				    NUM_VF_WEIGHT);
			return -EINVAL;
		}

		weights[i++] = weight_val;
	}

	free(tofree);

	if (i != NUM_VF_WEIGHT) {
		PMD_DRV_LOG(ERR, "vf_weights expects %d values, got %d",
			    NUM_VF_WEIGHT, i);
		return -EINVAL;
	}

	return 0;
}

static int id_parse_handler(__rte_unused const char *key,
			    const char *value, void *data)
{
	unsigned long val;
	char *end = NULL;

	val = strtoul(value, &end, 10);
	if (end == value || val > UINT8_MAX)
		return -EINVAL;

	*(uint8_t *)data = (uint8_t)val;
	return 0;
}

static int bar_idx_parse_handler(__rte_unused const char *key,
				 const char *value, void *data)
{
	unsigned long val;
	char *end = NULL;

	val = strtoul(value, &end, 10);
	if (end == value || val >= MCDMA_BAR_MAX)
		return -EINVAL;

	*(int *)data = (int)val;
	return 0;
}

#define MCDMA_BAM_BAR_KEY_IDX		0
#define MCDMA_VF_WEIGHT_KEY_IDX		1
#define MCDMA_PF_IDX			2
#define MCDMA_PARENT_PF_IDX		3

static int mcmda_parse_args(struct mcdma_pci_device *priv,
			    struct rte_pci_device *pci_dev)
{
	struct rte_devargs *devargs = priv->dev->device->devargs;
	struct rte_kvargs *kvlist;
	int bam_bar_idx = 0;
	int ret;

	if (!devargs)
		return -EINVAL;

	kvlist = rte_kvargs_parse(devargs->args, mcdma_kvargs_keys);
	if (!kvlist)
		return 0;

	priv->is_pf = false;

	/* Process pf_idx */
	if (rte_kvargs_count(kvlist, mcdma_kvargs_keys[MCDMA_PF_IDX])) {
		ret = rte_kvargs_process(kvlist, mcdma_kvargs_keys[MCDMA_PF_IDX],
					 id_parse_handler, &priv->pf_idx);
		if (ret) {
			PMD_DRV_LOG(WARNING, "PF index parse failed");
			rte_kvargs_free(kvlist);
			return ret;
		}

		if (priv->pf_idx >= MCDMA_MAX_PF) {
			PMD_DRV_LOG(ERR, "Invalid PF index: %u", priv->pf_idx);
			rte_kvargs_free(kvlist);
			return -EINVAL;
		}

		priv->is_pf = true;
	}

	if (priv->is_pf) {
		/* Process weight priority for VFs */
		if (rte_kvargs_count(kvlist, mcdma_kvargs_keys[MCDMA_VF_WEIGHT_KEY_IDX])) {
			int vf_weights[NUM_VF_WEIGHT];
			int i;

			ret = rte_kvargs_process(kvlist,
					mcdma_kvargs_keys[MCDMA_VF_WEIGHT_KEY_IDX],
					vf_weight_parse_handler, vf_weights);
			if (ret) {
				rte_kvargs_free(kvlist);
				return ret;
			}

			/* Program vf weights */
			for (i = 0; i < NUM_VF_WEIGHT; i++) {
				/* 4 vf weight configuration in 1 register */
				mcdma_csr_offset_t offset = MCDMA_CSR_VF_WEIGHT_0 + 4 * (i / 4);
				uint32_t shift = 8 * (unsigned int)(i % 4);
				uint32_t mask = 0xFFu << shift;

				mcdma_dmacsr_reg_updatel(priv->bar_base, offset,
							 vf_weights[i], shift, mask);
			}
		}

		/* Process BAM_bar index */
		if (rte_kvargs_count(kvlist, mcdma_kvargs_keys[MCDMA_BAM_BAR_KEY_IDX])) {
			ret = rte_kvargs_process(kvlist,
					mcdma_kvargs_keys[MCDMA_BAM_BAR_KEY_IDX],
					bar_idx_parse_handler, &bam_bar_idx);
			if (ret) {
				PMD_DRV_LOG(WARNING, "BAM BAR index parse failed");
				rte_kvargs_free(kvlist);
				return ret;
			}

			if (bam_bar_idx <= MCDMA_CONFIG_BAR ||
			    bam_bar_idx >= MCDMA_BAR_MAX) {
				PMD_DRV_LOG(ERR, "BAM BAR index not valid: %d",
					    bam_bar_idx);
				rte_kvargs_free(kvlist);
				return -EINVAL;
			}

			priv->bam = pci_dev->mem_resource[bam_bar_idx].addr;
		}
	}

	/* Process parent_pf idx */
	if (rte_kvargs_count(kvlist, mcdma_kvargs_keys[MCDMA_PARENT_PF_IDX])) {
		ret = rte_kvargs_process(kvlist,
				mcdma_kvargs_keys[MCDMA_PARENT_PF_IDX],
				id_parse_handler, &priv->parent_pf_idx);
		if (ret) {
			PMD_DRV_LOG(WARNING, "parent PF index parse failed");
			rte_kvargs_free(kvlist);
			return ret;
		}

		if (priv->parent_pf_idx >= MCDMA_MAX_PF) {
			PMD_DRV_LOG(ERR, "Invalid parent PF index: %u",
				    priv->parent_pf_idx);
			rte_kvargs_free(kvlist);
			return -EINVAL;
		}
	}

	rte_kvargs_free(kvlist);
	return 0;
}

static int mcdma_eth_dev_init(struct rte_eth_dev *dev)
{
	struct mcdma_pci_device *priv = dev->data->dev_private;
	struct rte_pci_device *pci_dev = RTE_CLASS_TO_BUS_DEVICE(dev, *pci_dev);
	uint32_t reg_val;
	int ret;

	dev->data->dev_private = priv;
	priv->dev = dev;
	priv->bar_base = pci_dev->mem_resource[MCDMA_CONFIG_BAR].addr;

	ret = mcmda_parse_args(priv, pci_dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "parse args failed with error: %d", ret);
		return ret;
	}

	PMD_DRV_LOG(INFO, "MCDMA RTL VERSION : 0x%x",
		    mcdma_dmacsr_reg_readl(priv->bar_base, MCDMA_CSR_VER_NUM));

	priv->pio = pci_dev->mem_resource[MCDMA_PIO_BAR].addr; /* user logic */
	priv->pio_bar_len = pci_dev->mem_resource[MCDMA_PIO_BAR].len;
	if (priv->pio == NULL) {
		priv->pio_bar_len = 0;
		PMD_DRV_LOG(WARNING, "PIO BAR %d is not mapped", MCDMA_PIO_BAR);
	}

	if (priv->is_pf) {
		reg_val = mcdma_dmacsr_reg_readl(priv->bar_base,
				MCDMA_CSR_PF_PARAM2_OFFSET(priv->pf_idx));
		priv->ip_num_chan = MCDMA_GET_NUM_CHAN_PER_PF(reg_val);
	} else {
		reg_val = mcdma_dmacsr_reg_readl(priv->bar_base,
				MCDMA_CSR_PF_PARAM2_OFFSET(priv->parent_pf_idx));
		priv->ip_num_chan = MCDMA_GET_NUM_CHAN_PER_VF(reg_val);
	}

	/* Register eth_dev_ops */
	mcdma_ethdev_ops_init(dev);

	dev->data->dev_flags |= RTE_ETH_DEV_NOLIVE_MAC_ADDR;

	dev->data->mac_addrs = rte_zmalloc("mcdma",
			RTE_ETHER_ADDR_LEN * MCDMA_MAX_MAC_ADDRS, 0);
	if (dev->data->mac_addrs == NULL)
		return -ENOMEM;

	return 0;
}

static int mcdma_eth_dev_uninit(struct rte_eth_dev *dev)
{
	rte_free(dev->data->mac_addrs);
	dev->data->mac_addrs = NULL;

	return 0;
}

static struct rte_pci_id mcdma_pci_id_tbl[] = {
#define RTE_PCI_DEV_ID_DECL_XNIC(vend, dev) {RTE_PCI_DEVICE(vend, dev)},
#ifndef PCI_VENDOR_ID_ALTERA
#define PCI_VENDOR_ID_ALTERA 0x1172
#endif
	RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_ALTERA, 0)
	{ .vendor_id = 0, },
};

static int mcdma_eth_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			      struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct mcdma_pci_device),
					     mcdma_eth_dev_init);
}

static int mcdma_eth_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, mcdma_eth_dev_uninit);
}

static struct rte_pci_driver rte_mcdma_pmd = {
	.id_table = mcdma_pci_id_tbl,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = mcdma_eth_pci_probe,
	.remove = mcdma_eth_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_mcdma, rte_mcdma_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_mcdma, mcdma_pci_id_tbl);
RTE_PMD_REGISTER_KMOD_DEP(net_mcdma, "* igb_uio | vfio-pci");
RTE_PMD_REGISTER_PARAM_STRING(net_mcdma,
	MCDMA_ARGS_PF_IDX "=<int> "
	MCDMA_ARGS_PARENT_PF_IDX "=<int> "
	MCDMA_ARGS_CFG_BAM_BAR "=<int> "
	MCDMA_ARGS_VF_WEIGHTS "=<string> ");
