/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_io.h>
#include <rte_vfio.h>
#include <rte_bus_pci.h>
#include <rte_bus_ifpga.h>
#include <rte_rawdev.h>

#include "afu_mf_rawdev.h"
#include "he_lbk.h"

static int he_lbk_afu_config(struct afu_mf_rawdev *dev)
{
	struct he_lbk_priv *priv = NULL;
	struct rte_pmd_afu_he_lbk_cfg *cfg = NULL;
	struct he_lbk_csr_cfg v;

	if (!dev)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	cfg = &priv->he_lbk_cfg;

	v.csr = 0;

	if (cfg->cont)
		v.cont = 1;

	v.mode = cfg->mode;
	v.trput_interleave = cfg->trput_interleave;
	if (cfg->multi_cl == 4)
		v.multicl_len = 2;
	else
		v.multicl_len = cfg->multi_cl - 1;

	AFU_MF_PMD_DEBUG("cfg: 0x%08x", v.csr);
	rte_write32(v.csr, priv->he_lbk_ctx.addr + CSR_CFG);

	return 0;
}

static void he_lbk_report(struct afu_mf_rawdev *dev, uint32_t cl)
{
	struct he_lbk_priv *priv = NULL;
	struct rte_pmd_afu_he_lbk_cfg *cfg = NULL;
	struct he_lbk_ctx *ctx = NULL;
	struct he_lbk_dsm_status *stat = NULL;
	struct he_lbk_status0 stat0;
	struct he_lbk_status1 stat1;
	uint64_t swtest_msg = 0;
	uint64_t ticks = 0;
	uint64_t info = 0;
	double num, rd_bw, wr_bw;

	if (!dev || !dev->priv)
		return;

	priv = (struct he_lbk_priv *)dev->priv;
	cfg = &priv->he_lbk_cfg;
	ctx = &priv->he_lbk_ctx;

	stat = ctx->status_ptr;

	swtest_msg = rte_read64(ctx->addr + CSR_SWTEST_MSG);
	stat0.csr = rte_read64(ctx->addr + CSR_STATUS0);
	stat1.csr = rte_read64(ctx->addr + CSR_STATUS1);

	if (cfg->cont)
		ticks = stat->num_clocks - stat->start_overhead;
	else
		ticks = stat->num_clocks -
			(stat->start_overhead + stat->end_overhead);

	if (cfg->freq_mhz == 0) {
		info = rte_read64(ctx->addr + CSR_HE_INFO0);
		AFU_MF_PMD_INFO("API version: %"PRIx64, info >> 16);
		cfg->freq_mhz = info & 0xffff;
		if (cfg->freq_mhz == 0) {
			AFU_MF_PMD_INFO("Frequency of AFU clock is unknown."
				" Assuming 350 MHz.");
			cfg->freq_mhz = 350;
		}
	}

	num = (double)stat0.num_reads;
	rd_bw = (num * CACHE_LINE_SIZE(1) * MHZ(cfg->freq_mhz)) / ticks;
	num = (double)stat0.num_writes;
	wr_bw = (num * CACHE_LINE_SIZE(1) * MHZ(cfg->freq_mhz)) / ticks;

	printf("Cachelines  Read_Count Write_Count Pend_Read Pend_Write "
		"Clocks@%uMHz   Rd_Bandwidth   Wr_Bandwidth\n",
		cfg->freq_mhz);
	printf("%10u  %10u %10u %10u %10u  %12"PRIu64
		"   %7.3f GB/s   %7.3f GB/s\n",
		cl, stat0.num_reads, stat0.num_writes,
		stat1.num_pend_reads, stat1.num_pend_writes,
		ticks, rd_bw / 1e9, wr_bw / 1e9);
	printf("Test Message: 0x%"PRIx64"\n", swtest_msg);
}

static int he_lbk_test(struct afu_mf_rawdev *dev)
{
	struct he_lbk_priv *priv = NULL;
	struct rte_pmd_afu_he_lbk_cfg *cfg = NULL;
	struct he_lbk_ctx *ctx = NULL;
	struct he_lbk_csr_ctl ctl;
	uint32_t *ptr = NULL;
	uint32_t i, j, cl, val = 0;
	uint64_t sval = 0;
	int ret = 0;

	if (!dev)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	cfg = &priv->he_lbk_cfg;
	ctx = &priv->he_lbk_ctx;

	ctl.csr = 0;
	rte_write32(ctl.csr, ctx->addr + CSR_CTL);
	rte_delay_us(1000);
	ctl.reset = 1;
	rte_write32(ctl.csr, ctx->addr + CSR_CTL);

	/* initialize DMA addresses */
	AFU_MF_PMD_DEBUG("src_addr: 0x%"PRIx64, ctx->src_iova);
	rte_write64(CACHE_LINE_ALIGNED(ctx->src_iova),
		ctx->addr + CSR_SRC_ADDR);

	AFU_MF_PMD_DEBUG("dst_addr: 0x%"PRIx64, ctx->dest_iova);
	rte_write64(CACHE_LINE_ALIGNED(ctx->dest_iova),
		ctx->addr + CSR_DST_ADDR);

	AFU_MF_PMD_DEBUG("dsm_addr: 0x%"PRIx64, ctx->dsm_iova);
	rte_write32(CACHE_LINE_ALIGNED(ctx->dsm_iova),
		ctx->addr + CSR_AFU_DSM_BASEL);
	rte_write32(CACHE_LINE_ALIGNED(ctx->dsm_iova) >> 32,
		ctx->addr + CSR_AFU_DSM_BASEH);

	ret = he_lbk_afu_config(dev);
	if (ret)
		return ret;

	/* initialize src data */
	ptr = (uint32_t *)ctx->src_ptr;
	j = CACHE_LINE_SIZE(cfg->end) >> 2;
	for (i = 0; i < j; i++)
		*ptr++ = i;

	/* start test */
	for (cl = cfg->begin; cl <= cfg->end; cl += cfg->multi_cl) {
		memset(ctx->dest_ptr, 0, CACHE_LINE_SIZE(cl));
		memset(ctx->dsm_ptr, 0, DSM_SIZE);

		ctl.csr = 0;
		rte_write32(ctl.csr, ctx->addr + CSR_CTL);
		rte_delay_us(1000);
		ctl.reset = 1;
		rte_write32(ctl.csr, ctx->addr + CSR_CTL);

		rte_write32(cl - 1, ctx->addr + CSR_NUM_LINES);

		ctl.start = 1;
		rte_write32(ctl.csr, ctx->addr + CSR_CTL);

		if (cfg->cont) {
			rte_delay_ms(cfg->timeout * 1000);
			ctl.force_completion = 1;
			rte_write32(ctl.csr, ctx->addr + CSR_CTL);
			ret = dsm_poll_timeout(&ctx->status_ptr->test_complete,
				val, (val & 0x1) == 1, DSM_POLL_INTERVAL,
				DSM_TIMEOUT);
			if (ret) {
				printf("DSM poll timeout\n");
				goto end;
			}
		} else {
			ret = dsm_poll_timeout(&ctx->status_ptr->test_complete,
				val, (val & 0x1) == 1, DSM_POLL_INTERVAL,
				DSM_TIMEOUT);
			if (ret) {
				printf("DSM poll timeout\n");
				goto end;
			}
			ctl.force_completion = 1;
			rte_write32(ctl.csr, ctx->addr + CSR_CTL);
		}

		he_lbk_report(dev, cl);

		i = 0;
		while (i++ < 100) {
			sval = rte_read64(ctx->addr + CSR_STATUS1);
			if (sval == 0)
				break;
			rte_delay_us(1000);
		}

		if (cfg->mode == NLB_MODE_LPBK) {
			ptr = (uint32_t *)ctx->dest_ptr;
			j = CACHE_LINE_SIZE(cl) >> 2;
			for (i = 0; i < j; i++) {
				if (*ptr++ != i) {
					AFU_MF_PMD_ERR("Data mismatch @ %u", i);
					break;
				}
			}
		}
	}

end:
	return 0;
}

static int he_lbk_ctx_release(struct afu_mf_rawdev *dev)
{
	struct he_lbk_priv *priv = NULL;
	struct he_lbk_ctx *ctx = NULL;

	if (!dev)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	ctx = &priv->he_lbk_ctx;

	rte_free(ctx->dsm_ptr);
	ctx->dsm_ptr = NULL;
	ctx->status_ptr = NULL;

	rte_free(ctx->src_ptr);
	ctx->src_ptr = NULL;

	rte_free(ctx->dest_ptr);
	ctx->dest_ptr = NULL;

	return 0;
}

static int he_lbk_ctx_init(struct afu_mf_rawdev *dev)
{
	struct he_lbk_priv *priv = NULL;
	struct he_lbk_ctx *ctx = NULL;
	int ret = 0;

	if (!dev)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	ctx = &priv->he_lbk_ctx;
	ctx->addr = (uint8_t *)dev->addr;

	ctx->dsm_ptr = (uint8_t *)rte_zmalloc(NULL, DSM_SIZE, TEST_MEM_ALIGN);
	if (!ctx->dsm_ptr) {
		ret = -ENOMEM;
		goto release;
	}
	ctx->dsm_iova = rte_malloc_virt2iova(ctx->dsm_ptr);
	if (ctx->dsm_iova == RTE_BAD_IOVA) {
		ret = -ENOMEM;
		goto release;
	}

	ctx->src_ptr = (uint8_t *)rte_zmalloc(NULL, NLB_BUF_SIZE,
		TEST_MEM_ALIGN);
	if (!ctx->src_ptr) {
		ret = -ENOMEM;
		goto release;
	}
	ctx->src_iova = rte_malloc_virt2iova(ctx->src_ptr);
	if (ctx->src_iova == RTE_BAD_IOVA) {
		ret = -ENOMEM;
		goto release;
	}

	ctx->dest_ptr = (uint8_t *)rte_zmalloc(NULL, NLB_BUF_SIZE,
		TEST_MEM_ALIGN);
	if (!ctx->dest_ptr) {
		ret = -ENOMEM;
		goto release;
	}
	ctx->dest_iova = rte_malloc_virt2iova(ctx->dest_ptr);
	if (ctx->dest_iova == RTE_BAD_IOVA) {
		ret = -ENOMEM;
		goto release;
	}

	ctx->status_ptr = (struct he_lbk_dsm_status *)ctx->dsm_ptr;
	return 0;

release:
	he_lbk_ctx_release(dev);
	return ret;
}

static int he_lbk_init(struct afu_mf_rawdev *dev)
{
	if (!dev)
		return -EINVAL;

	if (!dev->priv) {
		dev->priv = rte_zmalloc(NULL, sizeof(struct he_lbk_priv), 0);
		if (!dev->priv)
			return -ENOMEM;
	}

	return he_lbk_ctx_init(dev);
}

static int he_lbk_config(struct afu_mf_rawdev *dev, void *config,
	size_t config_size)
{
	struct he_lbk_priv *priv = NULL;
	struct rte_pmd_afu_he_lbk_cfg *cfg = NULL;

	if (!dev || !config || !config_size)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	if (config_size != sizeof(struct rte_pmd_afu_he_lbk_cfg))
		return -EINVAL;

	cfg = (struct rte_pmd_afu_he_lbk_cfg *)config;
	if (cfg->mode > NLB_MODE_TRPUT)
		return -EINVAL;
	if ((cfg->multi_cl != 1) && (cfg->multi_cl != 2) &&
		(cfg->multi_cl != 4))
		return -EINVAL;
	if ((cfg->begin < MIN_CACHE_LINES) || (cfg->begin > MAX_CACHE_LINES))
		return -EINVAL;
	if ((cfg->end < cfg->begin) || (cfg->end > MAX_CACHE_LINES))
		return -EINVAL;

	rte_memcpy(&priv->he_lbk_cfg, cfg, sizeof(priv->he_lbk_cfg));

	return 0;
}

static int he_lbk_close(struct afu_mf_rawdev *dev)
{
	if (!dev)
		return -EINVAL;

	he_lbk_ctx_release(dev);

	rte_free(dev->priv);
	dev->priv = NULL;

	return 0;
}

static int he_lbk_dump(struct afu_mf_rawdev *dev, FILE *f)
{
	struct he_lbk_priv *priv = NULL;
	struct he_lbk_ctx *ctx = NULL;

	if (!dev)
		return -EINVAL;

	priv = (struct he_lbk_priv *)dev->priv;
	if (!priv)
		return -ENOENT;

	if (!f)
		f = stdout;

	ctx = &priv->he_lbk_ctx;

	fprintf(f, "addr:\t\t%p\n", (void *)ctx->addr);
	fprintf(f, "dsm_ptr:\t%p\n", (void *)ctx->dsm_ptr);
	fprintf(f, "dsm_iova:\t0x%"PRIx64"\n", ctx->dsm_iova);
	fprintf(f, "src_ptr:\t%p\n", (void *)ctx->src_ptr);
	fprintf(f, "src_iova:\t0x%"PRIx64"\n", ctx->src_iova);
	fprintf(f, "dest_ptr:\t%p\n", (void *)ctx->dest_ptr);
	fprintf(f, "dest_iova:\t0x%"PRIx64"\n", ctx->dest_iova);
	fprintf(f, "status_ptr:\t%p\n", (void *)ctx->status_ptr);

	return 0;
}

static struct afu_mf_ops he_lbk_ops = {
	.init = he_lbk_init,
	.config = he_lbk_config,
	.start = NULL,
	.stop = NULL,
	.test = he_lbk_test,
	.close = he_lbk_close,
	.dump = he_lbk_dump,
	.reset = NULL
};

struct afu_mf_drv he_lbk_drv = {
	.uuid = { HE_LBK_UUID_L, HE_LBK_UUID_H },
	.ops = &he_lbk_ops
};

struct afu_mf_drv he_mem_lbk_drv = {
	.uuid = { HE_MEM_LBK_UUID_L, HE_MEM_LBK_UUID_H },
	.ops = &he_lbk_ops
};
