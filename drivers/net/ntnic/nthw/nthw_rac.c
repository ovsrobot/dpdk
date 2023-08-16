/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nt_util.h"
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"
#include "nthw_rac.h"

#include <pthread.h>

/*
 * Prevent that RAB echo debug trace ever gets into a release build
 */
#if defined(DEBUG)
#undef RAB_DEBUG_ECHO
#else
#undef RAB_DEBUG_ECHO
#endif /* DEBUG */

#define RAB_DMA_WAIT (1000000)
#define RAB_DMA_BUF_CNT (0x4000)

#define RAB_READ (0x01)
#define RAB_WRITE (0x02)
#define RAB_ECHO (0x08)
#define RAB_COMPLETION (0x0F)

#define RAB_READ_ECHO (RAB_READ | RAB_ECHO)
#define RAB_WRITE_ECHO (RAB_WRITE | RAB_ECHO)

#define RAB_OPR_LO (28)
#define RAB_OPR_HI (31)
#define RAB_OPR_BW (4)

#define RAB_CNT_LO (20)
#define RAB_CNT_HI (27)
#define RAB_CNT_BW (8)

#define RAB_BUSID_LO (16)
#define RAB_BUSID_HI (19)
#define RAB_BUSID_BW (4)

#define RAB_ADDR_LO (0)
#define RAB_ADDR_HI (15)
#define RAB_ADDR_BW (16)

nthw_rac_t *nthw_rac_new(void)
{
	nthw_rac_t *p = malloc(sizeof(nthw_rac_t));

	memset(p, 0, sizeof(nthw_rac_t));
	return p;
}

void nthw_rac_delete(nthw_rac_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_rac_t));
		free(p);
	}
}

int nthw_rac_init(nthw_rac_t *p, nt_fpga_t *p_fpga, struct fpga_info_s *p_fpga_info)
{
	assert(p_fpga_info);

	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_RAC, 0);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: RAC %d: no such instance\n",
		       p_adapter_id_str, 0);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mp_mod_rac = mod;

	{
		/*
		 * RAC is a primary communication channel
		 * turn off debug by default
		 * except for rac_rab_init
		 */
		const int n_debug_mode = module_get_debug_mode(p->mp_mod_rac);

		if (n_debug_mode && n_debug_mode <= 0xff) {
			module_set_debug_mode(p->mp_mod_rac, 0);
			register_set_debug_mode(p->mp_reg_rab_init, n_debug_mode);
		}
	}

	/* Params */
	p->mn_param_rac_rab_interfaces =
		fpga_get_product_param(p->mp_fpga, NT_RAC_RAB_INTERFACES, 3);
	NT_LOG(DBG, NTHW, "%s: NT_RAC_RAB_INTERFACES=%d\n", p_adapter_id_str,
	       p->mn_param_rac_rab_interfaces);

	p->mn_param_rac_rab_ob_update =
		fpga_get_product_param(p->mp_fpga, NT_RAC_RAB_OB_UPDATE, 0);
	NT_LOG(DBG, NTHW, "%s: NT_RAC_RAB_OB_UPDATE=%d\n", p_adapter_id_str,
	       p->mn_param_rac_rab_ob_update);

	/* Optional dummy test registers */
	p->mp_reg_dummy0 = module_query_register(p->mp_mod_rac, RAC_DUMMY0);
	p->mp_reg_dummy1 = module_query_register(p->mp_mod_rac, RAC_DUMMY1);
	p->mp_reg_dummy2 = module_query_register(p->mp_mod_rac, RAC_DUMMY2);

	p->mp_reg_rab_init = module_get_register(p->mp_mod_rac, RAC_RAB_INIT);
	p->mp_fld_rab_init = register_get_field(p->mp_reg_rab_init, RAC_RAB_INIT_RAB);
	p->mn_fld_rab_init_bw = field_get_bit_width(p->mp_fld_rab_init);
	p->mn_fld_rab_init_mask = field_get_mask(p->mp_fld_rab_init);

	/* RAC_RAB_INIT_RAB reg/field sanity checks: */
	assert(p->mn_fld_rab_init_mask == ((1UL << p->mn_fld_rab_init_bw) - 1));
	assert(p->mn_fld_rab_init_bw == p->mn_param_rac_rab_interfaces);

	p->mp_reg_dbg_ctrl = module_query_register(p->mp_mod_rac, RAC_DBG_CTRL);
	if (p->mp_reg_dbg_ctrl) {
		p->mp_fld_dbg_ctrl =
			register_query_field(p->mp_reg_dbg_ctrl, RAC_DBG_CTRL_C);
	} else {
		p->mp_fld_dbg_ctrl = NULL;
	}
	p->mp_reg_dbg_data = module_query_register(p->mp_mod_rac, RAC_DBG_DATA);
	if (p->mp_reg_dbg_data) {
		p->mp_fld_dbg_data =
			register_query_field(p->mp_reg_dbg_data, RAC_DBG_DATA_D);
	} else {
		p->mp_reg_dbg_data = NULL;
	}
	p->mp_reg_rab_ib_data = module_get_register(p->mp_mod_rac, RAC_RAB_IB_DATA);
	p->mp_fld_rab_ib_data =
		register_get_field(p->mp_reg_rab_ib_data, RAC_RAB_IB_DATA_D);

	p->mp_reg_rab_ob_data = module_get_register(p->mp_mod_rac, RAC_RAB_OB_DATA);
	p->mp_fld_rab_ob_data =
		register_get_field(p->mp_reg_rab_ob_data, RAC_RAB_OB_DATA_D);

	p->mp_reg_rab_buf_free = module_get_register(p->mp_mod_rac, RAC_RAB_BUF_FREE);
	p->mp_fld_rab_buf_free_ib_free =
		register_get_field(p->mp_reg_rab_buf_free, RAC_RAB_BUF_FREE_IB_FREE);
	p->mp_fld_rab_buf_free_ib_ovf =
		register_get_field(p->mp_reg_rab_buf_free, RAC_RAB_BUF_FREE_IB_OVF);
	p->mp_fld_rab_buf_free_ob_free =
		register_get_field(p->mp_reg_rab_buf_free, RAC_RAB_BUF_FREE_OB_FREE);
	p->mp_fld_rab_buf_free_ob_ovf =
		register_get_field(p->mp_reg_rab_buf_free, RAC_RAB_BUF_FREE_OB_OVF);
	p->mp_fld_rab_buf_free_timeout =
		register_get_field(p->mp_reg_rab_buf_free, RAC_RAB_BUF_FREE_TIMEOUT);

	p->mp_reg_rab_buf_used = module_get_register(p->mp_mod_rac, RAC_RAB_BUF_USED);
	p->mp_fld_rab_buf_used_ib_used =
		register_get_field(p->mp_reg_rab_buf_used, RAC_RAB_BUF_USED_IB_USED);
	p->mp_fld_rab_buf_used_ob_used =
		register_get_field(p->mp_reg_rab_buf_used, RAC_RAB_BUF_USED_OB_USED);
	p->mp_fld_rab_buf_used_flush =
		register_get_field(p->mp_reg_rab_buf_used, RAC_RAB_BUF_USED_FLUSH);

	/*
	 * RAC_RAB_DMA regs are optional - only found in real NT4GA - not found in 9231/9232 and
	 * earlier
	 */
	p->mp_reg_rab_dma_ib_lo = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_IB_LO);
	p->mp_fld_rab_dma_ib_lo_phy_addr =
		register_get_field(p->mp_reg_rab_dma_ib_lo, RAC_RAB_DMA_IB_LO_PHYADDR);

	p->mp_reg_rab_dma_ib_hi = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_IB_HI);
	p->mp_fld_rab_dma_ib_hi_phy_addr =
		register_get_field(p->mp_reg_rab_dma_ib_hi, RAC_RAB_DMA_IB_HI_PHYADDR);

	p->mp_reg_rab_dma_ob_lo = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_OB_LO);
	p->mp_fld_rab_dma_ob_lo_phy_addr =
		register_get_field(p->mp_reg_rab_dma_ob_lo, RAC_RAB_DMA_OB_LO_PHYADDR);

	p->mp_reg_rab_dma_ob_hi = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_OB_HI);
	p->mp_fld_rab_dma_ob_hi_phy_addr =
		register_get_field(p->mp_reg_rab_dma_ob_hi, RAC_RAB_DMA_OB_HI_PHYADDR);

	p->mp_reg_rab_dma_ib_wr = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_IB_WR);
	p->mp_fld_rab_dma_ib_wr_ptr =
		register_get_field(p->mp_reg_rab_dma_ib_wr, RAC_RAB_DMA_IB_WR_PTR);

	p->mp_reg_rab_dma_ib_rd = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_IB_RD);
	p->mp_fld_rab_dma_ib_rd_ptr =
		register_get_field(p->mp_reg_rab_dma_ib_rd, RAC_RAB_DMA_IB_RD_PTR);

	p->mp_reg_rab_dma_ob_wr = module_get_register(p->mp_mod_rac, RAC_RAB_DMA_OB_WR);
	p->mp_fld_rab_dma_ob_wr_ptr =
		register_get_field(p->mp_reg_rab_dma_ob_wr, RAC_RAB_DMA_OB_WR_PTR);

	p->rac_rab_init_addr = register_get_address(p->mp_reg_rab_init);
	p->rac_rab_ib_data_addr = register_get_address(p->mp_reg_rab_ib_data);
	p->rac_rab_ob_data_addr = register_get_address(p->mp_reg_rab_ob_data);
	p->rac_rab_buf_free_addr = register_get_address(p->mp_reg_rab_buf_free);
	p->rac_rab_buf_used_addr = register_get_address(p->mp_reg_rab_buf_used);

	/*
	 * RAC_RAB_DMA regs are optional - only found in real NT4GA -
	 * not found in 9231/9232 and earlier
	 */

	p->rac_rab_dma_ib_lo_addr = register_get_address(p->mp_reg_rab_dma_ib_lo);
	p->rac_rab_dma_ib_hi_addr = register_get_address(p->mp_reg_rab_dma_ib_hi);
	p->rac_rab_dma_ob_lo_addr = register_get_address(p->mp_reg_rab_dma_ob_lo);
	p->rac_rab_dma_ob_hi_addr = register_get_address(p->mp_reg_rab_dma_ob_hi);
	p->rac_rab_dma_ib_rd_addr = register_get_address(p->mp_reg_rab_dma_ib_rd);
	p->rac_rab_dma_ob_wr_addr = register_get_address(p->mp_reg_rab_dma_ob_wr);
	p->rac_rab_dma_ib_wr_addr = register_get_address(p->mp_reg_rab_dma_ib_wr);

	p->rac_rab_buf_free_ib_free_mask =
		field_get_mask(p->mp_fld_rab_buf_free_ib_free);
	p->rac_rab_buf_free_ob_free_mask =
		field_get_mask(p->mp_fld_rab_buf_free_ob_free);
	p->rac_rab_buf_used_ib_used_mask =
		field_get_mask(p->mp_fld_rab_buf_used_ib_used);
	p->rac_rab_buf_used_ob_used_mask =
		field_get_mask(p->mp_fld_rab_buf_used_ob_used);

	p->rac_rab_buf_used_flush_mask = field_get_mask(p->mp_fld_rab_buf_used_flush);

	p->rac_rab_buf_used_ob_used_low =
		field_get_bit_pos_low(p->mp_fld_rab_buf_used_ob_used);

	p->mp_reg_rab_nmb_rd = module_query_register(p->mp_mod_rac, RAC_NMB_RD_ADR);
	if (p->mp_reg_rab_nmb_rd)
		p->rac_nmb_rd_adr_addr = register_get_address(p->mp_reg_rab_nmb_rd);

	p->mp_reg_rab_nmb_data = module_query_register(p->mp_mod_rac, RAC_NMB_DATA);
	if (p->mp_reg_rab_nmb_data)
		p->rac_nmb_data_addr = register_get_address(p->mp_reg_rab_nmb_data);

	p->mp_reg_rab_nmb_wr = module_query_register(p->mp_mod_rac, RAC_NMB_WR_ADR);
	if (p->mp_reg_rab_nmb_wr)
		p->rac_nmb_wr_adr_addr = register_get_address(p->mp_reg_rab_nmb_wr);

	p->mp_reg_rab_nmb_status =
		module_query_register(p->mp_mod_rac, RAC_NMB_STATUS);
	if (p->mp_reg_rab_nmb_status) {
		p->rac_nmb_status_addr =
			register_get_address(p->mp_reg_rab_nmb_status);
	}

	p->m_dma = NULL;

	pthread_mutex_init(&p->m_mutex, NULL);

	return 0;
}

int nthw_rac_get_rab_interface_count(const nthw_rac_t *p)
{
	return p->mn_param_rac_rab_interfaces;
}

static inline int nthw_rac_wait_for_rab_done(const nthw_rac_t *p, uint32_t address,
		uint32_t word_cnt)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	uint32_t used = 0;
	uint32_t retry;

	for (retry = 0; retry < 100000; retry++) {
		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_used_addr, &used);
		used = (used & p->rac_rab_buf_used_ob_used_mask) >>
		       p->rac_rab_buf_used_ob_used_low;
		if (used >= word_cnt)
			break;
	}

	if (used < word_cnt) {
		NT_LOG(ERR, NTHW,
		       "%s: Fail rab bus r/w addr=0x%08X used=%x wordcount=%d\n",
		       p_adapter_id_str, address, used, word_cnt);
		return -1;
	}
	return 0;
}

/*
 * NT_PCI_REG_P9xyz_RAC_RAB_INIT
 *
 * Initializes (resets) the programmable registers on the Register Access Busses (RAB).
 * This initialization must be performed by software as part of the driver load procedure.
 *
 * Bit n of this field initializes the programmable registers on RAB interface n.
 * Software must write one to the bit and then clear the bit again.
 *
 * All RAB module registers will be reset to their defaults.
 * This includes the product specific RESET module (eg RST9xyz)
 * As a consequence of this behavior the official reset sequence
 * must be excersised - as all RAB modules will be held in reset.
 */
int nthw_rac_rab_init(nthw_rac_t *p, uint32_t n_rab_intf_mask)
{
	/*
	 * Write rac_rab_init
	 * Perform operation twice - first to get trace of operation -
	 * second to get things done...
	 */
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;

	field_set_val_flush32(p->mp_fld_rab_init, n_rab_intf_mask);
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_init_addr, n_rab_intf_mask);
	return 0;
}

int nthw_rac_rab_reset(nthw_rac_t *p)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;

	const char *const p_adapter_id_str _unused = p_fpga_info->mp_adapter_id_str;

	/* RAC RAB bus "flip/flip" reset */
	const int n_rac_rab_bus_count = nthw_rac_get_rab_interface_count(p);
	const int n_rac_rab_bus_mask = (1 << n_rac_rab_bus_count) - 1;

	NT_LOG(DBG, NTHW, "%s: NT_RAC_RAB_INTERFACES=%d (0x%02X)\n",
	       p_adapter_id_str, n_rac_rab_bus_count, n_rac_rab_bus_mask);
	assert(n_rac_rab_bus_count);
	assert(n_rac_rab_bus_mask);

	/* RAC RAB bus "flip/flip" reset first stage - new impl (ref RMT#37020) */
	nthw_rac_rab_init(p, 0);
	nthw_rac_rab_init(p, n_rac_rab_bus_mask);
	nthw_rac_rab_init(p, n_rac_rab_bus_mask & ~0x01);

	return 0;
}

int nthw_rac_rab_setup(nthw_rac_t *p)
{
	int rc = 0;

	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	uint32_t n_dma_buf_size = 2L * RAB_DMA_BUF_CNT * sizeof(uint32_t);
	const size_t align_size = ALIGN_SIZE(n_dma_buf_size);
	int numa_node = p_fpga_info->numa_node;
	uint64_t dma_addr;
	uint32_t buf;

	if (!p->m_dma) {
		struct nt_dma_s *vfio_dma;
		/* FPGA needs Page alignment (4K) */
		vfio_dma = nt_dma_alloc(align_size, 0x1000, numa_node);

		if (vfio_dma == NULL) {
			NT_LOG(ERR, ETHDEV, "%s: nt_dma_alloc failed\n",
			       __func__);
			return -1;
		}
		p->m_dma_in_buf = (uint32_t *)vfio_dma->addr;
		p->m_dma_out_buf = p->m_dma_in_buf + RAB_DMA_BUF_CNT;
		p->m_dma = vfio_dma;
	}

	/* Setup DMA on the adapter */
	dma_addr = p->m_dma->iova;
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_dma_ib_lo_addr,
			   dma_addr & 0xffffffff);
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_dma_ib_hi_addr,
			   (uint32_t)(dma_addr >> 32) & 0xffffffff);
	dma_addr += RAB_DMA_BUF_CNT * sizeof(uint32_t);
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_dma_ob_lo_addr,
			   dma_addr & 0xffffffff);
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_dma_ob_hi_addr,
			   (uint32_t)(dma_addr >> 32) & 0xffffffff);

	/* Set initial value of internal pointers */
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_dma_ib_rd_addr, &buf);
	p->m_dma_in_ptr_wr = (uint16_t)(buf / sizeof(uint32_t));
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_dma_ob_wr_addr, &buf);
	p->m_dma_out_ptr_rd = (uint16_t)(buf / sizeof(uint32_t));
	p->m_in_free = RAB_DMA_BUF_CNT;

	return rc;
}

int nthw_rac_rab_dma_begin(nthw_rac_t *p)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;

	pthread_mutex_lock(&p->m_mutex);

	if (p->m_dma_active) {
		pthread_mutex_unlock(&p->m_mutex);
		NT_LOG(ERR, NTHW,
		       "%s: DMA begin requested, but a DMA transaction is already active\n",
		       p_adapter_id_str);
		return -1;
	}

	p->m_dma_active = true;

	return 0;
}

static void nthw_rac_rab_dma_activate(nthw_rac_t *p)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const uint32_t completion = RAB_COMPLETION << RAB_OPR_LO;

	/* Write completion word */
	p->m_dma_in_buf[p->m_dma_in_ptr_wr] = completion;
	p->m_dma_in_ptr_wr =
		(uint16_t)((p->m_dma_in_ptr_wr + 1) & (RAB_DMA_BUF_CNT - 1));

	/* Clear output completion word */
	p->m_dma_out_buf[p->m_dma_out_ptr_rd] = 0;

	/* _update DMA pointer and start transfer */
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_dma_ib_wr_addr,
			   (uint32_t)(p->m_dma_in_ptr_wr * sizeof(uint32_t)));
}

static int nthw_rac_rab_dma_wait(nthw_rac_t *p)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const uint32_t completion = RAB_COMPLETION << RAB_OPR_LO;
	uint32_t i;

	for (i = 0; i < RAB_DMA_WAIT; i++) {
		NT_OS_WAIT_USEC_POLL(1);
		if ((p->m_dma_out_buf[p->m_dma_out_ptr_rd] & completion) ==
				completion)
			break;
	}

	if (i == RAB_DMA_WAIT) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Unexpected value of completion (0x%08X)\n",
		       p_fpga_info->mp_adapter_id_str,
		       p->m_dma_out_buf[p->m_dma_out_ptr_rd]);
		return -1;
	}

	p->m_dma_out_ptr_rd =
		(uint16_t)((p->m_dma_out_ptr_rd + 1) & (RAB_DMA_BUF_CNT - 1));
	p->m_in_free = RAB_DMA_BUF_CNT;

	return 0;
}

int nthw_rac_rab_dma_commit(nthw_rac_t *p)
{
	int ret;

	if (!p->m_dma_active) {
		/* Expecting mutex not to be locked! */
		assert(0); /* alert developer that something is wrong */
		return -1;
	}

	nthw_rac_rab_dma_activate(p);
	ret = nthw_rac_rab_dma_wait(p);

	p->m_dma_active = false;

	pthread_mutex_unlock(&p->m_mutex);

	return ret;
}

void nthw_rac_reg_read32(const struct fpga_info_s *p_fpga_info, uint32_t reg_addr,
		       uint32_t *p_data)
{
	*p_data = *(volatile uint32_t *)((uint8_t *)p_fpga_info->bar0_addr +
					reg_addr);
}

void nthw_rac_reg_write32(const struct fpga_info_s *p_fpga_info, uint32_t reg_addr,
			uint32_t p_data)
{
	*(volatile uint32_t *)((uint8_t *)p_fpga_info->bar0_addr + reg_addr) =
		p_data;
}

int nthw_rac_rab_write32_dma(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			    uint32_t word_cnt, const uint32_t *p_data)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;

	if (word_cnt == 0 || word_cnt > 256) {
		NT_LOG(ERR, NTHW,
		       "%s: Failed rab dma write length check - bus: %d addr: 0x%08X wordcount: %d - inBufFree: 0x%08X\n",
		       p_fpga_info->mp_adapter_id_str, bus_id, address, word_cnt,
		       p->m_in_free);
		assert(0); /* alert developer that something is wrong */
		return -1;
	}

	if (p->m_in_free < (word_cnt + 3)) {
		/*
		 * No more memory available.
		 * nthw_rac_rab_dma_commit() needs to be called to start and finish pending
		 * transfers.
		 */
		return -1;
	}

	p->m_in_free -= (word_cnt + 1);

	/* Write the command word */
#if defined(RAB_DEBUG_ECHO)
	p->m_dma_in_buf[p->m_dma_in_ptr_wr] =
		(RAB_WRITE_ECHO << RAB_OPR_LO) |
		((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
		(bus_id << RAB_BUSID_LO) | address;
	p->m_dma_out_ptr_rd = (uint16_t)((p->m_dma_out_ptr_rd + word_cnt + 1) &
				     (RAB_DMA_BUF_CNT - 1));
#else
	p->m_dma_in_buf[p->m_dma_in_ptr_wr] =
		(RAB_WRITE << RAB_OPR_LO) |
		((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
		(bus_id << RAB_BUSID_LO) | address;
#endif
	p->m_dma_in_ptr_wr =
		(uint16_t)((p->m_dma_in_ptr_wr + 1) & (RAB_DMA_BUF_CNT - 1));

	for (uint32_t i = 0; i < word_cnt; i++) {
		p->m_dma_in_buf[p->m_dma_in_ptr_wr] = p_data[i];
		p->m_dma_in_ptr_wr = (uint16_t)((p->m_dma_in_ptr_wr + 1) &
					    (RAB_DMA_BUF_CNT - 1));
	}

	return 0;
}

int nthw_rac_rab_read32_dma(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			   uint32_t word_cnt, struct dma_buf_ptr *buf_ptr)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;

	if (word_cnt == 0 || word_cnt > 256) {
		NT_LOG(ERR, NTHW,
		       "%s: Failed rab dma read length check - bus: %d addr: 0x%08X wordcount: %d - inBufFree: 0x%08X\n",
		       p_fpga_info->mp_adapter_id_str, bus_id, address, word_cnt,
		       p->m_in_free);
		assert(0); /* alert developer that something is wrong */
		return -1;
	}

	if ((word_cnt + 3) > RAB_DMA_BUF_CNT) {
		NT_LOG(ERR, NTHW,
		       "%s: Failed rab dma read length check - bus: %d addr: 0x%08X wordcount: %d: 0x%08X",
		       p_fpga_info->mp_adapter_id_str, bus_id, address, word_cnt);
		return -1;
	}

	if (p->m_in_free < 3) {
		/*
		 * No more memory available.
		 * nthw_rac_rab_dma_commit() needs to be called to start and finish pending
		 * transfers.
		 */
		return -1;
	}

	p->m_in_free -= 1;

	/* Write the command word */
#if defined(RAB_DEBUG_ECHO)
	p->m_dma_in_buf[p->m_dma_in_ptr_wr] =
		(RAB_READ_ECHO << RAB_OPR_LO) |
		((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
		(bus_id << RAB_BUSID_LO) | address;
	p->m_dma_out_ptr_rd =
		(uint16_t)((p->m_dma_out_ptr_rd + 1) & (RAB_DMA_BUF_CNT - 1));
#else
	p->m_dma_in_buf[p->m_dma_in_ptr_wr] =
		(RAB_READ << RAB_OPR_LO) |
		((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
		(bus_id << RAB_BUSID_LO) | address;
#endif
	p->m_dma_in_ptr_wr =
		(uint16_t)((p->m_dma_in_ptr_wr + 1) & (RAB_DMA_BUF_CNT - 1));

	buf_ptr->index = p->m_dma_out_ptr_rd;
	buf_ptr->size = RAB_DMA_BUF_CNT;
	buf_ptr->base = p->m_dma_out_buf;
	p->m_dma_out_ptr_rd = (uint16_t)((p->m_dma_out_ptr_rd + word_cnt) &
				     (RAB_DMA_BUF_CNT - 1U));

	return 0;
}

int nthw_rac_rab_write32(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			uint32_t word_cnt, const uint32_t *p_data)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	int res = 0;
	uint32_t rab_oper_wr;
	uint32_t rab_oper_cmpl;
	uint32_t rab_echo_oper_cmpl;
	uint32_t word_cnt_expected;
	uint32_t buf_used;
	uint32_t buf_free;
	uint32_t in_buf_free;
	uint32_t out_buf_free;

	if (address > (1 << RAB_ADDR_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal address: value too large %d - max %d\n",
		       p_adapter_id_str, address, (1 << RAB_ADDR_BW));
		return -1;
	}

	if (bus_id > (1 << RAB_BUSID_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal bus id: value too large %d - max %d\n",
		       p_adapter_id_str, bus_id, (1 << RAB_BUSID_BW));
		return -1;
	}

	if (word_cnt == 0) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal word count: value is zero (%d)\n",
		       p_adapter_id_str, word_cnt);
		return -1;
	}

	if (word_cnt > (1 << RAB_CNT_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal word count: value too large %d - max %d\n",
		       p_adapter_id_str, word_cnt, (1 << RAB_CNT_BW));
		return -1;
	}

	pthread_mutex_lock(&p->m_mutex);

	if (p->m_dma_active) {
		NT_LOG(ERR, NTHW, "%s: RAB: Illegal operation: DMA enabled\n",
		       p_adapter_id_str);
		res = -1;
		goto exit_unlock_res;
	}

	/* Read buffer free register */
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_free_addr, &buf_free);

	in_buf_free = buf_free & p->rac_rab_buf_free_ib_free_mask;
	out_buf_free = (buf_free & p->rac_rab_buf_free_ob_free_mask) >> 16;

	/* Read buffer used register */
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_used_addr, &buf_used);

	buf_used = buf_used & (p->rac_rab_buf_used_ib_used_mask |
			     p->rac_rab_buf_used_ob_used_mask);

	/*
	 * Verify that output buffer can hold one completion word,
	 * input buffer can hold the number of words to be written +
	 * one write and one completion command
	 * and that the input and output "used" buffer is 0
	 */
	if ((out_buf_free >= 1 && (in_buf_free >= word_cnt + 2)) && buf_used == 0) {
		uint32_t i;

		word_cnt_expected = 0;

		/* Compose write command */
#if defined(RAB_DEBUG_ECHO)
		rab_oper_wr =
			(RAB_WRITE_ECHO << RAB_OPR_LO) |
			((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
			(bus_id << RAB_BUSID_LO) | address;
		word_cnt_expected += word_cnt + 1;
#else
		rab_oper_wr =
			(RAB_WRITE << RAB_OPR_LO) |
			((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
			(bus_id << RAB_BUSID_LO) | address;
#endif /* RAB_DEBUG_ECHO */

		/* Write command */
		nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ib_data_addr,
				   rab_oper_wr);

		/* Write da to input buffer */
		for (i = 0; i < word_cnt; i++) {
			nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ib_data_addr,
					   *p_data);
			p_data++;
		}

		/* Compose completion command */
		rab_oper_cmpl = (RAB_COMPLETION << RAB_OPR_LO);
		word_cnt_expected++;

		/* Write command */
		nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ib_data_addr,
				   rab_oper_cmpl);

		/* Wait until done */
		if (nthw_rac_wait_for_rab_done(p, address, word_cnt_expected)) {
			res = -1;
			goto exit_unlock_res;
		}

#if defined(RAB_DEBUG_ECHO)
		{
			uint32_t rab_echo_oper_wr;

			nthw_rac_reg_read32(p_fpga_info, p->rac_rab_ob_data_addr,
					  &rab_echo_oper_wr);
			if (p->mn_param_rac_rab_ob_update) {
				nthw_rac_reg_write32(p_fpga_info,
						   p->rac_rab_ob_data_addr, 0);
			}
			if (rab_oper_wr != rab_echo_oper_wr) {
				NT_LOG(ERR, NTHW,
				       "%s: expected rab read echo oper (0x%08X) - read (0x%08X)\n",
				       p_adapter_id_str, rab_oper_wr, rab_echo_oper_wr);
			}
		}

		{
			/* Read data from output buffer */
			uint32_t data;

			for (i = 0; i < word_cnt; i++) {
				nthw_rac_reg_read32(p_fpga_info,
						  p->rac_rab_ob_data_addr,
						  &data);
				if (p->mn_param_rac_rab_ob_update) {
					nthw_rac_reg_write32(p_fpga_info,
							     p->rac_rab_ob_data_addr, 0);
				}
			}
		}
#endif /* RAB_DEBUG_ECHO */

		/* Read completion from out buffer */
		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_ob_data_addr,
				  &rab_echo_oper_cmpl);
		if (p->mn_param_rac_rab_ob_update) {
			nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ob_data_addr,
					   0);
		}
		if (rab_echo_oper_cmpl != rab_oper_cmpl) {
			NT_LOG(ERR, NTHW,
			       "%s: RAB: Unexpected value of completion (0x%08X)- inBufFree: 0x%08X, outBufFree: 0x%08X, bufUsed: 0x%08X\n",
			       p_adapter_id_str, rab_echo_oper_cmpl, in_buf_free,
			       out_buf_free, buf_used);
			res = -1;
			goto exit_unlock_res;
		}

		/* Read buffer free register */
		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_free_addr,
				  &buf_free);
		if (buf_free & 0x80000000) {
			/* Clear Timeout and overflow bits */
			nthw_rac_reg_write32(p_fpga_info, p->rac_rab_buf_free_addr,
					   0x0);
			NT_LOG(ERR, NTHW,
			       "%s: RAB: timeout - Access outside register - bus: %d addr: 0x%08X - inBufFree: 0x%08X, outBufFree: 0x%08X, bufUsed: 0x%08X\n",
			       p_adapter_id_str, bus_id, address, in_buf_free,
			       out_buf_free, buf_used);
			res = -1;
			goto exit_unlock_res;
		}

		res = 0;
		goto exit_unlock_res;
	} else {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Fail rab bus buffer check - bus: %d addr: 0x%08X wordcount: %d - inBufFree: 0x%08X, outBufFree: 0x%08X, bufUsed: 0x%08X\n",
		       p_adapter_id_str, bus_id, address, word_cnt, in_buf_free,
		       out_buf_free, buf_used);
		res = -1;
		goto exit_unlock_res;
	}

exit_unlock_res:
	pthread_mutex_unlock(&p->m_mutex);
	return res;
}

int nthw_rac_rab_read32(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
		       uint32_t word_cnt, uint32_t *p_data)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	int res = 0;
	uint32_t rab_oper_rd;
	uint32_t word_cnt_expected;
	uint32_t buf_used;
	uint32_t buf_free;
	uint32_t in_buf_free;
	uint32_t out_buf_free;

	pthread_mutex_lock(&p->m_mutex);

	if (address > (1 << RAB_ADDR_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal address: value too large %d - max %d\n",
		       p_adapter_id_str, address, (1 << RAB_ADDR_BW));
		res = -1;
		goto exit_unlock_res;
	}

	if (bus_id > (1 << RAB_BUSID_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal bus id: value too large %d - max %d\n",
		       p_adapter_id_str, bus_id, (1 << RAB_BUSID_BW));
		res = -1;
		goto exit_unlock_res;
	}

	if (word_cnt == 0) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal word count: value is zero (%d)\n",
		       p_adapter_id_str, word_cnt);
		res = -1;
		goto exit_unlock_res;
	}

	if (word_cnt > (1 << RAB_CNT_BW)) {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Illegal word count: value too large %d - max %d\n",
		       p_adapter_id_str, word_cnt, (1 << RAB_CNT_BW));
		res = -1;
		goto exit_unlock_res;
	}

	/* Read buffer free register */
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_free_addr, &buf_free);

	in_buf_free = buf_free & p->rac_rab_buf_free_ib_free_mask;
	out_buf_free = (buf_free & p->rac_rab_buf_free_ob_free_mask) >> 16;

	/* Read buffer used register */
	nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_used_addr, &buf_used);

	buf_used = buf_used & (p->rac_rab_buf_used_ib_used_mask |
			     p->rac_rab_buf_used_ob_used_mask);

	/*
	 * Verify that output buffer can hold the number of words to be read,
	 * input buffer can hold one read command
	 * and that the input and output "used" buffer is 0
	 */
	if ((out_buf_free >= word_cnt && in_buf_free >= 1) && buf_used == 0) {
		word_cnt_expected = word_cnt;

#if defined(RAB_DEBUG_ECHO)
		rab_oper_rd =
			(RAB_READ_ECHO << RAB_OPR_LO) |
			((word_cnt & ((1 << RAB_CNT_BW) - 1)) << RAB_CNT_LO) |
			(bus_id << RAB_BUSID_LO) | address;
		word_cnt_expected++;
#else
		rab_oper_rd = (RAB_READ << RAB_OPR_LO) | (word_cnt << RAB_CNT_LO) |
			    (bus_id << RAB_BUSID_LO) | address;
#endif /* RAB_DEBUG_ECHO */

		nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ib_data_addr,
				   rab_oper_rd);

		/* Wait until done */
		if (nthw_rac_wait_for_rab_done(p, address, word_cnt_expected)) {
			res = -1;
			goto exit_unlock_res;
		}

#if defined(RAB_DEBUG_ECHO)
		uint32_t rab_echo_oper_rd;

		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_ob_data_addr,
				  &rab_echo_oper_rd);
		if (p->mn_param_rac_rab_ob_update) {
			nthw_rac_reg_write32(p_fpga_info, p->rac_rab_ob_data_addr,
					   0);
		}
		if (rab_oper_rd != rab_echo_oper_rd) {
			NT_LOG(ERR, NTHW,
			       "%s: RAB: expected rab read echo oper (0x%08X) - read (0x%08X)\n",
			       p_adapter_id_str, rab_oper_rd, rab_echo_oper_rd);
		}
#endif /* RAB_DEBUG_ECHO */

		/* Read data from output buffer */
		{
			uint32_t i;

			for (i = 0; i < word_cnt; i++) {
				nthw_rac_reg_read32(p_fpga_info,
						  p->rac_rab_ob_data_addr,
						  p_data);
				if (p->mn_param_rac_rab_ob_update) {
					nthw_rac_reg_write32(p_fpga_info,
							     p->rac_rab_ob_data_addr,
							     0);
				}
				p_data++;
			}
		}

		/* Read buffer free register */
		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_free_addr,
				  &buf_free);
		if (buf_free & 0x80000000) {
			/* Clear Timeout and overflow bits */
			nthw_rac_reg_write32(p_fpga_info, p->rac_rab_buf_free_addr,
					   0x0);
			NT_LOG(ERR, NTHW,
			       "%s: RAB: timeout - Access outside register - bus: %d addr: 0x%08X - inBufFree: 0x%08X, outBufFree: 0x%08X, bufUsed: 0x%08X\n",
			       p_adapter_id_str, bus_id, address, in_buf_free,
			       out_buf_free, buf_used);
			res = -1;
			goto exit_unlock_res;
		}

		res = 0;
		goto exit_unlock_res;
	} else {
		NT_LOG(ERR, NTHW,
		       "%s: RAB: Fail rab bus buffer check - bus: %d addr: 0x%08X wordcount: %d - inBufFree: 0x%08X, outBufFree: 0x%08X, bufUsed: 0x%08X\n",
		       p_adapter_id_str, bus_id, address, word_cnt, in_buf_free,
		       out_buf_free, buf_used);
		res = -1;
		goto exit_unlock_res;
	}

exit_unlock_res:
	pthread_mutex_unlock(&p->m_mutex);
	return res;
}

int nthw_rac_rab_flush(nthw_rac_t *p)
{
	const struct fpga_info_s *const p_fpga_info = p->mp_fpga->p_fpga_info;
	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	uint32_t data = 0;
	uint32_t retry;
	int res = 0;

	pthread_mutex_lock(&p->m_mutex);

	/* Set the flush bit */
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_buf_used_addr,
			   p->rac_rab_buf_used_flush_mask);

	/* Reset BUF FREE register */
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_buf_free_addr, 0x0);

	/* Wait until OB_USED and IB_USED are 0 */
	for (retry = 0; retry < 100000; retry++) {
		nthw_rac_reg_read32(p_fpga_info, p->rac_rab_buf_used_addr, &data);

		if ((data & 0xFFFFFFFF) == p->rac_rab_buf_used_flush_mask)
			break;
	}

	if (data != p->rac_rab_buf_used_flush_mask) {
		NT_LOG(ERR, NTHW, "%s: RAB: Rab bus flush error.\n",
		       p_adapter_id_str);
		res = -1;
	}

	/* Clear flush bit when done */
	nthw_rac_reg_write32(p_fpga_info, p->rac_rab_buf_used_addr, 0x0);

	pthread_mutex_unlock(&p->m_mutex);
	return res;
}
