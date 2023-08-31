/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_bus_pci.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_reg.h"
#include "sssnic_msg.h"
#include "sssnic_eventq.h"

#define SSSNIC_EVENTQ_DEF_DEPTH 64
#define SSSNIC_EVENTQ_NUM_PAGES 4
#define SSSNIC_EVENTQ_MAX_PAGE_SZ 0x400000
#define SSSNIC_EVENTQ_MIN_PAGE_SZ 0x1000

#define SSSNIC_EVENT_ADDR(base_addr, event_sz, idx)                            \
	(struct sssnic_event *)(((uint8_t *)(base_addr)) + ((idx) * (event_sz)))

static inline struct sssnic_event *
sssnic_eventq_peek(struct sssnic_eventq *eq)
{
	uint16_t page = eq->ci / eq->page_len;
	uint16_t idx = eq->ci % eq->page_len;

	return SSSNIC_EVENT_ADDR(eq->pages[page]->addr, eq->entry_size, idx);
}

static inline void
sssnic_eventq_reg_write(struct sssnic_eventq *eq, uint32_t reg, uint32_t val)
{
	sssnic_cfg_reg_write(eq->hw, reg, val);
}

static inline uint32_t
sssnic_eventq_reg_read(struct sssnic_eventq *eq, uint32_t reg)
{
	return sssnic_cfg_reg_read(eq->hw, reg);
}

static inline void
sssnic_eventq_reg_write64(struct sssnic_eventq *eq, uint32_t reg, uint64_t val)
{
	sssnic_cfg_reg_write(eq->hw, reg, (uint32_t)((val >> 16) >> 16));
	sssnic_cfg_reg_write(eq->hw, reg + sizeof(uint32_t), (uint32_t)val);
}

/* all eventq registers that to be access must be selected first */
static inline void
sssnic_eventq_reg_select(struct sssnic_eventq *eq)
{
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_IDX_SEL_REG, eq->qid);
}

static const struct rte_memzone *
sssnic_eventq_page_alloc(struct sssnic_eventq *eq, int page_idx)
{
	const struct rte_memzone *mz = NULL;
	char mz_name[RTE_MEMZONE_NAMESIZE];

	snprintf(mz_name, sizeof(mz_name), "sssnic%u_eq%d_page%d",
		SSSNIC_ETH_PORT_ID(eq->hw), eq->qid, page_idx);
	mz = rte_memzone_reserve_aligned(mz_name, eq->page_size, SOCKET_ID_ANY,
		RTE_MEMZONE_IOVA_CONTIG, eq->page_size);
	return mz;
}

static uint32_t
sssnic_eventq_page_size_calc(uint32_t depth, uint32_t entry_size)
{
	uint32_t pages = SSSNIC_EVENTQ_NUM_PAGES;
	uint32_t size;

	size = RTE_ALIGN(depth * entry_size, SSSNIC_EVENTQ_MIN_PAGE_SZ);
	if (size <= pages * SSSNIC_EVENTQ_MIN_PAGE_SZ) {
		/* use minimum page size */
		return SSSNIC_EVENTQ_MIN_PAGE_SZ;
	}

	/* Calculate how many pages of minimum size page the big size page covers */
	size = RTE_ALIGN(size / pages, SSSNIC_EVENTQ_MIN_PAGE_SZ);
	pages = rte_fls_u32(size / SSSNIC_EVENTQ_MIN_PAGE_SZ);

	return SSSNIC_EVENTQ_MIN_PAGE_SZ * pages;
}

static int
sssnic_eventq_pages_setup(struct sssnic_eventq *eq)
{
	const struct rte_memzone *mz;
	struct sssnic_event *ev;
	int i, j;

	eq->pages = rte_zmalloc(NULL,
		eq->num_pages * sizeof(struct rte_memzone *), 1);
	if (eq->pages == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for pages");
		return -ENOMEM;
	}

	for (i = 0; i < eq->num_pages; i++) {
		mz = sssnic_eventq_page_alloc(eq, i);
		if (mz == NULL) {
			PMD_DRV_LOG(ERR,
				"Could not alloc DMA memory for eventq page %d",
				i);
			goto alloc_dma_fail;
		}
		/* init eventq entries */
		for (j = 0; j < eq->page_len; j++) {
			ev = SSSNIC_EVENT_ADDR(mz->addr, eq->entry_size, j);
			ev->desc.u32 = 0;
		}
		eq->pages[i] = mz;
		sssnic_eventq_reg_write64(eq,
			SSSNIC_EVENTQ_PAGE_ADDR_REG + i * sizeof(uint64_t),
			mz->iova);
	}

	return 0;

alloc_dma_fail:
	while (i--)
		rte_memzone_free(eq->pages[i]);
	rte_free(eq->pages);
	return -ENOMEM;
}

static void
sssnic_eventq_pages_cleanup(struct sssnic_eventq *eq)
{
	int i;

	if (eq->pages == NULL)
		return;
	for (i = 0; i < eq->num_pages; i++)
		rte_memzone_free(eq->pages[i]);
	rte_free(eq->pages);
	eq->pages = NULL;
}

static void
sssnic_eventq_ctrl_setup(struct sssnic_eventq *eq)
{
	struct sssnic_hw *hw = eq->hw;
	struct sssnic_eventq_ctrl0_reg ctrl_0;
	struct sssnic_eventq_ctrl1_reg ctrl_1;

	ctrl_0.u32 = sssnic_eventq_reg_read(eq, SSSNIC_EVENTQ_CTRL0_REG);
	ctrl_0.intr_idx = eq->msix_entry;
	ctrl_0.dma_attr = SSSNIC_REG_EVENTQ_DEF_DMA_ATTR;
	ctrl_0.pci_idx = hw->attr.pci_idx;
	ctrl_0.intr_mode = SSSNIC_REG_EVENTQ_INTR_MODE_0;
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_CTRL0_REG, ctrl_0.u32);

	ctrl_1.page_size = rte_log2_u32(eq->page_size >> 12);
	ctrl_1.depth = eq->depth;
	ctrl_1.entry_size = rte_log2_u32(eq->entry_size >> 5);
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_CTRL1_REG, ctrl_1.u32);
}

/* synchronize current software CI to hardware.
 * @ informed: indate event will be informed by interrupt.
 *             0: not to be informed
 *             1: informed by interrupt
 */
static void
sssnic_eventq_ci_update(struct sssnic_eventq *eq, int informed)
{
	struct sssnic_eventq_ci_ctrl_reg reg;

	reg.u32 = 0;
	if (eq->qid == 0)
		reg.informed = !!informed;
	reg.qid = eq->qid;
	reg.ci = eq->ci_wrapped;
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_CI_CTRL_REG, reg.u32);
}

static int
sssnic_event_default_handler_func(struct sssnic_eventq *eq,
	struct sssnic_event *ev, __rte_unused void *data)
{
	struct sssnic_hw *hw;
	int ret;

	hw = eq->hw;
	ret = sssnic_msg_rx_handle(hw, (struct sssnic_msg_hdr *)(ev->data));
	if (ret != SSSNIC_MSG_DONE)
		return -1;

	return SSSNIC_EVENT_DONE;
}

static void
sssnic_eventq_handlers_init(struct sssnic_eventq *eq)
{
	int i;

	for (i = SSSNIC_EVENT_CODE_MIN; i <= SSSNIC_EVENT_CODE_MAX; i++) {
		eq->handlers[i].func = sssnic_event_default_handler_func;
		eq->handlers[i].data = NULL;
	}
}

static int
sssnic_eventq_init(struct sssnic_hw *hw, struct sssnic_eventq *eq, uint16_t qid)
{
	int ret;

	if (hw == NULL || eq == NULL) {
		PMD_DRV_LOG(ERR,
			"Bad parameter for event queue initialization.");
		return -EINVAL;
	}

	eq->hw = hw;
	eq->msix_entry = 0; /* eventq uses msix 0 in PMD driver */
	eq->qid = qid;
	eq->depth = SSSNIC_EVENTQ_DEF_DEPTH;
	eq->entry_size = SSSNIC_EVENT_SIZE;
	eq->page_size = sssnic_eventq_page_size_calc(eq->depth, eq->entry_size);
	eq->page_len = eq->page_size / eq->entry_size;
	if (eq->page_len & (eq->page_len - 1)) {
		PMD_DRV_LOG(ERR, "Invalid page length: %d, must be power of 2",
			eq->page_len);
		return -EINVAL;
	}
	eq->num_pages = RTE_ALIGN((eq->depth * eq->entry_size), eq->page_size) /
			eq->page_size;
	if (eq->num_pages > SSSNIC_EVENTQ_NUM_PAGES) {
		PMD_DRV_LOG(ERR,
			"Invalid number of pages: %d, can't be more than %d pages.",
			eq->num_pages, SSSNIC_EVENTQ_NUM_PAGES);
		return -EINVAL;
	}

	/* select the eq which registers to be acesss */
	sssnic_eventq_reg_select(eq);
	rte_wmb();
	/* clear entries in eventq */
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_CTRL1_REG, 0);
	rte_wmb();
	/* reset pi to 0 */
	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_PROD_IDX_REG, 0);

	ret = sssnic_eventq_pages_setup(eq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup eventq pages!");
		return ret;
	}

	sssnic_eventq_handlers_init(eq);
	sssnic_eventq_ctrl_setup(eq);
	sssnic_eventq_ci_update(eq, 1);
	if (qid == 0)
		sssnic_msix_state_set(eq->hw, 0, SSSNIC_MSIX_ENABLE);

	PMD_DRV_LOG(DEBUG,
		"eventq %u: q_depth=%u, entry_size=%u, num_pages=%u, page_size=%u, page_len=%u",
		qid, eq->depth, eq->entry_size, eq->num_pages, eq->page_size,
		eq->page_len);

	return 0;
}

static void
sssnic_eventq_shutdown(struct sssnic_eventq *eq)
{
	if (eq->qid == 0)
		sssnic_msix_state_set(eq->hw, 0, SSSNIC_MSIX_DISABLE);

	sssnic_eventq_reg_select(eq);
	rte_wmb();

	sssnic_eventq_reg_write(eq, SSSNIC_EVENTQ_CTRL1_REG, 0);
	eq->ci = sssnic_eventq_reg_read(eq, SSSNIC_EVENTQ_PROD_IDX_REG);
	sssnic_eventq_ci_update(eq, 0);
	sssnic_eventq_pages_cleanup(eq);
}

static void
sssnic_event_be_to_cpu_32(struct sssnic_event *in, struct sssnic_event *out)
{
	uint32_t i;

	for (i = 0; i < SSSNIC_EVENT_SIZE; i += 4)
		*((uint32_t *)(out->data + i)) =
			rte_be_to_cpu_32(*((uint32_t *)(in->data + i)));
}

static int
sssinc_event_handle(struct sssnic_eventq *eq, struct sssnic_event *event)
{
	struct sssnic_event ev;
	sssnic_event_handler_func_t *func;
	void *data;

	sssnic_event_be_to_cpu_32(event, &ev);
	if (ev.desc.code < SSSNIC_EVENT_CODE_MIN ||
		ev.desc.code > SSSNIC_EVENT_CODE_MAX) {
		PMD_DRV_LOG(ERR, "Event code %d is not supported",
			ev.desc.code);
		return -1;
	}

	func = eq->handlers[ev.desc.code].func;
	data = eq->handlers[ev.desc.code].data;
	if (func == NULL) {
		PMD_DRV_LOG(NOTICE,
			"Could not find handler for event qid:%u code:%d",
			eq->qid, ev.desc.code);
		return -1;
	}

	return func(eq, &ev, data);
}

/* Poll one valid event in timeout_ms */
static struct sssnic_event *
sssnic_eventq_poll(struct sssnic_eventq *eq, uint32_t timeout_ms)
{
	struct sssnic_event *event;
	struct sssnic_eventd desc;
	uint64_t end;

	if (timeout_ms > 0)
		end = rte_get_timer_cycles() +
		      rte_get_timer_hz() * timeout_ms / 1000;

	do {
		event = sssnic_eventq_peek(eq);
		desc.u32 = rte_be_to_cpu_32(event->desc.u32);
		if (desc.wrapped != eq->wrapped)
			return event;

		if (timeout_ms > 0)
			rte_delay_us_sleep(1000);
	} while ((timeout_ms > 0) &&
		 (((long)(rte_get_timer_cycles() - end)) < 0));

	return NULL;
}

/*  Take one or more events to handle. */
int
sssnic_eventq_flush(struct sssnic_hw *hw, uint16_t qid, uint32_t timeout_ms)
{
	int found = 0;
	uint32_t i = 0;
	int done = 0;
	struct sssnic_event *event;
	struct sssnic_eventq *eq;

	if (qid >= hw->num_eventqs) {
		PMD_DRV_LOG(ERR,
			"Bad parameter, event queue id must be less than %u",
			hw->num_eventqs);
		return -EINVAL;
	}

	eq = &hw->eventqs[qid];
	for (i = 0; i < eq->depth; i++) {
		event = sssnic_eventq_poll(eq, timeout_ms);
		if (event == NULL)
			break;
		done = sssinc_event_handle(eq, event);
		eq->ci++;
		if (eq->ci == eq->depth) {
			eq->ci = 0;
			eq->wrapped = !eq->wrapped;
		}

		found++;
		if (done == SSSNIC_EVENT_DONE)
			break;
	}

	SSSNIC_DEBUG("found:%d, done:%d, ci:%u, depth:%u, wrapped:%u", found,
		done, eq->ci, eq->depth, eq->wrapped);

	if (!found)
		return -ETIME;

	sssnic_eventq_ci_update(eq, 1);

	if (event == NULL || done != SSSNIC_EVENT_DONE)
		return -ETIME;

	return 0;
}

int
sssnic_eventq_all_init(struct sssnic_hw *hw)
{
	struct sssnic_eventq *eventqs;
	int num_eventqs;
	int i = 0;
	int ret;

	PMD_INIT_FUNC_TRACE();

	num_eventqs = hw->attr.num_aeq;
	eventqs = rte_zmalloc(NULL, sizeof(struct sssnic_eventq) * num_eventqs,
		1);
	if (eventqs == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for event queue");
		return -ENOMEM;
	}

	for (i = 0; i < num_eventqs; i++) {
		ret = sssnic_eventq_init(hw, &eventqs[i], i);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to initialize event queue: %d",
				i);
			goto init_eventq_fail;
		}
	}
	hw->eventqs = eventqs;
	hw->num_eventqs = num_eventqs;

	PMD_DRV_LOG(INFO, "Initialized %d event queues", num_eventqs);

	return 0;

init_eventq_fail:
	while (i--)
		sssnic_eventq_shutdown(&eventqs[i]);
	rte_free(eventqs);
	return ret;
}

void
sssnic_eventq_all_shutdown(struct sssnic_hw *hw)
{
	int i;

	PMD_INIT_FUNC_TRACE();

	if (hw->eventqs == NULL)
		return;

	for (i = 0; i < hw->num_eventqs; i++)
		sssnic_eventq_shutdown(&hw->eventqs[i]);
	rte_free(hw->eventqs);
	hw->eventqs = NULL;
}
