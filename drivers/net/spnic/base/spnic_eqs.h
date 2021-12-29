/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_EQS_H_
#define _SPNIC_EQS_H_

#define SPNIC_MAX_AEQS			4
#define SPNIC_MIN_AEQS			2
#define SPNIC_EQ_MAX_PAGES		4

#define SPNIC_AEQE_SIZE                 64

#define SPNIC_AEQE_DESC_SIZE		4
#define SPNIC_AEQE_DATA_SIZE		\
			(SPNIC_AEQE_SIZE - SPNIC_AEQE_DESC_SIZE)

/* Linux is 1K, dpdk is 64 */
#define SPNIC_DEFAULT_AEQ_LEN		64

#define SPNIC_MIN_EQ_PAGE_SIZE		0x1000   /* Min eq page size 4K Bytes */
#define SPNIC_MAX_EQ_PAGE_SIZE		0x400000 /* Max eq page size 4M Bytes */

#define SPNIC_MIN_AEQ_LEN		64
#define SPNIC_MAX_AEQ_LEN		\
	((SPNIC_MAX_EQ_PAGE_SIZE / SPNIC_AEQE_SIZE) * SPNIC_EQ_MAX_PAGES)

#define EQ_IRQ_NAME_LEN			64

enum spnic_eq_intr_mode {
	SPNIC_INTR_MODE_ARMED,
	SPNIC_INTR_MODE_ALWAYS
};

enum spnic_eq_ci_arm_state {
	SPNIC_EQ_NOT_ARMED,
	SPNIC_EQ_ARMED
};

struct irq_info {
	u16 msix_entry_idx; /* IRQ corresponding index number */
	u32 irq_id;         /* The IRQ number from OS */
};

#define SPNIC_RETRY_NUM	10

enum spnic_aeq_type {
	SPNIC_HW_INTER_INT = 0,
	SPNIC_MBX_FROM_FUNC = 1,
	SPNIC_MSG_FROM_MGMT_CPU = 2,
	SPNIC_API_RSP = 3,
	SPNIC_API_CHAIN_STS = 4,
	SPNIC_MBX_SEND_RSLT = 5,
	SPNIC_MAX_AEQ_EVENTS
};

struct spnic_eq {
	struct spnic_hwdev *hwdev;
	u16 q_id;
	u32 page_size;
	u32 orig_page_size;
	u32 eq_len;

	u32 cons_idx;
	u16 wrapped;

	u16 elem_size;
	u16 num_pages;
	u32 num_elem_in_pg;

	struct irq_info eq_irq;

	const struct rte_memzone **eq_mz;
	rte_iova_t *dma_addr;
	u8 **virt_addr;

	u16 poll_retry_nr;
};

struct spnic_aeq_elem {
	u8  aeqe_data[SPNIC_AEQE_DATA_SIZE];
	u32 desc;
};

struct spnic_aeqs {
	struct spnic_hwdev *hwdev;

	struct spnic_eq aeq[SPNIC_MAX_AEQS];
	u16 num_aeqs;
};

int spnic_aeqs_init(struct spnic_hwdev *hwdev);

void spnic_aeqs_free(struct spnic_hwdev *hwdev);

void spnic_dump_aeq_info(struct spnic_hwdev *hwdev);

int spnic_aeq_poll_msg(struct spnic_eq *eq, u32 timeout, void *param);

void spnic_dev_handle_aeq_event(struct spnic_hwdev *hwdev, void *param);

#endif /* _SPNIC_EQS_H_ */
