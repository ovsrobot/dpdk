/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_EVENTQ_H_
#define _SSSNIC_EVENTQ_H_

#define SSSNIC_MAX_NUM_EVENTQ 4
#define SSSNIC_MIN_NUM_EVENTQ 2

#define SSSNIC_EVENT_DESC_SIZE sizeof(uint32_t)
#define SSSNIC_EVENT_SIZE 64
#define SSSNIC_EVENT_DATA_SIZE (SSSNIC_EVENT_SIZE - SSSNIC_EVENT_DESC_SIZE)

enum sssnic_event_code {
	SSSNIC_EVENT_CODE_RESVD = 0,
	SSSNIC_EVENT_FROM_FUNC = 1, /* event from PF and VF */
	SSSNIC_EVENT_FROM_MPU = 2, /* event form management processor unit*/
};
#define SSSNIC_EVENT_CODE_MIN SSSNIC_EVENT_FROM_FUNC
#define SSSNIC_EVENT_CODE_MAX SSSNIC_EVENT_FROM_MPU

struct sssnic_eventq;
struct sssnic_event;

/* Indicate that sssnic event has been finished to handle */
#define SSSNIC_EVENT_DONE 1

typedef int sssnic_event_handler_func_t(struct sssnic_eventq *eq,
	struct sssnic_event *ev, void *data);

struct sssnic_event_handler {
	sssnic_event_handler_func_t *func;
	void *data;
};

struct sssnic_eventq {
	struct sssnic_hw *hw;
	uint16_t qid;
	uint16_t entry_size;
	uint32_t depth; /* max number of entries in eventq */
	uint16_t page_len; /* number of entries in a page */
	uint16_t num_pages; /* number pages to store event entries */
	uint32_t page_size;
	const struct rte_memzone **pages;
	union {
		uint32_t ci_wrapped;
		struct {
			uint32_t ci : 19;
			uint32_t wrapped : 1;
			uint32_t resvd : 12;
		};
	};
	uint16_t msix_entry;
	struct sssnic_event_handler handlers[SSSNIC_EVENT_CODE_MAX + 1];
};

/* event descriptor */
struct sssnic_eventd {
	union {
		uint32_t u32;
		struct {
			uint32_t code : 7;
			uint32_t src : 1;
			uint32_t size : 8;
			uint32_t resvd : 15;
			uint32_t wrapped : 1;
		};
	};
};

/* event entry */
struct sssnic_event {
	uint8_t data[SSSNIC_EVENT_DATA_SIZE];
	struct sssnic_eventd desc;
};

int sssnic_eventq_flush(struct sssnic_hw *hw, uint16_t qid,
	uint32_t timeout_ms);

int sssnic_eventq_all_init(struct sssnic_hw *hw);
void sssnic_eventq_all_shutdown(struct sssnic_hw *hw);

#endif /* _SSSNIC_EVENTQ_H_ */
