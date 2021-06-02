/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_TYPE_H_
#define _NGBE_TYPE_H_

#define NGBE_ALIGN		128 /* as intel did */

#include "ngbe_status.h"
#include "ngbe_osdep.h"
#include "ngbe_devids.h"

struct ngbe_hw {
	void IOMEM *hw_addr;
	u16 device_id;
	u16 vendor_id;
	u16 sub_device_id;
	u16 sub_system_id;
	bool allow_unsupported_sfp;

	uint64_t isb_dma;
	void IOMEM *isb_mem;

	bool is_pf;
};

#include "ngbe_regs.h"

#endif /* _NGBE_TYPE_H_ */
