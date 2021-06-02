/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_common.h>

#include "hw/cpt.h"
#include "roc_api.h"

#include "cnxk_cpt_ops_helper.h"

int
cnxk_cpt_ops_helper_get_mlen(void)
{
	uint32_t len;

	/* For MAC */
	len = 2 * sizeof(uint64_t);
	len += ROC_SE_MAX_MAC_LEN * sizeof(uint8_t);

	len += CPT_OFFSET_CONTROL_BYTES + CPT_MAX_IV_LEN;
	len += RTE_ALIGN_CEIL((ROC_SE_SG_LIST_HDR_SIZE +
			       (RTE_ALIGN_CEIL(ROC_SE_MAX_SG_IN_OUT_CNT, 4) >>
				2) * SG_ENTRY_SIZE),
			      8);

	return len;
}
