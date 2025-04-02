/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef _ROC_CONSTANTS_H_
#define _ROC_CONSTANTS_H_

#define ROC_IPV6_ADDR_LEN 16

/* ROC Cache */
#define ROC_CACHE_LINE_SZ 128
#define ROC_ALIGN	  ROC_CACHE_LINE_SZ

/* LMTST constants */
/* [CN10K, .) */
#define ROC_LMT_LINE_SZ		    128
#define ROC_NUM_LMT_LINES	    2048
#define ROC_LMT_LINES_PER_STR_LOG2  4
#define ROC_LMT_LINES_PER_CORE_LOG2 5
#define ROC_LMT_LINE_SIZE_LOG2	    7
#define ROC_LMT_BASE_PER_CORE_LOG2                                             \
	(ROC_LMT_LINES_PER_CORE_LOG2 + ROC_LMT_LINE_SIZE_LOG2)
#define ROC_LMT_MAX_THREADS		42UL
#define ROC_LMT_CPT_LINES_PER_CORE_LOG2 4
#define ROC_LMT_CPT_BASE_ID_OFF                                                \
	(ROC_LMT_MAX_THREADS << ROC_LMT_LINES_PER_CORE_LOG2)

/* PCI IDs */
#define PCI_VENDOR_ID_CAVIUM	      0x177D
#define PCI_DEVID_CNXK_RVU_PF	      0xA063
#define PCI_DEVID_CNXK_RVU_VF	      0xA064
#define PCI_DEVID_CNXK_RVU_AF	      0xA065
#define PCI_DEVID_CNXK_RVU_SSO_TIM_PF 0xA0F9
#define PCI_DEVID_CNXK_RVU_SSO_TIM_VF 0xA0FA
#define PCI_DEVID_CNXK_RVU_NPA_PF     0xA0FB
#define PCI_DEVID_CNXK_RVU_NPA_VF     0xA0FC
#define PCI_DEVID_CNXK_RVU_AF_VF      0xA0f8
#define PCI_DEVID_CNXK_DPI_VF	      0xA081
#define PCI_DEVID_CNXK_EP_VF	      0xB203
#define PCI_DEVID_CNXK_RVU_SDP_PF     0xA0f6
#define PCI_DEVID_CNXK_RVU_SDP_VF     0xA0f7
#define PCI_DEVID_CNXK_BPHY	      0xA089
#define PCI_DEVID_CNXK_RVU_NIX_INL_PF 0xA0F0
#define PCI_DEVID_CNXK_RVU_NIX_INL_VF 0xA0F1
#define PCI_DEVID_CNXK_RVU_REE_PF     0xA0f4
#define PCI_DEVID_CNXK_RVU_REE_VF     0xA0f5
#define PCI_DEVID_CNXK_RVU_ESWITCH_PF 0xA0E0
#define PCI_DEVID_CNXK_RVU_ESWITCH_VF 0xA0E1
#define PCI_DEVID_CNXK_RVU_BPHY_PF    0xA0E4
#define PCI_DEVID_CNXK_RVU_BPHY_VF    0xA0E5

#define PCI_DEVID_CN9K_CGX  0xA059
#define PCI_DEVID_CN10K_RPM 0xA060

#define PCI_DEVID_CN9K_RVU_CPT_PF  0xA0FD
#define PCI_DEVID_CN9K_RVU_CPT_VF  0xA0FE
#define PCI_DEVID_CN10K_RVU_CPT_PF 0xA0F2
#define PCI_DEVID_CN10K_RVU_CPT_VF 0xA0F3
#define PCI_DEVID_CN20K_RVU_CPT_PF 0xA0F2
#define PCI_DEVID_CN20K_RVU_CPT_VF 0xA0F3

#define PCI_DEVID_CN10K_ML_PF 0xA092

#define PCI_SUBSYSTEM_DEVID_CN10KA  0xB900
#define PCI_SUBSYSTEM_DEVID_CN10KAS 0xB900
#define PCI_SUBSYSTEM_DEVID_CNF10KA 0xBA00
#define PCI_SUBSYSTEM_DEVID_CN10KB  0xBD00
#define PCI_SUBSYSTEM_DEVID_CNF10KB 0xBC00

#define PCI_SUBSYSTEM_DEVID_CN20KA 0xC220
#define PCI_SUBSYSTEM_DEVID_CNF20KA 0xC200

#define PCI_SUBSYSTEM_DEVID_CN9KA  0x0000
#define PCI_SUBSYSTEM_DEVID_CN9KB  0xb400
#define PCI_SUBSYSTEM_DEVID_CN9KC  0x0200
#define PCI_SUBSYSTEM_DEVID_CN9KD  0xB200
#define PCI_SUBSYSTEM_DEVID_CN9KE  0xB100
#define PCI_SUBSYSTEM_DEVID_CNF9KA 0xB600

#endif /* _ROC_CONSTANTS_H_ */
