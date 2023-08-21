/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _SFP_P_REG_H
#define _SFP_P_REG_H

/*
 * SFP/SFP+ Registers
 */
#define SFP_GB_ETH_COMP_CODES_LIN_ADDR 6
#define SFP_GB_ETH_COMP_1000BASET_BIT (1 << 3)
#define SFP_GB_ETH_COMP_1000BASECX_BIT (1 << 2)
#define SFP_GB_ETH_COMP_1000BASELX_BIT (1 << 1)
#define SFP_GB_ETH_COMP_1000BASESX_BIT (1 << 0)

#define SFP_FIBER_CHAN_TRANS_TECH_LIN_ADDR 8
#define SFP_FIBER_CHAN_TRANS_TECH_ACTIVE_CU_BIT (1 << 3)
#define SFP_FIBER_CHAN_TRANS_TECH_PASSIVE_CU_BIT (1 << 2)

#define SFP_FIBER_CHAN_TRANS_MEDIA_LIN_ADDR 9
#define SFP_FIBER_CHAN_TRANS_MEDIA_MM62_BIT (1 << 3)
#define SFP_FIBER_CHAN_TRANS_MEDIA_MM50_BIT (1 << 2)
#define SFP_FIBER_CHAN_TRANS_MEDIA_SM_BIT (1 << 0)

#define SFP_CU_LINK_LEN_LIN_ADDR 18 /* 1byte */
#define SFP_SUP_LEN_INFO_LIN_ADDR 14 /* 5bytes */
#define SFP_CU_LINK_LEN_LIN_ADDR 18 /* 1byte */
#define SFP_VENDOR_NAME_LIN_ADDR 20 /* 16bytes */
#define SFP_VENDOR_PN_LIN_ADDR 40 /* 16bytes */
#define SFP_VENDOR_REV_LIN_ADDR 56 /* 4bytes */
#define SFP_VENDOR_SN_LIN_ADDR 68 /* 16bytes */
#define SFP_VENDOR_DATE_LIN_ADDR 84 /* 8bytes */

/* The following field is only relevant to SFP+ and is marked as reserved for SFP */
#define SFP_OPTION0_LIN_ADDR 64
#define SFP_POWER_LEVEL2_REQ_BIT (1 << 1)

#define SFP_DMI_OPTION_LIN_ADDR (92)
#define SFP_DMI_IMPL_BIT (1 << 6)
#define SFP_DMI_EXT_CAL_BIT (1 << 4)
#define SFP_DMI_AVG_PWR_BIT (1 << 3)
#define SFP_DMI_ADDR_CHG_BIT (1 << 2)

#define SFP_ENHANCED_OPTIONS_LIN_ADDR (93)
#define SFP_SOFT_TX_FAULT_IMPL_BIT (1 << 5)
#define SFP_SOFT_TX_DISABLE_IMPL_BIT (1 << 6)

#define SFP_SFF8472_COMPLIANCE_LIN_ADDR 94

#define SFP_TEMP_THRESH_LIN_ADDR (0 + 256)
/* 8bytes: HighAlarm, LowAlarm, HighWarn, LowWarn each 2 bytes */

#define SFP_VOLT_THRESH_LIN_ADDR (8 + 256)
/* 8bytes: HighAlarm, LowAlarm, HighWarn, LowWarn each 2 bytes */

#define SFP_TX_BIAS_THRESH_LIN_ADDR (16 + 256)
/* 8bytes: HighAlarm, LowAlarm, HighWarn, LowWarn each 2 bytes */

#define SFP_TX_PWR_THRESH_LIN_ADDR (24 + 256)
/* 8bytes: HighAlarm, LowAlarm, HighWarn, LowWarn each 2 bytes */

#define SFP_RX_PWR_THRESH_LIN_ADDR (32 + 256)
/* 8bytes: HighAlarm, LowAlarm, HighWarn, LowWarn each 2 bytes */

/* Calibration data addresses */
#define SFP_RX_PWR_COEFF_LIN_ADDR (56 + 256) /* 5 x 32bit float  values */

#define SFP_TX_BIAS_SLOPE_LIN_ADDR (76 + 256)
#define SFP_TX_BIAS_OFFSET_LIN_ADDR (78 + 256)

#define SFP_TX_PWR_SLOPE_LIN_ADDR (80 + 256)
#define SFP_TX_PWR_OFFSET_LIN_ADDR (82 + 256)

#define SFP_TEMP_SLOPE_LIN_ADDR (84 + 256)
#define SFP_TEMP_OFFSET_LIN_ADDR (86 + 256)

#define SFP_VOLT_SLOPE_LIN_ADDR (88 + 256)
#define SFP_VOLT_OFFSET_LIN_ADDR (90 + 256)

/* Live data */
#define SFP_TEMP_LIN_ADDR (96 + 256)
#define SFP_VOLT_LIN_ADDR (98 + 256)
#define SFP_TX_BIAS_LIN_ADDR (100 + 256)
#define SFP_TX_PWR_LIN_ADDR (102 + 256)
#define SFP_RX_PWR_LIN_ADDR (104 + 256)

#define SFP_SOFT_RATE0_BIT (1 << 3)
#define SFP_TX_FAULT_SET_BIT (1 << 2)

#define SFP_EXT_CTRL_STAT0_LIN_ADDR (118 + 256) /* 0xA2 area */
#define SFP_SOFT_RATE1_BIT (1 << 3)
#define SFP_POWER_LEVEL2_GET_BIT (1 << 1) /* For reading the actual level */
#define SFP_POWER_LEVEL2_SET_BIT (1 << 0) /* For setting the wanted level */

/* PHY addresses */
#define SFP_PHY_LIN_ADDR (12 * 128)
#define SFP_PHY_LIN_RNG 32 /* 16bit words */

#endif /* _SFP_P_REG_H */
