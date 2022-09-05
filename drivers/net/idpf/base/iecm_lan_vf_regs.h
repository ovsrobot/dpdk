/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _IECM_LAN_VF_REGS_H_
#define _IECM_LAN_VF_REGS_H_


/* Reset */
#define VFGEN_RSTAT			0x00008800
#define VFGEN_RSTAT_VFR_STATE_S		0
#define VFGEN_RSTAT_VFR_STATE_M		MAKEMASK(0x3, VFGEN_RSTAT_VFR_STATE_S)

/* Control(VF Mailbox) Queue */
#define VF_BASE				0x00006000

#define VF_ATQBAL             		(VF_BASE + 0x1C00)
#define VF_ATQBAH             		(VF_BASE + 0x1800)
#define VF_ATQLEN             		(VF_BASE + 0x0800)
#define VF_ATQLEN_ATQLEN_S    		0
#define VF_ATQLEN_ATQLEN_M    		MAKEMASK(0x3FF, VF_ATQLEN_ATQLEN_S)
#define VF_ATQLEN_ATQVFE_S    		28
#define VF_ATQLEN_ATQVFE_M     		BIT(VF_ATQLEN_ATQVFE_S)
#define VF_ATQLEN_ATQOVFL_S   		29
#define VF_ATQLEN_ATQOVFL_M    		BIT(VF_ATQLEN_ATQOVFL_S)
#define VF_ATQLEN_ATQCRIT_S   		30
#define VF_ATQLEN_ATQCRIT_M   		BIT(VF_ATQLEN_ATQCRIT_S)
#define VF_ATQLEN_ATQENABLE_S 		31
#define VF_ATQLEN_ATQENABLE_M 		BIT(VF_ATQLEN_ATQENABLE_S)
#define VF_ATQH               		(VF_BASE + 0x0400)
#define VF_ATQH_ATQH_S        		0
#define VF_ATQH_ATQH_M 			MAKEMASK(0x3FF, VF_ATQH_ATQH_S)
#define VF_ATQT               		(VF_BASE + 0x2400)

#define VF_ARQBAL             		(VF_BASE + 0x0C00)
#define VF_ARQBAH             		(VF_BASE)
#define VF_ARQLEN             		(VF_BASE + 0x2000)
#define VF_ARQLEN_ARQLEN_S    		0
#define VF_ARQLEN_ARQLEN_M    		MAKEMASK(0x3FF, VF_ARQLEN_ARQLEN_S)
#define VF_ARQLEN_ARQVFE_S    		28
#define VF_ARQLEN_ARQVFE_M     		BIT(VF_ARQLEN_ARQVFE_S)
#define VF_ARQLEN_ARQOVFL_S   		29
#define VF_ARQLEN_ARQOVFL_M    		BIT(VF_ARQLEN_ARQOVFL_S)
#define VF_ARQLEN_ARQCRIT_S   		30
#define VF_ARQLEN_ARQCRIT_M   		BIT(VF_ARQLEN_ARQCRIT_S)
#define VF_ARQLEN_ARQENABLE_S 		31
#define VF_ARQLEN_ARQENABLE_M		BIT(VF_ARQLEN_ARQENABLE_S)
#define VF_ARQH               		(VF_BASE + 0x1400)
#define VF_ARQH_ARQH_S        		0
#define VF_ARQH_ARQH_M        		MAKEMASK(0x1FFF, VF_ARQH_ARQH_S)
#define VF_ARQT               		(VF_BASE + 0x1000)

/* Transmit queues */
#define VF_QTX_TAIL_BASE		0x00000000
#define VF_QTX_TAIL(_QTX)		(VF_QTX_TAIL_BASE + (_QTX) * 0x4)
#define VF_QTX_TAIL_EXT_BASE		0x00040000
#define VF_QTX_TAIL_EXT(_QTX)		(VF_QTX_TAIL_EXT_BASE + ((_QTX) * 4))

/* Receive queues */
#define VF_QRX_TAIL_BASE		0x00002000
#define VF_QRX_TAIL(_QRX)		(VF_QRX_TAIL_BASE + ((_QRX) * 4))
#define VF_QRX_TAIL_EXT_BASE		0x00050000
#define VF_QRX_TAIL_EXT(_QRX)		(VF_QRX_TAIL_EXT_BASE + ((_QRX) * 4))
#define VF_QRXB_TAIL_BASE		0x00060000
#define VF_QRXB_TAIL(_QRX)		(VF_QRXB_TAIL_BASE + ((_QRX) * 4))

/* Interrupts */
#define VF_INT_DYN_CTL0			0x00005C00
#define VF_INT_DYN_CTL0_INTENA_S	0
#define VF_INT_DYN_CTL0_INTENA_M	BIT(VF_INT_DYN_CTL0_INTENA_S)
#define VF_INT_DYN_CTL0_ITR_INDX_S	3
#define VF_INT_DYN_CTL0_ITR_INDX_M MAKEMASK(0x3, VF_INT_DYN_CTL0_ITR_INDX_S)
#define VF_INT_DYN_CTLN(_INT)		(0x00003800 + ((_INT) * 4))
#define VF_INT_DYN_CTLN_EXT(_INT)	(0x00070000 + ((_INT) * 4))
#define VF_INT_DYN_CTLN_INTENA_S	0
#define VF_INT_DYN_CTLN_INTENA_M	BIT(VF_INT_DYN_CTLN_INTENA_S)
#define VF_INT_DYN_CTLN_CLEARPBA_S	1
#define VF_INT_DYN_CTLN_CLEARPBA_M	BIT(VF_INT_DYN_CTLN_CLEARPBA_S)
#define VF_INT_DYN_CTLN_SWINT_TRIG_S	2
#define VF_INT_DYN_CTLN_SWINT_TRIG_M	BIT(VF_INT_DYN_CTLN_SWINT_TRIG_S)
#define VF_INT_DYN_CTLN_ITR_INDX_S	3
#define VF_INT_DYN_CTLN_ITR_INDX_M	MAKEMASK(0x3, VF_INT_DYN_CTLN_ITR_INDX_S)
#define VF_INT_DYN_CTLN_INTERVAL_S	5
#define VF_INT_DYN_CTLN_INTERVAL_M	BIT(VF_INT_DYN_CTLN_INTERVAL_S)
#define VF_INT_DYN_CTLN_SW_ITR_INDX_ENA_S 24
#define VF_INT_DYN_CTLN_SW_ITR_INDX_ENA_M BIT(VF_INT_DYN_CTLN_SW_ITR_INDX_ENA_S)
#define VF_INT_DYN_CTLN_SW_ITR_INDX_S	25
#define VF_INT_DYN_CTLN_SW_ITR_INDX_M	BIT(VF_INT_DYN_CTLN_SW_ITR_INDX_S)
#define VF_INT_DYN_CTLN_WB_ON_ITR_S	30
#define VF_INT_DYN_CTLN_WB_ON_ITR_M	BIT(VF_INT_DYN_CTLN_WB_ON_ITR_S)
#define VF_INT_DYN_CTLN_INTENA_MSK_S	31
#define VF_INT_DYN_CTLN_INTENA_MSK_M	BIT(VF_INT_DYN_CTLN_INTENA_MSK_S)
#define VF_INT_ITR0(_i)			(0x00004C00 + ((_i) * 4))
#define VF_INT_ITRN_V2(_i, _reg_start)	((_reg_start) + (((_i)) * 4))
#define VF_INT_ITRN(_i, _INT)	(0x00002800 + ((_i) * 4) + ((_INT) * 0x40))
#define VF_INT_ITRN_64(_i, _INT) (0x00002C00 + ((_i) * 4) + ((_INT) * 0x100))
#define VF_INT_ITRN_2K(_i, _INT) (0x00072000 + ((_i) * 4) + ((_INT) * 0x100))
#define VF_INT_ITRN_MAX_INDEX		2
#define VF_INT_ITRN_INTERVAL_S		0
#define VF_INT_ITRN_INTERVAL_M		MAKEMASK(0xFFF, VF_INT_ITRN_INTERVAL_S)
#define VF_INT_PBA_CLEAR		0x00008900

#define VF_INT_ICR0_ENA1		0x00005000
#define VF_INT_ICR0_ENA1_ADMINQ_S	30
#define VF_INT_ICR0_ENA1_ADMINQ_M	BIT(VF_INT_ICR0_ENA1_ADMINQ_S)
#define VF_INT_ICR0_ENA1_RSVD_S		31
#define VF_INT_ICR01			0x00004800
#define VF_QF_HENA(_i)			(0x0000C400 + ((_i) * 4))
#define VF_QF_HENA_MAX_INDX		1
#define VF_QF_HKEY(_i)			(0x0000CC00 + ((_i) * 4))
#define VF_QF_HKEY_MAX_INDX		12
#define VF_QF_HLUT(_i)			(0x0000D000 + ((_i) * 4))
#define VF_QF_HLUT_MAX_INDX		15
#endif
