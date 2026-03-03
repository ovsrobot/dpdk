/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_CLI_H__
#define __SXE_CLI_H__

#ifdef SXE_HOST_DRIVER
#include "sxe_drv_type.h"
#endif

#define SXE_CODE_VERSION_LEN			(32)
#define SXE_MAC_NUM				(128)
#define SXE_PORT_TRANSCEIVER_LEN		(32)
#define SXE_PORT_VENDOR_LEN			(32)
#define SXE_CHIP_TYPE_LEN			(32)
#define SXE_VPD_SN_LEN				(16)
#define SXE_SOC_RST_TIME			(0x93A80)
#define SXE_SFP_TEMP_THRESHOLD_INTERVAL		(3)
#define MGC_TERMLOG_INFO_MAX_LEN		(12 * 1024)
#define SXE_REGS_DUMP_MAX_LEN			(12 * 1024)
#define SXE_PRODUCT_NAME_LEN			(32)

typedef enum sxe_led_mode {
	SXE_IDENTIFY_LED_BLINK_ON = 0,
	SXE_IDENTIFY_LED_BLINK_OFF,
	SXE_IDENTIFY_LED_ON,
	SXE_IDENTIFY_LED_OFF,
	SXE_IDENTIFY_LED_RESET,
} sxe_led_mode_s;

typedef struct sxe_led_ctrl {
	U32	mode;
	U32	duration;

} sxe_led_ctrl_s;

typedef struct sxe_led_ctrl_resp {
	U32	ack;
} sxe_led_ctrl_resp_s;

typedef enum port_link_speed {
	PORT_LINK_NO	= 0,
	PORT_LINK_100M	= 1,
	PORT_LINK_1G	= 2,
	PORT_LINK_10G	= 3,
} port_link_speed_e;

typedef struct sys_soc_info {
	S8	fw_ver[SXE_CODE_VERSION_LEN];
	S8	opt_ver[SXE_CODE_VERSION_LEN];
	U8	soc_status;
	U8	pad[3];
	S32	soc_temp;
	U64	chipid;
	S8	chip_type[SXE_CHIP_TYPE_LEN];
	S8	pba[SXE_VPD_SN_LEN];
	S8	product_name[SXE_PRODUCT_NAME_LEN];
} sys_soc_info_s;

typedef struct sys_port_info {
	U64	mac[SXE_MAC_NUM];
	U8	is_port_abs;
	U8	link_stat;
	U8	link_speed;


	U8	is_sfp:1;
	U8	is_get_info:1;
	U8	rvd:6;
	S8	optical_mod_temp;
	U8	pad[3];
	S8	transceiver_type[SXE_PORT_TRANSCEIVER_LEN];
	S8	vendor_name[SXE_PORT_VENDOR_LEN];
	S8	vendor_pn[SXE_PORT_VENDOR_LEN];
} sys_port_info_s;

typedef struct sys_info_resp {
	sys_soc_info_s	soc_info;
	sys_port_info_s	port_info;
} sys_info_resp_s;

typedef enum sfp_temp_td_mode {
	SFP_TEMP_THRESHOLD_MODE_ALARM   = 0,
	SFP_TEMP_THRESHOLD_MODE_WARN,
} sfp_temp_td_mode_e;

typedef struct sfp_temp_td_set {
	U8	mode;
	U8	pad[3];
	S8	hthreshold;
	S8	lthreshold;
} sfp_temp_td_set_s;

typedef struct sxe_log_export_resp {
	U16	cur_log_len;
	U8	is_end;
	U8	pad;
	S32	session_id;
	S8	data[0];
} sxe_log_export_resp_s;

typedef enum sxe_log_export_type  {
	SXE_LOG_EXPORT_REQ	= 0,
	SXE_LOG_EXPORT_FIN,
	SXE_LOG_EXPORT_ABORT,
} sxe_log_export_type_e;

typedef struct sxe_log_export_req {
	U8	is_all_log;
	U8	cmdtype;
	U8	is_begin;
	U8	pad;
	S32	session_id;
	U32	log_len;
} sxe_log_export_req_s;

typedef struct soc_rst_req {
	U32	time;
} soc_rst_req_s;

typedef struct regs_dump_resp {
	U32	curdw_len;
	U8	data[0];
} regs_dump_resp_s;

enum {
	SXE_MFG_PART_NUMBER_LEN   = 8,
	SXE_MFG_SERIAL_NUMBER_LEN = 16,
	SXE_MFG_REVISION_LEN	  = 4,
	SXE_MFG_OEM_STR_LEN	   = 64,
	SXE_MFG_SXE_BOARD_ASSEMBLY_LEN  = 32,
	SXE_MFG_SXE_BOARD_TRACE_NUM_LEN = 16,
	SXE_MFG_SXE_MAC_ADDR_CNT		= 2,
};

typedef struct sxe_mfg_info {
	U8 part_number[SXE_MFG_PART_NUMBER_LEN];
	U8 serial_number[SXE_MFG_SERIAL_NUMBER_LEN];
	U32 mfg_date;
	U8 revision[SXE_MFG_REVISION_LEN];
	U32 rework_date;
	U8 pad[4];
	U64 mac_addr[SXE_MFG_SXE_MAC_ADDR_CNT];
	U8 board_trace_num[SXE_MFG_SXE_BOARD_TRACE_NUM_LEN];
	U8 board_assembly[SXE_MFG_SXE_BOARD_ASSEMBLY_LEN];
	U8 extra1[SXE_MFG_OEM_STR_LEN];
	U8 extra2[SXE_MFG_OEM_STR_LEN];
} sxe_mfg_info_t;

typedef struct sxe_lldp_info {
	U8	lldp_state;
	U8	pad[3];
} sxe_lldp_info_t;

typedef struct regs_dump_req {
	U32	base_addr;
	U32	dw_len;
} regs_dump_req_s;

typedef enum sxe_pcs_mode {
	SXE_PCS_MODE_1000BASE_KX_WO = 0,
	SXE_PCS_MODE_1000BASE_KX_W,
	SXE_PCS_MODE_SGMII,
	SXE_PCS_MODE_10GBASE_KR_WO,
	SXE_PCS_MODE_AUTO_NEGT_73,
	SXE_PCS_MODE_LPBK_PHY_TX2RX,
	SXE_PCS_MODE_LPBK_PHY_RX2TX,
	SXE_PCS_MODE_LPBK_PCS_RX2TX,
	SXE_PCS_MODE_BUTT,
} sxe_pcs_mode_e;

typedef enum sxe_remote_fault_mode {
	SXE_REMOTE_FALUT_NO_ERROR		= 0,
	SXE_REMOTE_FALUT_OFFLINE,
	SXE_REMOTE_FALUT_LINK_FAILURE,
	SXE_REMOTE_FALUT_AUTO_NEGOTIATION,
	SXE_REMOTE_UNKNOWN,
} sxe_remote_fault_e;

typedef struct sxe_phy_cfg {
	sxe_pcs_mode_e mode;
	U32 mtu;
} sxe_pcs_cfg_s;

typedef enum sxe_an_speed {
	SXE_AN_SPEED_NO_LINK = 0,
	SXE_AN_SPEED_100M,
	SXE_AN_SPEED_1G,
	SXE_AN_SPEED_10G,
	SXE_AN_SPEED_UNKNOWN,
} sxe_an_speed_e;

typedef enum sxe_phy_pause_cap {
	SXE_PAUSE_CAP_NO_PAUSE	= 0,
	SXE_PAUSE_CAP_ASYMMETRIC_PAUSE,
	SXE_PAUSE_CAP_SYMMETRIC_PAUSE,
	SXE_PAUSE_CAP_BOTH_PAUSE,
	SXE_PAUSE_CAP_UNKNOWN,
} sxe_phy_pause_cap_e;

typedef enum sxe_phy_duplex_type {
	SXE_FULL_DUPLEX	= 0,
	SXE_HALF_DUPLEX	= 1,
	SXE_UNKNOWN_DUPLEX,
} sxe_phy_duplex_type_e;

typedef struct sxe_phy_an_cap {
	sxe_remote_fault_e   remote_fault;
	sxe_phy_pause_cap_e  pause_cap;
	sxe_phy_duplex_type_e duplex_cap;
} sxe_phy_an_cap_s;

typedef struct sxe_an_cap {
	sxe_phy_an_cap_s local;
	sxe_phy_an_cap_s peer;
} sxe_an_cap_s;
#endif
