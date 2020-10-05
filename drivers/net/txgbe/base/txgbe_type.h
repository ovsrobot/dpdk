/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

#ifndef _TXGBE_TYPE_H_
#define _TXGBE_TYPE_H_

#define TXGBE_LINK_UP_TIME	90 /* 9.0 Seconds */
#define TXGBE_AUTO_NEG_TIME	45 /* 4.5 Seconds */

#define TXGBE_FRAME_SIZE_MAX	(9728) /* Maximum frame size, +FCS */
#define TXGBE_FRAME_SIZE_DFT	(1518) /* Default frame size, +FCS */
#define TXGBE_NUM_POOL		(64)
#define TXGBE_MAX_UP		8
#define TXGBE_MAX_QP		(128)
#define TXGBE_MAX_UTA		128

#define TXGBE_ALIGN		128 /* as intel did */

#include "txgbe_status.h"
#include "txgbe_osdep.h"
#include "txgbe_devids.h"

struct txgbe_thermal_diode_data {
	s16 temp;
	s16 alarm_thresh;
	s16 dalarm_thresh;
};

struct txgbe_thermal_sensor_data {
	struct txgbe_thermal_diode_data sensor[1];
};

/* Physical layer type */
#define TXGBE_PHYSICAL_LAYER_UNKNOWN		0
#define TXGBE_PHYSICAL_LAYER_10GBASE_T		0x00001
#define TXGBE_PHYSICAL_LAYER_1000BASE_T		0x00002
#define TXGBE_PHYSICAL_LAYER_100BASE_TX		0x00004
#define TXGBE_PHYSICAL_LAYER_SFP_PLUS_CU	0x00008
#define TXGBE_PHYSICAL_LAYER_10GBASE_LR		0x00010
#define TXGBE_PHYSICAL_LAYER_10GBASE_LRM	0x00020
#define TXGBE_PHYSICAL_LAYER_10GBASE_SR		0x00040
#define TXGBE_PHYSICAL_LAYER_10GBASE_KX4	0x00080
#define TXGBE_PHYSICAL_LAYER_10GBASE_CX4	0x00100
#define TXGBE_PHYSICAL_LAYER_1000BASE_KX	0x00200
#define TXGBE_PHYSICAL_LAYER_1000BASE_BX	0x00400
#define TXGBE_PHYSICAL_LAYER_10GBASE_KR		0x00800
#define TXGBE_PHYSICAL_LAYER_10GBASE_XAUI	0x01000
#define TXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA	0x02000
#define TXGBE_PHYSICAL_LAYER_1000BASE_SX	0x04000
#define TXGBE_PHYSICAL_LAYER_10BASE_T		0x08000
#define TXGBE_PHYSICAL_LAYER_2500BASE_KX	0x10000

#define TXGBE_ATR_HASH_MASK			0x7fff

enum txgbe_eeprom_type {
	txgbe_eeprom_unknown = 0,
	txgbe_eeprom_spi,
	txgbe_eeprom_flash,
	txgbe_eeprom_none /* No NVM support */
};

enum txgbe_mac_type {
	txgbe_mac_unknown = 0,
	txgbe_mac_raptor,
	txgbe_mac_raptor_vf,
	txgbe_num_macs
};

enum txgbe_phy_type {
	txgbe_phy_unknown = 0,
	txgbe_phy_none,
	txgbe_phy_tn,
	txgbe_phy_aq,
	txgbe_phy_ext_1g_t,
	txgbe_phy_cu_mtd,
	txgbe_phy_cu_unknown,
	txgbe_phy_qt,
	txgbe_phy_xaui,
	txgbe_phy_nl,
	txgbe_phy_sfp_tyco_passive,
	txgbe_phy_sfp_unknown_passive,
	txgbe_phy_sfp_unknown_active,
	txgbe_phy_sfp_avago,
	txgbe_phy_sfp_ftl,
	txgbe_phy_sfp_ftl_active,
	txgbe_phy_sfp_unknown,
	txgbe_phy_sfp_intel,
	txgbe_phy_qsfp_unknown_passive,
	txgbe_phy_qsfp_unknown_active,
	txgbe_phy_qsfp_intel,
	txgbe_phy_qsfp_unknown,
	txgbe_phy_sfp_unsupported, /* Enforce bit set with unsupported module */
	txgbe_phy_sgmii,
	txgbe_phy_fw,
	txgbe_phy_generic
};

/*
 * SFP+ module type IDs:
 *
 * ID	Module Type
 * =============
 * 0	SFP_DA_CU
 * 1	SFP_SR
 * 2	SFP_LR
 * 3	SFP_DA_CU_CORE0 - chip-specific
 * 4	SFP_DA_CU_CORE1 - chip-specific
 * 5	SFP_SR/LR_CORE0 - chip-specific
 * 6	SFP_SR/LR_CORE1 - chip-specific
 */
enum txgbe_sfp_type {
	txgbe_sfp_type_unknown = 0,
	txgbe_sfp_type_da_cu,
	txgbe_sfp_type_sr,
	txgbe_sfp_type_lr,
	txgbe_sfp_type_da_cu_core0,
	txgbe_sfp_type_da_cu_core1,
	txgbe_sfp_type_srlr_core0,
	txgbe_sfp_type_srlr_core1,
	txgbe_sfp_type_da_act_lmt_core0,
	txgbe_sfp_type_da_act_lmt_core1,
	txgbe_sfp_type_1g_cu_core0,
	txgbe_sfp_type_1g_cu_core1,
	txgbe_sfp_type_1g_sx_core0,
	txgbe_sfp_type_1g_sx_core1,
	txgbe_sfp_type_1g_lx_core0,
	txgbe_sfp_type_1g_lx_core1,
	txgbe_sfp_type_not_present = 0xFFFE,
	txgbe_sfp_type_not_known = 0xFFFF
};

enum txgbe_media_type {
	txgbe_media_type_unknown = 0,
	txgbe_media_type_fiber,
	txgbe_media_type_fiber_qsfp,
	txgbe_media_type_copper,
	txgbe_media_type_backplane,
	txgbe_media_type_cx4,
	txgbe_media_type_virtual
};


/* Smart Speed Settings */
#define TXGBE_SMARTSPEED_MAX_RETRIES	3
enum txgbe_smart_speed {
	txgbe_smart_speed_auto = 0,
	txgbe_smart_speed_on,
	txgbe_smart_speed_off
};

/* PCI bus types */
enum txgbe_bus_type {
	txgbe_bus_type_unknown = 0,
	txgbe_bus_type_pci,
	txgbe_bus_type_pcix,
	txgbe_bus_type_pci_express,
	txgbe_bus_type_internal,
	txgbe_bus_type_reserved
};

/* PCI bus speeds */
enum txgbe_bus_speed {
	txgbe_bus_speed_unknown	= 0,
	txgbe_bus_speed_33	= 33,
	txgbe_bus_speed_66	= 66,
	txgbe_bus_speed_100	= 100,
	txgbe_bus_speed_120	= 120,
	txgbe_bus_speed_133	= 133,
	txgbe_bus_speed_2500	= 2500,
	txgbe_bus_speed_5000	= 5000,
	txgbe_bus_speed_8000	= 8000,
	txgbe_bus_speed_reserved
};

/* PCI bus widths */
enum txgbe_bus_width {
	txgbe_bus_width_unknown	= 0,
	txgbe_bus_width_pcie_x1	= 1,
	txgbe_bus_width_pcie_x2	= 2,
	txgbe_bus_width_pcie_x4	= 4,
	txgbe_bus_width_pcie_x8	= 8,
	txgbe_bus_width_32	= 32,
	txgbe_bus_width_64	= 64,
	txgbe_bus_width_reserved
};

struct txgbe_hw;

struct txgbe_addr_filter_info {
	u32 num_mc_addrs;
	u32 rar_used_count;
	u32 mta_in_use;
	u32 overflow_promisc;
	bool user_set_promisc;
};

/* Bus parameters */
struct txgbe_bus_info {
	s32 (*get_bus_info)(struct txgbe_hw *);
	void (*set_lan_id)(struct txgbe_hw *);

	enum txgbe_bus_speed speed;
	enum txgbe_bus_width width;
	enum txgbe_bus_type type;

	u16 func;
	u8 lan_id;
	u16 instance_id;
};

/* Statistics counters collected by the MAC */
/* PB[] RxTx */
struct txgbe_pb_stats {
	u64 tx_pb_xon_packets;
	u64 rx_pb_xon_packets;
	u64 tx_pb_xoff_packets;
	u64 rx_pb_xoff_packets;
	u64 rx_pb_dropped;
	u64 rx_pb_mbuf_alloc_errors;
	u64 tx_pb_xon2off_packets;
};

/* QP[] RxTx */
struct txgbe_qp_stats {
	u64 rx_qp_packets;
	u64 tx_qp_packets;
	u64 rx_qp_bytes;
	u64 tx_qp_bytes;
	u64 rx_qp_mc_packets;
};

struct txgbe_hw_stats {
	/* MNG RxTx */
	u64 mng_bmc2host_packets;
	u64 mng_host2bmc_packets;
	/* Basix RxTx */
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 rx_total_bytes;
	u64 rx_total_packets;
	u64 tx_total_packets;
	u64 rx_total_missed_packets;
	u64 rx_broadcast_packets;
	u64 tx_broadcast_packets;
	u64 rx_multicast_packets;
	u64 tx_multicast_packets;
	u64 rx_management_packets;
	u64 tx_management_packets;
	u64 rx_management_dropped;
	u64 rx_drop_packets;

	/* Basic Error */
	u64 rx_crc_errors;
	u64 rx_illegal_byte_errors;
	u64 rx_error_bytes;
	u64 rx_mac_short_packet_dropped;
	u64 rx_length_errors;
	u64 rx_undersize_errors;
	u64 rx_fragment_errors;
	u64 rx_oversize_errors;
	u64 rx_jabber_errors;
	u64 rx_l3_l4_xsum_error;
	u64 mac_local_errors;
	u64 mac_remote_errors;

	/* Flow Director */
	u64 flow_director_added_filters;
	u64 flow_director_removed_filters;
	u64 flow_director_filter_add_errors;
	u64 flow_director_filter_remove_errors;
	u64 flow_director_matched_filters;
	u64 flow_director_missed_filters;

	/* FCoE */
	u64 rx_fcoe_crc_errors;
	u64 rx_fcoe_mbuf_allocation_errors;
	u64 rx_fcoe_dropped;
	u64 rx_fcoe_packets;
	u64 tx_fcoe_packets;
	u64 rx_fcoe_bytes;
	u64 tx_fcoe_bytes;
	u64 rx_fcoe_no_ddp;
	u64 rx_fcoe_no_ddp_ext_buff;

	/* MACSEC */
	u64 tx_macsec_pkts_untagged;
	u64 tx_macsec_pkts_encrypted;
	u64 tx_macsec_pkts_protected;
	u64 tx_macsec_octets_encrypted;
	u64 tx_macsec_octets_protected;
	u64 rx_macsec_pkts_untagged;
	u64 rx_macsec_pkts_badtag;
	u64 rx_macsec_pkts_nosci;
	u64 rx_macsec_pkts_unknownsci;
	u64 rx_macsec_octets_decrypted;
	u64 rx_macsec_octets_validated;
	u64 rx_macsec_sc_pkts_unchecked;
	u64 rx_macsec_sc_pkts_delayed;
	u64 rx_macsec_sc_pkts_late;
	u64 rx_macsec_sa_pkts_ok;
	u64 rx_macsec_sa_pkts_invalid;
	u64 rx_macsec_sa_pkts_notvalid;
	u64 rx_macsec_sa_pkts_unusedsa;
	u64 rx_macsec_sa_pkts_notusingsa;

	/* MAC RxTx */
	u64 rx_size_64_packets;
	u64 rx_size_65_to_127_packets;
	u64 rx_size_128_to_255_packets;
	u64 rx_size_256_to_511_packets;
	u64 rx_size_512_to_1023_packets;
	u64 rx_size_1024_to_max_packets;
	u64 tx_size_64_packets;
	u64 tx_size_65_to_127_packets;
	u64 tx_size_128_to_255_packets;
	u64 tx_size_256_to_511_packets;
	u64 tx_size_512_to_1023_packets;
	u64 tx_size_1024_to_max_packets;

	/* Flow Control */
	u64 tx_xon_packets;
	u64 rx_xon_packets;
	u64 tx_xoff_packets;
	u64 rx_xoff_packets;

	/* PB[] RxTx */
	struct {
		u64 rx_up_packets;
		u64 tx_up_packets;
		u64 rx_up_bytes;
		u64 tx_up_bytes;
		u64 rx_up_drop_packets;

		u64 tx_up_xon_packets;
		u64 rx_up_xon_packets;
		u64 tx_up_xoff_packets;
		u64 rx_up_xoff_packets;
		u64 rx_up_dropped;
		u64 rx_up_mbuf_alloc_errors;
		u64 tx_up_xon2off_packets;
	} up[TXGBE_MAX_UP];

	/* QP[] RxTx */
	struct {
		u64 rx_qp_packets;
		u64 tx_qp_packets;
		u64 rx_qp_bytes;
		u64 tx_qp_bytes;
		u64 rx_qp_mc_packets;
	} qp[TXGBE_MAX_QP];

};

/* iterator type for walking multicast address lists */
typedef u8* (*txgbe_mc_addr_itr) (struct txgbe_hw *hw, u8 **mc_addr_ptr,
				  u32 *vmdq);

struct txgbe_link_info {
	s32 (*read_link)(struct txgbe_hw *, u8 addr, u16 reg, u16 *val);
	s32 (*read_link_unlocked)(struct txgbe_hw *, u8 addr, u16 reg,
				  u16 *val);
	s32 (*write_link)(struct txgbe_hw *, u8 addr, u16 reg, u16 val);
	s32 (*write_link_unlocked)(struct txgbe_hw *, u8 addr, u16 reg,
				   u16 val);

	u8 addr;
};

struct txgbe_rom_info {
	s32 (*init_params)(struct txgbe_hw *);
	s32 (*read16)(struct txgbe_hw *, u32, u16 *);
	s32 (*readw_sw)(struct txgbe_hw *, u32, u16 *);
	s32 (*readw_buffer)(struct txgbe_hw *, u32, u32, void *);
	s32 (*read32)(struct txgbe_hw *, u32, u32 *);
	s32 (*read_buffer)(struct txgbe_hw *, u32, u32, void *);
	s32 (*write16)(struct txgbe_hw *, u32, u16);
	s32 (*writew_sw)(struct txgbe_hw *, u32, u16);
	s32 (*writew_buffer)(struct txgbe_hw *, u32, u32, void *);
	s32 (*write32)(struct txgbe_hw *, u32, u32);
	s32 (*write_buffer)(struct txgbe_hw *, u32, u32, void *);
	s32 (*validate_checksum)(struct txgbe_hw *, u16 *);
	s32 (*update_checksum)(struct txgbe_hw *);
	s32 (*calc_checksum)(struct txgbe_hw *);

	enum txgbe_eeprom_type type;
	u32 semaphore_delay;
	u16 word_size;
	u16 address_bits;
	u16 word_page_size;
	u16 ctrl_word_3;

	u32 sw_addr;
};

struct txgbe_flash_info {
	s32 (*init_params)(struct txgbe_hw *);
	s32 (*read_buffer)(struct txgbe_hw *, u32, u32, u32 *);
	s32 (*write_buffer)(struct txgbe_hw *, u32, u32, u32 *);
	u32 semaphore_delay;
	u32 dword_size;
	u16 address_bits;
};

#define TXGBE_FLAGS_DOUBLE_RESET_REQUIRED	0x01
struct txgbe_mac_info {
	s32 (*init_hw)(struct txgbe_hw *);
	s32 (*reset_hw)(struct txgbe_hw *);
	s32 (*start_hw)(struct txgbe_hw *);
	s32 (*stop_hw)(struct txgbe_hw *);
	s32 (*clear_hw_cntrs)(struct txgbe_hw *);
	void (*enable_relaxed_ordering)(struct txgbe_hw *);
	u64 (*get_supported_physical_layer)(struct txgbe_hw *);
	s32 (*get_mac_addr)(struct txgbe_hw *, u8 *);
	s32 (*get_san_mac_addr)(struct txgbe_hw *, u8 *);
	s32 (*set_san_mac_addr)(struct txgbe_hw *, u8 *);
	s32 (*get_device_caps)(struct txgbe_hw *, u16 *);
	s32 (*get_wwn_prefix)(struct txgbe_hw *, u16 *, u16 *);
	s32 (*get_fcoe_boot_status)(struct txgbe_hw *, u16 *);
	s32 (*read_analog_reg8)(struct txgbe_hw*, u32, u8*);
	s32 (*write_analog_reg8)(struct txgbe_hw*, u32, u8);
	s32 (*setup_sfp)(struct txgbe_hw *);
	s32 (*enable_rx_dma)(struct txgbe_hw *, u32);
	s32 (*disable_sec_rx_path)(struct txgbe_hw *);
	s32 (*enable_sec_rx_path)(struct txgbe_hw *);
	s32 (*disable_sec_tx_path)(struct txgbe_hw *);
	s32 (*enable_sec_tx_path)(struct txgbe_hw *);
	s32 (*acquire_swfw_sync)(struct txgbe_hw *, u32);
	void (*release_swfw_sync)(struct txgbe_hw *, u32);
	void (*init_swfw_sync)(struct txgbe_hw *);
	u64 (*autoc_read)(struct txgbe_hw *);
	void (*autoc_write)(struct txgbe_hw *, u64);
	s32 (*prot_autoc_read)(struct txgbe_hw *, bool *, u64 *);
	s32 (*prot_autoc_write)(struct txgbe_hw *, bool, u64);
	s32 (*negotiate_api_version)(struct txgbe_hw *hw, int api);

	/* Link */
	void (*disable_tx_laser)(struct txgbe_hw *);
	void (*enable_tx_laser)(struct txgbe_hw *);
	void (*flap_tx_laser)(struct txgbe_hw *);
	s32 (*setup_link)(struct txgbe_hw *, u32, bool);
	s32 (*setup_mac_link)(struct txgbe_hw *, u32, bool);
	s32 (*check_link)(struct txgbe_hw *, u32 *, bool *, bool);
	s32 (*get_link_capabilities)(struct txgbe_hw *, u32 *,
				     bool *);
	void (*set_rate_select_speed)(struct txgbe_hw *, u32);

	/* Packet Buffer manipulation */
	void (*setup_pba)(struct txgbe_hw *, int, u32, int);

	/* LED */
	s32 (*led_on)(struct txgbe_hw *, u32);
	s32 (*led_off)(struct txgbe_hw *, u32);
	s32 (*blink_led_start)(struct txgbe_hw *, u32);
	s32 (*blink_led_stop)(struct txgbe_hw *, u32);
	s32 (*init_led_link_act)(struct txgbe_hw *);

	/* RAR, Multicast, VLAN */
	s32 (*set_rar)(struct txgbe_hw *, u32, u8 *, u32, u32);
	s32 (*set_uc_addr)(struct txgbe_hw *, u32, u8 *);
	s32 (*clear_rar)(struct txgbe_hw *, u32);
	s32 (*insert_mac_addr)(struct txgbe_hw *, u8 *, u32);
	s32 (*set_vmdq)(struct txgbe_hw *, u32, u32);
	s32 (*set_vmdq_san_mac)(struct txgbe_hw *, u32);
	s32 (*clear_vmdq)(struct txgbe_hw *, u32, u32);
	s32 (*init_rx_addrs)(struct txgbe_hw *);
	s32 (*update_uc_addr_list)(struct txgbe_hw *, u8 *, u32,
				   txgbe_mc_addr_itr);
	s32 (*update_mc_addr_list)(struct txgbe_hw *, u8 *, u32,
				   txgbe_mc_addr_itr, bool clear);
	s32 (*enable_mc)(struct txgbe_hw *);
	s32 (*disable_mc)(struct txgbe_hw *);
	s32 (*clear_vfta)(struct txgbe_hw *);
	s32 (*set_vfta)(struct txgbe_hw *, u32, u32, bool, bool);
	s32 (*set_vlvf)(struct txgbe_hw *, u32, u32, bool, u32 *, u32,
			bool);
	s32 (*init_uta_tables)(struct txgbe_hw *);
	void (*set_mac_anti_spoofing)(struct txgbe_hw *, bool, int);
	void (*set_vlan_anti_spoofing)(struct txgbe_hw *, bool, int);
	s32 (*update_xcast_mode)(struct txgbe_hw *, int);
	s32 (*set_rlpml)(struct txgbe_hw *, u16);

	/* Flow Control */
	s32 (*fc_enable)(struct txgbe_hw *);
	s32 (*setup_fc)(struct txgbe_hw *);
	void (*fc_autoneg)(struct txgbe_hw *);

	/* Manageability interface */
	s32 (*set_fw_drv_ver)(struct txgbe_hw *, u8, u8, u8, u8, u16,
			      const char *);
	s32 (*get_thermal_sensor_data)(struct txgbe_hw *);
	s32 (*init_thermal_sensor_thresh)(struct txgbe_hw *hw);
	void (*get_rtrup2tc)(struct txgbe_hw *hw, u8 *map);
	void (*disable_rx)(struct txgbe_hw *hw);
	void (*enable_rx)(struct txgbe_hw *hw);
	void (*set_source_address_pruning)(struct txgbe_hw *, bool,
					   unsigned int);
	void (*set_ethertype_anti_spoofing)(struct txgbe_hw *, bool, int);
	s32 (*dmac_update_tcs)(struct txgbe_hw *hw);
	s32 (*dmac_config_tcs)(struct txgbe_hw *hw);
	s32 (*dmac_config)(struct txgbe_hw *hw);
	s32 (*setup_eee)(struct txgbe_hw *hw, bool enable_eee);
	s32 (*read_iosf_sb_reg)(struct txgbe_hw *, u32, u32, u32 *);
	s32 (*write_iosf_sb_reg)(struct txgbe_hw *, u32, u32, u32);
	void (*disable_mdd)(struct txgbe_hw *hw);
	void (*enable_mdd)(struct txgbe_hw *hw);
	void (*mdd_event)(struct txgbe_hw *hw, u32 *vf_bitmap);
	void (*restore_mdd_vf)(struct txgbe_hw *hw, u32 vf);
	bool (*fw_recovery_mode)(struct txgbe_hw *hw);

	enum txgbe_mac_type type;
	u8 addr[ETH_ADDR_LEN];
	u8 perm_addr[ETH_ADDR_LEN];
	u8 san_addr[ETH_ADDR_LEN];
	/* prefix for World Wide Node Name (WWNN) */
	u16 wwnn_prefix;
	/* prefix for World Wide Port Name (WWPN) */
	u16 wwpn_prefix;
#define TXGBE_MAX_MTA			128
	u32 mta_shadow[TXGBE_MAX_MTA];
	s32 mc_filter_type;
	u32 mcft_size;
	u32 vft_size;
	u32 num_rar_entries;
	u32 max_tx_queues;
	u32 max_rx_queues;

	u8  san_mac_rar_index;
	bool get_link_status;
	u64 orig_autoc;  /* cached value of AUTOC */
	bool orig_link_settings_stored;
	bool autotry_restart;
	u8 flags;
	struct txgbe_thermal_sensor_data  thermal_sensor_data;
	bool set_lben;
	u32  max_link_up_time;
};

struct txgbe_phy_info {
	u32 (*get_media_type)(struct txgbe_hw *);
	s32 (*identify)(struct txgbe_hw *);
	s32 (*identify_sfp)(struct txgbe_hw *);
	s32 (*init)(struct txgbe_hw *);
	s32 (*reset)(struct txgbe_hw *);
	s32 (*read_reg)(struct txgbe_hw *, u32, u32, u16 *);
	s32 (*write_reg)(struct txgbe_hw *, u32, u32, u16);
	s32 (*read_reg_mdi)(struct txgbe_hw *, u32, u32, u16 *);
	s32 (*write_reg_mdi)(struct txgbe_hw *, u32, u32, u16);
	s32 (*setup_link)(struct txgbe_hw *);
	s32 (*setup_internal_link)(struct txgbe_hw *);
	s32 (*setup_link_speed)(struct txgbe_hw *, u32, bool);
	s32 (*check_link)(struct txgbe_hw *, u32 *, bool *);
	s32 (*get_firmware_version)(struct txgbe_hw *, u32 *);
	s32 (*read_i2c_byte)(struct txgbe_hw *, u8, u8, u8 *);
	s32 (*write_i2c_byte)(struct txgbe_hw *, u8, u8, u8);
	s32 (*read_i2c_sff8472)(struct txgbe_hw *, u8, u8 *);
	s32 (*read_i2c_eeprom)(struct txgbe_hw *, u8, u8 *);
	s32 (*write_i2c_eeprom)(struct txgbe_hw *, u8, u8);
	void (*i2c_bus_clear)(struct txgbe_hw *);
	s32 (*check_overtemp)(struct txgbe_hw *);
	s32 (*set_phy_power)(struct txgbe_hw *, bool on);
	s32 (*enter_lplu)(struct txgbe_hw *);
	s32 (*handle_lasi)(struct txgbe_hw *hw);
	s32 (*read_i2c_byte_unlocked)(struct txgbe_hw *, u8 offset, u8 addr,
				      u8 *value);
	s32 (*write_i2c_byte_unlocked)(struct txgbe_hw *, u8 offset, u8 addr,
				       u8 value);

	enum txgbe_phy_type type;
	u32 addr;
	u32 id;
	enum txgbe_sfp_type sfp_type;
	bool sfp_setup_needed;
	u32 revision;
	u32 media_type;
	u32 phy_semaphore_mask;
	bool reset_disable;
	u32 autoneg_advertised;
	u32 speeds_supported;
	enum txgbe_smart_speed smart_speed;
	bool smart_speed_active;
	bool multispeed_fiber;
	bool qsfp_shared_i2c_bus;
	u32 nw_mng_if_sel;
	u32 link_mode;
};

struct txgbe_mbx_info {
	void (*init_params)(struct txgbe_hw *hw);
	s32  (*read)(struct txgbe_hw *, u32 *, u16,  u16);
	s32  (*write)(struct txgbe_hw *, u32 *, u16, u16);
	s32  (*read_posted)(struct txgbe_hw *, u32 *, u16,  u16);
	s32  (*write_posted)(struct txgbe_hw *, u32 *, u16, u16);
	s32  (*check_for_msg)(struct txgbe_hw *, u16);
	s32  (*check_for_ack)(struct txgbe_hw *, u16);
	s32  (*check_for_rst)(struct txgbe_hw *, u16);
};

enum txgbe_isb_idx {
	TXGBE_ISB_HEADER,
	TXGBE_ISB_MISC,
	TXGBE_ISB_VEC0,
	TXGBE_ISB_VEC1,
	TXGBE_ISB_MAX
};

struct txgbe_hw {
	void IOMEM *hw_addr;
	void *back;
	struct txgbe_mac_info mac;
	struct txgbe_addr_filter_info addr_ctrl;
	struct txgbe_phy_info phy;
	struct txgbe_link_info link;
	struct txgbe_rom_info rom;
	struct txgbe_flash_info flash;
	struct txgbe_bus_info bus;
	struct txgbe_mbx_info mbx;
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	bool adapter_stopped;
	bool allow_unsupported_sfp;
	bool need_crosstalk_fix;

	uint64_t isb_dma;
	void IOMEM *isb_mem;
	u16 nb_rx_queues;
	u16 nb_tx_queues;
	enum txgbe_link_status {
		TXGBE_LINK_STATUS_NONE = 0,
		TXGBE_LINK_STATUS_KX,
		TXGBE_LINK_STATUS_KX4
	} link_status;
	enum txgbe_reset_type {
		TXGBE_LAN_RESET = 0,
		TXGBE_SW_RESET,
		TXGBE_GLOBAL_RESET
	} reset_type;

	u32 q_rx_regs[128 * 4];
	u32 q_tx_regs[128 * 4];
	bool offset_loaded;
	struct {
		u64 rx_qp_packets;
		u64 tx_qp_packets;
		u64 rx_qp_bytes;
		u64 tx_qp_bytes;
		u64 rx_qp_mc_packets;
	} qp_last[TXGBE_MAX_QP];
};

#include "txgbe_regs.h"
#include "txgbe_dummy.h"

#endif /* _TXGBE_TYPE_H_ */
