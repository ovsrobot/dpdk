/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_API_ADAPTER_H_
#define _NTCONNECT_API_ADAPTER_H_

/*
 * adapter get,interfaces
 */
enum port_speed {
	PORT_LINK_SPEED_UNKNOWN,
	PORT_LINK_SPEED_NONE_REPORTED,
	PORT_LINK_SPEED_10M,
	PORT_LINK_SPEED_100M,
	PORT_LINK_SPEED_1G,
	PORT_LINK_SPEED_10G,
	PORT_LINK_SPEED_25G,
	PORT_LINK_SPEED_40G,
	PORT_LINK_SPEED_50G,
	PORT_LINK_SPEED_100G,
};

enum port_states {
	PORT_STATE_DISABLED,
	PORT_STATE_NIM_PRESENT,
	PORT_STATE_NIM_ABSENT,
	PORT_STATE_VIRTUAL_UNATTACHED,
	PORT_STATE_VIRTUAL_SPLIT,
	PORT_STATE_VIRTUAL_PACKED,
	PORT_STATE_VIRTUAL_RELAY,
};

enum port_link { PORT_LINK_UNKNOWN, PORT_LINK_UP, PORT_LINK_DOWN };

enum port_type {
	PORT_TYPE_PHY_NORMAL, /* Normal phy port (no LAG) */
	/* Link aggregated phy port in active/active LAG configuration */
	PORT_TYPE_PHY_LAG_ACTIVE_ACTIVE,
	PORT_TYPE_PHY_LAG_PRIMARY, /* Primary phy port in active/backup LAG configuration */
	PORT_TYPE_PHY_LAG_BACKUP, /* Backup phy port in active/backup LAG configuration */
	PORT_TYPE_VIRT,
	PORT_TYPE_LAST
};

enum nim_identifier_e {
	NIM_UNKNOWN = 0x00, /* Nim type is unknown */
	NIM_GBIC = 0x01, /* Nim type = GBIC */
	NIM_FIXED = 0x02, /* Nim type = FIXED */
	NIM_SFP_SFP_PLUS = 0x03, /* Nim type = SFP/SFP+ */
	NIM_300_PIN_XBI = 0x04, /* Nim type = 300 pin XBI */
	NIM_XEN_PAK = 0x05, /* Nim type = XEN-PAK */
	NIM_XFP = 0x06, /* Nim type = XFP */
	NIM_XFF = 0x07, /* Nim type = XFF */
	NIM_XFP_E = 0x08, /* Nim type = XFP-E */
	NIM_XPAK = 0x09, /* Nim type = XPAK */
	NIM_X2 = 0x0A, /* Nim type = X2 */
	NIM_DWDM = 0x0B, /* Nim type = DWDM */
	NIM_QSFP = 0x0C, /* Nim type = QSFP */
	NIM_QSFP_PLUS = 0x0D, /* Nim type = QSFP+ */
	NIM_QSFP28 = 0x11, /* Nim type = QSFP28 */
	NIM_CFP4 = 0x12, /* Nim type = CFP4 */
};

/*
 * Port types
 */
enum port_type_e {
	PORT_TYPE_NOT_AVAILABLE =
		0, /* The NIM/port type is not available (unknown) */
	PORT_TYPE_NOT_RECOGNISED, /* The NIM/port type not recognized */
	PORT_TYPE_RJ45, /* RJ45 type */
	PORT_TYPE_SFP_NOT_PRESENT, /* SFP type but slot is empty */
	PORT_TYPE_SFP_SX, /* SFP SX */
	PORT_TYPE_SFP_SX_DD, /* SFP SX digital diagnostic */
	PORT_TYPE_SFP_LX, /* SFP LX */
	PORT_TYPE_SFP_LX_DD, /* SFP LX digital diagnostic */
	PORT_TYPE_SFP_ZX, /* SFP ZX */
	PORT_TYPE_SFP_ZX_DD, /* SFP ZX digital diagnostic */
	PORT_TYPE_SFP_CU, /* SFP copper */
	PORT_TYPE_SFP_CU_DD, /* SFP copper digital diagnostic */
	PORT_TYPE_SFP_NOT_RECOGNISED, /* SFP unknown */
	PORT_TYPE_XFP, /* XFP */
	PORT_TYPE_XPAK, /* XPAK */
	PORT_TYPE_SFP_CU_TRI_SPEED, /* SFP copper tri-speed */
	PORT_TYPE_SFP_CU_TRI_SPEED_DD, /* SFP copper tri-speed digital diagnostic */
	PORT_TYPE_SFP_PLUS, /* SFP+ type */
	PORT_TYPE_SFP_PLUS_NOT_PRESENT, /* SFP+ type but slot is empty */
	PORT_TYPE_XFP_NOT_PRESENT, /* XFP type but slot is empty */
	PORT_TYPE_QSFP_PLUS_NOT_PRESENT, /* QSFP type but slot is empty */
	PORT_TYPE_QSFP_PLUS, /* QSFP type */
	PORT_TYPE_SFP_PLUS_PASSIVE_DAC, /* SFP+ Passive DAC */
	PORT_TYPE_SFP_PLUS_ACTIVE_DAC, /* SFP+ Active DAC */
	PORT_TYPE_CFP4, /* CFP4 type */
	PORT_TYPE_CFP4_LR4 = PORT_TYPE_CFP4, /* CFP4 100G, LR4 type */
	PORT_TYPE_CFP4_NOT_PRESENT, /* CFP4 type but slot is empty */
	PORT_TYPE_INITIALIZE, /* The port type is not fully established yet */
	PORT_TYPE_NIM_NOT_PRESENT, /* Generic "Not present" */
	PORT_TYPE_HCB, /* Test mode: Host Compliance Board */
	PORT_TYPE_NOT_SUPPORTED, /* The NIM type is not supported in this context */
	PORT_TYPE_SFP_PLUS_DUAL_RATE, /* SFP+ supports 1G/10G */
	PORT_TYPE_CFP4_SR4, /* CFP4 100G, SR4 type */
	PORT_TYPE_QSFP28_NOT_PRESENT, /* QSFP28 type but slot is empty */
	PORT_TYPE_QSFP28, /* QSFP28 type */
	PORT_TYPE_QSFP28_SR4, /* QSFP28-SR4 type */
	PORT_TYPE_QSFP28_LR4, /* QSFP28-LR4 type */
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	PORT_TYPE_QSFP_PLUS_4X10,
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	PORT_TYPE_QSFP_PASSIVE_DAC_4X10,
	PORT_TYPE_QSFP_PASSIVE_DAC =
		PORT_TYPE_QSFP_PASSIVE_DAC_4X10, /* QSFP passive DAC type */
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	PORT_TYPE_QSFP_ACTIVE_DAC_4X10,
	PORT_TYPE_QSFP_ACTIVE_DAC =
		PORT_TYPE_QSFP_ACTIVE_DAC_4X10, /* QSFP active DAC type */
	PORT_TYPE_SFP_28, /* SFP28 type */
	PORT_TYPE_SFP_28_SR, /* SFP28-SR type */
	PORT_TYPE_SFP_28_LR, /* SFP28-LR type */
	PORT_TYPE_SFP_28_CR_CA_L, /* SFP28-CR-CA-L type */
	PORT_TYPE_SFP_28_CR_CA_S, /* SFP28-CR-CA-S type */
	PORT_TYPE_SFP_28_CR_CA_N, /* SFP28-CR-CA-N type */
	PORT_TYPE_QSFP28_CR_CA_L, /* QSFP28-CR-CA-L type */
	PORT_TYPE_QSFP28_CR_CA_S, /* QSFP28-CR-CA-S type */
	PORT_TYPE_QSFP28_CR_CA_N, /* QSFP28-CR-CA-N type */
	PORT_TYPE_SFP_28_SR_DR, /* SFP28-SR-DR type */
	PORT_TYPE_SFP_28_LR_DR, /* SFP28-LR-DR type */
	PORT_TYPE_SFP_FX, /* SFP FX */
	PORT_TYPE_SFP_PLUS_CU, /* SFP+ CU type */
	PORT_TYPE_QSFP28_FR, /* QSFP28-FR type. Uses PAM4 modulation on one lane only */
	PORT_TYPE_QSFP28_DR, /* QSFP28-DR type. Uses PAM4 modulation on one lane only */
	PORT_TYPE_QSFP28_LR, /* QSFP28-LR type. Uses PAM4 modulation on one lane only */
};

struct mac_addr_s {
	uint8_t addr_b[6];
};

struct nim_link_length_s {
	/* NIM link length (in meters) supported SM (9um). A value of 0xFFFF indicates that the
	 * length is >= 65535 m
	 */
	uint16_t sm;
	uint16_t ebw; /* NIM link length (in meters) supported EBW (50um) */
	uint16_t mm50; /* NIM link length (in meters) supported MM (50um) */
	uint16_t mm62; /* NIM link length (in meters) supported MM (62.5um) */
	uint16_t copper; /* NIM link length (in meters) supported copper */
};

struct nim_data_s {
	uint8_t nim_id;
	uint8_t port_type;
	char vendor_name[17];
	char prod_no[17];
	char serial_no[17];
	char date[9];
	char rev[5];
	uint8_t pwr_level_req;
	uint8_t pwr_level_cur;
	struct nim_link_length_s link_length;
};

struct sensor {
	uint8_t sign;
	uint8_t type;
	uint32_t current_value;
	uint32_t min_value;
	uint32_t max_value;
	char name[50];
};

struct ntc_sensors_s {
	uint16_t adapter_sensors_cnt;
	uint16_t ports_cnt;
	uint16_t nim_sensors_cnt[8];
	char adapter_name[24];
};

#define MAX_RSS_QUEUES 128

enum queue_dir_e { QUEUE_INPUT, QUEUE_OUTPUT };

struct queue_s {
	enum queue_dir_e dir;
	int idx;
};

struct ntc_interface_s {
	uint8_t port_id;
	enum port_type type;
	enum port_link link;
	enum port_states port_state;
	enum port_speed port_speed;
	struct pci_id_s pci_id;
	struct mac_addr_s mac;
	struct nim_data_s nim_data;
	uint16_t mtu;
	/* attached queues */
	struct {
		struct queue_s queue[MAX_RSS_QUEUES];
		int num_queues;
	};
};

/*
 * adapter get,interfaces
 */
struct ntc_interfaces_s {
	int final_list;
	uint8_t nb_ports;
	struct ntc_interface_s intf[];
};

/*
 * adapter get,info
 */
struct ntc_adap_get_info_s {
	char *fw_version[32];
};

#endif /* _NTCONNECT_API_ADAPTER_H_ */
