/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT4GA_LINK_H_
#define NT4GA_LINK_H_

#include "common_adapter_defs.h"
#include "nthw_drv.h"
#include "i2c_nim.h"
#include "nthw_fpga_rst_nt200a0x.h"

/*
 * Link state.\n
 * Just after start of ntservice the link state might be unknown since the
 * monitoring routine is busy reading NIM state and NIM data. This might also
 * be the case after a NIM is plugged into an interface.
 * The error state indicates a HW reading error.
 */
enum nt_link_state_e {
	NT_LINK_STATE_UNKNOWN = 0, /* The link state has not been read yet */
	NT_LINK_STATE_DOWN = 1, /* The link state is DOWN */
	NT_LINK_STATE_UP = 2, /* The link state is UP */
	NT_LINK_STATE_ERROR = 3 /* The link state could not be read */
};

typedef enum nt_link_state_e nt_link_state_t, *nt_link_state_p;

/*
 * Link duplex mode
 */
enum nt_link_duplex_e {
	NT_LINK_DUPLEX_UNKNOWN = 0,
	NT_LINK_DUPLEX_HALF = 0x01, /* Half duplex */
	NT_LINK_DUPLEX_FULL = 0x02, /* Full duplex */
};

typedef enum nt_link_duplex_e nt_link_duplex_t;

/*
 * Link loopback mode
 */
enum nt_link_loopback_e {
	NT_LINK_LOOPBACK_OFF = 0,
	NT_LINK_LOOPBACK_HOST = 0x01, /* Host loopback mode */
	NT_LINK_LOOPBACK_LINE = 0x02, /* Line loopback mode */
};

/*
 * Link MDI mode
 */
enum nt_link_mdi_e {
	NT_LINK_MDI_NA = 0,
	NT_LINK_MDI_AUTO = 0x01, /* MDI auto */
	NT_LINK_MDI_MDI = 0x02, /* MDI mode */
	NT_LINK_MDI_MDIX = 0x04, /* MDIX mode */
};

typedef enum nt_link_mdi_e nt_link_mdi_t;

/*
 * Link Auto/Manual mode
 */
enum nt_link_auto_neg_e {
	NT_LINK_AUTONEG_NA = 0,
	NT_LINK_AUTONEG_MANUAL = 0x01,
	NT_LINK_AUTONEG_OFF = NT_LINK_AUTONEG_MANUAL, /* Auto negotiation OFF */
	NT_LINK_AUTONEG_AUTO = 0x02,
	NT_LINK_AUTONEG_ON = NT_LINK_AUTONEG_AUTO, /* Auto negotiation ON */
};

typedef enum nt_link_auto_neg_e nt_link_auto_neg_t;

/*
 * Callback functions to setup mac, pcs and phy
 */
typedef struct link_state_s {
	bool link_disabled;
	bool nim_present;
	bool lh_nim_absent;
	bool link_up;
	enum nt_link_state_e link_state;
	enum nt_link_state_e link_state_latched;
} link_state_t;

typedef struct link_info_s {
	enum nt_link_speed_e link_speed;
	enum nt_link_duplex_e link_duplex;
	enum nt_link_auto_neg_e link_auto_neg;
} link_info_t;

typedef struct port_action_s {
	bool port_disable;
	enum nt_link_speed_e port_speed;
	enum nt_link_duplex_e port_duplex;
	uint32_t port_lpbk_mode;
} port_action_t;

typedef struct adapter_100g_s {
	nim_i2c_ctx_t
	nim_ctx[NUM_ADAPTER_PORTS_MAX]; /* Should be the first field */
	nthw_mac_pcs_t mac_pcs100g[NUM_ADAPTER_PORTS_MAX];
	nthw_gpio_phy_t gpio_phy[NUM_ADAPTER_PORTS_MAX];
} adapter_100g_t;

typedef union adapter_var_s {
	nim_i2c_ctx_t nim_ctx
	[NUM_ADAPTER_PORTS_MAX]; /* First field in all the adaptors type */
	adapter_100g_t var100g;
} adapter_var_u;

typedef struct nt4ga_link_s {
	link_state_t link_state[NUM_ADAPTER_PORTS_MAX];
	link_info_t link_info[NUM_ADAPTER_PORTS_MAX];
	port_action_t port_action[NUM_ADAPTER_PORTS_MAX];
	uint32_t speed_capa;
	/* */
	bool variables_initialized;
	adapter_var_u u;
} nt4ga_link_t;

bool nt4ga_port_get_nim_present(struct adapter_info_s *p, int port);

/*
 * port:s link mode
 */
void nt4ga_port_set_adm_state(struct adapter_info_s *p, int port,
			      bool adm_state);
bool nt4ga_port_get_adm_state(struct adapter_info_s *p, int port);

/*
 * port:s link status
 */
void nt4ga_port_set_link_status(struct adapter_info_s *p, int port, bool status);
bool nt4ga_port_get_link_status(struct adapter_info_s *p, int port);

/*
 * port: link autoneg
 */
void nt4ga_port_set_link_autoneg(struct adapter_info_s *p, int port,
				 bool autoneg);
bool nt4ga_port_get_link_autoneg(struct adapter_info_s *p, int port);

/*
 * port: link speed
 */
void nt4ga_port_set_link_speed(struct adapter_info_s *p, int port,
			       nt_link_speed_t speed);
nt_link_speed_t nt4ga_port_get_link_speed(struct adapter_info_s *p, int port);

/*
 * port: link duplex
 */
void nt4ga_port_set_link_duplex(struct adapter_info_s *p, int port,
				nt_link_duplex_t duplex);
nt_link_duplex_t nt4ga_port_get_link_duplex(struct adapter_info_s *p, int port);

/*
 * port: loopback mode
 */
void nt4ga_port_set_loopback_mode(struct adapter_info_s *p, int port,
				  uint32_t mode);
uint32_t nt4ga_port_get_loopback_mode(struct adapter_info_s *p, int port);

uint32_t nt4ga_port_get_link_speed_capabilities(struct adapter_info_s *p,
		int port);

/*
 * port: nim capabilities
 */
nim_i2c_ctx_t nt4ga_port_get_nim_capabilities(struct adapter_info_s *p,
		int port);

/*
 * port: tx power
 */
int nt4ga_port_tx_power(struct adapter_info_s *p, int port, bool disable);

#endif /* NT4GA_LINK_H_ */
