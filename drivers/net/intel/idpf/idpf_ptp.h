/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Intel Corporation
 */

#ifndef _IDPF_PTP_H_
#define _IDPF_PTP_H_

#include "idpf_osdep.h"
#include <rte_time.h>
#include "idpf_common_device.h"

/**
 * @struct idpf_ptp_cmd - PTP command masks
 * @exec_cmd_mask: mask to trigger command execution
 * @shtime_enable_mask: mask to enable shadow time
 */
struct idpf_ptp_cmd {
	uint32_t exec_cmd_mask;
	uint32_t shtime_enable_mask;
};

/* @struct idpf_ptp_dev_clk_regs - PTP device registers
 * @dev_clk_ns_l: low part of the device clock register
 * @dev_clk_ns_h: high part of the device clock register
 * @phy_clk_ns_l: low part of the PHY clock register
 * @phy_clk_ns_h: high part of the PHY clock register
 * @sys_time_ns_l: low part of the system time register
 * @sys_time_ns_h: high part of the system time register
 * @incval_l: low part of the increment value register
 * @incval_h: high part of the increment value register
 * @shadj_l: low part of the shadow adjust register
 * @shadj_h: high part of the shadow adjust register
 * phy_incval_l: low part of the PHY increment value register
 * phy_incval_h: high part of the PHY increment value register
 * phy_shadj_l: low part of the PHY shadow adjust register
 * phy_shadj_h: high part of the PHY shadow adjust register
 * @cmd: PTP command register
 * @phy_cmd: PHY command register
 * @cmd_sync: PTP command synchronization register
 */
struct idpf_ptp_dev_clk_regs {
	/* Main clock */
	volatile uint32_t *dev_clk_ns_l;
	volatile uint32_t *dev_clk_ns_h;

	/* PHY timer */
	volatile uint32_t *phy_clk_ns_l;
	volatile uint32_t *phy_clk_ns_h;

	/* System time */
	volatile uint32_t *sys_time_ns_l;
	volatile uint32_t *sys_time_ns_h;

	/* Main timer adjustments */
	volatile uint32_t *incval_l;
	volatile uint32_t *incval_h;
	volatile uint32_t *shadj_l;
	volatile uint32_t *shadj_h;

	/* PHY timer adjustments */
	volatile uint32_t *phy_incval_l;
	volatile uint32_t *phy_incval_h;
	volatile uint32_t *phy_shadj_l;
	volatile uint32_t *phy_shadj_h;

	/* Command */
	volatile uint32_t *cmd;
	volatile uint32_t *phy_cmd;
	volatile uint32_t *cmd_sync;
};

/**
 * @enum idpf_ptp_access - the type of access to PTP operations
 * @IDPF_PTP_NONE: no access
 * @IDPF_PTP_DIRECT: direct access through BAR registers
 * @IDPF_PTP_MAILBOX: access through mailbox messages
 */
enum idpf_ptp_access {
	IDPF_PTP_NONE = 0,
	IDPF_PTP_DIRECT,
	IDPF_PTP_MAILBOX,
};

/**
 * @struct idpf_ptp_secondary_mbx - PTP secondary mailbox
 * @peer_mbx_q_id: PTP mailbox queue ID
 * @peer_id: Peer ID for PTP Device Control daemon
 * @valid: indicates whether secondary mailblox is supported by the Control
 *	   Plane
 */
struct idpf_ptp_secondary_mbx {
	uint16_t peer_mbx_q_id;
	uint16_t peer_id;
	bool valid:1;
};

/**
 * @enum idpf_ptp_tx_tstamp_state - Tx timestamp states
 * @IDPF_PTP_FREE: Tx timestamp index free to use
 * @IDPF_PTP_REQUEST: Tx timestamp index set to the Tx descriptor
 * @IDPF_PTP_READ_VALUE: Tx timestamp value ready to be read
 */
enum idpf_ptp_tx_tstamp_state {
	IDPF_PTP_FREE,
	IDPF_PTP_REQUEST,
	IDPF_PTP_READ_VALUE,
};

/**
 * @struct idpf_ptp_tx_tstamp - Parameters for Tx timestamping
 * @list_member: the list member structure
 * @tx_latch_reg_offset_l: Tx tstamp latch low register offset
 * @tx_latch_reg_offset_h: Tx tstamp latch high register offset
 * @tstamp: the Tx tstamp value
 * @idx: the index of the Tx tstamp
 */
struct idpf_ptp_tx_tstamp {
	uint64_t tstamp;
	uint32_t tx_latch_reg_offset_l;
	uint32_t tx_latch_reg_offset_h;
	uint32_t idx;
};

/**
 * @struct idpf_ptp_vport_tx_tstamp_caps - Tx timestamp capabilities
 * @vport_id: the vport id
 * @num_entries: the number of negotiated Tx timestamp entries
 * @tstamp_ns_lo_bit: first bit for nanosecond part of the timestamp
 * @access: indicates an access to Tx timestamp
 * @latches_index: the index  of the latched Tx timestamps
 * @tx_tstamp: array of Tx timestamp parameters
 */
struct idpf_ptp_vport_tx_tstamp_caps {
	uint32_t vport_id;
	uint16_t num_entries;
	uint16_t tstamp_ns_lo_bit;
	uint16_t latched_idx;
	bool access:1;
	struct idpf_ptp_tx_tstamp tx_tstamp[];
};

/**
 * @struct idpf_ptp - PTP parameters
 * @base_incval: base increment value of the PTP clock
 * @max_adj: maximum adjustment of the PTP clock
 * @cmd: HW specific command masks
 * @dev_clk_regs: the set of registers to access the device clock
 * @caps: PTP capabilities negotiated with the Control Plane
 * @get_dev_clk_time_access: access type for getting the device clock time
 * @get_cross_tstamp_access: access type for the cross timestamping
 * @set_dev_clk_time_access: access type for setting the device clock time
 * @adj_dev_clk_time_access: access type for the adjusting the device clock
 * @tx_tstamp_access: access type for the Tx timestamp value read
 * @rsv: Reserved fields
 * @secondary_mbx: parameters for using dedicated PTP mailbox
 */
struct idpf_ptp {
	uint64_t base_incval;
	uint64_t max_adj;
	struct idpf_ptp_cmd cmd;
	struct idpf_ptp_dev_clk_regs dev_clk_regs;
	uint32_t caps;
	uint8_t get_dev_clk_time_access:2;
	uint8_t get_cross_tstamp_access:2;
	uint8_t set_dev_clk_time_access:2;
	uint8_t adj_dev_clk_time_access:2;
	uint8_t tx_tstamp_access:2;
	uint8_t rsv:6;
	struct idpf_ptp_secondary_mbx secondary_mbx;
};

/**
 * @struct idpf_ptp_dev_timers - System time and device time values
 * @sys_time_ns: system time value expressed in nanoseconds
 * @dev_clk_time_ns: device clock time value expressed in nanoseconds
 */
struct idpf_ptp_dev_timers {
	uint64_t sys_time_ns;
	uint64_t dev_clk_time_ns;
};

int idpf_ptp_get_caps(struct idpf_adapter *adapter);
int idpf_ptp_read_src_clk_reg(struct idpf_adapter *adapter, uint64_t *src_clk);
int idpf_ptp_get_dev_clk_time(struct idpf_adapter *adapter,
			      struct idpf_ptp_dev_timers *dev_clk_time);
int idpf_ptp_get_cross_time(struct idpf_adapter *adapter,
			    struct idpf_ptp_dev_timers *cross_time);
int idpf_ptp_set_dev_clk_time(struct idpf_adapter *adapter, uint64_t time);
int idpf_ptp_adj_dev_clk_fine(struct idpf_adapter *adapter, uint64_t incval);
int idpf_ptp_adj_dev_clk_time(struct idpf_adapter *adapter, int64_t delta);
int idpf_ptp_get_vport_tstamps_caps(struct idpf_vport *vport);
int idpf_ptp_get_tx_tstamp(struct idpf_vport *vport);

/* Helper function to convert a 32b nanoseconds timestamp to 64b. */
static inline uint64_t
idpf_tstamp_convert_32b_64b(struct idpf_adapter *ad, uint32_t flag,
			    bool is_rx, uint32_t in_timestamp)
{
	const uint64_t mask = 0xFFFFFFFF;
	uint32_t phc_time_lo, delta;
	uint64_t ns;

	if (flag != 0)
		idpf_ptp_read_src_clk_reg(ad, &ad->time_hw);

    /* Extract the lower 32 bits of the PHC time */
	phc_time_lo = (uint32_t)(ad->time_hw);

	/* Calculate the delta between the lower 32bits of the cached PHC
	 * time and the in_timestamp value.
	 */
	delta = in_timestamp - phc_time_lo;

	if (delta > mask / 2) {
		/* Reverse the delta calculation here */
		delta = phc_time_lo - in_timestamp;
		ns = ad->time_hw - delta;
	} else {
		if (is_rx)
			ns = ad->time_hw - delta;
		else
			ns = ad->time_hw + delta;
	}

	return ns;
}
#endif /* _IDPF_PTP_H_ */
