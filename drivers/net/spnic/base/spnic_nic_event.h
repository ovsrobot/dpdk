/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_NIC_EVENT_H_
#define _SPNIC_NIC_EVENT_H_

struct spnic_cmd_link_state {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 state;
	u16 rsvd1;
};

void spnic_pf_event_handler(void *hwdev, __rte_unused void *pri_handle,
			    u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size);

int spnic_vf_event_handler(void *hwdev, __rte_unused void *pri_handle,
			   u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size);

void spnic_pf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
				void *buf_in, u16 in_size, void *buf_out,
				u16 *out_size);

int spnic_vf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
			       void *buf_in, u16 in_size, void *buf_out,
			       u16 *out_size);

u8 spnic_nic_sw_aeqe_handler(__rte_unused void *hwdev, u8 event, u8 *data);

#endif /* _SPNIC_NIC_EVENT_H_ */
