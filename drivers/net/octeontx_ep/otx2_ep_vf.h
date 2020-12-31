/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */
#ifndef _OTX2_EP_VF_H_
#define _OTX2_EP_VF_H_

int
otx2_ep_vf_setup_device(struct otx_ep_device *sdpvf);

struct otx2_ep_instr_64B {
	/* Pointer where the input data is available. */
	uint64_t dptr;

	/* OTX_EP Instruction Header. */
	union otx_ep_instr_ih ih;

	/** Pointer where the response for a RAW mode packet
	 * will be written by OCTEON TX.
	 */
	uint64_t rptr;

	/* Input Request Header. */
	union otx_ep_instr_irh irh;

	/* Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[4];
};

union out_int_lvl_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timet:22;
		uint64_t max_len:7;
		uint64_t max_len_en:1;
		uint64_t time_cnt_en:1;
		uint64_t bmode:1;
	} s;
};

union out_cnts_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timer:22;
		uint64_t rsvd:5;
		uint64_t resend:1;
		uint64_t mbox_int:1;
		uint64_t in_int:1;
		uint64_t out_int:1;
		uint64_t send_ism:1;
	} s;
};

#endif /*_OTX2_EP_VF_H_ */

