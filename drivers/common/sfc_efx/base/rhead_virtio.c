/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Xilinx, Inc.
 */

#include "efx.h"
#include "efx_impl.h"

#if EFSYS_OPT_RIVERHEAD && EFSYS_OPT_VIRTIO

/*
 * Get function-local index of the associated VI from the
 * virtqueue number queue 0 is reserved for MCDI
 */
#define EFX_VIRTIO_GET_VI_INDEX(vq_num) (((vq_num) / 2) + 1)

	__checkReturn   efx_rc_t
rhead_virtio_qstart(
	__in		efx_virtio_vq_t *evvp,
	__in		efx_virtio_vq_cfg_t *evvcp,
	__in_opt	efx_virtio_vq_dyncfg_t *evvdp)

{
	efx_nic_t *enp = evvp->evv_enp;
	efx_mcdi_req_t req;
	uint32_t vi_index;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN,
		MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN);
	efx_rc_t rc;

	EFX_STATIC_ASSERT(EFX_VIRTIO_VQ_TYPE_NET_RXQ ==
		MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_RXQ);
	EFX_STATIC_ASSERT(EFX_VIRTIO_VQ_TYPE_NET_TXQ ==
		MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_TXQ);
	EFX_STATIC_ASSERT(EFX_VIRTIO_VQ_TYPE_BLOCK ==
		MC_CMD_VIRTIO_INIT_QUEUE_REQ_BLOCK);

	if (evvcp->evvc_type >= EFX_VIRTIO_VQ_NTYPES) {
		rc = EINVAL;
		goto fail1;
	}

	/* virtqueue size must be power of 2 */
	if ((!ISP2(evvcp->evvc_vq_size)) ||
	    (evvcp->evvc_vq_size > EFX_VIRTIO_MAX_VQ_SIZE)) {
		rc = EINVAL;
		goto fail2;
	}

	if (evvdp != NULL) {
		if ((evvdp->evvd_vq_cidx > evvcp->evvc_vq_size) ||
		    (evvdp->evvd_vq_pidx > evvcp->evvc_vq_size)) {
			rc = EINVAL;
			goto fail3;
		}
	}

	req.emr_cmd = MC_CMD_VIRTIO_INIT_QUEUE;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN;

	MCDI_IN_SET_BYTE(req, VIRTIO_INIT_QUEUE_REQ_QUEUE_TYPE,
		evvcp->evvc_type);
	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF,
		evvcp->evvc_target_vf);

	vi_index = EFX_VIRTIO_GET_VI_INDEX(evvcp->evvc_vq_num);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE, vi_index);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_SIZE,
		evvcp->evvc_vq_size);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_LO,
		evvcp->evvc_desc_tbl_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_HI,
		evvcp->evvc_desc_tbl_addr >> 32);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_LO,
		evvcp->evvc_avail_ring_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_HI,
		evvcp->evvc_avail_ring_addr >> 32);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_LO,
		evvcp->evvc_used_ring_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_HI,
		evvcp->evvc_used_ring_addr >> 32);

	if (evvcp->evvc_use_pasid) {
		MCDI_IN_POPULATE_DWORD_1(req, VIRTIO_INIT_QUEUE_REQ_FLAGS,
			VIRTIO_INIT_QUEUE_REQ_USE_PASID, 1);
		MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_PASID,
			evvcp->evvc_pas_id);
	}

	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_MSIX_VECTOR,
		evvcp->evvc_msix_vector);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_LO,
		evvcp->evcc_features & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_HI,
		evvcp->evcc_features >> 32);

	if (evvdp != NULL) {
		MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_PIDX,
			evvdp->evvd_vq_pidx);
		MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_CIDX,
			evvdp->evvd_vq_cidx);
	}

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_MPORT_SELECTOR,
		MAE_MPORT_SELECTOR_ASSIGNED);

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail4;
	}

	evvp->evv_vi_index = vi_index;

	return (0);

fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn   efx_rc_t
rhead_virtio_qstop(
	__in		efx_virtio_vq_t *evvp,
	__out_opt	efx_virtio_vq_dyncfg_t *evvdp)
{
	efx_mcdi_req_t req;
	efx_nic_t *enp = evvp->evv_enp;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_FINI_QUEUE_REQ_LEN,
		MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_VIRTIO_FINI_QUEUE;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_FINI_QUEUE_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN;

	MCDI_IN_SET_BYTE(req, VIRTIO_FINI_QUEUE_REQ_QUEUE_TYPE, evvp->evv_type);
	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF,
		evvp->evv_target_vf);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE,
		evvp->evv_vi_index);

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (req.emr_out_length_used < MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN) {
		rc = EMSGSIZE;
		goto fail2;
	}

	if (evvdp != NULL) {
		evvdp->evvd_vq_pidx =
		    MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_PIDX);
		evvdp->evvd_vq_cidx =
		    MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_CIDX);
	}

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_RIVERHEAD && EFSYS_OPT_VIRTIO */
