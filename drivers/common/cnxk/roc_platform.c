/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_log.h>

#include "roc_api.h"
#include "roc_priv.h"

#if defined(__linux__)

#include <inttypes.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MSIX_IRQ_SET_BUF_LEN                                                                       \
	(sizeof(struct vfio_irq_set) + sizeof(int) * (plt_intr_max_intr_get(intr_handle)))

static int
irq_get_info(struct plt_intr_handle *intr_handle)
{
	struct vfio_irq_info irq = {.argsz = sizeof(irq)};
	int rc, vfio_dev_fd;

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;

	vfio_dev_fd = plt_intr_dev_fd_get(intr_handle);
	rc = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
	if (rc < 0) {
		plt_err("Failed to get IRQ info rc=%d errno=%d", rc, errno);
		return rc;
	}

	plt_base_dbg("Flags=0x%x index=0x%x count=0x%x max_intr_vec_id=0x%x", irq.flags, irq.index,
		     irq.count, PLT_MAX_RXTX_INTR_VEC_ID);

	if (irq.count == 0) {
		plt_err("HW max=%d > PLT_MAX_RXTX_INTR_VEC_ID: %d", irq.count,
			PLT_MAX_RXTX_INTR_VEC_ID);
		plt_intr_max_intr_set(intr_handle, PLT_MAX_RXTX_INTR_VEC_ID);
	} else {
		if (plt_intr_max_intr_set(intr_handle, irq.count))
			return -1;
	}

	return 0;
}

static int
irq_config(struct plt_intr_handle *intr_handle, unsigned int vec)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int len, rc, vfio_dev_fd;
	int32_t *fd_ptr;

	if (vec > (uint32_t)plt_intr_max_intr_get(intr_handle)) {
		plt_err("vector=%d greater than max_intr=%d", vec,
			plt_intr_max_intr_get(intr_handle));
		return -EINVAL;
	}

	len = sizeof(struct vfio_irq_set) + sizeof(int32_t);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;

	irq_set->start = vec;
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	/* Use vec fd to set interrupt vectors */
	fd_ptr = (int32_t *)&irq_set->data[0];
	fd_ptr[0] = plt_intr_efds_index_get(intr_handle, vec);

	vfio_dev_fd = plt_intr_dev_fd_get(intr_handle);
	rc = ioctl(vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		plt_err("Failed to set_irqs vector=0x%x rc=%d", vec, rc);

	return rc;
}

static int
irq_init(struct plt_intr_handle *intr_handle)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int len, rc, vfio_dev_fd;
	int32_t *fd_ptr;
	uint32_t i;

	len = sizeof(struct vfio_irq_set) + sizeof(int32_t) * plt_intr_max_intr_get(intr_handle);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->start = 0;
	irq_set->count = plt_intr_max_intr_get(intr_handle);
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	fd_ptr = (int32_t *)&irq_set->data[0];
	for (i = 0; i < irq_set->count; i++)
		fd_ptr[i] = -1;

	vfio_dev_fd = plt_intr_dev_fd_get(intr_handle);
	rc = ioctl(vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		plt_err("Failed to set irqs vector rc=%d", rc);

	return rc;
}

int
plt_irq_disable(struct plt_intr_handle *intr_handle)
{
	/* Clear max_intr to indicate re-init next time */
	plt_intr_max_intr_set(intr_handle, 0);
	return plt_intr_disable(intr_handle);
}

int
plt_irq_reconfigure(struct plt_intr_handle *intr_handle, uint16_t max_intr)
{
	/* Disable interrupts if enabled. */
	if (plt_intr_max_intr_get(intr_handle))
		dev_irqs_disable(intr_handle);

	plt_intr_max_intr_set(intr_handle, max_intr);
	return irq_init(intr_handle);
}

int
plt_irq_register(struct plt_intr_handle *intr_handle, plt_intr_callback_fn cb, void *data,
		 unsigned int vec)
{
	struct plt_intr_handle *tmp_handle;
	uint32_t nb_efd, tmp_nb_efd;
	int rc, fd;

	/* If no max_intr read from VFIO */
	if (plt_intr_max_intr_get(intr_handle) == 0) {
		irq_get_info(intr_handle);
		irq_init(intr_handle);
	}

	if (vec > (uint32_t)plt_intr_max_intr_get(intr_handle)) {
		plt_err("Vector=%d greater than max_intr=%d or ", vec,
			plt_intr_max_intr_get(intr_handle));
		return -EINVAL;
	}

	tmp_handle = intr_handle;
	/* Create new eventfd for interrupt vector */
	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd == -1)
		return -ENODEV;

	if (plt_intr_fd_set(tmp_handle, fd))
		return -errno;

	/* Register vector interrupt callback */
	rc = plt_intr_callback_register(tmp_handle, cb, data);
	if (rc) {
		plt_err("Failed to register vector:0x%x irq callback.", vec);
		return rc;
	}

	rc = plt_intr_efds_index_set(intr_handle, vec, fd);
	if (rc)
		return rc;

	nb_efd = (vec > (uint32_t)plt_intr_nb_efd_get(intr_handle)) ?
			 vec :
			 (uint32_t)plt_intr_nb_efd_get(intr_handle);
	plt_intr_nb_efd_set(intr_handle, nb_efd);

	tmp_nb_efd = plt_intr_nb_efd_get(intr_handle) + 1;
	if (tmp_nb_efd > (uint32_t)plt_intr_max_intr_get(intr_handle))
		plt_intr_max_intr_set(intr_handle, tmp_nb_efd);
	plt_base_dbg("Enable vector:0x%x for vfio (efds: %d, max:%d)", vec,
		     plt_intr_nb_efd_get(intr_handle), plt_intr_max_intr_get(intr_handle));

	/* Enable MSIX vectors to VFIO */
	return irq_config(intr_handle, vec);
}

void
plt_irq_unregister(struct plt_intr_handle *intr_handle, plt_intr_callback_fn cb, void *data,
		   unsigned int vec)
{
	struct plt_intr_handle *tmp_handle;
	uint8_t retries = 5; /* 5 ms */
	int rc, fd;

	if (vec > (uint32_t)plt_intr_max_intr_get(intr_handle)) {
		plt_err("Error unregistering MSI-X interrupts vec:%d > %d", vec,
			plt_intr_max_intr_get(intr_handle));
		return;
	}

	tmp_handle = intr_handle;
	fd = plt_intr_efds_index_get(intr_handle, vec);
	if (fd == -1)
		return;

	if (plt_intr_fd_set(tmp_handle, fd))
		return;

	do {
		/* Un-register callback func from platform lib */
		rc = plt_intr_callback_unregister(tmp_handle, cb, data);
		/* Retry only if -EAGAIN */
		if (rc != -EAGAIN)
			break;
		plt_delay_ms(1);
		retries--;
	} while (retries);

	if (rc < 0) {
		plt_err("Error unregistering MSI-X vec %d cb, rc=%d", vec, rc);
		return;
	}

	plt_base_dbg("Disable vector:0x%x for vfio (efds: %d, max:%d)", vec,
		     plt_intr_nb_efd_get(intr_handle), plt_intr_max_intr_get(intr_handle));

	if (plt_intr_efds_index_get(intr_handle, vec) != -1)
		close(plt_intr_efds_index_get(intr_handle, vec));
	/* Disable MSIX vectors from VFIO */
	plt_intr_efds_index_set(intr_handle, vec, -1);

	irq_config(intr_handle, vec);
}
#endif

#define PLT_INIT_CB_MAX 8

static int plt_init_cb_num;
static roc_plt_init_cb_t plt_init_cbs[PLT_INIT_CB_MAX];

RTE_EXPORT_INTERNAL_SYMBOL(roc_plt_init_cb_register)
int
roc_plt_init_cb_register(roc_plt_init_cb_t cb)
{
	if (plt_init_cb_num >= PLT_INIT_CB_MAX)
		return -ERANGE;

	plt_init_cbs[plt_init_cb_num++] = cb;
	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(roc_plt_control_lmt_id_get)
uint16_t
roc_plt_control_lmt_id_get(void)
{
	uint32_t lcore_id = plt_lcore_id();
	if (lcore_id != LCORE_ID_ANY)
		return lcore_id << ROC_LMT_LINES_PER_CORE_LOG2;
	else
		/* Return Last LMT ID to be use in control path functionality */
		return ROC_NUM_LMT_LINES - 1;
}

RTE_EXPORT_INTERNAL_SYMBOL(roc_plt_lmt_validate)
uint16_t
roc_plt_lmt_validate(void)
{
	if (!roc_model_is_cn9k()) {
		/* Last LMT line is reserved for control specific operation and can be
		 * use from any EAL or non EAL cores.
		 */
		if ((RTE_MAX_LCORE << ROC_LMT_LINES_PER_CORE_LOG2) >
		    (ROC_NUM_LMT_LINES - 1))
			return 0;
	}
	return 1;
}

RTE_EXPORT_INTERNAL_SYMBOL(roc_plt_init)
int
roc_plt_init(void)
{
	const struct rte_memzone *mz;
	int i, rc;

	mz = rte_memzone_lookup(PLT_MODEL_MZ_NAME);
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (mz == NULL) {
			mz = rte_memzone_reserve(PLT_MODEL_MZ_NAME,
						 sizeof(struct roc_model),
						 SOCKET_ID_ANY, 0);
			if (mz == NULL) {
				plt_err("Failed to reserve mem for roc_model");
				return -ENOMEM;
			}
			if (roc_model_init(mz->addr)) {
				plt_err("Failed to init roc_model");
				rte_memzone_free(mz);
				return -EINVAL;
			}
		}
	} else {
		if (mz == NULL) {
			plt_err("Failed to lookup mem for roc_model");
			return -ENOMEM;
		}
		roc_model = mz->addr;
	}

	for (i = 0; i < plt_init_cb_num; i++) {
		rc = (*plt_init_cbs[i])();
		if (rc)
			return rc;
	}

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_base)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_base, base, INFO);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_mbox)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_mbox, mbox, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_cpt)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_cpt, crypto, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_ml)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_ml, ml, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_npa)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_npa, mempool, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_nix)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_nix, nix, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_npc)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_npc, flow, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_sso)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_sso, event, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_tim)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_tim, timer, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_tm)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_tm, tm, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_dpi)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_dpi, dpi, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_rep)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_rep, rep, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_esw)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_esw, esw, NOTICE);
RTE_EXPORT_INTERNAL_SYMBOL(cnxk_logtype_ree)
RTE_LOG_REGISTER_SUFFIX(cnxk_logtype_ree, ree, NOTICE);

/* Export all ROC symbols */
RTE_EXPORT_INTERNAL_SYMBOL(roc_ae_ec_grp_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ae_ec_grp_put)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ae_fpm_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ae_fpm_put)
RTE_EXPORT_INTERNAL_SYMBOL(roc_aes_xcbc_key_derive)
RTE_EXPORT_INTERNAL_SYMBOL(roc_aes_hash_key_derive)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_npa_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_sso_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_start_rxtx)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_stop_rxtx)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_set_link_state)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_get_linkinfo)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_set_link_mode)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_intlbk_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_intlbk_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_ptp_rx_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_ptp_rx_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_fec_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_fec_supported_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_cpri_mode_change)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_cpri_mode_tx_control)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_cgx_cpri_mode_misc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_handler)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_available)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_max_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_clear)
RTE_EXPORT_INTERNAL_SYMBOL(roc_bphy_intr_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_inline_ipsec_cfg)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_inline_ipsec_inb_cfg_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_inline_ipsec_inb_cfg)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_rxc_time_cfg)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_dev_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lf_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lf_ctx_flush)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lf_ctx_reload)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lf_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lf_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_dev_clear)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_eng_grp_add)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_iq_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_iq_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lmtline_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_ctx_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_int_misc_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_int_misc_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_parse_hdr_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_afs_print)
RTE_EXPORT_INTERNAL_SYMBOL(roc_cpt_lfs_print)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_wait_queue_idle)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_configure_v2)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_dpi_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_npc_mcam_tx_rule)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_npc_mcam_delete_rule)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_npc_mcam_rx_rule)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_npc_rss_action_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_nix_vlan_tpid_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_nix_process_repte_notify_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_nix_process_repte_notify_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_nix_repte_stats)
RTE_EXPORT_INTERNAL_SYMBOL(roc_eswitch_is_repte_pfs_vf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_hash_md5_gen)
RTE_EXPORT_INTERNAL_SYMBOL(roc_hash_sha1_gen)
RTE_EXPORT_INTERNAL_SYMBOL(roc_hash_sha256_gen)
RTE_EXPORT_INTERNAL_SYMBOL(roc_hash_sha512_gen)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_npa_maxpools_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_npa_maxpools_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_lmt_base_addr_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_num_lmtlines_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_cpt_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_rvu_lf_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_rvu_lf_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_rvu_lf_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_mcs_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_mcs_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_mcs_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_ring_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_list_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_cpt_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_npa_nix_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_inl_meta_aura_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_rx_inject_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_rx_inject_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_rx_chan_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_rx_chan_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_idev_nix_inl_dev_pffunc_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ot_ipsec_inb_sa_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ot_ipsec_outb_sa_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ow_ipsec_inb_sa_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ow_reass_inb_sa_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ow_ipsec_outb_sa_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_is_supported)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_hw_info_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_active_lmac_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_lmac_mode_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_pn_threshold_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_ctrl_pkt_rule_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_ctrl_pkt_rule_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_ctrl_pkt_rule_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_port_cfg_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_port_cfg_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_custom_tag_cfg_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_intr_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_port_recovery)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_port_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_event_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_event_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rsrc_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rsrc_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_sa_policy_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_sa_policy_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_pn_table_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_pn_table_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rx_sc_cam_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rx_sc_cam_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rx_sc_cam_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_secy_policy_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_secy_policy_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rx_sc_sa_map_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_rx_sc_sa_map_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_tx_sc_sa_map_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_tx_sc_sa_map_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_flowid_entry_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_flowid_entry_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_flowid_entry_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_sa_port_map_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_flowid_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_secy_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_sc_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_port_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_mcs_stats_clear)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_reg_read64)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_reg_write64)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_reg_read32)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_reg_write32)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_reg_save)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_addr_ap2mlip)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_addr_mlip2ap)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_addr_pa_to_offset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_addr_offset_to_pa)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_write_job)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_is_valid_bit_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_is_done_bit_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_enqueue)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_dequeue)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_scratch_queue_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_jcmdq_enqueue_lf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_jcmdq_enqueue_sl)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_clk_force_on)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_clk_force_off)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_dma_stall_on)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_dma_stall_off)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_mlip_is_enabled)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_mlip_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_blk_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_blk_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ml_sso_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_model)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_is_lbk)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_is_esw)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_base_chan)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_rx_chan_cnt)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_vwqe_interval)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_is_sdp)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_is_pf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_pf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_vf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_is_vf_or_sdp)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_get_pf_func)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lf_inl_ipsec_cfg)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cpt_ctx_cache_sync)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_max_pkt_len)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lf_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lf_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_max_rep_count)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_level_to_idx)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_stats_to_idx)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_timeunit_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_count_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_free_all)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_pre_color_tbl_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_connect)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_stats_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_stats_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_lf_stats_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpf_lf_stats_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lf_get_reg_count)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lf_reg_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_queues_ctx_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cqe_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cq_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_cpt_lfs_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_desc_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_fc_config_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_fc_config_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_fc_mode_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_fc_mode_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_fc_npa_bp_cfg)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_pfc_mode_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_pfc_mode_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_chan_count_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpids_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_bpids_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rx_chan_cfg_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rx_chan_cfg_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_chan_bpid_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_meta_aura_check)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_lf_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_inj_lf_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_sa_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_sa_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_rx_inject_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_spi_range)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_sa_sz)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_sa_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_reassembly_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_is_probed)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_is_multi_channel)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_is_enabled)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_is_enabled)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_rq_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_rq_put)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_rq_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inb_mode_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_soft_exp_poll_switch)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inb_is_with_inl_dev)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_rq)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_outb_sso_pffunc_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_inb_tag_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_sa_sync)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_ctx_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_cpt_lf_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_ts_pkind_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_lock)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_unlock)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_meta_pool_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_eng_caps_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_custom_meta_pool_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_xaq_realloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_qptr_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_stats_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_cpt_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_inl_dev_cpt_release)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rx_queue_intr_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rx_queue_intr_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_err_intr_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ras_intr_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_register_queue_irqs)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_unregister_queue_irqs)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_register_cq_irqs)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_unregister_cq_irqs)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_rxtx_start_stop)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_event_start_stop)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_loopback_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_addr_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_max_entries_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_addr_add)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_addr_del)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_promisc_mode_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_info_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_state_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_info_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_mtu_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_max_rx_len_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_stats_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_info_get_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mac_link_info_get_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_mcam_entry_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_mcam_entry_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_mcam_entry_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_mcam_entry_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_list_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_mcast_list_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_npc_promisc_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_npc_mac_addr_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_npc_mac_addr_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_npc_rx_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_npc_mcast_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lso_custom_fmt_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lso_fmt_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_lso_fmt_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_switch_hdr_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_eeprom_info_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rx_drop_re_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_rx_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_tx_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_clock_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_sync_time_adjust)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_info_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_info_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_ptp_is_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_is_sso_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_modify)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_cman_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rq_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cq_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cq_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_cq_head_tail_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_sq_head_tail_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_q_err_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_q_err_cb_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_key_default_fill)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_key_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_key_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_reta_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_reta_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_flowkey_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_rss_default_setup)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_num_xstats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_stats_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_stats_queue_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_stats_queue_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_xstats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_xstats_names_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_sq_flush_spin)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_prepare_rate_limited_tree)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_pfc_prepare_tree)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_mark_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_mark_format_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_sq_aura_fc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_free_resources)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_profile_add)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_profile_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_profile_delete)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_add)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_pkt_mode_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_name_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_delete)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_smq_flush)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_hierarchy_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_hierarchy_xmit_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_hierarchy_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_suspend_resume)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_prealloc_res)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_shaper_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_parent_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_pfc_rlimit_sq)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_rlimit_sq)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_rsrc_count)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_rsrc_max)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_root_has_sp)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_egress_link_cfg_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_leaf_cnt)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_lvl)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_next)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_profile_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_profile_next)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_node_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_is_user_hierarchy_enabled)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_tree_type_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_max_prio)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_lvl_is_leaf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_shaper_default_red_algo)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_lvl_cnt_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_tm_lvl_have_link_access)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_mcam_entry_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_mcam_entry_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_mcam_entry_alloc_and_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_mcam_entry_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_mcam_entry_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_strip_vtag_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_insert_ena_dis)
RTE_EXPORT_INTERNAL_SYMBOL(roc_nix_vlan_tpid_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_lf_init_cb_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pool_op_range_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_op_range_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_op_range_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pool_op_pc_reset)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_drop_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pool_create)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_create)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_limit_modify)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pool_destroy)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_destroy)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_pool_range_update_check)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_zero_aura_handle)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_aura_bp_configure)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_dev_lock)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_dev_unlock)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_ctx_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_buf_type_update)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_buf_type_mask)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npa_buf_type_limit_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mark_actions_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mark_actions_sub_return)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_vtag_actions_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_vtag_actions_sub_return)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_free_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_inl_mcam_read_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_inl_mcam_clear_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_alloc_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_get_free_mcam_entry)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_read_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_get_stats)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_clear_counter)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_free_entry)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_move)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_free_all_resources)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_alloc_entries)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_enable_all_entries)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_alloc_entry)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_ena_dis_entry)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_write_entry)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_get_low_priority_mcam)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_profile_name_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_kex_capa_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_validate_portid_action)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_flow_parse)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_sdp_channel_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_flow_create)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_flow_destroy)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_flow_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_mcam_merge_base_steering_rule)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_aged_flow_ctx_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_npc_flow_mcam_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_queues_attach)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_queues_detach)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_msix_offsets_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_config_lf)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_af_reg_read)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_af_reg_write)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_rule_db_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_rule_db_len_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_rule_db_prog)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_qp_get_base)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_err_intr_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_err_intr_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_iq_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_iq_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_ree_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_msg_id_range_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_msg_id_range_check)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_msg_process)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_irq_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_irq_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_msg_handler_register)
RTE_EXPORT_INTERNAL_SYMBOL(roc_rvu_lf_msg_handler_unregister)
RTE_EXPORT_INTERNAL_SYMBOL(roc_se_hmac_opad_ipad_gen)
RTE_EXPORT_INTERNAL_SYMBOL(roc_se_auth_key_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_se_ciph_key_set)
RTE_EXPORT_INTERNAL_SYMBOL(roc_se_ctx_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hws_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_pf_func_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_ns_to_gw)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hws_link)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hws_unlink)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hws_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hws_gwc_invalidate)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_agq_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_agq_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_agq_release)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_agq_from_tag)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_stats_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_hws_link_status)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_qos_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_init_xaq_aura)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_free_xaq_aura)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_alloc_xaq)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_release_xaq)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_set_priority)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_hwgrp_stash_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_rsrc_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_rsrc_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_dev_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_dev_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_sso_dump)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_enable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_disable)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_base_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_config)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_config_hwwqe)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_interval)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_alloc)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_lf_free)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_init)
RTE_EXPORT_INTERNAL_SYMBOL(roc_tim_fini)
RTE_EXPORT_INTERNAL_SYMBOL(roc_error_msg_get)
RTE_EXPORT_INTERNAL_SYMBOL(roc_clk_freq_get)
