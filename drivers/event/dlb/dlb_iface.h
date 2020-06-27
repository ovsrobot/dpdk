/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB_IFACE_H
#define _DLB_IFACE_H

/* DLB PMD Internal interface function pointers.
 * If VDEV (bifurcated PMD),  these will resolve to functions that issue ioctls
 * serviced by DLB kernel module.
 * If PCI (PF PMD),  these will be implemented locally in user mode.
 */

extern void (*dlb_iface_low_level_io_init)(struct dlb_eventdev *dlb);

extern int (*dlb_iface_open)(struct dlb_hw_dev *handle, const char *name);

extern void (*dlb_iface_domain_close)(struct dlb_eventdev *dlb);

extern int (*dlb_iface_get_driver_version)(struct dlb_hw_dev *handle,
				    struct dlb_cmd_response *response);

extern int (*dlb_iface_get_device_version)(struct dlb_hw_dev *handle,
					   uint8_t *revision);

extern int (*dlb_iface_get_num_resources)(struct dlb_hw_dev *handle,
				   struct dlb_get_num_resources_args *rsrcs);

extern int (*dlb_iface_sched_domain_create)(struct dlb_hw_dev *handle,
				     struct dlb_create_sched_domain_args *args);

extern int (*dlb_iface_ldb_credit_pool_create)(struct dlb_hw_dev *handle,
					struct dlb_create_ldb_pool_args *cfg);

extern int (*dlb_iface_dir_credit_pool_create)(struct dlb_hw_dev *handle,
					struct dlb_create_dir_pool_args *cfg);

extern int (*dlb_iface_ldb_queue_create)(struct dlb_hw_dev *handle,
				  struct dlb_create_ldb_queue_args *cfg);

extern int (*dlb_iface_dir_queue_create)(struct dlb_hw_dev *handle,
				  struct dlb_create_dir_queue_args *cfg);

extern int (*dlb_iface_ldb_port_create)(struct dlb_hw_dev *handle,
					struct dlb_create_ldb_port_args *cfg,
					enum dlb_cq_poll_modes poll_mode);

extern int (*dlb_iface_dir_port_create)(struct dlb_hw_dev *handle,
					struct dlb_create_dir_port_args *cfg,
					enum dlb_cq_poll_modes poll_mode);

extern int (*dlb_iface_map_qid)(struct dlb_hw_dev *handle,
			 struct dlb_map_qid_args *cfg);

extern int (*dlb_iface_unmap_qid)(struct dlb_hw_dev *handle,
			   struct dlb_unmap_qid_args *cfg);

extern int (*dlb_iface_sched_domain_start)(struct dlb_hw_dev *handle,
				    struct dlb_start_domain_args *cfg);

extern int (*dlb_iface_block_on_cq_interrupt)(struct dlb_hw_dev *handle,
				       int port_id, bool is_ldb,
				       volatile void *cq_va, uint8_t cq_gen,
				       bool arm);

extern int (*dlb_iface_pending_port_unmaps)(struct dlb_hw_dev *handle,
				struct dlb_pending_port_unmaps_args *args);

extern int (*dlb_iface_get_ldb_queue_depth)(struct dlb_hw_dev *handle,
				    struct dlb_get_ldb_queue_depth_args *args);

extern int (*dlb_iface_get_dir_queue_depth)(struct dlb_hw_dev *handle,
				    struct dlb_get_dir_queue_depth_args *args);

extern int (*dlb_iface_enqueue_domain_alert)(struct dlb_hw_dev *handle,
				      uint64_t alert_data);

extern int (*dlb_iface_get_cq_poll_mode)(struct dlb_hw_dev *handle,
					 enum dlb_cq_poll_modes *mode);

extern int (*dlb_iface_get_sn_allocation)(struct dlb_hw_dev *handle,
				  struct dlb_get_sn_allocation_args *args);

extern int (*dlb_iface_set_sn_allocation)(struct dlb_hw_dev *handle,
				  struct dlb_set_sn_allocation_args *args);

extern int (*dlb_iface_get_sn_occupancy)(struct dlb_hw_dev *handle,
				  struct dlb_get_sn_occupancy_args *args);

extern void (*dlb_iface_port_mmap)(struct dlb_port *qm_port);

#endif /* _DLB_IFACE_H */
