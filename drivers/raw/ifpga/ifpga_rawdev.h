/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

#ifndef _IFPGA_RAWDEV_H_
#define _IFPGA_RAWDEV_H_

extern int ifpga_rawdev_logtype;

#define IFPGA_RAWDEV_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ifpga_rawdev_logtype, "%s(): " fmt "\n", \
				__func__, ##args)

#define IFPGA_RAWDEV_PMD_FUNC_TRACE() IFPGA_RAWDEV_PMD_LOG(DEBUG, ">>")

#define IFPGA_RAWDEV_PMD_DEBUG(fmt, args...) \
	IFPGA_RAWDEV_PMD_LOG(DEBUG, fmt, ## args)
#define IFPGA_RAWDEV_PMD_INFO(fmt, args...) \
	IFPGA_RAWDEV_PMD_LOG(INFO, fmt, ## args)
#define IFPGA_RAWDEV_PMD_ERR(fmt, args...) \
	IFPGA_RAWDEV_PMD_LOG(ERR, fmt, ## args)
#define IFPGA_RAWDEV_PMD_WARN(fmt, args...) \
	IFPGA_RAWDEV_PMD_LOG(WARNING, fmt, ## args)

enum ifpga_rawdev_device_state {
	IFPGA_IDLE,
	IFPGA_READY,
	IFPGA_ERROR
};

/** Set a bit in the uint64 variable */
#define IFPGA_BIT_SET(var, pos) \
	((var) |= ((uint64_t)1 << ((pos))))

/** Reset the bit in the variable */
#define IFPGA_BIT_RESET(var, pos) \
	((var) &= ~((uint64_t)1 << ((pos))))

/** Check the bit is set in the variable */
#define IFPGA_BIT_ISSET(var, pos) \
	(((var) & ((uint64_t)1 << ((pos)))) ? 1 : 0)

static inline struct opae_adapter *
ifpga_rawdev_get_priv(const struct rte_rawdev *rawdev)
{
	return (struct opae_adapter *)rawdev->dev_private;
}

#define IFPGA_RAWDEV_MSIX_IRQ_NUM 7
#define IFPGA_RAWDEV_NUM 32

struct ifpga_rawdev {
	int dev_id;
	struct rte_rawdev *rawdev;
	int aer_enable;
	int intr_fd[IFPGA_RAWDEV_MSIX_IRQ_NUM+1];
	uint32_t aer_old[2];
	char fvl_bdf[8][16];
	char parent_bdf[16];
};

struct ifpga_rawdev *
ifpga_rawdev_get(const struct rte_rawdev *rawdev);

enum ifpga_irq_type {
	IFPGA_FME_IRQ = 0,
	IFPGA_AFU_IRQ = 1,
};

typedef struct {
	uint8_t b[16];
} ifpga_uuid;

typedef struct {
	uint32_t boot_page;
	uint32_t num_ports;
	uint64_t bitstream_id;
	uint64_t bitstream_metadata;
	ifpga_uuid pr_id;
} ifpga_fme_property;

typedef struct {
	ifpga_uuid afu_id;
	uint32_t type;   /* AFU memory access control type */
} ifpga_port_property;

typedef struct {
	uint32_t bmc_version;
	uint32_t fw_version;
} ifpga_bmc_property;

typedef struct {
	uint32_t num_retimers;
	uint32_t link_speed;
	uint32_t link_status;
} ifpga_phy_info;

int
ifpga_register_msix_irq(struct rte_rawdev *dev, int port_id,
		enum ifpga_irq_type type, int vec_start, int count,
		rte_intr_callback_fn handler, const char *name,
		void *arg);
int
ifpga_unregister_msix_irq(enum ifpga_irq_type type,
		int vec_start, rte_intr_callback_fn handler, void *arg);

struct rte_pci_bus *ifpga_get_pci_bus(void);
int ifpga_rawdev_lock(struct rte_rawdev *dev);
int ifpga_rawdev_unlock(struct rte_rawdev *dev);
uint32_t ifpga_rawdev_get_rsu_stat(struct rte_rawdev *dev);
void ifpga_rawdev_set_rsu_stat(struct rte_rawdev *dev, uint32_t value);
int ifpga_rawdev_get_fme_property(struct rte_rawdev *dev,
	ifpga_fme_property *prop);
int ifpga_rawdev_get_port_property(struct rte_rawdev *dev, uint32_t port,
	ifpga_port_property *prop);
int ifpga_rawdev_get_bmc_property(struct rte_rawdev *dev,
	ifpga_bmc_property *prop);
int ifpga_rawdev_get_phy_info(struct rte_rawdev *dev, ifpga_phy_info *info);
int ifpga_rawdev_update_flash(struct rte_rawdev *dev, const char *image,
	uint64_t *status);
int ifpga_rawdev_stop_flash_update(struct rte_rawdev *dev, int force);
int ifpga_rawdev_reload(struct rte_rawdev *dev, int type, int page);
int ifpga_rawdev_partial_reconfigure(struct rte_rawdev *dev, int port,
	const char *file);
void ifpga_rawdev_cleanup(void);

#endif /* _IFPGA_RAWDEV_H_ */
