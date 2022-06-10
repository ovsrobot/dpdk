/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _IFPGA_FME_RSU_H_
#define _IFPGA_FME_RSU_H_


#include "ifpga_hw.h"

#define IFPGA_N3000_VID     0x8086
#define IFPGA_N3000_DID     0x0b30

#define IFPGA_BOOT_TYPE_FPGA     0
#define IFPGA_BOOT_TYPE_BMC      1

#define IFPGA_BOOT_PAGE_FACTORY  0
#define IFPGA_BOOT_PAGE_USER     1

#define IFPGA_RSU_DATA_BLK_SIZE  32768
#define IFPGA_RSU_START_RETRY    120
#define IFPGA_RSU_WRITE_RETRY    10
#define IFPGA_RSU_CANCEL_RETRY   30

#define IFPGA_N3000_COPY_SPEED   42700

/* status */
#define IFPGA_RSU_IDLE         0
#define IFPGA_RSU_PREPARING    1
#define IFPGA_RSU_WRITING      2
#define IFPGA_RSU_PROGRAMMING  3
#define IFPGA_RSU_REBOOT       4

#define IFPGA_RSU_GET_STAT(v)  (((v) >> 16) & 0xff)
#define IFPGA_RSU_GET_PROG(v)  ((v) & 0xff)
#define IFPGA_RSU_STATUS(s, p) ((((s) << 16) & 0xff0000) | ((p) & 0xff))

/* control */
#define IFPGA_RSU_CANCEL         1

#define IFPGA_HW_ERRINFO_POISON  0xffffffff

#define IFPGA_DUAL_CFG_CTRL0     0x200020
#define IFPGA_DUAL_CFG_CTRL1     0x200024

#define IFPGA_NIOS_HANDSHAKE_INTERVAL_US  (100 * 1000)
#define IFPGA_NIOS_HANDSHAKE_TIMEOUT_US   (5000 * 1000)
/* Wait about 2 minutes to erase flash staging area */
#define IFPGA_RSU_PREP_INTERVAL_US        (100 * 1000)
#define IFPGA_RSU_PREP_TIMEOUT_US         (120000 * 1000)

enum ifpga_sec_err {
	IFPGA_SEC_ERR_NONE = 0,
	IFPGA_SEC_ERR_HW_ERROR,
	IFPGA_SEC_ERR_TIMEOUT,
	IFPGA_SEC_ERR_CANCELED,
	IFPGA_SEC_ERR_BUSY,
	IFPGA_SEC_ERR_INVALID_SIZE,
	IFPGA_SEC_ERR_RW_ERROR,
	IFPGA_SEC_ERR_WEAROUT,
	IFPGA_SEC_ERR_FILE_READ,
	IFPGA_SEC_ERR_NO_MEM,
	IFPGA_SEC_ERR_NO_FUNC,
	IFPGA_SEC_ERR_MAX
};

/* Supported fpga secure manager types */
enum fpga_sec_type {
	N3000BMC_SEC,
	N6000BMC_SEC
};

/* Supported names for power-on images */
enum fpga_image {
	FPGA_FACTORY,
	FPGA_USER1,
	FPGA_USER2,
	FPGA_MAX
};

struct ifpga_sec_mgr;

struct image_load {
	const char *name;
	int (*load_image)(struct ifpga_sec_mgr *smgr);
};

struct fpga_power_on {
	u32 avail_image_mask;
	int (*get_sequence)(struct ifpga_sec_mgr *smgr, char *buf,
			size_t size);
	int (*set_sequence)(struct ifpga_sec_mgr *smgr,
			enum fpga_image images[]);
};

struct ifpga_sec_mgr_ops {
	enum ifpga_sec_err (*prepare)(struct ifpga_sec_mgr *smgr);
	enum ifpga_sec_err (*write_blk)(struct ifpga_sec_mgr *smgr,
		uint32_t offset, uint32_t size);
	enum ifpga_sec_err (*write_done)(struct ifpga_sec_mgr *smgr);
	enum ifpga_sec_err (*check_complete)(struct ifpga_sec_mgr *smgr);
	enum ifpga_sec_err (*cancel)(struct ifpga_sec_mgr *smgr);
	void (*cleanup)(struct ifpga_sec_mgr *smgr);
	u64 (*get_hw_errinfo)(struct ifpga_sec_mgr *smgr);
	struct image_load *image_load;  /* terminated with { } member */
};

struct ifpga_sec_mgr {
	struct ifpga_fme_hw *fme;
	struct intel_max10_device *max10_dev;
	unsigned int *rsu_status;
	unsigned int *rsu_control;
	unsigned int one_percent;  /* use to calculate progress value */
	unsigned int copy_speed;  /* flash copy speed in bytes/second */

	const struct ifpga_sec_mgr_ops *sops;
	const char *filename;
	char *data;		/* pointer to update data */
	u32 remaining_size;		/* size remaining to transfer */
	enum ifpga_sec_err err_code;
	u64 hw_errinfo;  /* 64 bits of HW specific error info */
	enum fpga_sec_type type;
	const struct fpga_power_on *poc; /* power on image configuration */
};

int init_sec_mgr(struct ifpga_fme_hw *fme, enum fpga_sec_type type);
void release_sec_mgr(struct ifpga_fme_hw *fme);
int fpga_update_flash(struct ifpga_fme_hw *fme, const char *image,
	uint64_t *status);
int fpga_stop_flash_update(struct ifpga_fme_hw *fme, int force);
int fpga_reload(struct ifpga_fme_hw *fme, char *str);
int fpga_available_images(struct ifpga_fme_hw *fme, char *buf, size_t size);
int fpga_set_poc_image(struct ifpga_fme_hw *fme, char *buf);
int fpga_get_poc_images(struct ifpga_fme_hw *fme, char *buf, size_t size);

int pmci_set_poc_image(struct ifpga_sec_mgr *smgr, char *buf);
int pmci_get_poc_images(struct ifpga_sec_mgr *smgr, char *buf, size_t size);

#endif /* _IFPGA_FME_RSU_H_ */
