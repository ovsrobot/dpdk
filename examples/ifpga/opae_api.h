/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _OPAE_API_H
#define _OPAE_API_H


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

extern int opae_log_level;
extern FILE *opae_log_file;

#define OPAE_LOG_API      0  /**< Critical conditions.              */
#define OPAE_LOG_ERR      1  /**< Error conditions.                 */
#define OPAE_LOG_WARN     2  /**< Warning conditions.               */
#define OPAE_LOG_INFO     3  /**< Informational.                    */
#define OPAE_LOG_DEBUG    4  /**< Debug-level messages.             */

#define opae_log(type, fmt, args...)             \
do {                                             \
	if (opae_log_level >= OPAE_LOG_##type) {     \
		printf(fmt, ##args);                     \
		if (opae_log_file) {                     \
			fprintf(opae_log_file, fmt, ##args); \
			fflush(opae_log_file);               \
		}                                        \
	}                                            \
} while (0)

#define opae_log_api(fmt, args...)  opae_log(API, "OPAE-API: "fmt, ##args)
#define opae_log_err(fmt, args...)  opae_log(ERR, "OPAE-ERR: "fmt, ##args)
#define opae_log_dbg(fmt, args...)  opae_log(DEBUG, "OPAE-DBG: "fmt, ##args)
#define opae_log_warn(fmt, args...) opae_log(WARN, "OPAE-WARN: "fmt, ##args)
#define opae_log_info(fmt, args...) opae_log(INFO, "OPAE-INFO: "fmt, ##args)

#define EAL_INIT_FUNCTION    "init"
#define EAL_DEFAULT_OPTIONS  "--proc-type auto"

#define OPAE_KDRV_UNKNOWN           "unknown"
#define OPAE_KDRV_VFIO_PCI          "vfio-pci"
#define OPAE_KDRV_IGB_UIO           "igb_uio"
#define OPAE_KDRV_UIO_PCI           "uio_pci_generic"
#define OPAE_KDRV_INTEL_FPGA_PCI    "intel-fpga-pci"

typedef struct {
	uint32_t major;
	uint32_t minor;
	uint32_t micro;
} opae_api_version;

#define OPAE_NAME_SIZE  32

typedef struct {
	char bdf[OPAE_NAME_SIZE];   /* segment:bus:device.function */
} opae_pci_device;

typedef opae_pci_device *pcidev_id;

typedef struct {
	uint32_t class_id;            /**< Class ID or RTE_CLASS_ANY_ID. */
	uint16_t vendor_id;           /**< Vendor ID or PCI_ANY_ID. */
	uint16_t device_id;           /**< Device ID or PCI_ANY_ID. */
	uint16_t subsystem_vendor_id; /**< Subsystem vendor ID or PCI_ANY_ID. */
	uint16_t subsystem_device_id; /**< Subsystem device ID or PCI_ANY_ID. */
} opae_pci_id;

typedef struct {
	uint32_t domain;              /**< Device domain */
	uint8_t bus;                  /**< Device bus */
	uint8_t devid;                /**< Device ID */
	uint8_t function;             /**< Device function. */
} opae_pci_addr;

typedef struct {
	char pci_addr[OPAE_NAME_SIZE];  /* segment:bus:device.function */
	char drv_name[OPAE_NAME_SIZE];  /* vfio-pci, intel-fpga-pci, etc. */
	opae_pci_id id;
	opae_pci_addr addr;
} opae_pci_property;

#define BIT_SET_8   0xFF
#define BIT_SET_16  0xFFFF
#define BIT_SET_32  0xFFFFFFFF

typedef struct {
	uint8_t b[16];
} opae_uuid;

typedef struct {
	uint32_t boot_page;
	uint32_t num_ports;
	uint64_t bitstream_id;
	uint64_t bitstream_metadata;
	opae_uuid pr_id;
	char platform_name[OPAE_NAME_SIZE];
	char dcp_version[OPAE_NAME_SIZE];
	char release_name[OPAE_NAME_SIZE];
	char interface_type[OPAE_NAME_SIZE];
	char build_version[OPAE_NAME_SIZE];
} opae_fme_property;

typedef struct {
	opae_uuid afu_id;
	uint32_t type;   /* AFU memory access control type */
	uint32_t index;  /* PORT index */
} opae_port_property;

typedef struct {
	char bmc_version[OPAE_NAME_SIZE];
	char fw_version[OPAE_NAME_SIZE];
} opae_bmc_property;

typedef struct {
	uint32_t num_retimers;
	uint32_t link_speed;
	uint32_t link_status;  /* each bit corresponding to one link status */
} opae_phy_info;

typedef struct {
	union {
		uint64_t id;
		struct {
			uint8_t build_patch;
			uint8_t build_minor;
			uint8_t build_major;
			uint8_t fvl_bypass:1;
			uint8_t mac_lightweight:1;
			uint8_t disagregate:1;
			uint8_t lightweiht:1;
			uint8_t seu:1;
			uint8_t ptp:1;
			uint8_t reserve:2;
			uint16_t interface:4;
			uint16_t afu_revision:12;
			uint16_t patch:4;
			uint16_t minor:4;
			uint16_t major:4;
			uint16_t reserved:4;
		};
	};
} opae_bitstream_id;

typedef struct {
	union {
		uint32_t version;
		struct {
			uint8_t micro;
			uint8_t minor;
			uint8_t major;
			uint8_t board;
		};
	};
} opae_bmc_version;

#define OPAE_MAX_PORT_NUM   4

#define OPAE_PROP_PCI   0x01
#define OPAE_PROP_FME   0x02
#define OPAE_PROP_PORT  0x04
#define OPAE_PROP_BMC   0x08
#define OPAE_PROP_ALL   \
	(OPAE_PROP_PCI | OPAE_PROP_FME | OPAE_PROP_PORT | OPAE_PROP_BMC)

typedef struct {
	opae_pci_property pci;
	opae_fme_property fme;
	opae_port_property port[OPAE_MAX_PORT_NUM];
	opae_bmc_property bmc;
} opae_fpga_property;

typedef struct {
	uint64_t guid_h;
	uint64_t guid_l;
	uint32_t metadata_len;
} gbs_header;

#define OPAE_IMG_TYPE_BBS       0
#define OPAE_IMG_TYPE_BMC       1
#define OPAE_IMG_TYPE_GBS       2
#define OPAE_IMG_TYPE(t)        ((t) & 0xff)

#define OPAE_IMG_SUBTYPE_UPDATE             0
#define OPAE_IMG_SUBTYPE_CANCELLATION       1
#define OPAE_IMG_SUBTYPE_ROOT_KEY_HASH_256  2
#define OPAE_IMG_SUBTYPE_ROOT_KEY_HASH_384  3
#define OPAE_IMG_SUBTYPE(t)     (((t) >> 8) & 0xff)

#define OPAE_IMG_BLK0_SIZE      128
#define OPAE_IMG_BLK0_MAGIC     0xb6eafd19
#define OPAE_IMG_BLK1_SIZE      896
#define OPAE_IMG_HDR_SIZE   (OPAE_IMG_BLK0_SIZE + OPAE_IMG_BLK1_SIZE)
#define OPAE_IMG_PL_MIN_SIZE    128

typedef struct {
	uint32_t magic;
	uint32_t payload_len;
	uint32_t payload_type;
} opae_img_hdr;

typedef struct {
	int type;
	int subtype;
	uint32_t total_len;
	uint32_t payload_offset;
	uint32_t payload_len;
} opae_img_info;

void opae_get_api_version(opae_api_version *version);
int opae_set_log_level(int level);
int opae_set_log_file(char *path, int clean);
int opae_get_proc_type(void);
int opae_get_parent(pcidev_id id, pcidev_id parent);
int opae_get_child(pcidev_id id, pcidev_id child, int size);
int opae_get_pf1(pcidev_id id, pcidev_id peer, int size);
int opae_init_eal(int argc, char **argv);
int opae_cleanup_eal(void);
int opae_enumerate(opae_pci_id *filter, pcidev_id list, int size);
int opae_probe_device(pcidev_id id);
int opae_remove_device(pcidev_id id);
int opae_unbind_driver(pcidev_id id);
int opae_bind_driver(pcidev_id id, char *drv_name);
int opae_get_property(pcidev_id id, opae_fpga_property *prop, int type);
int opae_get_phy_info(pcidev_id id, opae_phy_info *info);
int opae_partial_reconfigure(pcidev_id id, int port, const char *gbs);
int opae_get_image_info(const char *image, opae_img_info *info);
int opae_cancel_flash_update(pcidev_id id, int force);
int opae_update_flash(pcidev_id id, const char *image, uint64_t *status);
int opae_reboot_device(pcidev_id id, int type, int page);
int opae_store_rsu_status(pcidev_id id, uint32_t status, uint32_t progress);
int opae_load_rsu_status(pcidev_id id, uint32_t *status, uint32_t *progress);
int opae_read_pci_cfg(pcidev_id id, uint32_t address, uint32_t *value);
int opae_write_pci_cfg(pcidev_id id, uint32_t address, uint32_t value);

#ifdef __cplusplus
}
#endif


#endif  /* _OPAE_API_H */
