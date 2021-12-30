/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_ETHDEV_H_
#define _SPNIC_ETHDEV_H_

/* Vendor id */
#define PCI_VENDOR_ID_RAMAXEL	0x1E81

/* Device ids */
#define SPNIC_DEV_ID_PF			0x9020
#define SPNIC_DEV_ID_VF			0x9001

enum spnic_dev_status {
	SPNIC_DEV_INIT
};

#define SPNIC_DEV_NAME_LEN		32
struct spnic_nic_dev {
	u32 dev_status;
	char dev_name[SPNIC_DEV_NAME_LEN];
};

#define SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev) \
	((struct spnic_nic_dev *)(dev)->data->dev_private)

#endif /* _SPNIC_ETHDEV_H_ */
