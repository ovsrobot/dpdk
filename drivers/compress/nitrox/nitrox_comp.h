/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef _NITROX_COMP_H_
#define _NITROX_COMP_H_

struct nitrox_device;

int nitrox_comp_pmd_create(struct nitrox_device *ndev);
int nitrox_comp_pmd_destroy(struct nitrox_device *ndev);

#endif /* _NITROX_COMP_H_ */
