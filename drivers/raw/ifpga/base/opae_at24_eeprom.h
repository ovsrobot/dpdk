
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _OPAE_AT24_EEPROM_H
#define _OPAE_AT24_EEPROM_H

#define AT24C512_PAGE_SIZE 128
#define AT24C512_IO_LIMIT  128

#define AT24512_SLAVE_ADDR 0x51

int at24_eeprom_read(struct altera_i2c_dev *dev, unsigned int slave_addr,
		u32 offset, u8 *buf, int count);
int at24_eeprom_write(struct altera_i2c_dev *dev, unsigned int slave_addr,
		u32 offset, u8 *buf, int count);

#endif /* _OPAE_AT24_EEPROM_H */
