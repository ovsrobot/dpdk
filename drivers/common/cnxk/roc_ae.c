/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"

#define AE_EC_GRP_TBL_NAME "ae_ec_grp_tbl"

struct ae_ec_grp_tbl {
	uint64_t refcount;
	uint8_t ec_grp_tbl[];
};

const struct roc_ae_ec_group ae_ec_grp[ROC_AE_EC_ID_PMAX] = {
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 24},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B,
				   0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31},
			  .length = 24},
		.consta = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC},
			   .length = 24},
		.constb = {.data = {0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C,
				    0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
				    0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8,
				    0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1},
			   .length = 24},
	},
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			  .length = 28},
		.order = {.data = {0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
				   0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
				   0X16, 0XA2, 0XE0, 0XB8, 0XF0, 0X3E, 0X13,
				   0XDD, 0X29, 0X45, 0X5C, 0X5C, 0X2A, 0X3D},
			  .length = 28},
		.consta = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
			   .length = 28},
		.constb = {.data = {0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3,
				    0xAB, 0xF5, 0x41, 0x32, 0x56, 0x50, 0x44,
				    0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27,
				    0x0B, 0x39, 0x43, 0x23, 0x55, 0xFF, 0xB4},
			   .length = 28},
	},
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
				   0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 32},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
				   0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7,
				   0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
				   0xFC, 0x63, 0x25, 0x51},
			  .length = 32},
		.consta = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
				    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFC},
			   .length = 32},
		.constb = {.data = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93,
				    0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98,
				    0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC,
				    0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E,
				    0x27, 0xD2, 0x60, 0x4B},
			   .length = 32},
	},
	{.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
		   .length = 48},
	 .order = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
			    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
			    0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73},
		   .length = 48},
	 .consta = {.data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC},
		    .length = 48},
	 .constb = {.data = {0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
			     0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
			     0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
			     0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
			     0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
			     0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF},
		    .length = 48}},
	{.prime = {.data = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF},
		   .length = 66},
	 .order = {.data = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
			    0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
			    0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
			    0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
			    0x64, 0x09},
		   .length = 66},
	 .consta = {.data = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			     0xFF, 0xFC},
		    .length = 66},
	 .constb = {.data = {0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C,
			     0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85,
			     0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
			     0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1,
			     0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E,
			     0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
			     0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C,
			     0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50,
			     0x3F, 0x00},
		    .length = 66},
	},
	{ /* ROC_AE_EC_ID_P160 */ },
	{ /* ROC_AE_EC_ID_P320 */ },
	{ /* ROC_AE_EC_ID_P512 */ },
	{
		.prime = {.data = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
				   0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF},
			  .length = 32},
		.order = {.data = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0x72, 0x03, 0xDF, 0x6B, 0x21,
				   0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09,
				   0x39, 0xD5, 0x41, 0x23},
			  .length = 32},
		.consta = {.data = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
				    0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
				    0xFF, 0xFF, 0xFF, 0xFC},
			   .length = 32},
		.constb = {.data = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E,
				    0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65,
				    0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15,
				    0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41,
				    0x4D, 0x94, 0x0E, 0x93},
			   .length = 32},
	},
	{
		.prime = {.data = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0x7F},
			  .length = 32},
		.order = {.data = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12,
				   0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
				   0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x10},
			  .length = 32},
		.consta = {.data = {0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb,
				    0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
				    0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79,
				    0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
				    0xee, 0x6c, 0x03, 0x52},
			   .length = 32},
	},
	{
		.prime = {.data = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			  .length = 56},
		.order = {.data = {0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78,
				   0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2,
				   0x6c, 0x21, 0x90, 0x36, 0xd6, 0xae, 0x49,
				   0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f},
			  .length = 56},
		.consta = {.data = {0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			   .length = 56},
	},
};

int
roc_ae_ec_grp_get(struct roc_ae_ec_group **tbl)
{
	const char name[] = AE_EC_GRP_TBL_NAME;
	struct ae_ec_grp_tbl *ec_grp;
	const struct plt_memzone *mz;
	int i, len = 0;
	uint8_t *data;

	if (tbl == NULL)
		return -EINVAL;

	len = sizeof(ae_ec_grp);

	mz = plt_memzone_lookup(name);
	if (mz == NULL) {
		/* Create memzone first time */
		mz = plt_memzone_reserve_cache_align(
			name, len + sizeof(struct ae_ec_grp_tbl));
		if (mz == NULL)
			return -ENOMEM;
	}

	ec_grp = mz->addr;

	if (__atomic_fetch_add(&ec_grp->refcount, 1, __ATOMIC_SEQ_CST) != 0)
		return 0;

	data = PLT_PTR_ADD(mz->addr, sizeof(uint64_t));

	for (i = 0; i < ROC_AE_EC_ID_PMAX; i++) {
		memcpy(data, &ae_ec_grp[i], sizeof(struct roc_ae_ec_group));
		tbl[i] = (struct roc_ae_ec_group *)data;
		data += sizeof(struct roc_ae_ec_group);
	}

	return 0;
}

void
roc_ae_ec_grp_put(void)
{
	const char name[] = AE_EC_GRP_TBL_NAME;
	const struct plt_memzone *mz;
	struct ae_ec_grp_tbl *ec_grp;

	mz = plt_memzone_lookup(name);
	if (mz == NULL)
		return;

	ec_grp = mz->addr;
	/* Decrement number of devices using EC grp table */
	if (__atomic_fetch_sub(&ec_grp->refcount, 1, __ATOMIC_SEQ_CST) - 1 == 0)
		plt_memzone_free(mz);
}
