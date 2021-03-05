/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

struct roc_model *roc_model;

/* RoC and CPU IDs and revisions */
#define VENDOR_ARM    0x41 /* 'A' */
#define VENDOR_CAVIUM 0x43 /* 'C' */

#define PART_106XX  0xD49
#define PART_98XX   0xB1
#define PART_96XX   0xB2
#define PART_95XX   0xB3
#define PART_95XXN  0xB4
#define PART_95XXMM 0xB5

#define MODEL_IMPL_BITS	  8
#define MODEL_IMPL_SHIFT  24
#define MODEL_IMPL_MASK	  ((1 << MODEL_IMPL_BITS) - 1)
#define MODEL_PART_BITS	  12
#define MODEL_PART_SHIFT  4
#define MODEL_PART_MASK	  ((1 << MODEL_PART_BITS) - 1)
#define MODEL_MAJOR_BITS  4
#define MODEL_MAJOR_SHIFT 20
#define MODEL_MAJOR_MASK  ((1 << MODEL_MAJOR_BITS) - 1)
#define MODEL_MINOR_BITS  4
#define MODEL_MINOR_SHIFT 0
#define MODEL_MINOR_MASK  ((1 << MODEL_MINOR_BITS) - 1)

static const struct model_db {
	uint32_t impl;
	uint32_t part;
	uint32_t major;
	uint32_t minor;
	uint64_t flag;
	char name[ROC_MODEL_STR_LEN_MAX];
} model_db[] = {
	{VENDOR_ARM, PART_106XX, 0, 0, ROC_MODEL_CN10K, "cn10k"},
	{VENDOR_CAVIUM, PART_98XX, 0, 0, ROC_MODEL_CN98xx_A0, "cn98xx_a0"},
	{VENDOR_CAVIUM, PART_96XX, 0, 0, ROC_MODEL_CN96xx_A0, "cn96xx_a0"},
	{VENDOR_CAVIUM, PART_96XX, 0, 1, ROC_MODEL_CN96xx_B0, "cn96xx_b0"},
	{VENDOR_CAVIUM, PART_96XX, 2, 0, ROC_MODEL_CN96xx_C0, "cn96xx_c0"},
	{VENDOR_CAVIUM, PART_95XX, 0, 0, ROC_MODEL_CNF95xx_A0, "cnf95xx_a0"},
	{VENDOR_CAVIUM, PART_95XX, 1, 0, ROC_MODEL_CNF95xx_B0, "cnf95xx_b0"},
	{VENDOR_CAVIUM, PART_95XXN, 0, 0, ROC_MODEL_CNF95XXN_A0, "cnf95xxn_a0"},
	{VENDOR_CAVIUM, PART_95XXMM, 0, 0, ROC_MODEL_CNF95XXMM_A0,
	 "cnf95xxmm_a0"}
};

static bool
populate_model(struct roc_model *model, uint32_t midr)
{
	uint32_t impl, major, part, minor;
	bool found = false;
	size_t i;

	impl = (midr >> MODEL_IMPL_SHIFT) & MODEL_IMPL_MASK;
	part = (midr >> MODEL_PART_SHIFT) & MODEL_PART_MASK;
	major = (midr >> MODEL_MAJOR_SHIFT) & MODEL_MAJOR_MASK;
	minor = (midr >> MODEL_MINOR_SHIFT) & MODEL_MINOR_MASK;

	for (i = 0; i < PLT_DIM(model_db); i++)
		if (model_db[i].impl == impl && model_db[i].part == part &&
		    model_db[i].major == major && model_db[i].minor == minor) {
			model->flag = model_db[i].flag;
			strncpy(model->name, model_db[i].name,
				ROC_MODEL_STR_LEN_MAX - 1);
			found = true;
			break;
		}
	if (!found) {
		model->flag = 0;
		strncpy(model->name, "unknown", ROC_MODEL_STR_LEN_MAX - 1);
		plt_err("Invalid RoC model (impl=0x%x, part=0x%x)", impl, part);
	}

	return found;
}

static int
midr_get(unsigned long *val)
{
	const char *file =
		"/sys/devices/system/cpu/cpu0/regs/identification/midr_el1";
	int rc = UTIL_ERR_FS;
	char buf[BUFSIZ];
	char *end = NULL;
	FILE *f;

	if (val == NULL)
		goto err;
	f = fopen(file, "r");
	if (f == NULL)
		goto err;

	if (fgets(buf, sizeof(buf), f) == NULL)
		goto fclose;

	*val = strtoul(buf, &end, 0);
	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n'))
		goto fclose;

	rc = 0;
fclose:
	fclose(f);
err:
	return rc;
}

static void
detect_invalid_config(void)
{
#ifdef ROC_PLATFORM_CN9K
#ifdef ROC_PLATFORM_CN10K
	PLT_STATIC_ASSERT(0);
#endif
#endif
}

int
roc_model_init(struct roc_model *model)
{
	int rc = UTIL_ERR_PARAM;
	unsigned long midr;

	detect_invalid_config();

	if (!model)
		goto err;

	rc = midr_get(&midr);
	if (rc)
		goto err;

	rc = UTIL_ERR_INVALID_MODEL;
	if (!populate_model(model, midr))
		goto err;

	rc = 0;
	plt_info("RoC Model: %s", model->name);
	roc_model = model;
err:
	return rc;
}
