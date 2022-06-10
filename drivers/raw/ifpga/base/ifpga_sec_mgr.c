/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include "ifpga_sec_mgr.h"
#include "opae_intel_max10.h"
#include "opae_osdep.h"

static const char * const rsu_stat_string[] = {
	[SEC_STATUS_NORMAL] = "Initial normal status",
	[SEC_STATUS_TIMEOUT] = "Host timeout",
	[SEC_STATUS_AUTH_FAIL] = "Authentication failure",
	[SEC_STATUS_COPY_FAIL] = "Image copy failure",
	[SEC_STATUS_FATAL] = "Fatal error, Nios boot-up failure",
	[SEC_STATUS_PKVL_REJECT] = "pkvl reject",
	[SEC_STATUS_NON_INC] = "Staging area non-incremental write fail",
	[SEC_STATUS_ERASE_FAIL] = "Staging area erase fail",
	[SEC_STATUS_WEAROUT] = "Staging area write wearout",
	[SEC_STATUS_PMCI_SS_FAIL] = "PMCI SS Access fail",
	[SEC_STATUS_FLASH_CMD] = "Unsupported flash command",
	[SEC_STATUS_FACTORY_UNVERITY] = "factory image is unverified",
	[SEC_STATUS_FACTORY_ACTIVE] = "current active image is factory",
	[SEC_STATUS_POWER_DOWN] = "FPGA/Board powered down",
	[SEC_STATUS_CANCELLATION] = "Cancellation not supported",
	[SEC_STATUS_HASH] = "Hash Programming not supported",
	[SEC_STATUS_FLASH_ACCESS] = "FPGA Flash Access Error",
	[SEC_STATUS_SDM_PR_CERT] = "PR: cert not programmed to SDM",
	[SEC_STATUS_SDM_PR_NIOS_BUSY] = "PR: Nios Busy waiting for SDM",
	[SEC_STATUS_SDM_PR_TIMEOUT] = "PR: SDM Response timed out",
	[SEC_STATUS_SDM_PR_FAILED] = "PR Key Hash program failed",
	[SEC_STATUS_SDM_PR_MISMATCH] = "PR: SDM Response mismatched",
	[SEC_STATUS_SDM_PR_FLUSH] = "PR: SDM Buffer Flushing failed",
	[SEC_STATUS_SDM_SR_CERT] = "SR: cert is not programmed to SDM",
	[SEC_STATUS_SDM_SR_NIOS_BUSY] = "SR: Nios Busy waiting for SDM",
	[SEC_STATUS_SDM_SR_TIMEOUT] = "SR: SDM Response timed out",
	[SEC_STATUS_SDM_SR_FAILED] = "SR Key Hash program failed",
	[SEC_STATUS_SDM_SR_MISMATCH] = "SR: SDM Response mismatched",
	[SEC_STATUS_SDM_SR_FLUSH] = "SR: SDM Buffer Flushing failed",
	[SEC_STATUS_SDM_KEY_CERT] = "KEY: cert is not programmed to SDM",
	[SEC_STATUS_SDM_KEY_NIOS_BUSY] = "KEY: Nios Busy waiting for SDM",
	[SEC_STATUS_SDM_KEY_TIMEOUT] = "KEY: SDM Response timed out",
	[SEC_STATUS_SDM_KEY_FAILED] = "KEY: Key Hash program failed",
	[SEC_STATUS_SDM_KEY_MISMATCH] = "KEY: SDM Response mismatched",
	[SEC_STATUS_SDM_KEY_FLUSH] = "KEY: SDM Buffer Flushing failed",
	[SEC_STATUS_USER_FAIL] = "Update Failure",
	[SEC_STATUS_FACTORY_FAIL] = "Factory Failure",
	[SEC_STATUS_NIOS_FLASH_ERR] = "NIOS Flash Open Error",
	[SEC_STATUS_FPGA_FLASH_ERR] = "FPGA Flash Open Error",
};

static const char * const auth_stat_string[] = {
	[AUTH_STAT_PASS] = "Authenticate Pass",
	[AUTH_STAT_B0_MAGIC] = "Block0 Magic value error",
	[AUTH_STAT_CONLEN] = "Block0 ConLen error",
	[AUTH_STAT_CONTYPE] = "Block0 ConType B[7:0] > 2",
	[AUTH_STAT_B1_MAGIC] = "Block1 Magic value error",
	[AUTH_STAT_ROOT_MAGIC] = "Root Entry Magic value error",
	[AUTH_STAT_CURVE_MAGIC] = "Root Entry Curve Magic value error",
	[AUTH_STAT_PERMISSION] = "Root Entry Permission error",
	[AUTH_STAT_KEY_ID] = "Root Entry Key ID error",
	[AUTH_STAT_CSK_MAGIC] = "CSK Entry Magic value error",
	[AUTH_STAT_CSK_CURVE] = "CSK Entry Curve Magic value error",
	[AUTH_STAT_CSK_PERMISSION] = "CSK Entry Permission error",
	[AUTH_STAT_CSK_ID] = "CSK Entry Key ID error",
	[AUTH_STAT_CSK_SM] = "CSK Entry Signature Magic value error",
	[AUTH_STAT_B0_E_MAGIC] = "Block0 Entry Magic value error",
	[AUTH_STAT_B0_E_SIGN] = "Block0 Entry Signature Magic value error",
	[AUTH_STAT_RK_P] = "Root Key Hash not programmed for RSU",
	[AUTH_STAT_RE_SHA] = "Root Entry verify SHA failed",
	[AUTH_STAT_CSK_SHA] = "CSK Entry verify ECDSA and SHA failed",
	[AUTH_STAT_B0_SHA] = "Block0 Entry verify ECDSA and SHA failed",
	[AUTH_STAT_KEY_INV] = "KEY ID of authenticate blob is invalid",
	[AUTH_STAT_KEY_CAN] = "KEY ID is cancelled",
	[AUTH_STAT_UP_SHA] = "Update content SHA verify failed",
	[AUTH_STAT_CAN_SHA] = "Cancellation content SHA verify failed",
	[AUTH_STAT_HASH] = "HASH Programming content SHA verify failed",
	[AUTH_STAT_INV_ID] = "Invalid cancellation ID of cancellation cert",
	[AUTH_STAT_KEY_PROG] = "KEY hash programmed for KEY hash programming cert",
	[AUTH_STAT_INV_BC] = "Invalid operation of Block0 ConType",
	[AUTH_STAT_INV_SLOT] = "Invalid slot in Block0 ConType",
	[AUTH_STAT_IN_OP] = "Incompatible operation of Block0 ConType",
	[AUTH_STAT_TIME_OUT] = "Flash transfer to staging area timed out",
	[AUTH_STAT_SHA_TO] = "Root Entry verify SHA timeout",
	[AUTH_STAT_CSK_TO] = "CSK Entry verify ECDSA and SHA timeout",
	[AUTH_STAT_B0_TO] = "Block0 Entry verify ECDSA and SHA timeout",
	[AUTH_STAT_UP_TO] = "Update content SHA verify timeout",
	[AUTH_STAT_CAN_TO] = "Cancellation content SHA verify timeout",
	[AUTH_STAT_HASH_TO] = "HASH Programming content SHA verify timeout",
	[AUTH_STAT_AUTH_IDLE] = "Authentication engine Idle",
	[AUTH_STAT_GA_FAIL] = "Generic Authentication Failure",
	[AUTH_STAT_S_ERR] = "Sensor Blob Generic Error",
	[AUTH_STAT_S_MN] = "Sensor Blob Magic number error",
	[AUTH_STAT_SH_CRC] = "Sensor Blob Header CRC error",
	[AUTH_STAT_SD_CRC] = "Sensor Blob Data CRC error",
	[AUTH_STAT_SD_LEN] = "Sensor Blob Data Length error",
	[AUTH_STAT_S_ID] = "Sensor Blob Sensor ID not supported",
	[AUTH_STAT_S_THR] = "Sensor Blob Invalid threshold type",
	[AUTH_STAT_S_TO] = "Sensor Blob threshold out of bounds",
	[AUTH_STAT_S_EN] = "Sensor Blob exceeds number of sensor count",
	[AUTH_STAT_SF] = "only FPGA thermal Sensor Thresholds are allowed",
};

static const char * const sdm_stat_string[] = {
	[SDM_STAT_DONE] = "SR Key Hash program successful",
	[SDM_STAT_PROV] = "ignored,SR Hash is already provisioned to SDM",
	[SDM_STAT_BUSY] = "Ignored; Configuration Module Busy",
	[SDM_STAT_INV] = "Invalid configuration Status from Configuration",
	[SDM_STAT_FAIL] = "SDM Flush Buffer failed",
	[SDM_STAT_BMC_BUSY] = "BMC Busy waiting for another SDM command response",
	[SDM_STAT_TO] = "SDM Response timed out during SDM Provisioning",
	[SDM_STAT_DB] = "SDM device busy during SDM Provisioning",
	[SDM_STAT_CON_R] = "Config Status retry count exceeded",
	[SDM_STAT_CON_E] = "Config status command returned error",
	[SDM_STAT_WAIT] = "BMC Busy waiting for another SDM command response",
	[SDM_STAT_RTO] = "timed out during PUBKEY_PROGRAM command to SDM",
	[SDM_STAT_SB] = "busy during PUBKEY_PROGRAM command to SDM",
	[SDM_STAT_RE] = "SR Key Hash program failed with recoverable error",
	[SDM_STAT_PDD] = "SR Key Hash program failed permanent device damage",
	[SDM_STAT_ISC] = "SR Key program failed by invalid SDM command",
	[SDM_STAT_SIC] = "SDM Congiguration failed by Shell Image configured",
	[SDM_STAT_NO_PROV] = "SR Key Hash not provisioned to BMC",
	[SDM_STAT_CS_MIS] = "failed by SDM CONFIG_STATUS response mismatch",
	[SDM_STAT_PR_MIS] = "failed by SDM PUBKEY_PROGRAM Response mismatch",
};

static const char * const rsu_prog[] = {"IDLE", "PREPARING", "SLEEPING",
	"READY", "AUTHENTICATING", "COPYING", "CANCELLATION", "PROGRAMMING_KEY",
	"DONE", "PKVL_DONE"};
static const char * const rsu_statl[] = {"NORMAL", "TIMEOUT", "AUTH_FAIL",
	"COPY_FAIL", "FATAL", "PKVL_REJECT", "NON_INCR", "ERASE_FAIL",
	"WEAROUT"};
static const char * const rsu_stath[] = {"NIOS_OK", "USER_OK", "FACTORY_OK",
	"USER_FAIL", "FACTORY_FAIL", "NIOS_FLASH_ERR", "FPGA_FLASH_ERR"};

static const char * const fpga_image_names[] = {
	[FPGA_FACTORY] = "fpga_factory",
	[FPGA_USER1] = "fpga_user1",
	[FPGA_USER2] = "fpga_user2"
};

static enum fpga_image
fpga_image_by_name(char *image_name)
{
	enum fpga_image i;

	for (i = 0; i < FPGA_MAX; i++)
		if (!strcmp(image_name, fpga_image_names[i]))
			return i;

	return FPGA_MAX;
}

static int
fpga_images(struct ifpga_sec_mgr *smgr, char *names, enum fpga_image images[])
{
	u32 image_mask = smgr->poc->avail_image_mask;
	enum fpga_image image;
	char *image_name;
	int i = 0;

	while ((image_name = strsep(&names, "\n"))) {
		image = fpga_image_by_name(image_name);
		if (image >= FPGA_MAX || !(image_mask & BIT(image)))
			return -EINVAL;

		images[i++] = image;
		image_mask &= ~BIT(image);
	}

	return (i == 0) ? -EINVAL : 0;
}

int pmci_set_poc_image(struct ifpga_sec_mgr *smgr, char *buf)
{
	enum fpga_image images[FPGA_MAX] = { [0 ... FPGA_MAX - 1] = FPGA_MAX };
	int ret;

	if (!smgr)
		return -ENODEV;

	ret = fpga_images(smgr, buf, images);
	if (ret)
		return -EINVAL;

	return smgr->poc->set_sequence(smgr, images);
}

int pmci_get_poc_images(struct ifpga_sec_mgr *smgr, char *buf, size_t size)
{
	if (!smgr)
		return -ENODEV;

	return smgr->poc->get_sequence(smgr, buf, size);
}

static int pmci_get_power_on_image(struct ifpga_sec_mgr *smgr,
		char *buf, size_t size)
{
	const char *image_names[FPGA_MAX] = { 0 };
	int ret, i = 0;
	int j;
	u32 poc;
	size_t count = 0;

	if (!smgr->max10_dev)
		return -ENODEV;

	if (!buf)
		return -EINVAL;

	ret = max10_sys_read(smgr->max10_dev, M10BMC_PMCI_FPGA_POC, &poc);
	if (ret)
		return ret;

	if (poc & PMCI_FACTORY_IMAGE_SEL)
		image_names[i++] = fpga_image_names[FPGA_FACTORY];

	if (GET_FIELD(PMCI_USER_IMAGE_PAGE, poc) == POC_USER_IMAGE_1) {
		image_names[i++] = fpga_image_names[FPGA_USER1];
		image_names[i++] = fpga_image_names[FPGA_USER2];
	} else {
		image_names[i++] = fpga_image_names[FPGA_USER2];
		image_names[i++] = fpga_image_names[FPGA_USER1];
	}

	if (!(poc & PMCI_FACTORY_IMAGE_SEL))
		image_names[i] = fpga_image_names[FPGA_FACTORY];

	for (j = 0; j < FPGA_MAX; j++) {
		if ((size > count) &&
				((size - count) > strlen(image_names[j])))
			count += snprintf(buf + count, size - count,
					"%s ", image_names[j]);
	}
	buf[count - 1] = '\0';

	return count;
}

static int
pmci_set_power_on_image(struct ifpga_sec_mgr *smgr, enum fpga_image images[])
{
	struct intel_max10_device *dev = smgr->max10_dev;
	u32 poc_mask = PMCI_FACTORY_IMAGE_SEL;
	int ret, first_user = 0;
	u32 poc = 0;

	if (!dev)
		return -ENODEV;

	if (images[1] == FPGA_FACTORY)
		return -EINVAL;

	if (images[0] == FPGA_FACTORY) {
		poc = PMCI_FACTORY_IMAGE_SEL;
		first_user = 1;
	}

	if (images[first_user] == FPGA_USER1 ||
			images[first_user] == FPGA_USER2) {
		poc_mask |= PMCI_USER_IMAGE_PAGE;
		if (images[first_user] == FPGA_USER1)
			poc |= SET_FIELD(PMCI_USER_IMAGE_PAGE,
					POC_USER_IMAGE_1);
		else
			poc |= SET_FIELD(PMCI_USER_IMAGE_PAGE,
					POC_USER_IMAGE_2);
	}

	ret = max10_sys_update_bits(dev,
			m10bmc_base(dev) + M10BMC_PMCI_FPGA_POC,
			poc_mask | PMCI_FPGA_POC, poc | PMCI_FPGA_POC);
	if (ret)
		return ret;

	ret = opae_max10_read_poll_timeout(dev,
			m10bmc_base(dev) + M10BMC_PMCI_FPGA_POC,
			poc,
			(!(poc & PMCI_FPGA_POC)),
			IFPGA_NIOS_HANDSHAKE_INTERVAL_US,
			IFPGA_NIOS_HANDSHAKE_TIMEOUT_US);

	if (ret || (GET_FIELD(PMCI_NIOS_STATUS, poc) != NIOS_STATUS_SUCCESS))
		return -EIO;

	return 0;
}

static const char *rsu_progress_name(uint32_t prog)
{
	if (prog > SEC_PROGRESS_PKVL_PROM_DONE)
		return "UNKNOWN";
	else
		return rsu_prog[prog];
}

static const char *rsu_status_name(uint32_t stat)
{
	if (stat >= SEC_STATUS_NIOS_OK) {
		if (stat > SEC_STATUS_FPGA_FLASH_ERR)
			return "UNKNOWN";
		else
			return rsu_stath[stat-SEC_STATUS_NIOS_OK];
	} else {
		if (stat > SEC_STATUS_WEAROUT)
			return "UNKNOWN";
		else
			return rsu_statl[stat];
	}
}

static void print_sdm_status(struct intel_max10_device *dev)
{
	u32 val, sdm_stat;

	const char *sdm_string;

	if (dev->type == M10_N6000) {
		if (!max10_sys_read(dev, m10bmc_base(dev) +
					M10BMC_PMCI_SDM_CTRL_STS, &val))
			dev_err(dev, "sdm ctrl reg: 0x%08x\n", val);

		sdm_stat = GET_FIELD(val, PMCI_SDM_STAT);
		if (sdm_stat > SDM_STAT_MAX)
			dev_err(dev, "unknown sdm stat: 0x%08x\n", sdm_stat);

		sdm_string = sdm_stat_string[sdm_stat];
		if (sdm_string)
			dev_err(dev, "sdm stat: %s\n", sdm_string);
		else
			dev_err(dev, "unknown sdm stat\n");
	}
}

static void print_error_regs(struct intel_max10_device *dev)
{
	u32 auth_result, doorbell, rsu_stat, auth_stat;

	const char *rsu_string, *auth_string;

	if (!max10_sys_read(dev, doorbell_reg(dev), &doorbell))
		dev_err(dev, "RSU doorbell reg: 0x%08x\n", doorbell);

	if (!max10_sys_read(dev, auth_result_reg(dev), &auth_result))
		dev_err(dev, "RSU auth result reg: 0x%08x\n", auth_result);

	rsu_stat = SEC_STATUS_G(auth_result);
	if (rsu_stat > SEC_STATUS_MAX)
		dev_err(dev, "unknown rsu stat, error code exceed: 0x%08x\n", rsu_stat);

	rsu_string = rsu_stat_string[rsu_stat];
	if (rsu_string)
		dev_err(dev, "rsu stat: %s\n", rsu_string);
	else
		dev_err(dev, "unknown rsu stat\n");

	if (rsu_stat == SEC_STATUS_SDM_PR_FAILED ||
			rsu_stat == SEC_STATUS_SDM_SR_FAILED)
		print_sdm_status(dev);

	auth_stat = SEC_AUTH_G(auth_result);
	if (auth_stat > AUTH_STAT_MAX)
		dev_err(dev, "unknown Authentication status, code exceed: 0x%08x\n", rsu_stat);

	auth_string = auth_stat_string[auth_stat];
	if (auth_string)
		dev_err(dev, "auth stat: %s\n", auth_string);
	else
		dev_err(dev, "unknown auth stat\n");
}

static bool rsu_status_ok(u32 status)
{
	return (status == SEC_STATUS_NORMAL ||
		status == SEC_STATUS_NIOS_OK ||
		status == SEC_STATUS_USER_OK ||
		status == SEC_STATUS_FACTORY_OK);
}

static bool rsu_progress_done(u32 progress)
{
	return (progress == SEC_PROGRESS_IDLE ||
		progress == SEC_PROGRESS_RSU_DONE);
}

static bool rsu_progress_busy(u32 progress)
{
	return (progress == SEC_PROGRESS_AUTHENTICATING ||
		progress == SEC_PROGRESS_COPYING ||
		progress == SEC_PROGRESS_UPDATE_CANCEL ||
		progress == SEC_PROGRESS_PROGRAM_KEY_HASH);
}

static enum ifpga_sec_err rsu_check_idle(struct intel_max10_device *dev)
{
	uint32_t doorbell = 0;
	uint32_t prog = 0;
	int ret = 0;

	ret = max10_sys_read(dev, doorbell_reg(dev), &doorbell);
	if (ret) {
		dev_err(dev,
			"Failed to read max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	prog = SEC_PROGRESS_G(doorbell);
	if (!rsu_progress_done(prog)) {
		dev_info(dev, "Current RSU progress is %s\n",
			rsu_progress_name(prog));
		return IFPGA_SEC_ERR_BUSY;
	}

	return IFPGA_SEC_ERR_NONE;
}

static bool cond_start_done(uint32_t doorbell, uint32_t progress,
		uint32_t status)
{
	if (doorbell & RSU_REQUEST)
		return false;

	if (status == SEC_STATUS_ERASE_FAIL ||
		status == SEC_STATUS_WEAROUT)
		return true;

	if (!rsu_progress_done(progress))
		return true;

	return false;
}

static int
m10bmc_sec_status(struct intel_max10_device *dev, u32 *status)
{
	u32 reg_offset, reg_value;
	int ret;

	reg_offset = (dev->type == M10_N6000) ?
		auth_result_reg(dev) : doorbell_reg(dev);

	ret = max10_sys_read(dev, reg_offset, &reg_value);
	if (ret)
		return ret;

	*status = SEC_STATUS_G(reg_value);

	return 0;
}

static int
m10bmc_sec_progress_status(struct intel_max10_device *dev, u32 *doorbell,
			   u32 *progress, u32 *status)
{
	u32 auth_reg;
	int ret;

	ret = max10_sys_read(dev,
			      doorbell_reg(dev),
			      doorbell);
	if (ret)
		return ret;

	*progress = SEC_PROGRESS_G(*doorbell);

	if (dev->type == M10_N6000) {
		ret = max10_sys_read(dev,
				      auth_result_reg(dev),
				      &auth_reg);
		if (ret)
			return ret;
		*status = SEC_STATUS_G(auth_reg);
	} else {
		*status = SEC_STATUS_G(*doorbell);
	}

	return 0;
}

static int rsu_poll_start_done(struct intel_max10_device *dev, u32 *doorbell,
			       u32 *progress, u32 *status)
{
	unsigned long time = 0;
	int ret;

	do {
		if (time > IFPGA_NIOS_HANDSHAKE_TIMEOUT_US)
			return -ETIMEDOUT;

		ret = m10bmc_sec_progress_status(dev, doorbell,
				progress, status);
		if (ret)
			return ret;
		usleep(IFPGA_NIOS_HANDSHAKE_INTERVAL_US);
		time += IFPGA_NIOS_HANDSHAKE_INTERVAL_US;

	} while (!cond_start_done(*doorbell, *progress, *status));

	return 0;
}

static enum ifpga_sec_err rsu_update_init(struct intel_max10_device *dev)
{
	uint32_t doorbell, progress, status;
	int ret = 0;

	ret = max10_sys_update_bits(dev, doorbell_reg(dev),
		RSU_REQUEST | HOST_STATUS, RSU_REQUEST);
	if (ret) {
		dev_err(dev,
			"Failed to updt max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	ret = rsu_poll_start_done(dev, &doorbell, &progress, &status);
	if (ret == -ETIMEDOUT) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		dev_err(dev,
			"Failed to poll max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	status = SEC_STATUS_G(doorbell);
	if (status == SEC_STATUS_WEAROUT) {
		dev_err(dev, "Excessive flash update count detected\n");
		return IFPGA_SEC_ERR_WEAROUT;
	} else if (status == SEC_STATUS_ERASE_FAIL) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	dev_info(dev, "Current RSU progress is %s\n",
			rsu_progress_name(SEC_PROGRESS_G(doorbell)));

	return IFPGA_SEC_ERR_NONE;
}

static bool cond_prepare_done(uint32_t doorbell)
{
	return (SEC_PROGRESS_G(doorbell) != SEC_PROGRESS_PREPARE);
}

static enum ifpga_sec_err rsu_prog_ready(struct intel_max10_device *dev)
{
	uint32_t doorbell = 0;
	uint32_t prog = 0;
	int ret = 0;

	ret = opae_max10_read_poll_timeout(dev, doorbell_reg(dev),
			doorbell, cond_prepare_done(doorbell),
			IFPGA_RSU_PREP_INTERVAL_US,
			IFPGA_RSU_PREP_TIMEOUT_US);
	if (ret == -ETIMEDOUT) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		dev_err(dev,
			"Failed to poll max10 prog [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	prog = SEC_PROGRESS_G(doorbell);
	if (prog == SEC_PROGRESS_PREPARE) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (prog != SEC_PROGRESS_READY) {
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	dev_info(dev, "Current RSU progress is %s\n",
			rsu_progress_name(SEC_PROGRESS_G(doorbell)));

	return IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err m10bmc_sec_prepare(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = NULL;
	int ret = 0;

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;

	if (smgr->remaining_size > dev->staging_area_size) {
		dev_err(smgr, "Size of staging area is smaller than image "
			"length [%u<%u]\n", smgr->max10_dev->staging_area_size,
			smgr->remaining_size);
		return IFPGA_SEC_ERR_INVALID_SIZE;
	}

	ret = rsu_check_idle(dev);
	if (ret != IFPGA_SEC_ERR_NONE)
		return ret;

	ret = rsu_update_init(dev);
	if (ret != IFPGA_SEC_ERR_NONE)
		return ret;

	return rsu_prog_ready(dev);
}


static enum ifpga_sec_err m10bmc_sec_write_blk(struct ifpga_sec_mgr *smgr,
	uint32_t offset, uint32_t len)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell = 0;
	int ret = 0;

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;
	if (!dev || !dev->bmc_ops.flash_write)
		return IFPGA_SEC_ERR_HW_ERROR;

	if (offset + len > dev->staging_area_size) {
		dev_err(dev,
			"Write position would be out of staging area [e:%u]\n",
			dev->staging_area_size);
		return IFPGA_SEC_ERR_INVALID_SIZE;
	}

	ret = max10_sys_read(dev, doorbell_reg(dev), &doorbell);
	if (ret < 0) {
		dev_err(dev,
			"Failed to read max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	if (SEC_PROGRESS_G(doorbell) != SEC_PROGRESS_READY)
		return IFPGA_SEC_ERR_HW_ERROR;

	ret = dev->bmc_ops.flash_write(dev, dev->staging_area_base + offset,
			smgr->data, len);

	return ret ? IFPGA_SEC_ERR_RW_ERROR : IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err pmci_sec_write_blk(struct ifpga_sec_mgr *smgr,
	uint32_t offset, uint32_t len)
{
	struct intel_max10_device *dev;
	uint32_t doorbell = 0;
	int ret = 0;
	UNUSED(offset);

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;
	if (!dev || !dev->bmc_ops.flash_write)
		return IFPGA_SEC_ERR_HW_ERROR;

	ret = max10_sys_read(dev, doorbell_reg(dev), &doorbell);
	if (ret < 0) {
		dev_err(dev,
			"Failed to read max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	if (SEC_PROGRESS_G(doorbell) != SEC_PROGRESS_READY)
		return IFPGA_SEC_ERR_HW_ERROR;

	ret = dev->bmc_ops.flash_write(dev, 0, smgr->data, len);

	return ret ? IFPGA_SEC_ERR_RW_ERROR : IFPGA_SEC_ERR_NONE;
}

static bool cond_prog_ready(uint32_t doorbell)
{
	return (SEC_PROGRESS_G(doorbell) != SEC_PROGRESS_READY);
}

static enum ifpga_sec_err m10bmc_sec_write_done(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell, status;
	int ret = 0;

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;

	ret = max10_sys_update_bits(dev, doorbell_reg(dev), HOST_STATUS,
		HOST_STATUS_S(HOST_STATUS_WRITE_DONE));
	if (ret < 0) {
		dev_err(dev,
			"Failed to update max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	ret = opae_max10_read_poll_timeout(dev, doorbell_reg(dev),
			doorbell, cond_prog_ready(doorbell),
			IFPGA_NIOS_HANDSHAKE_INTERVAL_US,
			IFPGA_NIOS_HANDSHAKE_TIMEOUT_US);
	if (ret == -ETIMEDOUT) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_TIMEOUT;
	} else if (ret) {
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	ret = m10bmc_sec_status(dev, &status);
	if (ret)
		return IFPGA_SEC_ERR_RW_ERROR;

	if (!rsu_status_ok(status)) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	return IFPGA_SEC_ERR_NONE;
}

static enum ifpga_sec_err m10bmc_sec_check_complete(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell, status, progress;

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;

	if (m10bmc_sec_progress_status(dev, &doorbell, &progress, &status)) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	if (!rsu_status_ok(status)) {
		print_error_regs(dev);
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	if (rsu_progress_done(progress))
		return IFPGA_SEC_ERR_NONE;

	if (rsu_progress_busy(progress))
		return IFPGA_SEC_ERR_BUSY;

	return IFPGA_SEC_ERR_HW_ERROR;
}

static enum ifpga_sec_err m10bmc_sec_cancel(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell = 0;
	int ret = 0;

	if (!smgr || !smgr->max10_dev)
		return IFPGA_SEC_ERR_HW_ERROR;

	dev = smgr->max10_dev;

	ret = max10_sys_read(dev, doorbell_reg(dev), &doorbell);
	if (ret < 0) {
		dev_err(dev,
			"Failed to read max10 doorbell register [e:%d]\n",
			ret);
		return IFPGA_SEC_ERR_RW_ERROR;
	}

	if (SEC_PROGRESS_G(doorbell) != SEC_PROGRESS_READY)
		return IFPGA_SEC_ERR_BUSY;

	ret = max10_sys_update_bits(dev, doorbell_reg(dev), HOST_STATUS,
		HOST_STATUS_S(HOST_STATUS_ABORT_RSU));

	return ret ? IFPGA_SEC_ERR_RW_ERROR : IFPGA_SEC_ERR_NONE;
}

static uint64_t m10bmc_sec_hw_errinfo(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell = IFPGA_HW_ERRINFO_POISON;
	uint32_t auth_result = IFPGA_HW_ERRINFO_POISON;
	uint32_t stat = 0;
	uint32_t prog = 0;

	if (smgr && smgr->max10_dev) {
		dev = smgr->max10_dev;
		switch (smgr->err_code) {
		case IFPGA_SEC_ERR_HW_ERROR:
		case IFPGA_SEC_ERR_TIMEOUT:
		case IFPGA_SEC_ERR_BUSY:
		case IFPGA_SEC_ERR_WEAROUT:
			if (max10_sys_read(dev, doorbell_reg(dev),
					&doorbell))
				doorbell = IFPGA_HW_ERRINFO_POISON;
			if (max10_sys_read(dev, auth_result_reg(dev),
					&auth_result))
				auth_result = IFPGA_HW_ERRINFO_POISON;
			break;
		default:
			doorbell = 0;
			auth_result = 0;
			break;
		}
	}

	stat = SEC_STATUS_G(doorbell);
	prog = SEC_PROGRESS_G(doorbell);
	dev_info(dev, "Current RSU status is %s, progress is %s\n",
		rsu_status_name(stat), rsu_progress_name(prog));

	return (uint64_t)doorbell << 32 | (uint64_t)auth_result;
}

static int m10bmc_sec_fpga_image_load(struct ifpga_sec_mgr *smgr, int page)
{
	struct intel_max10_device *dev = NULL;
	int ret = 0;

	dev_info(dev, "Reload FPGA\n");

	if (!smgr || !smgr->max10_dev)
		return -ENODEV;

	dev = smgr->max10_dev;

	if (dev->flags & MAX10_FLAGS_SECURE) {
		ret = max10_sys_update_bits(dev, FPGA_RECONF_REG,
			SFPGA_RP_LOAD, 0);
		if (ret < 0) {
			dev_err(dev,
				"Failed to update max10 reconfig register [e:%d]\n",
				ret);
			goto end;
		}
		ret = max10_sys_update_bits(dev, FPGA_RECONF_REG,
			SFPGA_RP_LOAD | SFPGA_RECONF_PAGE,
			SFPGA_RP_LOAD | SFPGA_PAGE(page));
		if (ret < 0) {
			dev_err(dev,
				"Failed to update max10 reconfig register [e:%d]\n",
				ret);
			goto end;
		}
	} else {
		ret = max10_sys_update_bits(dev, RSU_REG, FPGA_RP_LOAD, 0);
		if (ret < 0) {
			dev_err(dev,
				"Failed to update max10 rsu register [e:%d]\n",
				ret);
			goto end;
		}
		ret = max10_sys_update_bits(dev, RSU_REG,
			FPGA_RP_LOAD | FPGA_RECONF_PAGE,
			FPGA_RP_LOAD | FPGA_PAGE(page));
		if (ret < 0) {
			dev_err(dev,
				"Failed to update max10 rsu register [e:%d]\n",
				ret);
			goto end;
		}
	}

	ret = max10_sys_update_bits(dev, FPGA_RECONF_REG, COUNTDOWN_START, 0);
	if (ret < 0) {
		dev_err(dev,
			"Failed to update max10 reconfig register [e:%d]\n",
			ret);
		goto end;
	}

	ret = max10_sys_update_bits(dev, FPGA_RECONF_REG, COUNTDOWN_START,
		COUNTDOWN_START);
	if (ret < 0) {
		dev_err(dev,
			"Failed to update max10 reconfig register [e:%d]\n",
			ret);
	}
end:
	if (ret < 0)
		dev_err(dev, "Failed to reload FPGA\n");

	return ret;
}

static int m10bmc_sec_bmc_image_load(struct ifpga_sec_mgr *smgr, int page)
{
	struct intel_max10_device *dev = NULL;
	uint32_t doorbell = 0;
	int ret = 0;

	dev_info(dev, "Reload BMC\n");

	if (!smgr || !smgr->max10_dev)
		return -ENODEV;

	dev = smgr->max10_dev;

	ret = max10_sys_read(dev, doorbell_reg(dev), &doorbell);
	if (ret < 0) {
		dev_err(dev, "Failed to read max10 doorbell register [e:%d]\n",
				ret);
		return ret;
	}

	switch (dev->type) {
	case N3000BMC_SEC:
		if (doorbell & REBOOT_DISABLED)
			return -EBUSY;

		ret = max10_sys_update_bits(dev, doorbell_reg(dev),
			CONFIG_SEL | REBOOT_REQ,
			CONFIG_SEL_S(page) | REBOOT_REQ);
		break;
	case N6000BMC_SEC:
		if (doorbell & PMCI_DRBL_REBOOT_DISABLED)
			return -EBUSY;

		ret = max10_sys_update_bits(dev, m10bmc_base(dev) +
				M10BMC_PMCI_MAX10_RECONF,
				PMCI_MAX10_REBOOT_REQ | PMCI_MAX10_REBOOT_PAGE,
				SET_FIELD(PMCI_MAX10_REBOOT_PAGE, page) |
				PMCI_MAX10_REBOOT_REQ);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int pmci_sec_fpga_image_load(struct ifpga_sec_mgr *smgr,
				    unsigned int val)
{
	struct intel_max10_device *dev;
	int ret;

	if (!smgr || !smgr->max10_dev)
		return -ENODEV;

	dev = smgr->max10_dev;

	if (val > 2) {
		dev_err(dev, "%s invalid reload val = %d\n",
			__func__, val);
		return -EINVAL;
	}

	ret = max10_sys_update_bits(dev,
				 M10BMC_PMCI_FPGA_RECONF,
				 PMCI_FPGA_RP_LOAD, 0);
	if (ret)
		return ret;

	return max10_sys_update_bits(dev,
				  M10BMC_PMCI_FPGA_RECONF,
				  PMCI_FPGA_RECONF_PAGE | PMCI_FPGA_RP_LOAD,
				  SET_FIELD(PMCI_FPGA_RECONF_PAGE, val) |
				  PMCI_FPGA_RP_LOAD);
}

static int n3000_sec_fpga_image_load_0(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_fpga_image_load(smgr, 0);
}

static int n3000_sec_fpga_image_load_1(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_fpga_image_load(smgr, 1);
}

static int n3000_sec_bmc_image_load_0(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 0);
}

static int n3000_sec_bmc_image_load_1(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 1);
}

static int pmci_sec_bmc_image_load_0(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 0);
}

static int pmci_sec_bmc_image_load_1(struct ifpga_sec_mgr *smgr)
{
	return m10bmc_sec_bmc_image_load(smgr, 1);
}

static int pmci_sec_fpga_image_load_0(struct ifpga_sec_mgr *smgr)
{
	return pmci_sec_fpga_image_load(smgr, 0);
}

static int pmci_sec_fpga_image_load_1(struct ifpga_sec_mgr *smgr)
{
	return pmci_sec_fpga_image_load(smgr, 1);
}

static int pmci_sec_fpga_image_load_2(struct ifpga_sec_mgr *smgr)
{
	return pmci_sec_fpga_image_load(smgr, 2);
}

static int pmci_sec_sdm_image_load(struct ifpga_sec_mgr *smgr)
{
	struct intel_max10_device *dev = smgr->max10_dev;

	return max10_sys_update_bits(dev,
			m10bmc_base(dev) + M10BMC_PMCI_SDM_CTRL_STS,
			PMCI_SDM_IMG_REQ, PMCI_SDM_IMG_REQ);
}

static struct image_load n3000_image_load_hndlrs[] = {
	{
		.name = "fpga_factory",
		.load_image = n3000_sec_fpga_image_load_0,
	},
	{
		.name = "fpga_user",
		.load_image = n3000_sec_fpga_image_load_1,
	},
	{
		.name = "bmc_factory",
		.load_image = n3000_sec_bmc_image_load_1,
	},
	{
		.name = "bmc_user",
		.load_image = n3000_sec_bmc_image_load_0,
	},
	{}
};

static struct image_load pmci_image_load_hndlrs[] = {
	{
		.name = "bmc_factory",
		.load_image = pmci_sec_bmc_image_load_0,
	},
	{
		.name = "bmc_user",
		.load_image = pmci_sec_bmc_image_load_1,
	},
	{
		.name = "fpga_factory",
		.load_image = pmci_sec_fpga_image_load_0,
	},
	{
		.name = "fpga_user1",
		.load_image = pmci_sec_fpga_image_load_1,
	},
	{
		.name = "fpga_user2",
		.load_image = pmci_sec_fpga_image_load_2,
	},
	{
		.name = "sdm",
		.load_image = pmci_sec_sdm_image_load,
	},
	{}
};

static const struct ifpga_sec_mgr_ops n3000_sec_ops = {
	.prepare = m10bmc_sec_prepare,
	.write_blk = m10bmc_sec_write_blk,
	.write_done = m10bmc_sec_write_done,
	.check_complete = m10bmc_sec_check_complete,
	.cancel = m10bmc_sec_cancel,
	.get_hw_errinfo = m10bmc_sec_hw_errinfo,
	.image_load = n3000_image_load_hndlrs,
};

static const struct ifpga_sec_mgr_ops pmci_sec_ops = {
	.prepare = m10bmc_sec_prepare,
	.write_blk = pmci_sec_write_blk,
	.write_done = m10bmc_sec_write_done,
	.check_complete = m10bmc_sec_check_complete,
	.cancel = m10bmc_sec_cancel,
	.get_hw_errinfo = m10bmc_sec_hw_errinfo,
	.image_load = pmci_image_load_hndlrs,
};

static const struct fpga_power_on pmci_power_on_image = {
	.avail_image_mask = BIT(FPGA_FACTORY) |
		BIT(FPGA_USER1) | BIT(FPGA_USER2),
	.set_sequence = pmci_set_power_on_image,
	.get_sequence = pmci_get_power_on_image,
};

int init_sec_mgr(struct ifpga_fme_hw *fme, enum fpga_sec_type type)
{
	struct ifpga_hw *hw = NULL;
	opae_share_data *sd = NULL;
	struct ifpga_sec_mgr *smgr = NULL;

	if (!fme || !fme->max10_dev)
		return -ENODEV;

	smgr = (struct ifpga_sec_mgr *)malloc(sizeof(*smgr));
	if (!smgr) {
		dev_err(NULL, "Failed to allocate memory for security manager\n");
		return -ENOMEM;
	}
	fme->sec_mgr = smgr;

	hw = (struct ifpga_hw *)fme->parent;
	if (hw && hw->adapter && hw->adapter->shm.ptr) {
		sd = (opae_share_data *)hw->adapter->shm.ptr;
		smgr->rsu_control = &sd->rsu_ctrl;
		smgr->rsu_status = &sd->rsu_stat;
	} else {
		smgr->rsu_control = NULL;
		smgr->rsu_status = NULL;
	}

	smgr->fme = fme;
	smgr->max10_dev = fme->max10_dev;
	smgr->type = type;

	switch (type) {
	case N3000BMC_SEC:
		smgr->sops = &n3000_sec_ops;
		smgr->copy_speed = IFPGA_N3000_COPY_SPEED;
		break;
	case N6000BMC_SEC:
		smgr->sops = &pmci_sec_ops;
		smgr->copy_speed = IFPGA_N3000_COPY_SPEED;
		smgr->poc = &pmci_power_on_image;
		break;
	default:
		dev_err(NULL, "No operation for security manager\n");
		smgr->sops = NULL;
	}

	return 0;
}

void release_sec_mgr(struct ifpga_fme_hw *fme)
{
	struct ifpga_sec_mgr *smgr = NULL;

	if (fme) {
		smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;
		if (smgr) {
			fme->sec_mgr = NULL;
			free(smgr);
		}
	}
}
