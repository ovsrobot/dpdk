/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "ifpga_sec_mgr.h"

static struct ifpga_sec_mgr *sec_mgr;

static void lock(struct ifpga_sec_mgr *smgr)
{
	struct ifpga_hw *hw = NULL;

	if (smgr && smgr->fme) {
		hw = (struct ifpga_hw *)smgr->fme->parent;
		if (hw)
			opae_adapter_lock(hw->adapter, -1);
	}
}

static void unlock(struct ifpga_sec_mgr *smgr)
{
	struct ifpga_hw *hw = NULL;

	if (smgr && smgr->fme) {
		hw = (struct ifpga_hw *)smgr->fme->parent;
		if (hw)
			opae_adapter_unlock(hw->adapter);
	}
}

static void set_rsu_control(struct ifpga_sec_mgr *smgr, uint32_t ctrl)
{
	if (smgr && smgr->rsu_control)
		*smgr->rsu_control = ctrl;
}

static uint32_t get_rsu_control(struct ifpga_sec_mgr *smgr)
{
	if (smgr && smgr->rsu_control)
		return *smgr->rsu_control;
	return 0;
}

static void cancel_rsu(struct ifpga_sec_mgr *smgr)
{
	uint32_t ctrl = IFPGA_RSU_CANCEL;

	lock(smgr);
	ctrl |= get_rsu_control(smgr);
	set_rsu_control(smgr, ctrl);
	unlock(smgr);
}

static void set_rsu_status(struct ifpga_sec_mgr *smgr, uint32_t status,
	uint32_t progress)
{
	if (smgr && smgr->rsu_status)
		*smgr->rsu_status = IFPGA_RSU_STATUS(status, progress);
}

static void get_rsu_status(struct ifpga_sec_mgr *smgr, uint32_t *status,
	uint32_t *progress)
{
	if (smgr && smgr->rsu_status) {
		if (status)
			*status = IFPGA_RSU_GET_STAT(*smgr->rsu_status);
		if (progress)
			*progress = IFPGA_RSU_GET_PROG(*smgr->rsu_status);
	}
}

static void update_rsu_stat(struct ifpga_sec_mgr *smgr, uint32_t stat)
{
	uint32_t prog = 0;

	lock(smgr);
	get_rsu_status(smgr, NULL, &prog);
	set_rsu_status(smgr, stat, prog);
	unlock(smgr);
}

static void update_rsu_prog(struct ifpga_sec_mgr *smgr, uint32_t prog)
{
	uint32_t stat = 0;

	lock(smgr);
	get_rsu_status(smgr, &stat, NULL);
	set_rsu_status(smgr, stat, prog);
	unlock(smgr);
}

static void sig_handler(int sig, siginfo_t *info, void *data)
{
	(void)(info);
	(void)(data);

	switch (sig) {
	case SIGINT:
		if (sec_mgr) {
			dev_info(sec_mgr, "Interrupt secure flash update"
				" by keyboard\n");
			cancel_rsu(sec_mgr);
		}
		break;
	default:
		break;
	}
}

static void log_time(time_t t, const char *msg)
{
	uint32_t h = 0;
	uint32_t m = 0;
	uint32_t s = 0;

	if (t < 60) {
		s = (uint32_t)t;
	} else if (t < 3600) {
		s = (uint32_t)(t % 60);
		m = (uint32_t)(t / 60);
	} else {
		s = (uint32_t)(t % 60);
		m = (uint32_t)((t % 3600) / 60);
		h = (uint32_t)(t / 3600);
	}
	printf("%s - %02u:%02u:%02u\n", msg, h, m, s);
}

static enum ifpga_sec_err fpga_sec_dev_prepare(struct ifpga_sec_mgr *smgr)
{
	if (!smgr)
		return IFPGA_SEC_ERR_HW_ERROR;

	if (!smgr->sops || !smgr->sops->prepare)
		return IFPGA_SEC_ERR_NO_FUNC;

	return smgr->sops->prepare(smgr);
}

static int fill_buf(int fd, uint32_t offset, void *buf, uint32_t size)
{
	ssize_t read_size = 0;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -EIO;

	read_size = read(fd, buf, size);
	if (read_size < 0)
		return -EIO;

	if ((uint32_t)read_size != size) {
		dev_err(smgr,
			"Read length %zd is not expected [e:%u]\n",
			read_size, size);
		return -EIO;
	}

	return 0;
}

static enum ifpga_sec_err fpga_sec_dev_write(struct ifpga_sec_mgr *smgr)
{
	void *buf = NULL;
	int fd = -1;
	uint32_t blk_size = 0;
	uint32_t offset = 0;
	uint32_t prog = 0;
	uint32_t old_prog = -1;
	enum ifpga_sec_err ret = 0;

	if (!smgr)
		return IFPGA_SEC_ERR_HW_ERROR;

	if (!smgr->sops || !smgr->sops->write_blk)
		return IFPGA_SEC_ERR_NO_FUNC;

	buf = malloc(IFPGA_RSU_DATA_BLK_SIZE);
	if (!buf) {
		dev_err(smgr, "Failed to allocate memory for flash update\n");
		return IFPGA_SEC_ERR_NO_MEM;
	}
	smgr->data = buf;

	fd = open(smgr->filename, O_RDONLY);
	if (fd < 0) {
		dev_err(smgr,
			"Failed to open \'%s\' for RD [e:%s]\n",
			smgr->filename, strerror(errno));
		return IFPGA_SEC_ERR_FILE_READ;
	}

	while (smgr->remaining_size) {
		if (get_rsu_control(smgr) & IFPGA_RSU_CANCEL) {
			ret = IFPGA_SEC_ERR_CANCELED;
			break;
		}

		blk_size = (smgr->remaining_size > IFPGA_RSU_DATA_BLK_SIZE) ?
			IFPGA_RSU_DATA_BLK_SIZE : smgr->remaining_size;
		if (fill_buf(fd, offset, buf, blk_size)) {
			ret = IFPGA_SEC_ERR_FILE_READ;
			break;
		}

		ret = smgr->sops->write_blk(smgr, offset, blk_size);
		if (ret != IFPGA_SEC_ERR_NONE)
			break;

		smgr->remaining_size -= blk_size;
		offset += blk_size;

		/* output progress percent */
		prog = offset / smgr->one_percent;
		if (prog != old_prog) {
			printf("\r%d%%", prog);
			fflush(stdout);
			update_rsu_prog(smgr, prog);
			old_prog = prog;
		}
	}

	if (ret == IFPGA_SEC_ERR_NONE) {
		update_rsu_prog(smgr, 100);
		printf("\r100%%\n");
	} else {
		printf("\n");
	}

	close(fd);
	smgr->data = NULL;
	free(buf);
	return ret;
}

static enum ifpga_sec_err fpga_sec_dev_poll_complete(struct ifpga_sec_mgr *smgr)
{
	uint32_t one_percent_time = 0;
	uint32_t prog = 0;
	uint32_t old_prog = -1;
	uint32_t copy_time = 0;
	int timeout = 2400;   /* 2400 seconds */
	enum ifpga_sec_err ret = 0;

	if (!smgr)
		return IFPGA_SEC_ERR_HW_ERROR;

	if (!smgr->sops || !smgr->sops->write_done ||
		!smgr->sops->check_complete)
		return IFPGA_SEC_ERR_NO_FUNC;

	if (smgr->sops->write_done(smgr) != IFPGA_SEC_ERR_NONE) {
		dev_err(smgr, "Failed to apply flash update\n");
		return IFPGA_SEC_ERR_HW_ERROR;
	}

	/* calculate time period of one percent */
	if (smgr->copy_speed == 0)   /* avoid zero divide fault */
		smgr->copy_speed = 1;
	one_percent_time = (smgr->one_percent + smgr->copy_speed) /
		smgr->copy_speed;
	if (one_percent_time == 0)   /* avoid zero divide fault */
		one_percent_time = 1;

	while (true) {
		sleep(1);
		ret = smgr->sops->check_complete(smgr);
		if (ret != IFPGA_SEC_ERR_BUSY)
			break;
		if (--timeout < 0) {
			ret = IFPGA_SEC_ERR_TIMEOUT;
			break;
		}

		/* output progress percent */
		copy_time += 1;
		prog = copy_time / one_percent_time;
		if (prog >= 100)
			prog = 99;
		if (prog != old_prog) {
			printf("\r%d%%", prog);
			fflush(stdout);
			update_rsu_prog(smgr, prog);
			old_prog = prog;
		}
	}

	if (ret == IFPGA_SEC_ERR_NONE) {
		update_rsu_prog(smgr, 100);
		printf("\r100%%\n");
	} else {
		printf("\n");
	}

	return ret;
}

static enum ifpga_sec_err fpga_sec_dev_cancel(struct ifpga_sec_mgr *smgr)
{
	if (!smgr)
		return IFPGA_SEC_ERR_HW_ERROR;

	if (!smgr->sops || !smgr->sops->cancel)
		return IFPGA_SEC_ERR_NO_FUNC;

	return smgr->sops->cancel(smgr);
}

static void set_error(struct ifpga_sec_mgr *smgr, enum ifpga_sec_err err_code)
{
	uint32_t stat = 0;

	lock(smgr);
	get_rsu_status(smgr, &stat, NULL);
	set_rsu_status(smgr, stat, stat);
	smgr->err_code = err_code;
	unlock(smgr);
}

static int progress_transition(struct ifpga_sec_mgr *smgr,
	uint32_t new_progress)
{
	if (get_rsu_control(smgr) & IFPGA_RSU_CANCEL) {
		set_error(smgr, IFPGA_SEC_ERR_CANCELED);
		smgr->sops->cancel(smgr);
		return -ECANCELED;
	}

	set_rsu_status(smgr, new_progress, 0);
	return 0;
}

static void progress_complete(struct ifpga_sec_mgr *smgr)
{
	update_rsu_stat(smgr, IFPGA_RSU_IDLE);
}

static void fpga_sec_dev_error(struct ifpga_sec_mgr *smgr,
	enum ifpga_sec_err err_code)
{
	set_error(smgr, err_code);
	if (smgr->sops->get_hw_errinfo)
		smgr->hw_errinfo = smgr->sops->get_hw_errinfo(smgr);
	if (smgr->sops->cancel)
		smgr->sops->cancel(smgr);
}

static int fpga_sec_mgr_update(struct ifpga_sec_mgr *smgr)
{
	int fd = -1;
	off_t len = 0;
	struct sigaction old_sigint_action;
	struct sigaction sa;
	time_t start;
	enum ifpga_sec_err ret = 0;

	if (!smgr) {
		dev_err(smgr, "Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	fd = open(smgr->filename, O_RDONLY);
	if (fd < 0) {
		dev_err(smgr,
			"Failed to open \'%s\' for RD [e:%s]\n",
			smgr->filename, strerror(errno));
		return -EIO;
	}
	len = lseek(fd, 0, SEEK_END);
	close(fd);

	if (len < 0) {
		dev_err(smgr,
			"Failed to get file length of \'%s\' [e:%s]\n",
			smgr->filename, strerror(errno));
		return -EIO;
	}
	if (len == 0) {
		dev_err(smgr, "Length of file \'%s\' is invalid\n",
			smgr->filename);
		set_error(smgr, IFPGA_SEC_ERR_INVALID_SIZE);
		return -EINVAL;
	}
	smgr->remaining_size = len;
	smgr->one_percent = smgr->remaining_size / 100;

	printf("Updating from file \'%s\' with size %u\n",
		smgr->filename, smgr->remaining_size);

	/* setup signal handler */
	sec_mgr = smgr;
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sa.sa_sigaction = sig_handler;
	ret = sigaction(SIGINT, &sa, &old_sigint_action);
	if (ret < 0) {
		dev_warn(dev, "Failed to register signal handler"
			" [e:%d]\n", ret);
		sec_mgr = NULL;
	}
	start = time(NULL);

	log_time(time(NULL) - start, "Starting secure flash update");
	if (progress_transition(smgr, IFPGA_RSU_PREPARING)) {
		ret = smgr->err_code;
		goto exit;
	}

	ret = fpga_sec_dev_prepare(smgr);
	if (ret != IFPGA_SEC_ERR_NONE) {
		fpga_sec_dev_error(smgr, ret);
		goto exit;
	}

	log_time(time(NULL) - start, "Writing to staging area");
	if (progress_transition(smgr, IFPGA_RSU_WRITING)) {
		ret = smgr->err_code;
		goto done;
	}

	ret = fpga_sec_dev_write(smgr);
	if (ret != IFPGA_SEC_ERR_NONE) {
		fpga_sec_dev_error(smgr, ret);
		goto done;
	}

	log_time(time(NULL) - start, "Applying secure flash update");
	if (progress_transition(smgr, IFPGA_RSU_PROGRAMMING)) {
		ret = smgr->err_code;
		goto done;
	}

	ret = fpga_sec_dev_poll_complete(smgr);
	if (ret != IFPGA_SEC_ERR_NONE)
		fpga_sec_dev_error(smgr, ret);

done:
	if (smgr->sops->cleanup)
		smgr->sops->cleanup(smgr);

exit:
	if (ret != IFPGA_SEC_ERR_NONE)
		log_time(time(NULL) - start, "Secure flash update ERROR");
	else
		log_time(time(NULL) - start, "Secure flash update OK");

	if (sec_mgr) {
		sec_mgr = NULL;
		if (sigaction(SIGINT, &old_sigint_action, NULL) < 0)
			dev_err(smgr, "Failed to unregister signal handler\n");
	}

	progress_complete(smgr);

	dev_info(smgr, "Return %d\n", ret);
	return ret == IFPGA_SEC_ERR_NONE ? 0 : -1;
}

int fpga_update_flash(struct ifpga_fme_hw *fme, const char *image,
	uint64_t *status)
{
	struct ifpga_sec_mgr *smgr = NULL;
	uint32_t rsu_stat = 0;
	int ret = 0;

	if (!fme || !image || !status) {
		dev_err(fme, "Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;
	if (!smgr) {
		dev_err(smgr, "Security manager not initialized\n");
		return -ENODEV;
	}
	if (!smgr->sops) {
		dev_err(smgr, "Security manager not support flash update\n");
		return -EOPNOTSUPP;
	}

	lock(smgr);
	get_rsu_status(smgr, &rsu_stat, NULL);
	if (rsu_stat != IFPGA_RSU_IDLE) {
		unlock(smgr);
		if (rsu_stat == IFPGA_RSU_REBOOT)
			dev_info(smgr, "Reboot is in progress\n");
		else
			dev_info(smgr, "Update is in progress\n");
		return -EAGAIN;
	}
	set_rsu_control(smgr, 0);
	set_rsu_status(smgr, IFPGA_RSU_PREPARING, 0);

	smgr->filename = image;
	smgr->err_code = IFPGA_SEC_ERR_NONE;
	smgr->hw_errinfo = 0;
	unlock(smgr);

	ret = fpga_sec_mgr_update(smgr);
	*status = smgr->hw_errinfo;

	return ret;
}

int fpga_stop_flash_update(struct ifpga_fme_hw *fme, int force)
{
	struct ifpga_sec_mgr *smgr = NULL;
	uint32_t status = 0;
	int retry = IFPGA_RSU_CANCEL_RETRY;
	int ret = 0;

	if (!fme) {
		dev_err(fme, "Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}
	smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;

	get_rsu_status(smgr, &status, NULL);
	if (status != IFPGA_RSU_IDLE) {
		dev_info(smgr, "Cancel secure flash update\n");
		cancel_rsu(smgr);
	}

	if (force) {
		sleep(2);
		do {
			get_rsu_status(smgr, &status, NULL);
			if (status == IFPGA_RSU_IDLE)
				break;
			if (fpga_sec_dev_cancel(smgr) == IFPGA_SEC_ERR_NONE)
				update_rsu_stat(smgr, IFPGA_RSU_IDLE);
			sleep(1);
		} while (--retry > 0);
		if (retry <= 0) {
			dev_err(smgr, "Failed to stop flash update\n");
			ret = -EAGAIN;
		}
	}

	return ret;
}

int fpga_reload(struct ifpga_fme_hw *fme, char *str)
{
	struct ifpga_sec_mgr *smgr = NULL;
	const struct image_load *hndlr = NULL;
	int ret = -EOPNOTSUPP;

	if (!fme) {
		dev_err(fme, "Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}
	smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;

	if (!smgr)
		return -ENODEV;

	if (!smgr->sops || !smgr->sops->image_load)
		return -EOPNOTSUPP;

	for (hndlr = smgr->sops->image_load; hndlr->name; hndlr++) {
		if (!strcmp(str, hndlr->name)) {
			ret = hndlr->load_image(smgr);
			break;
		}
	}

	return ret;
}

int fpga_available_images(struct ifpga_fme_hw *fme, char *buf, size_t size)
{
	struct ifpga_sec_mgr *smgr = NULL;
	const struct image_load *hndlr = NULL;
	size_t count = 0;

	if (!fme) {
		dev_err(fme, "Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}
	smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;

	if (!smgr)
		return -ENODEV;

	if (!smgr->sops || !smgr->sops->image_load)
		return 0;

	if (buf) {
		for (hndlr = smgr->sops->image_load; hndlr->name; hndlr++) {
			if ((size > count) &&
				((size - count) > strlen(hndlr->name))) {
				count += snprintf(buf + count, size - count,
					"%s ", hndlr->name);
			}
		}
		buf[count - 1] = '\0';
	} else {
		for (hndlr = smgr->sops->image_load; hndlr->name; hndlr++)
			count += strlen(hndlr->name) + 1;
	}

	return count;
}

int fpga_set_poc_image(struct ifpga_fme_hw *fme, char *buf)
{
	struct ifpga_sec_mgr *smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;

	if (!smgr)
		return -ENODEV;

	return pmci_set_poc_image(smgr, buf);
}

int fpga_get_poc_images(struct ifpga_fme_hw *fme, char *buf, size_t size)
{
	struct ifpga_sec_mgr *smgr = (struct ifpga_sec_mgr *)fme->sec_mgr;

	if (!smgr)
		return -ENODEV;

	return pmci_get_poc_images(smgr, buf, size);
}
