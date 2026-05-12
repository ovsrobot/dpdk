/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <inttypes.h>
#include <rte_version.h>
#include <eal_export.h>

#include "sxe2_osal.h"
#include "sxe2_errno.h"
#include "sxe2_common_log.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_ioctl_chnl_func.h"

#define SXE2_CHR_DEV_NAME "/dev/sxe2-dpdk-"

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_cmd_close)
void
sxe2_drv_cmd_close(struct sxe2_common_device *cdev)
{
	cdev->config.kernel_reset = true;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_cmd_exec)
s32
sxe2_drv_cmd_exec(struct sxe2_common_device *cdev,
		struct sxe2_drv_cmd_params *cmd_params)
{
	s32 cmd_fd;
	s32 ret = -EIO;

	if (cdev->config.kernel_reset) {
		ret = -EPERM;
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_end;
	}

	cmd_fd = SXE2_CDEV_TO_CMD_FD(cdev);
	if (cmd_fd < 0) {
		ret = -EBADF;
		PMD_LOG_ERR(COM, "Fail to exec cmd, fd[%d] error", cmd_fd);
		goto l_end;
	}

	PMD_LOG_DEBUG(COM, "Exec drv cmd fd[%d] trace_id[0x%"PRIx64"]"
			"opcode[0x%x] req_len[%d] resp_len[%d]",
			cmd_fd, cmd_params->trace_id, cmd_params->opcode,
			cmd_params->req_len, cmd_params->resp_len);

	rte_ticketlock_lock(&cdev->config.lock);
	ret = ioctl(cmd_fd, SXE2_COM_CMD_PASSTHROUGH, cmd_params);
	if (ret < 0) {
		PMD_LOG_ERR(COM, "Fail to exec cmd, fd[%d] opcode[0x%x] ret[%d], err:%s",
				cmd_fd, cmd_params->opcode, ret, strerror(errno));
		ret = -errno;
		rte_ticketlock_unlock(&cdev->config.lock);
		goto l_end;
	}
	rte_ticketlock_unlock(&cdev->config.lock);

l_end:
	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_open)
s32
sxe2_drv_dev_open(struct sxe2_common_device *cdev, struct rte_pci_device *pci_dev)
{
	s32 ret = SXE2_SUCCESS;
	s32 fd = 0;
	char drv_name[32] = {0};

	snprintf(drv_name, sizeof(drv_name),
				"%s%04"PRIx32":%02"PRIx8":%02"PRIx8".%"PRIx8,
				SXE2_CHR_DEV_NAME,
				pci_dev->addr.domain,
				pci_dev->addr.bus,
				pci_dev->addr.devid,
				pci_dev->addr.function);

	fd = open(drv_name, O_RDWR);
	if (fd < 0) {
		ret = -EBADF;
		PMD_LOG_ERR(COM, "Fail to open device:%s, ret=%d, err:%s",
				drv_name, ret, strerror(errno));
		goto l_end;
	}

	SXE2_CDEV_TO_CMD_FD(cdev) = fd;

	PMD_LOG_INFO(COM, "Successfully opened device:%s, fd=%d",
				drv_name, SXE2_CDEV_TO_CMD_FD(cdev));

l_end:
	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_close)
void
sxe2_drv_dev_close(struct sxe2_common_device *cdev)
{
	s32 fd = SXE2_CDEV_TO_CMD_FD(cdev);

	if (fd >= 0)
		close(fd);
	PMD_LOG_INFO(COM, "closed device fd=%d", fd);
	SXE2_CDEV_TO_CMD_FD(cdev) = -1;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_handshark)
s32
sxe2_drv_dev_handshark(struct sxe2_common_device *cdev)
{
	s32 ret = SXE2_SUCCESS;
	s32 cmd_fd = 0;
	struct sxe2_ioctl_cmd_common_hdr cmd_params;

	if (cdev->config.kernel_reset) {
		ret = -EPERM;
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_end;
	}

	cmd_fd = SXE2_CDEV_TO_CMD_FD(cdev);
	if (cmd_fd < 0) {
		ret = -EBADF;
		PMD_LOG_ERR(COM, "Failed to exec cmd, fd=%d", cmd_fd);
		goto l_end;
	}

	PMD_LOG_DEBUG(COM, "Open fd=%d to handshark with kernel", cmd_fd);

	memset(&cmd_params, 0, sizeof(struct sxe2_ioctl_cmd_common_hdr));
	cmd_params.dpdk_ver = SXE2_COM_VER;
	cmd_params.msg_len = sizeof(struct sxe2_ioctl_cmd_common_hdr);

	rte_ticketlock_lock(&cdev->config.lock);
	ret = ioctl(cmd_fd, SXE2_COM_CMD_HANDSHAKE, &cmd_params);
	if (ret < 0) {
		PMD_LOG_ERR(COM, "Failed to handshark, fd=%d, ret=%d, err:%s",
				cmd_fd, ret, strerror(errno));
		ret = -EIO;
		rte_ticketlock_unlock(&cdev->config.lock);
		goto l_end;
	}
	rte_ticketlock_unlock(&cdev->config.lock);

	if (cmd_params.cap & BIT(SXE2_COM_CAP_IOMMU_MAP))
		cdev->config.support_iommu = true;
	else
		cdev->config.support_iommu = false;

l_end:
	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_mmap)
void
*sxe2_drv_dev_mmap(struct sxe2_common_device *cdev, u8 bar_idx, u64 len, u64 offset)
{
	s32 cmd_fd = 0;
	void *virt = NULL;

	if (cdev->config.kernel_reset) {
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_err;
	}

	cmd_fd = SXE2_CDEV_TO_CMD_FD(cdev);
	if (cmd_fd < 0) {
		PMD_LOG_ERR(COM, "Failed to exec cmd, fd=%d", cmd_fd);
		goto l_err;
	}

	PMD_LOG_DEBUG(COM, "fd=%d, bar idx=%d, len=%"PRIu64", src=0x%"PRIx64", offset=0x%"PRIx64"",
		bar_idx, cmd_fd, len, offset, SXE2_COM_PCI_OFFSET_GEN(bar_idx, offset));

	virt = mmap(NULL, len, PROT_READ | PROT_WRITE,
		MAP_SHARED, cmd_fd, SXE2_COM_PCI_OFFSET_GEN(bar_idx, offset));
	if (virt == MAP_FAILED) {
		PMD_LOG_ERR(COM, "Failed mmap, cmd_fd=%d, len=%"PRIu64", offset=0x%"PRIx64", err:%s",
			cmd_fd, len, offset, strerror(errno));
		goto l_err;
	}

	return virt;
l_err:
	return NULL;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_munmap)
s32
sxe2_drv_dev_munmap(struct sxe2_common_device *cdev, void *virt, u64 len)
{
	s32 ret = SXE2_SUCCESS;

	if (cdev->config.kernel_reset) {
		ret = -EPERM;
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_end;
	}

	PMD_LOG_DEBUG(COM, "Munmap virt=%p, len=0x%"PRIx64"",
		virt, len);

	ret = munmap(virt, len);
	if (ret < 0) {
		PMD_LOG_ERR(COM, "Failed to munmap, virt=%p, len=%"PRIu64", err:%s",
			virt, len, strerror(errno));
		ret = -EIO;
		goto l_end;
	}

l_end:
	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_dma_map)
s32
sxe2_drv_dev_dma_map(struct sxe2_common_device *cdev, u64 vaddr,
			u64 iova, u64 size)
{
	struct sxe2_ioctl_iommu_dma_map cmd_params;
	enum rte_iova_mode iova_mode;
	s32 ret = SXE2_SUCCESS;
	s32 cmd_fd = 0;

	if (cdev->config.kernel_reset) {
		ret = -EPERM;
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_end;
	}

	iova_mode = rte_eal_iova_mode();
	if (iova_mode == RTE_IOVA_PA) {
		if (cdev->config.support_iommu) {
			PMD_LOG_ERR(COM, "iommu not support pa mode");
			ret = -EIO;
		}
		goto l_end;
	} else if (iova_mode == RTE_IOVA_VA) {
		if (!cdev->config.support_iommu) {
			PMD_LOG_ERR(COM, "no iommu not support va mode, please use pa mode.");
			ret = -EIO;
			goto l_end;
		}
	}

	cmd_fd = SXE2_CDEV_TO_CMD_FD(cdev);
	if (cmd_fd < 0) {
		ret = -EBADF;
		PMD_LOG_ERR(COM, "Failed to exec cmd, fd=%d", cmd_fd);
		goto l_end;
	}

	memset(&cmd_params, 0, sizeof(struct sxe2_ioctl_iommu_dma_map));
	cmd_params.vaddr = vaddr;
	cmd_params.iova = iova;
	cmd_params.size = size;

	rte_ticketlock_lock(&cdev->config.lock);
	ret = ioctl(cmd_fd, SXE2_COM_CMD_DMA_MAP, &cmd_params);
	if (ret < 0) {
		PMD_LOG_ERR(COM, "Failed to dma map, fd=%d, ret=%d, err:%s",
				cmd_fd, ret, strerror(errno));
		ret = -EIO;
		rte_ticketlock_unlock(&cdev->config.lock);
		goto l_end;
	}
	rte_ticketlock_unlock(&cdev->config.lock);

l_end:
	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_drv_dev_dma_unmap)
s32
sxe2_drv_dev_dma_unmap(struct sxe2_common_device *cdev, u64 iova)
{
	s32 ret = SXE2_SUCCESS;
	s32 cmd_fd = 0;
	struct sxe2_ioctl_iommu_dma_unmap cmd_params;

	if (cdev->config.kernel_reset) {
		ret = -EPERM;
		PMD_LOG_WARN(COM, "kernel reset, need restart app.");
		goto l_end;
	}

	if (!cdev->config.support_iommu)
		goto l_end;

	cmd_fd = SXE2_CDEV_TO_CMD_FD(cdev);
	if (cmd_fd < 0) {
		ret = -EBADF;
		PMD_LOG_ERR(COM, "Failed to exec cmd, fd=%d", cmd_fd);
		goto l_end;
	}

	PMD_LOG_DEBUG(COM, "fd %d dma unmap iova=0x%"PRIX64"",
		cmd_fd, iova);

	memset(&cmd_params, 0, sizeof(struct sxe2_ioctl_iommu_dma_unmap));
	cmd_params.iova = iova;

	rte_ticketlock_lock(&cdev->config.lock);
	ret = ioctl(cmd_fd, SXE2_COM_CMD_DMA_UNMAP, &cmd_params);
	if (ret < 0) {
		PMD_LOG_INFO(COM, "Failed to dma unmap, fd=%d, ret=%d, err:%s",
				cmd_fd, ret, strerror(errno));
		ret = -EIO;
		rte_ticketlock_unlock(&cdev->config.lock);
		goto l_end;
	}
	rte_ticketlock_unlock(&cdev->config.lock);

l_end:
	return ret;
}

