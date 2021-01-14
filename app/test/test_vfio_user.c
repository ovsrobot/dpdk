/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <inttypes.h>
#include <limits.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <sys/mman.h>

#include <rte_vfio_user.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>
#include <rte_pause.h>
#include <rte_log.h>

#include "test.h"

#define REGION_SIZE 0x100

struct server_mem_tb {
	uint32_t entry_num;
	struct rte_vfio_user_mtb_entry entry[];
};

static const char test_sock[] = "/tmp/dpdk_vfio_test";
struct server_mem_tb *server_mem;
int server_irqfd;
atomic_uint test_failed;
atomic_uint server_destroyed;

static int
test_set_dev_info(const char *sock,
	struct vfio_device_info *info)
{
	int ret;

	info->argsz = sizeof(*info);
	info->flags = VFIO_DEVICE_FLAGS_RESET | VFIO_DEVICE_FLAGS_PCI;
	info->num_irqs = VFIO_PCI_NUM_IRQS;
	info->num_regions = VFIO_PCI_NUM_REGIONS;
	ret = rte_vfio_user_set_dev_info(sock, info);
	if (ret) {
		printf("Failed to set device info\n");
		return -1;
	}

	return 0;
}

static ssize_t
test_dev_cfg_rw(struct rte_vfio_user_reg_info *reg, char *buf,
	size_t count, loff_t pos, bool iswrite)
{
	char *loc = (char *)reg->base + pos;

	if (!iswrite) {
		if (pos + count > reg->info->size)
			return -1;
		memcpy(buf, loc, count);
		return count;
	}

	memcpy(loc, buf, count);
	return count;
}

static int
test_set_reg_info(const char *sock_addr,
	struct rte_vfio_user_regions *reg)
{
	struct rte_vfio_user_reg_info *reg_info;
	void *cfg_base = NULL;
	uint32_t i, j, sz = 0, reg_sz = REGION_SIZE;
	int ret;

	reg->reg_num = VFIO_PCI_NUM_REGIONS;
	sz = sizeof(struct vfio_region_info);

	for (i = 0; i < reg->reg_num; i++) {
		reg_info = &reg->reg_info[i];

		reg_info->info = rte_zmalloc(NULL, sz, 0);
		if (!reg_info->info) {
			printf("Failed to alloc vfio region info\n");
			goto err;
		}

		reg_info->priv = NULL;
		reg_info->fd = -1;
		reg_info->info->argsz = sz;
		reg_info->info->cap_offset = sz;
		reg_info->info->index = i;
		reg_info->info->offset = 0;
		reg_info->info->flags = VFIO_REGION_INFO_FLAG_READ |
			VFIO_REGION_INFO_FLAG_WRITE;

		if (i == VFIO_PCI_CONFIG_REGION_INDEX) {
			cfg_base = rte_zmalloc(NULL, reg_sz, 0);
			if (!cfg_base) {
				printf("Failed to alloc cfg space\n");
				goto err;
			}
			reg_info->base = cfg_base;
			reg_info->rw = test_dev_cfg_rw;
			reg_info->info->size = reg_sz;
		} else {
			reg_info->base = NULL;
			reg_info->rw = NULL;
			reg_info->info->size = 0;
		}
	}

	ret = rte_vfio_user_set_reg_info(sock_addr, reg);
	if (ret) {
		printf("Failed to set region info\n");
		return -1;
	}

	return 0;
err:
	for (j = 0; j < i; j++)
		rte_free(reg->reg_info[i].info);
	rte_free(cfg_base);
	return -1;
}

static void
cleanup_reg(struct rte_vfio_user_regions *reg)
{
	struct rte_vfio_user_reg_info *reg_info;
	uint32_t i;

	for (i = 0; i < reg->reg_num; i++) {
		reg_info = &reg->reg_info[i];

		rte_free(reg_info->info);

		if (i == VFIO_PCI_CONFIG_REGION_INDEX)
			rte_free(reg_info->base);
	}
}

static int
test_set_irq_info(const char *sock,
	struct rte_vfio_user_irq_info *info)
{
	struct vfio_irq_info *irq_info;
	int ret;
	uint32_t i;

	info->irq_num = VFIO_PCI_NUM_IRQS;
	for (i = 0; i < info->irq_num; i++) {
		irq_info = &info->irq_info[i];
		irq_info->argsz = sizeof(irq_info);
		irq_info->index = i;

		if (i == VFIO_PCI_MSIX_IRQ_INDEX) {
			irq_info->flags = VFIO_IRQ_INFO_EVENTFD |
				VFIO_IRQ_INFO_NORESIZE;
			irq_info->count = 1;
		} else {
			irq_info->flags = 0;
			irq_info->count = 0;
		}
	}

	ret = rte_vfio_user_set_irq_info(sock, info);
	if (ret) {
		printf("Failed to set irq info\n");
		return -1;
	}

	return 0;
}

static int
test_get_mem(int dev_id)
{
	const struct rte_vfio_user_mem *mem;
	uint32_t entry_sz;

	mem = rte_vfio_user_get_mem_table(dev_id);
	if (!mem) {
		printf("Failed to get memory table\n");
		return -1;
	}

	entry_sz = sizeof(struct rte_vfio_user_mtb_entry) * mem->entry_num;
	server_mem = rte_zmalloc(NULL, sizeof(*server_mem) + entry_sz, 0);

	memcpy(server_mem->entry, mem->entry, entry_sz);
	server_mem->entry_num = mem->entry_num;

	return 0;
}

static int
test_get_irq(int dev_id)
{
	int ret;

	server_irqfd = -1;
	ret = rte_vfio_user_get_irq(dev_id, VFIO_PCI_MSIX_IRQ_INDEX, 1,
		&server_irqfd);
	if (ret) {
		printf("Failed to get IRQ\n");
		return -1;
	}

	return 0;
}

static int
test_create_device(int dev_id)
{
	char sock[PATH_MAX];

	RTE_LOG(DEBUG, USER1, "Device created\n");

	if (rte_vfio_get_sock_addr(dev_id, sock, sizeof(sock))) {
		printf("Failed to get socket addr\n");
		goto err;
	}

	if (strcmp(sock, test_sock)) {
		printf("Wrong socket addr\n");
		goto err;
	}

	printf("Get socket address: TEST OK\n");

	return 0;
err:
	atomic_store(&test_failed, 1);
	return -1;
}

static void
test_destroy_device(int dev_id __rte_unused)
{
	int ret;

	RTE_LOG(DEBUG, USER1, "Device destroyed\n");

	ret = test_get_mem(dev_id);
	if (ret)
		goto err;

	printf("Get memory table: TEST OK\n");

	ret = test_get_irq(dev_id);
	if (ret)
		goto err;

	printf("Get IRQ: TEST OK\n");

	atomic_store(&server_destroyed, 1);
	return;
err:
	atomic_store(&test_failed, 1);
}

static int
test_update_device(int dev_id __rte_unused)
{
	RTE_LOG(DEBUG, USER1, "Device updated\n");

	return 0;
}

static int
test_lock_dp(int dev_id __rte_unused, int lock)
{
	RTE_LOG(DEBUG, USER1, "Device data path %slocked\n", lock ? "" : "un");
	return 0;
}

static int
test_reset_device(int dev_id __rte_unused)
{
	RTE_LOG(DEBUG, USER1, "Device reset\n");
	return 0;
}

const struct rte_vfio_user_notify_ops test_vfio_ops = {
	.new_device = test_create_device,
	.destroy_device = test_destroy_device,
	.update_status = test_update_device,
	.lock_dp = test_lock_dp,
	.reset_device = test_reset_device,
};

static int
test_vfio_user_server(void)
{
	struct vfio_device_info dev_info;
	struct rte_vfio_user_regions *reg;
	struct rte_vfio_user_reg_info *reg_info;
	struct vfio_region_info *info;
	struct rte_vfio_user_irq_info *irq_info;
	struct rte_vfio_user_mtb_entry *ent;
	int ret, err;
	uint32_t i;

	atomic_init(&test_failed, 0);
	atomic_init(&server_destroyed, 0);

	ret = rte_vfio_user_register(test_sock, &test_vfio_ops);
	if (ret) {
		printf("Failed to register\n");
		ret = TEST_FAILED;
		goto err_regis;
	}

	printf("Register device: TEST OK\n");

	reg = rte_zmalloc(NULL, sizeof(*reg) + VFIO_PCI_NUM_REGIONS *
		sizeof(struct rte_vfio_user_reg_info), 0);
	if (!reg) {
		printf("Failed to alloc regions\n");
		ret = TEST_FAILED;
		goto err_reg;
	}

	irq_info = rte_zmalloc(NULL, sizeof(*irq_info) + VFIO_PCI_NUM_IRQS *
		sizeof(struct vfio_irq_info), 0);
	if (!irq_info) {
		printf("Failed to alloc irq info\n");
		ret = TEST_FAILED;
		goto err_irq;
	}

	if (test_set_dev_info(test_sock, &dev_info)) {
		ret = TEST_FAILED;
		goto err_set;
	}

	printf("Set device info: TEST OK\n");

	if (test_set_reg_info(test_sock, reg)) {
		ret = TEST_FAILED;
		goto err_set;
	}

	printf("Set device info: TEST OK\n");

	if (test_set_irq_info(test_sock, irq_info)) {
		ret = TEST_FAILED;
		goto err;
	}

	printf("Set irq info: TEST OK\n");

	ret = rte_vfio_user_start(test_sock);
	if (ret) {
		printf("Failed to start\n");
		ret = TEST_FAILED;
		goto err;
	}

	printf("Start device: TEST OK\n");

	while (atomic_load(&test_failed) == 0 &&
		atomic_load(&server_destroyed) == 0)
		rte_pause();

	if (atomic_load(&test_failed) == 1) {
		printf("Test failed during device running\n");
		ret = TEST_FAILED;
		goto err;
	}

	printf("=================================\n");
	printf("Device layout:\n");
	printf("=================================\n");
	printf("%u regions, %u IRQs\n", dev_info.num_regions,
		dev_info.num_irqs);
	printf("=================================\n");

	reg_info = &reg->reg_info[VFIO_PCI_CONFIG_REGION_INDEX];
	info = reg_info->info;
	printf("Configuration Space:\nsize : 0x%llx, prot: %s%s\n",
		info->size,
		(info->flags & VFIO_REGION_INFO_FLAG_READ) ? "read/" : "",
		(info->flags & VFIO_REGION_INFO_FLAG_WRITE) ? "write" : "");
	rte_hexdump(stdout, "Content", (const void *)reg_info->base,
		info->size);

	printf("=================================\n");
	printf("DMA memory table (Entry num: %u):\n", server_mem->entry_num);

	for (i = 0; i < server_mem->entry_num; i++) {
		ent = &server_mem->entry[i];
		printf("(Entry %u) gpa: 0x%" PRIx64
			", size: 0x%" PRIx64 ", hva: 0x%" PRIx64 "\n"
			", mmap_addr: 0x%" PRIx64 ", mmap_size: 0x%" PRIx64
			", fd: %d\n", i, ent->gpa, ent->size,
			ent->host_user_addr, (uint64_t)ent->mmap_addr,
			ent->mmap_size, ent->fd);
	}

	printf("=================================\n");
	printf("MSI-X Interrupt:\nNumber: %u, irqfd: %s\n",
		irq_info->irq_info[VFIO_PCI_MSIX_IRQ_INDEX].count,
		server_irqfd == -1 ? "Invalid" : "Valid");

	ret = TEST_SUCCESS;

err:
	cleanup_reg(reg);
err_set:
	rte_free(irq_info);
err_irq:
	rte_free(reg);
err_reg:
	err = rte_vfio_user_unregister(test_sock);
	if (err)
		ret = TEST_FAILED;
	else
		printf("Unregister device: TEST OK\n");
err_regis:
	return ret;
}

static int
test_get_dev_info(int dev_id, struct vfio_device_info *info)
{
	int ret;

	ret = rte_vfio_user_get_dev_info(dev_id, info);
	if (ret) {
		printf("Failed to get device info\n");
		return -1;
	}

	return 0;
}

static int
test_get_reg_info(int dev_id, struct vfio_region_info *info)
{
	int ret, fd = -1;

	info->index = VFIO_PCI_CONFIG_REGION_INDEX;
	info->argsz = sizeof(*info);
	ret = rte_vfio_user_get_reg_info(dev_id, info, &fd);
	if (ret) {
		printf("Failed to get region info\n");
		return -1;
	}

	return 0;
}

static int
test_get_irq_info(int dev_id, struct vfio_irq_info *info)
{
	int ret;

	info->index = VFIO_PCI_MSIX_IRQ_INDEX;
	ret = rte_vfio_user_get_irq_info(dev_id, info);
	if (ret) {
		printf("Failed to get irq info\n");
		return -1;
	}

	return 0;
}

static int
test_set_irqs(int dev_id, struct vfio_irq_set *set, int *fd)
{
	int ret;

	*fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (*fd < 0) {
		printf("Failed to create eventfd\n");
		return -1;
	}

	set->argsz = sizeof(*set) + sizeof(int);
	set->count = 1;
	set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	set->start = 0;
	memcpy(set->data, fd, sizeof(*fd));

	ret = rte_vfio_user_set_irqs(dev_id, set);
	if (ret) {
		printf("Failed to set irqs\n");
		return -1;
	}

	return 0;
}

static int
test_dma_map_unmap(int dev_id, struct rte_vfio_user_mem_reg *mem)
{
	int ret, fd = -1;

	mem->fd_offset = 0;
	mem->flags = 0;
	mem->gpa = 0x12345678;
	mem->protection = PROT_READ | PROT_WRITE;
	mem->size = 0x10000;

	/* Map -> Unmap -> Map */
	ret = rte_vfio_user_dma_map(dev_id, mem, &fd, 1);
	if (ret) {
		printf("Failed to dma map\n");
		return -1;
	}

	ret = rte_vfio_user_dma_unmap(dev_id, mem, 1);
	if (ret) {
		printf("Failed to dma unmap\n");
		return -1;
	}

	ret = rte_vfio_user_dma_map(dev_id, mem, &fd, 1);
	if (ret) {
		printf("Failed to dma re-map\n");
		return -1;
	}

	return 0;
}

static int
test_region_read_write(int dev_id, void *read_data, uint64_t sz)
{
	int ret;
	uint32_t data = 0x1A2B3C4D, idx = VFIO_PCI_CONFIG_REGION_INDEX;

	ret = rte_vfio_user_region_write(dev_id, idx, 0, 4, (void *)&data);
	if (ret) {
		printf("Failed to write region\n");
		return -1;
	}

	ret = rte_vfio_user_region_read(dev_id, idx, 0, sz, read_data);
	if (ret) {
		printf("Failed to read region\n");
		return -1;
	}

	return 0;
}

static int
test_vfio_user_client(void)
{
	int ret = 0, dev_id, fd = -1;
	struct vfio_device_info dev_info;
	struct vfio_irq_info irq_info;
	struct rte_vfio_user_mem_reg mem;
	struct vfio_irq_set *set;
	struct vfio_region_info reg_info;
	void *data;

	ret = rte_vfio_user_attach_dev(test_sock);
	if (ret) {
		printf("Failed to attach device\n");
		return TEST_FAILED;
	}

	printf("Attach device: TEST OK\n");

	dev_id = ret;
	ret = rte_vfio_user_reset(dev_id);
	if (ret) {
		printf("Failed to reset device\n");
		return TEST_FAILED;
	}

	printf("Reset device: TEST OK\n");

	if (test_get_dev_info(dev_id, &dev_info))
		return TEST_FAILED;

	printf("Get device info: TEST OK\n");

	if (test_get_reg_info(dev_id, &reg_info))
		return TEST_FAILED;

	printf("Get region info: TEST OK\n");

	if (test_get_irq_info(dev_id, &irq_info))
		return TEST_FAILED;

	printf("Get irq info: TEST OK\n");

	set = rte_zmalloc(NULL, sizeof(*set) + sizeof(int), 0);
	if (!set) {
		printf("Failed to allocate irq set\n");
		return TEST_FAILED;
	}

	data = rte_zmalloc(NULL, reg_info.size, 0);
	if (!data) {
		printf("Failed to allocate data\n");
		ret = TEST_FAILED;
		goto err_data;
	}

	if (test_set_irqs(dev_id, set, &fd)) {
		ret = TEST_FAILED;
		goto err;
	}

	printf("Set irqs: TEST OK\n");

	if (test_dma_map_unmap(dev_id, &mem)) {
		ret = TEST_FAILED;
		goto err;
	}

	printf("DMA map/unmap: TEST OK\n");

	if (test_region_read_write(dev_id, data, reg_info.size)) {
		ret = TEST_FAILED;
		goto err;
	}

	printf("Region read/write: TEST OK\n");

	printf("=================================\n");
	printf("Device layout:\n");
	printf("=================================\n");
	printf("%u regions, %u IRQs\n", dev_info.num_regions,
		dev_info.num_irqs);
	printf("=================================\n");
	printf("Configuration Space:\nsize : 0x%llx, prot: %s%s\n",
		reg_info.size,
		(reg_info.flags & VFIO_REGION_INFO_FLAG_READ) ? "read/" : "",
		(reg_info.flags & VFIO_REGION_INFO_FLAG_WRITE) ? "write" : "");
	rte_hexdump(stdout, "Content", (const void *)data, reg_info.size);

	printf("=================================\n");
	printf("DMA memory table (Entry num: 1):\ngpa: 0x%" PRIx64
		", size: 0x%" PRIx64 ", fd: -1, fd_offset:0x%" PRIx64 "\n",
		mem.gpa, mem.size, mem.fd_offset);
	printf("=================================\n");
	printf("MSI-X Interrupt:\nNumber: %u, irqfd: %s\n", irq_info.count,
		fd == -1 ? "Invalid" : "Valid");

	ret = rte_vfio_user_detach_dev(dev_id);
	if (ret) {
		printf("Failed to detach device\n");
		ret = TEST_FAILED;
		goto err;
	}

	printf("Device detach: TEST OK\n");
err:
	rte_free(data);
err_data:
	rte_free(set);
	return ret;
}

REGISTER_TEST_COMMAND(vfio_user_autotest_client, test_vfio_user_client);
REGISTER_TEST_COMMAND(vfio_user_autotest_server, test_vfio_user_server);
