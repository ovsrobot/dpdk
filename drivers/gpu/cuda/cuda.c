/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_dev.h>

#include <gpudev_driver.h>
#include <cuda.h>

/* NVIDIA GPU vendor */
#define NVIDIA_GPU_VENDOR_ID (0x10de)

/* NVIDIA GPU device IDs */
#define NVIDIA_GPU_A100_40GB_DEVICE_ID (0x20f1)
#define NVIDIA_GPU_A100_80GB_DEVICE_ID (0x20b5)

#define NVIDIA_GPU_A30_24GB_DEVICE_ID (0x20b7)
#define NVIDIA_GPU_A10_24GB_DEVICE_ID (0x2236)

#define NVIDIA_GPU_V100_32GB_DEVICE_ID (0x1db6)
#define NVIDIA_GPU_V100_16GB_DEVICE_ID (0x1db4)

#define CUDA_MAX_ALLOCATION_NUM 512

#define GPU_PAGE_SHIFT 16
#define GPU_PAGE_SIZE (1UL << GPU_PAGE_SHIFT)

static RTE_LOG_REGISTER_DEFAULT(cuda_logtype, NOTICE);

/** Helper macro for logging */
#define rte_gpu_cuda_log(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, cuda_logtype, fmt "\n", ##__VA_ARGS__)

#define rte_gpu_cuda_log_debug(fmt, ...) \
	rte_gpu_cuda_log(DEBUG, RTE_STR(__LINE__) ":%s() " fmt, __func__, \
		##__VA_ARGS__)

/* NVIDIA GPU address map */
static struct rte_pci_id pci_id_cuda_map[] = {
	{
		RTE_PCI_DEVICE(NVIDIA_GPU_VENDOR_ID,
				NVIDIA_GPU_A100_40GB_DEVICE_ID)
	},
	{
		RTE_PCI_DEVICE(NVIDIA_GPU_VENDOR_ID,
				NVIDIA_GPU_V100_32GB_DEVICE_ID)
	},
	/* {.device_id = 0}, ?? */
};

/* Device private info */
struct cuda_info {
	char gpu_name[RTE_DEV_NAME_MAX_LEN];
	CUdevice cu_dev;
};

/* Type of memory allocated by CUDA driver */
enum mem_type {
	GPU_MEM = 0,
	CPU_REGISTERED,
	GPU_REGISTERED /* Not used yet */
};

/* key associated to a memory address */
typedef uintptr_t cuda_ptr_key;

/* Single entry of the memory list */
struct mem_entry {
	CUdeviceptr ptr_d;
	void *ptr_h;
	size_t size;
	struct rte_gpu *dev;
	CUcontext ctx;
	cuda_ptr_key pkey;
	enum mem_type mtype;
	struct mem_entry *prev;
	struct mem_entry *next;
};

static struct mem_entry *mem_alloc_list_head;
static struct mem_entry *mem_alloc_list_tail;
static uint32_t mem_alloc_list_last_elem;

/* Generate a key from a memory pointer */
static cuda_ptr_key
get_hash_from_ptr(void *ptr)
{
	return (uintptr_t) ptr;
}

static uint32_t
mem_list_count_item(void)
{
	return mem_alloc_list_last_elem;
}

/* Initiate list of memory allocations if not done yet */
static struct mem_entry *
mem_list_add_item(void)
{
	/* Initiate list of memory allocations if not done yet */
	if (mem_alloc_list_head == NULL) {
		mem_alloc_list_head = rte_zmalloc(NULL,
						sizeof(struct mem_entry),
						RTE_CACHE_LINE_SIZE);
		if (mem_alloc_list_head == NULL) {
			rte_gpu_cuda_log(ERR, "Failed to allocate memory for memory list.\n");
			return NULL;
		}

		mem_alloc_list_head->next = NULL;
		mem_alloc_list_head->prev = NULL;
		mem_alloc_list_tail = mem_alloc_list_head;
	} else {
		struct mem_entry *mem_alloc_list_cur = rte_zmalloc(NULL,
								sizeof(struct mem_entry),
								RTE_CACHE_LINE_SIZE);

		if (mem_alloc_list_cur == NULL) {
			rte_gpu_cuda_log(ERR, "Failed to allocate memory for memory list.\n");
			return NULL;
		}

		mem_alloc_list_tail->next = mem_alloc_list_cur;
		mem_alloc_list_cur->prev = mem_alloc_list_tail;
		mem_alloc_list_tail = mem_alloc_list_tail->next;
		mem_alloc_list_tail->next = NULL;
	}

	mem_alloc_list_last_elem++;

	return mem_alloc_list_tail;
}

static struct mem_entry *
mem_list_find_item(cuda_ptr_key pk)
{
	struct mem_entry *mem_alloc_list_cur = NULL;

	if (mem_alloc_list_head == NULL) {
		rte_gpu_cuda_log(ERR, "Memory list doesn't exist\n");
		return NULL;
	}

	if (mem_list_count_item() == 0) {
		rte_gpu_cuda_log(ERR, "No items in memory list\n");
		return NULL;
	}

	mem_alloc_list_cur = mem_alloc_list_head;

	while (mem_alloc_list_cur != NULL) {
		if (mem_alloc_list_cur->pkey == pk)
			return mem_alloc_list_cur;
		mem_alloc_list_cur = mem_alloc_list_cur->next;
	}

	return mem_alloc_list_cur;
}

static int
mem_list_del_item(cuda_ptr_key pk)
{
	struct mem_entry *mem_alloc_list_cur = NULL;

	mem_alloc_list_cur = mem_list_find_item(pk);
	if (mem_alloc_list_cur == NULL)
		return -EINVAL;

	/* if key is in head */
	if (mem_alloc_list_cur->prev == NULL)
		mem_alloc_list_head = mem_alloc_list_cur->next;
	else {
		mem_alloc_list_cur->prev->next = mem_alloc_list_cur->next;
		if (mem_alloc_list_cur->next != NULL)
			mem_alloc_list_cur->next->prev = mem_alloc_list_cur->prev;
	}

	rte_free(mem_alloc_list_cur);

	mem_alloc_list_last_elem--;

	return 0;
}

static int
cuda_dev_info_get(struct rte_gpu *dev, struct rte_gpu_info *info)
{
	int ret = 0;
	CUresult res;
	struct rte_gpu_info parent_info;
	CUexecAffinityParam affinityPrm;
	const char *err_string;
	struct cuda_info *private;
	CUcontext current_ctx;
	CUcontext input_ctx;

	if (dev == NULL)
		return -EINVAL;

	/* Child initialization time probably called by rte_gpu_add_child() */
	if (dev->mpshared->info.parent != RTE_GPU_ID_NONE && dev->mpshared->dev_private == NULL) {
		/* Store current ctx */
		res = cuCtxGetCurrent(&current_ctx);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuCtxGetCurrent failed with %s.\n", err_string);

			return -1;
		}

		/* Set child ctx as current ctx */
		input_ctx = (CUcontext)dev->mpshared->info.context;
		res = cuCtxSetCurrent(input_ctx);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuCtxSetCurrent input failed with %s.\n", err_string);

			return -1;
		}

		/*
		 * Ctx capacity info
		 */

		/* MPS compatible */
		res = cuCtxGetExecAffinity(&affinityPrm, CU_EXEC_AFFINITY_TYPE_SM_COUNT);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuCtxGetExecAffinity failed with %s.\n", err_string);
		}
		dev->mpshared->info.processor_count = (uint32_t)affinityPrm.param.smCount.val;

		ret = rte_gpu_info_get(dev->mpshared->info.parent, &parent_info);
		if (ret)
			return -ENODEV;
		dev->mpshared->info.total_memory = parent_info.total_memory;

		/*
		 * GPU Device private info
		 */
		dev->mpshared->dev_private = rte_zmalloc(NULL,
							sizeof(struct cuda_info),
							RTE_CACHE_LINE_SIZE);
		if (dev->mpshared->dev_private == NULL) {
			rte_gpu_cuda_log(ERR, "Failed to allocate memory for GPU process private.\n");

			return -1;
		}

		private = (struct cuda_info *)dev->mpshared->dev_private;

		res = cuCtxGetDevice(&(private->cu_dev));
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuCtxGetDevice failed with %s.\n", err_string);

			return -1;
		}

		res = cuDeviceGetName(private->gpu_name, RTE_DEV_NAME_MAX_LEN, private->cu_dev);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuDeviceGetName failed with %s.\n", err_string);

			return -1;
		}

		/* Restore original ctx as current ctx */
		res = cuCtxSetCurrent(current_ctx);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuCtxSetCurrent current failed with %s.\n", err_string);

			return -1;
		}
	}

	*info = dev->mpshared->info;

	return 0;
}

/*
 * GPU Memory
 */

static int
cuda_mem_alloc(struct rte_gpu *dev, size_t size, void **ptr)
{
	CUresult res;
	const char *err_string;
	CUcontext current_ctx;
	CUcontext input_ctx;
	unsigned int flag = 1;

	if (dev == NULL || size == 0)
		return -EINVAL;

	/* Store current ctx */
	res = cuCtxGetCurrent(&current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxGetCurrent failed with %s.\n", err_string);

		return -1;
	}

	/* Set child ctx as current ctx */
	input_ctx = (CUcontext)dev->mpshared->info.context;
	res = cuCtxSetCurrent(input_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxSetCurrent input failed with %s.\n", err_string);

		return -1;
	}

	/* Get next memory list item */
	mem_alloc_list_tail = mem_list_add_item();
	if (mem_alloc_list_tail == NULL)
		return -ENOMEM;

	/* Allocate memory */
	mem_alloc_list_tail->size = size;
	res = cuMemAlloc(&(mem_alloc_list_tail->ptr_d), mem_alloc_list_tail->size);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuCtxSetCurrent current failed with %s.\n",
				err_string);

		return -1;
	}

	/* GPUDirect RDMA attribute required */
	res = cuPointerSetAttribute(&flag,
					CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
					mem_alloc_list_tail->ptr_d);
	if (res != CUDA_SUCCESS) {
		rte_gpu_cuda_log(ERR,
				"Could not set SYNC MEMOP attribute for GPU memory at %llx , err %d\n",
				mem_alloc_list_tail->ptr_d, res);
		return -1;
	}

	mem_alloc_list_tail->pkey = get_hash_from_ptr((void *) mem_alloc_list_tail->ptr_d);
	mem_alloc_list_tail->ptr_h = NULL;
	mem_alloc_list_tail->size = size;
	mem_alloc_list_tail->dev = dev;
	mem_alloc_list_tail->ctx = (CUcontext)dev->mpshared->info.context;
	mem_alloc_list_tail->mtype = GPU_MEM;

	/* Restore original ctx as current ctx */
	res = cuCtxSetCurrent(current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxSetCurrent current failed with %s.\n", err_string);

		return -1;
	}

	*ptr = (void *) mem_alloc_list_tail->ptr_d;

	return 0;
}

static int
cuda_mem_register(struct rte_gpu *dev, size_t size, void *ptr)
{
	CUresult res;
	const char *err_string;
	CUcontext current_ctx;
	CUcontext input_ctx;
	unsigned int flag = 1;
	int use_ptr_h = 0;

	if (dev == NULL || size == 0 || ptr == NULL)
		return -EINVAL;

	/* Store current ctx */
	res = cuCtxGetCurrent(&current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxGetCurrent failed with %s.\n", err_string);

		return -1;
	}

	/* Set child ctx as current ctx */
	input_ctx = (CUcontext)dev->mpshared->info.context;
	res = cuCtxSetCurrent(input_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxSetCurrent input failed with %s.\n", err_string);

		return -1;
	}

	/* Get next memory list item */
	mem_alloc_list_tail = mem_list_add_item();
	if (mem_alloc_list_tail == NULL)
		return -ENOMEM;

	/* Allocate memory */
	mem_alloc_list_tail->size = size;
	mem_alloc_list_tail->ptr_h = ptr;

	res = cuMemHostRegister(mem_alloc_list_tail->ptr_h, mem_alloc_list_tail->size, CU_MEMHOSTREGISTER_PORTABLE | CU_MEMHOSTREGISTER_DEVICEMAP);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuMemHostRegister failed with %s ptr %p size %zd.\n",
				err_string, mem_alloc_list_tail->ptr_h, mem_alloc_list_tail->size);

		return -1;
	}

	res = cuDeviceGetAttribute(&(use_ptr_h),
					CU_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM,
					((struct cuda_info *)(dev->mpshared->dev_private))->cu_dev);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuDeviceGetAttribute failed with %s.\n",
					err_string
			);

		return -1;
	}

	if (use_ptr_h == 0) {
		res = cuMemHostGetDevicePointer(&(mem_alloc_list_tail->ptr_d),
						mem_alloc_list_tail->ptr_h,
						0);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR,
					"cuMemHostGetDevicePointer failed with %s.\n",
					err_string);

			return -1;
		}

		if ((uintptr_t) mem_alloc_list_tail->ptr_d != (uintptr_t) mem_alloc_list_tail->ptr_h) {
			rte_gpu_cuda_log(ERR, "Host input pointer is different wrt GPU registered pointer\n");
			return -1;
		}
	} else {
		mem_alloc_list_tail->ptr_d = (CUdeviceptr) mem_alloc_list_tail->ptr_h;
	}

	/* GPUDirect RDMA attribute required */
	res = cuPointerSetAttribute(&flag,
					CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
					mem_alloc_list_tail->ptr_d);
	if (res != CUDA_SUCCESS) {
		rte_gpu_cuda_log(ERR,
				"Could not set SYNC MEMOP attribute for GPU memory at %llx , err %d\n",
				mem_alloc_list_tail->ptr_d, res);
		return -1;
	}

	mem_alloc_list_tail->pkey = get_hash_from_ptr((void *) mem_alloc_list_tail->ptr_h);
	mem_alloc_list_tail->size = size;
	mem_alloc_list_tail->dev = dev;
	mem_alloc_list_tail->ctx = (CUcontext)dev->mpshared->info.context;
	mem_alloc_list_tail->mtype = CPU_REGISTERED;

	/* Restore original ctx as current ctx */
	res = cuCtxSetCurrent(current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuCtxSetCurrent current failed with %s.\n",
				err_string);

		return -1;
	}

	return 0;
}

static int
cuda_mem_free(struct rte_gpu *dev, void *ptr)
{
	CUresult res;
	struct mem_entry *mem_item;
	const char *err_string;
	cuda_ptr_key hk;

	if (dev == NULL || ptr == NULL)
		return -EINVAL;

	hk = get_hash_from_ptr((void *) ptr);

	mem_item = mem_list_find_item(hk);
	if (mem_item == NULL) {
		rte_gpu_cuda_log(ERR, "Memory address 0x%p not found in driver memory\n", ptr);
		return -1;
	}

	if (mem_item->mtype == GPU_MEM) {
		res = cuMemFree(mem_item->ptr_d);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR, "cuMemFree current failed with %s.\n", err_string);

			return -1;
		}

		return mem_list_del_item(hk);
	}

	rte_gpu_cuda_log(ERR, "Memory type %d not supported\n", mem_item->mtype);
	return -1;
}

static int
cuda_mem_unregister(struct rte_gpu *dev, void *ptr)
{
	CUresult res;
	struct mem_entry *mem_item;
	const char *err_string;
	cuda_ptr_key hk;

	if (dev == NULL || ptr == NULL)
		return -EINVAL;

	hk = get_hash_from_ptr((void *) ptr);

	mem_item = mem_list_find_item(hk);
	if (mem_item == NULL) {
		rte_gpu_cuda_log(ERR, "Memory address 0x%p not nd in driver memory\n", ptr);
		return -1;
	}

	if (mem_item->mtype == CPU_REGISTERED) {
		res = cuMemHostUnregister(ptr);
		if (res != CUDA_SUCCESS) {
			cuGetErrorString(res, &(err_string));
			rte_gpu_cuda_log(ERR,
					"cuMemHostUnregister current failed with %s.\n",
					err_string);

			return -1;
		}

		return mem_list_del_item(hk);
	}

	rte_gpu_cuda_log(ERR, "Memory type %d not supported\n", mem_item->mtype);
	return -1;
}

static int
cuda_dev_close(struct rte_gpu *dev)
{
	if (dev == NULL)
		return -EINVAL;

	rte_free(dev->mpshared->dev_private);

	return 0;
}

static int
cuda_wmb(struct rte_gpu *dev)
{
	CUresult res;
	const char *err_string;
	CUcontext current_ctx;
	CUcontext input_ctx;

	if (dev == NULL)
		return -EINVAL;

	/* Store current ctx */
	res = cuCtxGetCurrent(&current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxGetCurrent failed with %s.\n", err_string);

		return -1;
	}

	/* Set child ctx as current ctx */
	input_ctx = (CUcontext)dev->mpshared->info.context;
	res = cuCtxSetCurrent(input_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxSetCurrent input failed with %s.\n", err_string);

		return -1;
	}

	res = cuFlushGPUDirectRDMAWrites(CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TARGET_CURRENT_CTX, CU_FLUSH_GPU_DIRECT_RDMA_WRITES_TO_ALL_DEVICES);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuFlushGPUDirectRDMAWrites current failed with %s.\n", err_string);

		return -1;
	}

	/* Restore original ctx as current ctx */
	res = cuCtxSetCurrent(current_ctx);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR, "cuCtxSetCurrent current failed with %s.\n", err_string);

		return -1;
	}

	return 0;
}

static int
cuda_gpu_probe(__rte_unused struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	struct rte_gpu *dev = NULL;
	CUresult res;
	CUdevice cu_dev_id;
	CUcontext pctx;
	char dev_name[RTE_DEV_NAME_MAX_LEN];
	const char *err_string;
	int processor_count = 0;
	struct cuda_info *private;

	if (pci_dev == NULL) {
		rte_gpu_cuda_log(ERR, "NULL PCI device");
		return -EINVAL;
	}

	rte_pci_device_name(&pci_dev->addr, dev_name, sizeof(dev_name));

	/* Allocate memory to be used privately by drivers */
	dev = rte_gpu_allocate(pci_dev->device.name);
	if (dev == NULL)
		return -ENODEV;

	/* Initialize values only for the first CUDA driver call */
	if (dev->mpshared->info.dev_id == 0) {
		mem_alloc_list_head = NULL;
		mem_alloc_list_tail = NULL;
		mem_alloc_list_last_elem = 0;
	}

	/* Fill HW specific part of device structure */
	dev->device = &pci_dev->device;
	dev->mpshared->info.numa_node = pci_dev->device.numa_node;

	/*
	 * GPU Device init
	 */

	/*
	 * Required to initialize the CUDA Driver.
	 * Multiple calls of cuInit() will return immediately
	 * without making any relevant change
	 */
	cuInit(0);

	/* Get NVIDIA GPU Device descriptor */
	res = cuDeviceGetByPCIBusId(&cu_dev_id, dev->device->name);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuDeviceGetByPCIBusId name %s failed with %d: %s.\n",
				dev->device->name, res, err_string);

		return -1;
	}

	res = cuDevicePrimaryCtxRetain(&pctx, cu_dev_id);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuDevicePrimaryCtxRetain name %s failed with %d: %s.\n",
				dev->device->name, res, err_string);

		return -1;
	}

	dev->mpshared->info.context = (uint64_t) pctx;

	/*
	 * GPU Device generic info
	 */

	/* Processor count */
	res = cuDeviceGetAttribute(&(processor_count),
					CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
					cu_dev_id);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuDeviceGetAttribute failed with %s.\n",
				err_string);

		return -1;
	}
	dev->mpshared->info.processor_count = (uint32_t)processor_count;

	/* Total memory */
	res = cuDeviceTotalMem(&dev->mpshared->info.total_memory, cu_dev_id);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuDeviceTotalMem failed with %s.\n",
				err_string);

		return -1;
	}

	/*
	 * GPU Device private info
	 */
	dev->mpshared->dev_private = rte_zmalloc(NULL,
						sizeof(struct cuda_info),
						RTE_CACHE_LINE_SIZE);
	if (dev->mpshared->dev_private == NULL) {
		rte_gpu_cuda_log(ERR,
				"Failed to allocate memory for GPU process private.\n");

		return -1;
	}

	private = (struct cuda_info *)dev->mpshared->dev_private;
	private->cu_dev = cu_dev_id;
	res = cuDeviceGetName(private->gpu_name,
				RTE_DEV_NAME_MAX_LEN,
				cu_dev_id);
	if (res != CUDA_SUCCESS) {
		cuGetErrorString(res, &(err_string));
		rte_gpu_cuda_log(ERR,
				"cuDeviceGetName failed with %s.\n",
				err_string);

		return -1;
	}

	dev->ops.dev_info_get = cuda_dev_info_get;
	dev->ops.dev_close = cuda_dev_close;
	dev->ops.mem_alloc = cuda_mem_alloc;
	dev->ops.mem_free = cuda_mem_free;
	dev->ops.mem_register = cuda_mem_register;
	dev->ops.mem_unregister = cuda_mem_unregister;
	dev->ops.wmb = cuda_wmb;

	rte_gpu_complete_new(dev);

	rte_gpu_cuda_log_debug("dev id = %u name = %s\n", dev->mpshared->info.dev_id, private->gpu_name);

	return 0;
}

static int
cuda_gpu_remove(struct rte_pci_device *pci_dev)
{
	struct rte_gpu *dev;
	int ret;
	uint8_t gpu_id;

	if (pci_dev == NULL)
		return -EINVAL;

	dev = rte_gpu_get_by_name(pci_dev->device.name);
	if (dev == NULL) {
		rte_gpu_cuda_log(ERR,
				"Couldn't find HW dev \"%s\" to uninitialise it",
				pci_dev->device.name);
		return -ENODEV;
	}
	gpu_id = dev->mpshared->info.dev_id;

	/* release dev from library */
	ret = rte_gpu_release(dev);
	if (ret)
		rte_gpu_cuda_log(ERR, "Device %i failed to uninit: %i", gpu_id, ret);

	rte_gpu_cuda_log_debug("Destroyed dev = %u", gpu_id);

	return 0;
}

static struct rte_pci_driver rte_cuda_driver = {
	.id_table = pci_id_cuda_map,
	.drv_flags = RTE_PCI_DRV_WC_ACTIVATE,
	.probe = cuda_gpu_probe,
	.remove = cuda_gpu_remove,
};

RTE_PMD_REGISTER_PCI(gpu_cuda, rte_cuda_driver);
RTE_PMD_REGISTER_PCI_TABLE(gpu_cuda, pci_id_cuda_map);
RTE_PMD_REGISTER_KMOD_DEP(gpu_cuda, "* nvidia & (nv_peer_mem | nvpeer_mem)");
