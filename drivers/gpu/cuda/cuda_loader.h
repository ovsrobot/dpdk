/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

/*
 * This header is inspired from cuda.h and cudaTypes.h
 * tipically found in /usr/local/cuda/include
 */

#ifndef DPDK_CUDA_LOADER_H
#define DPDK_CUDA_LOADER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <rte_bitops.h>

#if defined(__LP64__)
typedef unsigned long long cuDevPtr_v2;
#else
typedef unsigned int cuDevPtr_v2;
#endif
typedef cuDevPtr_v2 cuDevPtr;

typedef int cuDev_v1;
typedef cuDev_v1 cuDev;
typedef struct CUctx_st *CUcontext;

enum cuError {
	SUCCESS = 0,
	ERROR_INVALID_VALUE = 1,
	ERROR_OUT_OF_MEMORY = 2,
	ERROR_NOT_INITIALIZED = 3,
	ERROR_DEINITIALIZED = 4,
	ERROR_PROFILER_DISABLED = 5,
	ERROR_PROFILER_NOT_INITIALIZED = 6,
	ERROR_PROFILER_ALREADY_STARTED = 7,
	ERROR_PROFILER_ALREADY_STOPPED = 8,
	ERROR_STUB_LIBRARY = 34,
	ERROR_NO_DEVICE = 100,
	ERROR_INVALID_DEVICE = 101,
	ERROR_DEVICE_NOT_LICENSED = 102,
	ERROR_INVALID_IMAGE = 200,
	ERROR_INVALID_CONTEXT = 201,
	ERROR_CONTEXT_ALREADY_CURRENT = 202,
	ERROR_MAP_FAILED = 205,
	ERROR_UNMAP_FAILED = 206,
	ERROR_ARRAY_IS_MAPPED = 207,
	ERROR_ALREADY_MAPPED = 208,
	ERROR_NO_BINARY_FOR_GPU = 209,
	ERROR_ALREADY_ACQUIRED = 210,
	ERROR_NOT_MAPPED = 211,
	ERROR_NOT_MAPPED_AS_ARRAY = 212,
	ERROR_NOT_MAPPED_AS_POINTER = 213,
	ERROR_ECC_UNCORRECTABLE = 214,
	ERROR_UNSUPPORTED_LIMIT = 215,
	ERROR_CONTEXT_ALREADY_IN_USE = 216,
	ERROR_PEER_ACCESS_UNSUPPORTED = 217,
	ERROR_INVALID_PTX = 218,
	ERROR_INVALID_GRAPHICS_CONTEXT = 219,
	ERROR_NVLINK_UNCORRECTABLE = 220,
	ERROR_JIT_COMPILER_NOT_FOUND = 221,
	ERROR_UNSUPPORTED_PTX_VERSION = 222,
	ERROR_JIT_COMPILATION_DISABLED = 223,
	ERROR_UNSUPPORTED_EXEC_AFFINITY = 224,
	ERROR_INVALID_SOURCE = 300,
	ERROR_FILE_NOT_FOUND = 301,
	ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND = 302,
	ERROR_SHARED_OBJECT_INIT_FAILED = 303,
	ERROR_OPERATING_SYSTEM = 304,
	ERROR_INVALID_HANDLE = 400,
	ERROR_ILLEGAL_STATE = 401,
	ERROR_NOT_FOUND = 500,
	ERROR_NOT_READY = 600,
	ERROR_ILLEGAL_ADDRESS = 700,
	ERROR_LAUNCH_OUT_OF_RESOURCES = 701,
	ERROR_LAUNCH_TIMEOUT = 702,
	ERROR_LAUNCH_INCOMPATIBLE_TEXTURING = 703,
	ERROR_PEER_ACCESS_ALREADY_ENABLED = 704,
	ERROR_PEER_ACCESS_NOT_ENABLED = 705,
	ERROR_PRIMARY_CONTEXT_ACTIVE = 708,
	ERROR_CONTEXT_IS_DESTROYED = 709,
	ERROR_ASSERT = 710,
	ERROR_TOO_MANY_PEERS = 711,
	ERROR_HOST_MEMORY_ALREADY_REGISTERED = 712,
	ERROR_HOST_MEMORY_NOT_REGISTERED = 713,
	ERROR_HARDWARE_STACK_ERROR = 714,
	ERROR_ILLEGAL_INSTRUCTION = 715,
	ERROR_MISALIGNED_ADDRESS = 716,
	ERROR_INVALID_ADDRESS_SPACE = 717,
	ERROR_INVALID_PC = 718,
	ERROR_LAUNCH_FAILED = 719,
	ERROR_COOPERATIVE_LAUNCH_TOO_LARGE = 720,
	ERROR_NOT_PERMITTED = 800,
	ERROR_NOT_SUPPORTED = 801,
	ERROR_SYSTEM_NOT_READY = 802,
	ERROR_SYSTEM_DRIVER_MISMATCH = 803,
	ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE = 804,
	ERROR_MPS_CONNECTION_FAILED = 805,
	ERROR_MPS_RPC_FAILURE = 806,
	ERROR_MPS_SERVER_NOT_READY = 807,
	ERROR_MPS_MAX_CLIENTS_REACHED = 808,
	ERROR_MPS_MAX_CONNECTIONS_REACHED = 809,
	ERROR_STREAM_CAPTURE_UNSUPPORTED = 900,
	ERROR_STREAM_CAPTURE_INVALIDATED = 901,
	ERROR_STREAM_CAPTURE_MERGE = 902,
	ERROR_STREAM_CAPTURE_UNMATCHED = 903,
	ERROR_STREAM_CAPTURE_UNJOINED = 904,
	ERROR_STREAM_CAPTURE_ISOLATION = 905,
	ERROR_STREAM_CAPTURE_IMPLICIT = 906,
	ERROR_CAPTURED_EVENT = 907,
	ERROR_STREAM_CAPTURE_WRONG_THREAD = 908,
	ERROR_TIMEOUT = 909,
	ERROR_GRAPH_EXEC_UPDATE_FAILURE = 910,
	ERROR_EXTERNAL_DEVICE = 911,
	ERROR_UNKNOWN = 999
};

/*
 * Execution Affinity Types. Useful for MPS to detect number of SMs
 * associated to a CUDA context v3.
 */
enum cuExecAffinityParamType {
	CU_EXEC_AFFINITY_TYPE_SM_COUNT = 0,
	CU_EXEC_AFFINITY_TYPE_MAX
};

/*
 * Number of SMs associated to a context.
 */
struct cuExecAffinitySMCount {
	unsigned int val;
	/* The number of SMs the context is limited to use. */
} cuExecAffinitySMCount;

/**
 * Execution Affinity Parameters
 */
struct cuExecAffinityParams {
	enum cuExecAffinityParamType type;
	union {
		struct cuExecAffinitySMCount smCount;
	} param;
};

/* GPU device properties to query */
enum cuDevAttr {
	CU_DEV_ATTR_MULTIPROCESSOR_COUNT = 16,
	/* Number of multiprocessors on device */
	CU_DEV_ATTR_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM = 91,
	/* Device can access host registered memory at the same virtual address as the CPU */
	CU_DEV_ATTR_GPU_DIRECT_RDMA_SUPPORTED = 116,
	/* Device supports GPUDirect RDMA APIs, like nvidia_p2p_get_pages (see https://docs.nvidia.com/cuda/gpudirect-rdma for more information) */
	CU_DEV_ATTR_GPU_DIRECT_RDMA_FLUSH_WRITES_OPTIONS = 117,
	/* The returned attribute shall be interpreted as a bitmask, where the individual bits are described by the cuFlushGDRWriteOpts enum */
	CU_DEV_ATTR_GPU_DIRECT_RDMA_WRITES_ORDERING = 118,
	/* GPUDirect RDMA writes to the device do not need to be flushed for consumers within the scope indicated by the returned attribute. See cuGDRWriteOrdering for the numerical values returned here. */
};

/* Memory pointer info */
enum cuPtrAttr {
	CU_PTR_ATTR_CONTEXT = 1,
	/* The CUcontext on which a pointer was allocated or registered */
	CU_PTR_ATTR_MEMORY_TYPE = 2,
	/* The CUmemorytype describing the physical location of a pointer */
	CU_PTR_ATTR_DEVICE_POINTER = 3,
	/* The address at which a pointer's memory may be accessed on the device */
	CU_PTR_ATTR_HOST_POINTER = 4,
	/* The address at which a pointer's memory may be accessed on the host */
	CU_PTR_ATTR_P2P_TOKENS = 5,
	/* A pair of tokens for use with the nv-p2p.h Linux kernel interface */
	CU_PTR_ATTR_SYNC_MEMOPS = 6,
	/* Synchronize every synchronous memory operation initiated on this region */
	CU_PTR_ATTR_BUFFER_ID = 7,
	/* A process-wide unique ID for an allocated memory region*/
	CU_PTR_ATTR_IS_MANAGED = 8,
	/* Indicates if the pointer points to managed memory */
	CU_PTR_ATTR_DEVICE_ORDINAL = 9,
	/* A device ordinal of a device on which a pointer was allocated or registered */
	CU_PTR_ATTR_IS_LEGACY_CUDA_IPC_CAPABLE = 10,
	/* 1 if this pointer maps to an allocation that is suitable for cudaIpcGetMemHandle, 0 otherwise **/
	CU_PTR_ATTR_RANGE_START_ADDR = 11,
	/* Starting address for this requested pointer */
	CU_PTR_ATTR_RANGE_SIZE = 12,
	/* Size of the address range for this requested pointer */
	CU_PTR_ATTR_MAPPED = 13,
	/* 1 if this pointer is in a valid address range that is mapped to a backing allocation, 0 otherwise **/
	CU_PTR_ATTR_ALLOWED_HANDLE_TYPES = 14,
	/* Bitmask of allowed CUmemAllocationHandleType for this allocation **/
	CU_PTR_ATTR_IS_GPU_DIRECT_RDMA_CAPABLE = 15,
	/* 1 if the memory this pointer is referencing can be used with the GPUDirect RDMA API **/
	CU_PTR_ATTR_ACCESS_FLAGS = 16,
	/* Returns the access flags the device associated with the current context has on the corresponding memory referenced by the pointer given */
	CU_PTR_ATTR_MEMPOOL_HANDLE = 17
	/* Returns the mempool handle for the allocation if it was allocated from a mempool. Otherwise returns NULL. **/
};

/* GPUDirect RDMA flush option types */
#define CU_FLUSH_GDR_WRITES_OPTION_HOST RTE_BIT32(0)
/* cuFlushGPUDirectRDMAWrites() and its CUDA Runtime API counterpart are supported on the device. */
#define CU_FLUSH_GDR_WRITES_OPTION_MEMOPS RTE_BIT32(1)
/* The CU_STREAM_WAIT_VALUE_FLUSH flag and the CU_STREAM_MEM_OP_FLUSH_REMOTE_WRITES MemOp are supported on the device. */

/* Type of platform native ordering for GPUDirect RDMA writes */
#define CU_GDR_WRITES_ORDERING_NONE 0
/* The device does not natively support ordering of remote writes. cuFlushGPUDirectRDMAWrites() can be leveraged if supported. */
#define CU_GDR_WRITES_ORDERING_OWNER 100
/* Natively, the device can consistently consume remote writes, although other CUDA devices may not. */
#define CU_GDR_WRITES_ORDERING_ALL_DEVICES 200
/* Any CUDA device in the system can consistently consume remote writes to this device. */

/* Device scope for cuFlushGPUDirectRDMAWrites */
enum cuFlushGDRScope {
	CU_FLUSH_GDR_WRITES_TO_OWNER = 100,
	/* Blocks until remote writes are visible to the CUDA device context owning the data. */
	CU_FLUSH_GDR_WRITES_TO_ALL_DEVICES = 200
	/* Blocks until remote writes are visible to all CUDA device contexts. */
};

/* Targets for cuFlushGPUDirectRDMAWrites */
enum cuFlushGDRTarget {
	/* Target is currently active CUDA device context. */
	CU_FLUSH_GDR_WRITES_TARGET_CURRENT_CTX = 0
};

#define CU_MHOST_REGISTER_PORTABLE 0x01
#define CU_MHOST_REGISTER_DEVICEMAP 0x02
#define CU_MHOST_REGISTER_IOMEMORY 0x04
#define CU_MHOST_REGISTER_READ_ONLY 0x08

extern enum cuError (*sym_cuInit)(unsigned int flags);
extern enum cuError (*sym_cuDriverGetVersion)(int *driverVersion);
extern enum cuError (*sym_cuGetProcAddress)(const char *symbol, void **pfn, int cudaVersion, uint64_t flags);

/* Dynamically loaded symbols with cuGetProcAddress with proper API version */

#ifdef __cplusplus
extern "C" {
#endif

/* Generic */
#define PFN_cuGetErrorString  PFN_cuGetErrorString_v6000
#define PFN_cuGetErrorName  PFN_cuGetErrorName_v6000
#define PFN_cuPointerSetAttribute  PFN_cuPointerSetAttribute_v6000
#define PFN_cuDeviceGetAttribute  PFN_cuDeviceGetAttribute_v2000

/* cuDevice */
#define PFN_cuDeviceGetByPCIBusId  PFN_cuDeviceGetByPCIBusId_v4010
#define PFN_cuDevicePrimaryCtxRetain  PFN_cuDevicePrimaryCtxRetain_v7000
#define PFN_cuDevicePrimaryCtxRelease  PFN_cuDevicePrimaryCtxRelease_v11000
#define PFN_cuDeviceTotalMem  PFN_cuDeviceTotalMem_v3020
#define PFN_cuDeviceGetName  PFN_cuDeviceGetName_v2000

/* cuCtx */
#define PFN_cuCtxGetApiVersion  PFN_cuCtxGetApiVersion_v3020
#define PFN_cuCtxSetCurrent  PFN_cuCtxSetCurrent_v4000
#define PFN_cuCtxGetCurrent  PFN_cuCtxGetCurrent_v4000
#define PFN_cuCtxGetDevice  PFN_cuCtxGetDevice_v2000
#define PFN_cuCtxGetExecAffinity  PFN_cuCtxGetExecAffinity_v11040

/* cuMem */
#define PFN_cuMemAlloc PFN_cuMemAlloc_v3020
#define PFN_cuMemFree PFN_cuMemFree_v3020
#define PFN_cuMemHostRegister  PFN_cuMemHostRegister_v6050
#define PFN_cuMemHostUnregister  PFN_cuMemHostUnregister_v4000
#define PFN_cuMemHostGetDevicePointer  PFN_cuMemHostGetDevicePointer_v3020
#define PFN_cuFlushGPUDirectRDMAWrites PFN_cuFlushGPUDirectRDMAWrites_v11030

/* Generic */
typedef enum cuError (*PFN_cuGetErrorString_v6000)(enum cuError error, const char **pStr);
typedef enum cuError (*PFN_cuGetErrorName_v6000)(enum cuError error, const char **pStr);
typedef enum cuError (*PFN_cuPointerSetAttribute_v6000)(const void *value, enum cuPtrAttr attribute, cuDevPtr_v2 ptr);
typedef enum cuError (*PFN_cuDeviceGetAttribute_v2000)(int *pi, enum cuDevAttr attrib, cuDev_v1 dev);

/* Device */
typedef enum cuError (*PFN_cuDeviceGetByPCIBusId_v4010)(cuDev_v1 *dev, const char *pciBusId);
typedef enum cuError (*PFN_cuDevicePrimaryCtxRetain_v7000)(CUcontext *pctx, cuDev_v1 dev);
typedef enum cuError (*PFN_cuDevicePrimaryCtxRelease_v11000)(cuDev_v1 dev);
typedef enum cuError (*PFN_cuDeviceTotalMem_v3020)(size_t *bytes, cuDev_v1 dev);
typedef enum cuError (*PFN_cuDeviceGetName_v2000)(char *name, int len, cuDev_v1 dev);

/* Context */
typedef enum cuError (*PFN_cuCtxGetApiVersion_v3020)(CUcontext ctx, unsigned int *version);
typedef enum cuError (*PFN_cuCtxSetCurrent_v4000)(CUcontext ctx);
typedef enum cuError (*PFN_cuCtxGetCurrent_v4000)(CUcontext *pctx);
typedef enum cuError (*PFN_cuCtxGetDevice_v2000)(cuDev_v1 *device);
typedef enum cuError (*PFN_cuCtxGetExecAffinity_v11040)(struct cuExecAffinityParams *pExecAffinity, enum cuExecAffinityParamType type);

/* Memory */
typedef enum cuError (*PFN_cuMemAlloc_v3020)(cuDevPtr_v2 *dptr, size_t bytesize);
typedef enum cuError (*PFN_cuMemFree_v3020)(cuDevPtr_v2 dptr);
typedef enum cuError (*PFN_cuMemHostRegister_v6050)(void *p, size_t bytesize, unsigned int Flags);
typedef enum cuError (*PFN_cuMemHostUnregister_v4000)(void *p);
typedef enum cuError (*PFN_cuMemHostGetDevicePointer_v3020)(cuDevPtr_v2 *pdptr, void *p, unsigned int Flags);
typedef enum cuError (*PFN_cuFlushGPUDirectRDMAWrites_v11030)(enum cuFlushGDRTarget target, enum cuFlushGDRScope scope);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
