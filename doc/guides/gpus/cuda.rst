.. SPDX-License-Identifier: BSD-3-Clause
   Copyright (c) 2021 NVIDIA Corporation & Affiliates

CUDA GPU driver
===============

The CUDA GPU driver library (**librte_gpu_cuda**) provides support for NVIDIA GPUs.
Information and documentation about these devices can be found on the
`NVIDIA website <http://www.nvidia.com>`__. Help is also provided by the
`NVIDIA CUDA Toolkit developer zone <https://docs.nvidia.com/cuda>`__.

Design
------

**librte_gpu_cuda** relies on CUDA Driver API (no need for CUDA Runtime API).

Goal of this driver library is not to provide a wrapper for the whole CUDA Driver API.
Instead, the scope is to implement the generic features of gpudev API.
For a CUDA application, integrating the gpudev library functions using the CUDA driver library
is quite straightforward and doesn't create any compatibility problem.

Initialization
~~~~~~~~~~~~~~

During initialization, CUDA driver library detects NVIDIA physical GPUs on the
system or specified via EAL device options (e.g. ``-a b6:00.0``).
The driver initializes the CUDA driver environment through ``cuInit(0)`` function.
For this reason, it's required to set any CUDA environment configuration before
calling ``rte_eal_init`` function in the DPDK application.

If the CUDA driver environment has been already initialized, the ``cuInit(0)``
in CUDA driver library has no effect.

CUDA Driver sub-contexts
~~~~~~~~~~~~~~~~~~~~~~~~

After initialization, a CUDA application can create multiple sub-contexts on GPU
physical devices. Through gpudev library, is possible to register these sub-contexts
in the CUDA driver library as child devices having as parent a GPU physical device.

CUDA driver library also supports `MPS <https://docs.nvidia.com/deploy/pdf/CUDA_Multi_Process_Service_Overview.pdf>`__.

GPU memory management
~~~~~~~~~~~~~~~~~~~~~

The CUDA driver library maintains a table of GPU memory addresses allocated
and CPU memory addresses registered associated to the input CUDA context.
Whenever the application tried to deallocate or deregister a memory address,
if the address is not in the table the CUDA driver library will return an error.

Features
--------

- Register new child devices aka new CUDA Driver contexts
- Allocate memory on the GPU
- Register CPU memory to make it visible from GPU

Minimal requirements
--------------------

Minimal requirements to enable the CUDA driver library are:

- NVIDIA GPU Ampere or Volta
- CUDA 11.4 Driver API or newer

`GPUDirect RDMA Technology <https://docs.nvidia.com/cuda/gpudirect-rdma/index.html>`__
allows compatible network cards (e.g. Mellanox) to directly send and receive packets
using GPU memory instead of additional memory copies through the CPU system memory.
To enable this technology, system requirements are:

- `nvidia-peermem <https://docs.nvidia.com/cuda/gpudirect-rdma/index.html#nvidia-peermem>`__ module running on the system
- Mellanox Network card ConnectX-5 or newer (BlueField models included)
- DPDK mlx5 PMD enabled
- To reach the best performance, a PCIe switch between GPU and NIC is recommended

Limitations
-----------

Supported only on Linux.

Supported GPUs
--------------

The following NVIDIA GPU devices are supported by this CUDA driver:

- NVIDIA A100 80GB PCIe
- NVIDIA A100 40GB PCIe
- NVIDIA A30 24GB
- NVIDIA A10 24GB
- NVIDIA V100 32GB PCIe
- NVIDIA V100 16GB PCIe

External references
-------------------

A good example of how to use the GPU CUDA driver through the gpudev library
is the l2fwd-nv application that can be found `here <https://github.com/NVIDIA/l2fwd-nv>`__.

The application is based on vanilla DPDK example l2fwd and it's enhanced with GPU memory
managed through gpudev library and CUDA to launch the swap of packets' MAC addresses workload
on the GPU.

l2fwd-nv is not intended to be used for performance (testpmd is the good candidate for this).
The goal is to show different use-cases about how a CUDA application can use DPDK to:

- allocate memory on GPU device using gpudev library
- use that memory to create an external GPU memory mempool
- receive packets directly in GPU memory
- coordinate the workload on the GPU with the network and CPU activity to receive packets
- send modified packets directly from the GPU memory
