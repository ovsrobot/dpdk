..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

Glossary
========

This glossary provides definitions for key terms and concepts used within DPDK. Understanding these terms will help in comprehending the functionality and architecture of DPDK.

**BIOS (Basic Input/Output System)**

The firmware used to perform hardware initialization during the booting process and to provide runtime services for operating systems and programs.

**Bifurcated Driver**

A driver model that splits functionality between kernel and userspace, often used in high-performance networking.

**Clang-LLVM**

A compiler toolchain that includes the Clang C compiler and LLVM linker, used for building DPDK on Windows.

**contigmem Module**

A module in FreeBSD that provides physically contiguous memory allocation used by DPDK.

**DMA (Direct Memory Access)**

A feature that allows hardware devices to access the main system memory directly, without involving the CPU.

**EAL (Environment Abstraction Layer)**

The layer within DPDK that abstracts environmental specifics and provides a standard programming interface.

**hugepages**

Large memory pages used by the operating system to manage memory more efficiently, especially in high-performance applications like DPDK.

**IOMMU (Input-Output Memory Management Unit)**

A hardware component that translates device-visible virtual addresses to physical addresses, providing memory protection and isolation.

**MinGW-w64 Toolchain**

A development environment for creating Windows applications, used as an option for compiling DPDK on Windows.

**NIC (Network Interface Card)**

A hardware component that connects a computer to a network.

**nic_uio Module**

A UIO driver for network devices in FreeBSD, used by DPDK.

**NUMA (Non-Uniform Memory Access)**

A computer memory design used in multiprocessing where the memory access time depends on the memory location relative to the processor.

**PMD (POLL Mode Driver)**

A type of driver in DPDK that continuously polls for events rather than relying on interrupts, often used for high-performance networking.

**SoC (System on a Chip)**

An integrated circuit that integrates all components of a computer or other electronic system into a single chip.

**UIO (Userspace I/O)**

A Linux kernel module that enables user-space applications to access hardware devices directly.

**VFIO (Virtual Function I/O)**

A kernel driver that allows a virtual machine to access physical devices directly, used in DPDK for device assignment.

**VFIO Platform**

A framework in Linux that allows exposing direct device access to userspace, in a secure, IOMMU-protected way.