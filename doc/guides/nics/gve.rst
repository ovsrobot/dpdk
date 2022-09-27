..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2022 Intel Corporation.

GVE poll mode driver
=======================

The GVE PMD (**librte_net_gve**) provides poll mode driver support for
Google Virtual Ethernet device.

Please refer to https://cloud.google.com/compute/docs/networking/using-gvnic
for the device description.

The base code is under MIT license and based on GVE kernel driver v1.3.0.
GVE base code files are:

- gve_adminq.h
- gve_adminq.c
- gve_desc.h
- gve_desc_dqo.h
- gve_register.h
- gve.h

Please refer to https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-linux/tree/v1.3.0/google/gve
to find the original base code.

GVE has 3 queue formats:

- GQI_QPL - GQI with queue page list
- GQI_RDA - GQI with raw DMA addressing
- DQO_RDA - DQO with raw DMA addressing

GQI_QPL queue format is queue page list mode. Driver needs to allocate
memory and register this memory as a Queue Page List (QPL) in hardware
(Google Hypervisor/GVE Backend) first. Each queue has its own QPL.
Then Tx needs to copy packets to QPL memory and put this packet's offset
in the QPL memory into hardware descriptors so that hardware can get the
packets data. And Rx needs to read descriptors of offset in QPL to get
QPL address and copy packets from the address to get real packets data.

GQI_RDA queue format works like usual NICs that driver can put packets'
physical address into hardware descriptors.

DQO_RDA queue format has submission and completion queue pair for each
Tx/Rx queue. And similar as GQI_RDA, driver can put packets' physical
address into hardware descriptors.

Please refer to https://www.kernel.org/doc/html/latest/networking/device_drivers/ethernet/google/gve.html
to get more information about GVE queue formats.

Features and Limitations
------------------------

In this release, the GVE PMD provides the basic functionality of packet
reception and transmission.
Supported features of the GVE PMD are:

- Multiple queues for TX and RX
- Receiver Side Scaling (RSS)
- TSO offload
- Port hardware statistics
- Link state information
- TX multi-segments (Scatter TX)
- Tx UDP/TCP/SCTP Checksum

Currently, only GQI_QPL and GQI_RDA queue format are supported in PMD.
Jumbo Frame is not supported in PMD for now. It'll be added in the future
DPDK release.
Also, only GQI_QPL queue format is in use on GCP since GQI_RDA hasn't been
released in production.
