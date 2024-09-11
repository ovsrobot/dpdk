..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2019 Intel Corporation.

############################################
What is the Dataplane Development Kit (DPDK)
############################################

The Dataplane Development Kit (DPDK) is a set of libraries to accelerate packet processing
workloads running on a wide variety of CPU architectures.

Network performance, throughput, and latency are crucial for diverse applications, including wireless and wireline infrastructure, routers, load balancers, firewalls, video streaming, and VoIP. DPDK (Data Plane Development Kit), an open source project hosted by the Linux Foundation, provides a robust framework that boosts packet processing speeds on various CPU architectures like Intel x86, ARM, and PowerPC. This framework is key to rapidly developing high-speed data packet networking applications.

By running DPDK, new users can significantly accelerate their network applications’ performance due to its efficient run-to-completion model and optimized libraries that ensure all necessary resources are allocated upfront.

.. toctree::
   :caption: About DPDK
   :maxdepth: 1

   glossary/index
   contributing/index
   rel_notes/index
   faq/index

.. toctree::
   :caption: Getting Started
   :maxdepth: 1

   linux_gsg/index
   freebsd_gsg/index
   windows_gsg/index
   sample_app_ug/index

.. toctree::
   :caption: Programmers Guide
   :maxdepth: 1

   prog_guide/index
   howto/index
   tools/index
   testpmd_app_ug/index

.. toctree::
   :caption: Device Drivers
   :maxdepth: 1

   nics/index
   bbdevs/index
   cryptodevs/index
   compressdevs/index
   vdpadevs/index
   regexdevs/index
   mldevs/index
   dmadevs/index
   gpus/index
   eventdevs/index
   rawdevs/index
   mempool/index
   platform/index
