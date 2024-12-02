..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

Glossary
========


ACL
   An `access control list (ACL) <https://en.wikipedia.org/wiki/Access-control_list>`_
   is a set of rules that define who can access a resource and what actions they can perform.

API
   Application Programming Interface

ASLR
   `Address-Space Layout Randomization (ASLR) <https://en.wikipedia.org/wiki/Address_space_layout_randomization>`_
   is a computer security technique that protects against buffer overflow attacks by randomizing the location of
   executables in memory.

BSD
   `Berkeley Software Distribution (BSD) <https://en.wikipedia.org/wiki/Berkeley_Software_Distribution>`_
   is an version of Unix™ operating system.

Clr
   Clear

CIDR
   `Classless Inter-Domain Routing (CIDR) <https://datatracker.ietf.org/doc/html/rfc1918>`_
   is a method of assigning IP address that improves data routing efficiency on the internet and is used in IPv4 and IPv6.

Control Plane
   A `Control Plane <https://en.wikipedia.org/wiki/Control_plane>`_ is a concept in networking that refers to the part of the system
   responsible for managing and making decisions about where and how data packets are forwarded within a network.

Core
   A core may include several lcores or threads if the processor supports
   `simultaneous multithreading (SMT) <https://en.wikipedia.org/wiki/Simultaneous_multithreading>`_

Core Components
   A set of libraries provided by DPDK which are used by nearly all applications and
   upon which other DPDK libraries and drivers depend. For example, eal, ring, mempool and mbuf.

CPU
   Central Processing Unit

CRC
   Cyclic Redundancy Check
   An algorithm that detects errors in data transmission and storage.

Data Plane
   In contrast to the control plane, which is responsible for setting up and managing data connections,
   the `data plane <https://en.wikipedia.org/wiki/Data_plane>`_ in a network architecture includes the
   layers involved when processing and forwarding data packets between communicating endpoints.
   These layers must be highly optimized to achieve good performance.

DIMM
   Dual In-line Memory Module
   A module containing one or several Random Access Memory (RAM) or Dynamic RAM (DRAM) chips on a printed
   circuit board that connect it directly to the computer motherboard.

Doxygen
   `Doxygen <https://www.doxygen.nl/>`_ is a
   documentation generator used in the DPDK to generate the API reference.

DPDK
   Data Plane Development Kit

DRAM
   `Dynamic Random Access Memory <https://en.wikipedia.org/wiki/Dynamic_random-access_memory>`_
   is  type of random access memory (RAM) that is used in computers to temporarily store information.

EAL
   :doc:`Environment Abstraction Layer (EAL) <env_abstraction_layer>`
   is a the core DPDK library that provides a generic interface
   that hides the environment specifics from the applications and libraries.
   The services expected from the EAL are: loading and launching, core management,
   memory allocation, bus management, and inter-partition communication.

EAL Thread
   An EAL thread is typically a thread that runs packet processing tasks. These threads are often
   pinned to logical cores (lcores), which helps to ensure that packet processing tasks are executed with
   minimal interruption and maximal performance by utilizing specific CPU resources dedicated to those tasks.
   EAL threads can also handle other tasks like managing buffers, queues, and I/O operations.

FIFO
   `First In First Out (FIFO) <https://en.wikipedia.org/wiki/FIFO_(computing_and_electronics)>`_
   is a method for organizing the manipulation of a data structure where the oldest (first) entry, or
   "head" of the queue, is processed first.

FPGA
   `Field Programmable Gate Array (FPGA) <https://en.wikipedia.org/wiki/Field-programmable_gate_array>`_
   An integrated circuit with a programmable hardware fabric that can be reconfigured to suit different purposes.

GbE
   Gigabit Ethernet

HW
   Hardware

HPET
   High Precision Event Timer; a hardware timer that provides a precise time
   reference on x86 platforms.

Huge Pages
   `Huge pages <https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html>`_
   are memory page sizes, larger than the default page size, which are supported by the host CPU.
   These pages are generally megabytes or even a gigabytes in size,  depending on platform,
   compared to the default page size on most platforms which is measured in kilobytes, e.g. 4k.
   Where the operating system provides access to hugepage memory, DPDK will take advantage of
   those hugepages for increased performance.

ID
   Identifier

IOCTL
   Input/Output Control
   A system call that allows applications to communicate with device drivers to perform specific input/output operations.

I/O
   Input/Output

IP
   Internet Protocol

IPv4
   Internet Protocol version 4

IPv6
   Internet Protocol version 6

lcore
   A logical execution unit of the processor, sometimes called a hardware thread or EAL thread;
   Also known as logical core.

L1
   Layer 1 - `Physical Layer <https://en.wikipedia.org/wiki/Physical_layer>`_
   The Physical layer of the network responsible for sending and receiving signals to transmit data.

L2
   Layer 2 - `Datalink Layer <https://en.wikipedia.org/wiki/Data_link_layer>`_

L3
   Layer 3 - `Network Layer <https://en.wikipedia.org/wiki/Network_layer>`_
   Also known as the network layer, Layer 3 is responsible for packet forwarding including routing through intermediate routers
   Example protocols include IP v4 and IP v6.

L4
   Layer 4 - `Transport Layer <https://en.wikipedia.org/wiki/Transport_layer>`_
   Examples include UDP and TCP.


LAN
   Local Area Network

LPM
   `Longest Prefix Match <https://en.wikipedia.org/wiki/Longest_prefix_match>`_ is
   a lookup algorithm where the entry selected is that which matches the longest initial part (or prefix)
   of the lookup key, rather than requiring an exact match on the full key.

main lcore
   The logical core or thread that executes the main function and that launches tasks on other logical
   cores used by the application.

master lcore
   Deprecated name for *main lcore*. No longer used.

mbuf
   An mbuf is a data structure used internally to carry messages (mainly
   network packets).  The name is derived from BSD stacks.  To understand the
   concepts of packet buffers or mbuf, refer to *TCP/IP Illustrated, Volume 2:
   The Implementation*.

MTU
   Maximum Transfer Unit
   The size of the largest protocol data unit (PDU) that can be communicated in a single network layer transaction.

NIC
   Network Interface Card
   A hardware component, usually a circuit board or chip, installed on a computer so it can connect to a network.

OOO
   Out Of Order (execution of instructions within the CPU pipeline)

NUMA
   `Non-uniform Memory Access (NUMA) <https://en.wikipedia.org/wiki/Non-uniform_memory_access>`_
   A computer memory design that allows processors to access memory faster when it's located closer to them.

PCI
   Peripheral Connect Interface

PHY
   An abbreviation for the physical layer of the OSI model.

PIE
   Proportional Integral Controller Enhanced (RFC8033)

pktmbuf
   An *mbuf* carrying a network packet.

PMD
   Poll Mode Driver
   A program that continuously polls a network interface card (NIC) for new packets,
   instead of waiting for the NIC to interrupt the CPU. PMDs are used to quickly receive,
   process, and deliver packets in a user's application and use APIs to configure devices and queues.

QoS
   Quality of Service

RCU
   Read-Copy-Update algorithm, an alternative to simple rwlocks.
   A synchronization mechanism that allows multiple threads to read and update shared data structures without using locks.

Rd
   Read

RED
   Random Early Detection

RSS
   Receive Side Scaling

RTE
   Run Time Environment. Provides a fast and simple framework for fast packet
   processing, in a lightweight environment as a Linux* application and using
   Poll Mode Drivers (PMDs) to increase speed.

Rx
   Reception

Slave lcore
   Deprecated name for *worker lcore*. No longer used.

Socket
   A physical CPU, that includes several *cores*.

SLA
   Service Level Agreement

srTCM
   Single Rate Three Color Marking
   A policer meters an IP packet stream and marks its packets either green, yellow, or red.

SRTD
   Scheduler Round Trip Delay

SW
   Software

Target
   In the DPDK, the target is a combination of architecture, machine,
   executive environment and toolchain.  For example:
   i686-native-linux-gcc.

TCP
   Transmission Control Protocol

TC
   Traffic Class

TLB
   Translation Lookaside Buffer
   A memory cache that stores the recent translations of virtual memory to physical memory to enable faster retrieval.

TLS
   `Thread Local Storage <https://en.wikipedia.org/wiki/Thread-local_storage>`_
   A memory management method that uses static or global memory local to a thread.

trTCM
   `Two Rate Three Color Marking <https://datatracker.ietf.org/doc/html/rfc2698>`
   A component that meters an IP traffic stream, marks it as one of three color category
   sand assists in traffic congestion-control.

TSC
   Time Stamp Counter

Tx
   Transmission

TUN/TAP
   TUN and TAP are virtual network kernel devices.

VLAN
   Virtual Local Area Network

Wr
   Write

Worker lcore
   Any *lcore* that is not the *main lcore*.

WRED
   Weighted Random Early Detection
   A queueing discipline that allows the router to drop random packets to prevent tail drop.
   This is helpful for TCP/IP connections.

WRR
   Weighted Round Robin
   A scheduling algorithm used to distribute workloads across multiple resources based on assigned weights.
