..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

Glossary
========


ACL
   An access control list (ACL) is a set of rules that define who can access a resource and what actions they can perform. 
   `ACL Link <https://www.fortinet.com/resources/cyberglossary/network-access-control-list#:~:text=A%20network%20access%20control%20list%20(ACL)%20is%20made%20up%20of,device%2C%20it%20cannot%20gain%20access.>`_

API
   Application Programming Interface

ASLR
   Linux* kernel Address-Space Layout Randomization
   A computer security technique that protects against buffer overflow attacks by randomizing the location of executables in memory in Linux. 
   `ASLR Link <https://en.wikipedia.org/wiki/Address_space_layout_randomization>`_

BSD
   Berkeley Software Distribution is a Unix-like operating system.

Clr
   Clear

CIDR
   Classless Inter-Domain Routing
   A method of assigning IP address that improves data routing efficiency on the internet and is used in IPv4 and IPv6.
   `RFC Link <https://datatracker.ietf.org/doc/html/rfc1918>`_

Control Plane
   A Control Plane is a key concept in networking that refers to the part of a network system
   responsible for managing and making decisions about where and how data packets are forwarded within a network.

Core
   A core may include several lcores or threads if the processor supports simultaneous multithreading (SMT).
   `Simultaneous Multithreading <https://en.wikipedia.org/wiki/Simultaneous_multithreading>`_

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
   the data plane in a network architecture includes the layers involved when processing and forwarding
   data packets between communicating endpoints. These layers must be highly optimized to achieve good performance.

DIMM
   Dual In-line Memory Module
   A module containing one or several Random Access Memory (RAM) or Dynamic RAM (DRAM) chips on a printed
   circuit board that connect it directly to the computer motherboard.
   
Doxygen
   A documentation generator used in the DPDK to generate the API reference.
   `Doxygen Link <https://www.doxygen.nl/>`_

DPDK
   Data Plane Development Kit

DRAM
   Dynamic Random Access Memory
   A type of random access memory (RAM) that is used in computers to temporarily store information.
   `Link <https://en.wikipedia.org/wiki/Dynamic_random-access_memory>`_

EAL
   The Environment Abstraction Layer (EAL) is a DPDK core library that provides a generic interface
   that hides the environment specifics from the applications and libraries. The services expected
   from the EAL are: development kit loading and launching, core affinity/ assignment procedures, system
   memory allocation/description, PCI bus access, inter-partition communication.
   `Link <https://github.com/emmericp/dpdk-github-inofficial/blob/master/doc/guides/prog_guide/env_abstraction_layer.rst>`_

EAL Thread
   An EAL thread is typically a thread that runs packet processing tasks. These threads are often
   pinned to logical cores (lcores), which helps to ensure that packet processing tasks are executed with
   minimal interruption and maximal performance by utilizing specific CPU resources dedicated to those tasks.
   EAL threads can also handle other tasks like managing buffers, queues, and I/O operations.
   
FIFO
   First In First Out
   A method for organizing the manipulation of a data structure where the oldest (first) entry, or
   "head" of the queue, is processed first.
   `Link <https://en.wikipedia.org/wiki/FIFO_(computing_and_electronics)>`_ 

FPGA
   Field Programmable Gate Array
   An integrated circuit with a programmable hardware fabric that can be reconfigured to suit different purposes.
   `Link <https://en.wikipedia.org/wiki/Field-programmable_gate_array>`_

GbE
   Gigabit Ethernet

HW
   Hardware

HPET
   High Precision Event Timer; a hardware timer that provides a precise time
   reference on x86 platforms.
   
Huge Pages
   Memory page sizes, larger than the default page size, which are supported by the host CPU.
   These pages are generally megabytes or even a gigabytes in size,  depending on platform,
   compared to the default page size on most platforms which is measured in kilobytes, e.g. 4k.
   Where the operating system provides access to hugepage memory, DPDK will take advantage of
   those hugepages for increased performance.
   `Link <https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html>`_

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
   Layer 1
   The Physical layer of the network responsible for sending and receiving signals to transmit data.

L2
   Layer 2

L3
   Layer 3
   Also known as the network layer, Layer 3 is responsible for packet forwarding including routing through intermediate routers
   Example protocols include IP v4 and IP v6.
   `Network Layer <https://en.wikipedia.org/wiki/Network_layer>`_   

L4
   Layer 4
   Examples include UDP and TCP.
   `Transport Layer <https://en.wikipedia.org/wiki/Transport_layer>`_

LAN
   Local Area Network

LPM
   Longest Prefix Match
   A table lookup algorithm where the entry selected is that which matches the longest initial part (or prefix)
   of the lookup key, rather than requiring an exact match on the full key.
   `Reference Link <https://en.wikipedia.org/wiki/Longest_prefix_match>`_

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
   Non-uniform Memory Access
   A computer memory design that allows processors to access memory faster when it's located closer to them.
   `Reference Link <https://en.wikipedia.org/wiki/Non-uniform_memory_access>`_

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
   Thread Local Storage
   A memory management method that uses static or global memory local to a thread.
   `Reference Link <https://en.wikipedia.org/wiki/Thread-local_storage>`_
   
trTCM
   Two Rate Three Color Marking
   A component that meters an IP traffic stream, marks it as one of three color categorie
   sand assists in traffic congestion-control.
   `RFC Link <https://datatracker.ietf.org/doc/html/rfc2698>`_

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
