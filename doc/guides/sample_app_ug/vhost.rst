..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2016 Intel Corporation.

Vhost Sample Application
========================

Overview
--------

The vhost sample application demonstrates integration of DPDK with the
Linux KVM hypervisor by implementing the vhost-user protocol. The
application performs packet switching between virtual machines and
physical network interfaces. Packets are switched based on Media Access
Control (MAC) address or Virtual Local Area Network (VLAN) tag. When
using supported NICs, the splitting of Ethernet traffic can be performed
in hardware by Virtual Machine Device Queues (VMDQ) and Data Center
Bridging (DCB) features.

Testing steps
~~~~~~~~~~~~~

This section shows the steps to test a typical PVP (physical-virtual-physical)
case with this dpdk-vhost sample. Packets are received from the physical NIC
port first and enqueued to the VM's Rx queue. Through the guest testpmd's
default forwarding mode (io forward), those packets will be put into
the Tx queue. The dpdk-vhost example, in turn, gets the packets and
puts back to the same physical NIC port.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``vhost`` sub-directory.

.. note::
   In this example, you need to build DPDK both on the host and inside the guest.

.. _vhost_app_run_vm:

Start the VM
~~~~~~~~~~~~

.. code-block:: console

    qemu-system-x86_64 -machine accel=kvm -cpu host \
        -m $mem -object memory-backend-file,id=mem,size=$mem,mem-path=/dev/hugepages,share=on \
                -mem-prealloc -numa node,memdev=mem \
        \
        -chardev socket,id=char1,path=/tmp/sock0,server \
        -netdev type=vhost-user,id=hostnet1,chardev=char1  \
        -device virtio-net-pci,netdev=hostnet1,id=net1,mac=52:54:00:00:00:14 \
        ...

.. note::
    For basic vhost-user support, QEMU 2.2 (or above) is required. For
    some specific features, a higher version might be needed. For example,
    QEMU 2.7 or above is required for the reconnect feature.


Start the vswitch example
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

        ./dpdk-vhost -l 0-3 --numa-mem 1024  \
             -- --socket-file /tmp/sock0 --client \
             ...

Check the `Parameters`_ section for the explanations on what the
parameters mean.

Running the Application
-----------------------

.. _vhost_app_run_dpdk_inside_guest:

Run testpmd inside guest
~~~~~~~~~~~~~~~~~~~~~~~~

Ensure DPDK is built inside the guest and that the
corresponding virtio-net PCI device is bound to a UIO driver, which
can be done by:

.. code-block:: console

   modprobe vfio-pci
   dpdk/usertools/dpdk-devbind.py -b vfio-pci 0000:00:04.0

Then, start testpmd for packet forwarding testing.

.. code-block:: console

    ./<build_dir>/app/dpdk-testpmd -l 0-1 -- -i
    > start tx_first

For more information about vIOMMU, NO-IOMMU, and VFIO, refer to the
:doc:`../linux_gsg/linux_drivers` section of the DPDK Getting started guide.

Explanation
-----------

Inject packets
~~~~~~~~~~~~~~

When a virtio-net device is connected to dpdk-vhost, a VLAN tag starting
from 1000 is assigned to it. Therefore, configure your packet generator
with the correct MAC address and VLAN tag. You should see the following
log from the dpdk-vhost console::

    VHOST_DATA: (0) mac 52:54:00:00:00:14 and vlan 1000 registered



.. _vhost_app_parameters:

Parameters
~~~~~~~~~~

**--socket-file path**
   Specifies the vhost-user socket file path.

**--client**
   DPDK vhost-user will act in client mode when this option is given.
   In client mode, QEMU creates the socket file. Otherwise, DPDK creates
   it. In other words, the server creates the socket file.


**--vm2vm mode**
   Sets the mode of packet switching between guests on the host:

   - 0 disables vm2vm, meaning VM packets always go to the NIC port.
   - 1 enables normal MAC lookup packet routing.
   - 2 enables hardware mode packet forwarding between guests. Packets can
     go to the NIC port, and the hardware L2 switch determines which guest
     receives the packet or whether to send it externally, based on the
     destination MAC address and VLAN tag.

**--mergeable 0|1**
   Set to 0 or 1 to disable or enable the mergeable Rx feature. Disabled by default.

**--stats interval**
   Controls printing of virtio-net device statistics. Specifies the interval
   (in seconds) to print statistics. Setting the interval to 0 disables statistics.

**--rx-retry 0|1**
   Enables or disables enqueue retries when the guest Rx queue is full. This
   feature resolves packet loss observed at high data rates by allowing delays
   and retries in the receive path. Enabled by default.

**--rx-retry-num num**
   Specifies the number of retries on an Rx burst. Takes effect only when
   rx-retry is enabled. Default value is 4.

**--rx-retry-delay msec**
   Specifies the timeout (in microseconds) between retries on an Rx burst.
   Takes effect only when rx-retry is enabled. Default value is 15.

**--builtin-net-driver**
   Uses a simple built-in vhost-user net driver that demonstrates how to use
   the generic vhost APIs. Disabled by default.

**--dmas**
   Specifies the assigned DMA device for a vhost device. The async vhost-user
   net driver will be used if --dmas is set.

   For example::

      --dmas [txd0@00:04.0,txd1@00:04.1,rxd0@00:04.2,rxd1@00:04.3]

   This means use
DMA channel 00:04.0/00:04.2 for vhost device 0 enqueue/dequeue operation
and use DMA channel 00:04.1/00:04.3 for vhost device 1 enqueue/dequeue
operation. The index of the device corresponds to the socket file in order,
that means vhost device 0 is created through the first socket file, vhost
device 1 is created through the second socket file, and so on.

**--total-num-mbufs N**
   Sets the number of mbufs to allocate in mbuf pools. Default value is 147456.
   Use this option if port startup fails due to mbuf shortage.

**--tso 0|1**
   Disables or enables TCP segment offload.

**--tx-csum 0|1**
   Disables or enables TX checksum offload.

**-p mask**
   Port mask specifying which ports to use.

Common Issues
~~~~~~~~~~~~~

* QEMU fails to allocate memory on hugetlbfs and shows an error like the
  following::

      file_ram_alloc: can't mmap RAM pages: Cannot allocate memory

  When running QEMU, the above error indicates that it has failed to allocate
  memory for the virtual machine on hugetlbfs. This is typically due to
  insufficient hugepages being free to support the allocation request. The
  number of free hugepages can be checked with:

  .. code-block:: console

     dpdk-hugepages.py --show

  The command above indicates how many hugepages are free to support QEMU's
  allocation request.

* Failed to build DPDK in VM

  Make sure the "-cpu host" QEMU option is given.

* Device start fails if the NIC's max queues exceeds the default number of 128

  The mbuf pool size is dependent on the MAX_QUEUES configuration.
  If the NIC's maximum queue count is larger than 128,
  then the device start will fail due to insufficient mbufs.
  Adjust this using the ``--total-num-mbufs`` parameter.

* Option "builtin-net-driver" is incompatible with QEMU

  QEMU vhost-net device start will fail if the protocol feature is not negotiated.
  The DPDK virtio-user PMD can replace QEMU.

* Device start fails when enabling "builtin-net-driver" without memory
  pre-allocation

  The builtin example does not support dynamic memory allocation.
  When vhost backend enables "builtin-net-driver", the "--numa-mem" option should
  be added on the virtio-user PMD side as a startup parameter.
