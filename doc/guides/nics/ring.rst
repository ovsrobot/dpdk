.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2010-2015 Intel Corporation.

Ring Based Poll Mode Driver
===========================

The ring-based PMD (``librte_net_ring``) allows software FIFOs (rte_ring)
to be accessed using the PMD API, as though they were physical NICs.


Using the Driver from the EAL Command Line
------------------------------------------

DPDK allows pseudo-Ethernet devices, as the ring driver,
to be created at application startup time during EAL initialization.

To do so, pass the ``--vdev=net_ring0`` parameter to the EAL.
This parameter accepts options to allocate and use ring-based Ethernet
transparently by the application.
This can be used, for example, for testing on a virtual machine
where there are no Ethernet ports.

The device names passed to the ``--vdev`` option must start with ``net_ring``
and take no additional parameters.
Multiple devices may be specified using multiple ``--vdev`` arguments.

.. code-block:: console

   ./dpdk-testpmd -l 1-3 --vdev=net_ring0 --vdev=net_ring1 -- -i
   ...
   Interactive-mode selected
   Configuring Port 0 (socket 0)
   Configuring Port 1 (socket 0)
   Checking link statuses...
   Port 0 Link Up - speed 10000 Mbps - full-duplex
   Port 1 Link Up - speed 10000 Mbps - full-duplex
   Done

   testpmd> start tx_first
   io packet forwarding - CRC stripping disabled - packets/burst=16
   nb forwarding cores=1 - nb forwarding ports=2
   RX queues=1 - RX desc=128 - RX free threshold=0
   RX threshold registers: pthresh=8 hthresh=8 wthresh=4
   TX queues=1 - TX desc=512 - TX free threshold=0
   TX threshold registers: pthresh=36 hthresh=0 wthresh=0
   TX RS bit threshold=0 - TXQ flags=0x0

   testpmd> stop
   Telling cores to stop...
   Waiting for lcores to finish...

.. image:: img/forward_stats.*

.. code-block:: console

   +++++++++++++++ Accumulated forward statistics for allports++++++++++
   RX-packets: 462384736  RX-dropped: 0 RX-total: 462384736
   TX-packets: 462384768  TX-dropped: 0 TX-total: 462384768
   +++++++++++++++++++++++++++++++++++++++++++++++++++++

   Done.


Using the Ring-based PMD from an Application
--------------------------------------------

The driver provides an API to create PMD (``rte_ethdev`` structure) instances
at run-time in the end-application using the function ``rte_eth_from_rings()``.
This functionality can be used to allow data exchange between cores using rings
in the same way as sending or receiving packets from an Ethernet device.

Usage Examples
^^^^^^^^^^^^^^

To create two pseudo-Ethernet ports where all traffic sent to a port is looped back
for reception on the same port (error handling omitted for clarity):

.. code-block:: c

   #define RING_SIZE 256
   #define NUM_RINGS 2
   #define SOCKET0 0

   struct rte_ring *ring[NUM_RINGS];
   int port0, port1;

   ring[0] = rte_ring_create("R0", RING_SIZE, SOCKET0, RING_F_SP_ENQ|RING_F_SC_DEQ);
   ring[1] = rte_ring_create("R1", RING_SIZE, SOCKET0, RING_F_SP_ENQ|RING_F_SC_DEQ);

   /* create two ethdev's */
   port0 = rte_eth_from_rings("net_ring0", ring, NUM_RINGS, ring, NUM_RINGS, SOCKET0);
   port1 = rte_eth_from_rings("net_ring1", ring, NUM_RINGS, ring, NUM_RINGS, SOCKET0);


To create two pseudo-Ethernet ports where the traffic is switched between them
(traffic sent to port 0 is read back from port 1 and vice-versa),
the final two lines can be changed as follows:

.. code-block:: c

   port0 = rte_eth_from_rings("net_ring0", &ring[0], 1, &ring[1], 1, SOCKET0);
   port1 = rte_eth_from_rings("net_ring1", &ring[1], 1, &ring[0], 1, SOCKET0);

This type of configuration is useful in a pipeline model where inter-core communication
using pseudo Ethernet devices is preferred over raw rings for API consistency.

Peer Link State (veth-like Carrier Detection)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, a ring-based port reports link-up as soon as it is started,
regardless of the state of any other port.  For use cases that model a
virtual Ethernet cable between two ports, this can be changed by pairing
the ports with ``rte_eth_ring_attach_peer()``.

Once two ports are paired, their link state follows the same rules as the
Linux veth driver:

* The link comes up only when **both** sides are started.
* Stopping, closing, or administratively setting link-down on one side
  causes the other side to report link-down as well.
* When the stopped side is restarted, both sides regain carrier.

Pairing is supported for any two ring-based ports, whether they were created
with ``rte_eth_from_rings()`` or via the ``--vdev=net_ring`` EAL option.

.. code-block:: c

   struct rte_ring *ring_ab, *ring_ba;

   ring_ab = rte_ring_create("AB", 1024, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
   ring_ba = rte_ring_create("BA", 1024, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);

   /* Port A: TX into ring_ab, RX from ring_ba */
   int port_a = rte_eth_from_rings("veth_a", &ring_ba, 1, &ring_ab, 1, 0);
   /* Port B: TX into ring_ba, RX from ring_ab */
   int port_b = rte_eth_from_rings("veth_b", &ring_ab, 1, &ring_ba, 1, 0);

   /* Enable veth-like link state tracking */
   rte_eth_ring_attach_peer(port_a, port_b);

   /* At this point both links are down.
    * Starting port_a alone still shows link-down (peer is not ready).
    * Starting port_b as well brings both links up.
    */

Unpaired ports (the default) are unaffected and retain the original
behaviour where link-up is reported immediately on start.

Enqueuing and dequeuing items from an ``rte_ring``
using the ring-based PMD may be slower than using the native ring API.
DPDK Ethernet drivers use function pointers
to call the appropriate enqueue or dequeue functions,
while the ``rte_ring`` specific functions are direct function calls
and are often inlined by the compiler.

Once an ethdev has been created for a ring-based PMD,
it should be configured and started in the same way as a regular Ethernet device:
call ``rte_eth_dev_configure()`` to set the number of receive and transmit queues,
then call ``rte_eth_rx_queue_setup()`` / ``tx_queue_setup()`` for each of those queues,
and finally call ``rte_eth_dev_start()`` to allow transmission and reception of packets to begin.
