..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

Telemetry Packet Capture Library
================================

The capture library records packets going in and out of the Ethernet ports of a
running DPDK primary process, and writes them in pcapng format to a FIFO.

Overview
--------

Three pieces are involved. The application links the library, which does
nothing until asked. A capture tool creates a FIFO, asks the library to start
capturing to it, and reads pcapng from the other end. The request travels over
the :doc:`telemetry <telemetry_lib>` socket; the packets never do.

.. figure:: img/capture_overview.*

   Capture from a DPDK application into Wireshark

The tool is usually ``dpdk-wireshark-extcap``, which makes the ports appear
as capture interfaces in Wireshark, but any telemetry client will do; see
:doc:`../howto/telemetry` for the ``dpdk-telemetry.py`` script used in the
examples below.

Unlike the older pdump library, no secondary process is involved and the
application needs no source changes and no additional EAL arguments. The
library registers itself at load time, so capture can be started on an
application that is already running, including a sealed vendor appliance.

Operation
---------

When a capture is started the library installs Rx and Tx callbacks on the
requested queues of the port. Each callback copies matching packets into a
new mbuf already formatted as a pcapng Enhanced Packet Block
(``rte_pcapng_copy``) and enqueues it on a ring. A dedicated capture thread
reads that ring and writes the blocks to the output.
The receive and transmit callbacks do not block, but the capture
thread may block. The capture file is set into blocking mode so that if an
external reader cannot keep up, the capture thread will block writing to FIFO.

The callbacks copy the packet; the original mbuf is not modified and is
returned to the datapath unchanged. Packets are dropped, and counted,
if an mbuf cannot be allocated or if the ring is full.

Several captures can be active at once, including on the same port and queue.
Each has its own id, filter, ring, output and callbacks, and stopping one does
not disturb the others. Each capture runs its own filter
and copies the packets that match.

Requirements
------------

* Capture can only be started in a primary process.

* Filtering requires that DPDK was built with ``libpcap`` available. Without
  it, a capture that specifies a filter will fail to start.

* The library can be excluded from a build with
  ``-Ddisable_libs=capture``.

* The callbacks use a memory barrier that the OS applies to every CPU
  running a thread of the process: ``membarrier()`` on Linux and FreeBSD.
  It is not built where that is missing, and registers no telemetry
  commands if the call does not work at startup, so capture is simply
  unavailable rather than unsafe.

* Capture can be refused at runtime with the ``--no-capture`` EAL option,
  which is also implied by ``--no-telemetry``.

Telemetry commands
------------------

.. csv-table:: Capture telemetry commands
   :header: "Command", "Parameters"
   :widths: 30, 50

   "``/ethdev/capture/start``", "port id and options, see below"
   "``/ethdev/capture/stop``", "capture id"
   "``/ethdev/capture/list``", "none"
   "``/ethdev/capture/stats``", "capture id"

``/ethdev/capture/start`` takes the port id as its first parameter, followed by
``name=value`` options separated by commas:

``out=<path>``
   Required. Path of the output, which must already exist and be a FIFO.

``snaplen=<n>``
   Number of bytes to capture from each packet. Default is 262144;
   ``snaplen=0`` means capture the whole packet.

``queue=<n>``
   Capture only this hardware queue. Default is all queues of the port.

``filter=<expression>``
   A libpcap filter expression, compiled to eBPF and run over each packet.

Because the parameter string is split on commas, neither the output path nor
the filter expression may contain one.

On success the reply contains the capture ``id``, which is used to stop the
capture and to query its statistics. On failure the reply contains an
``error`` string. The whole parameter string is limited to 1024 bytes.

.. note::

   The telemetry commands for capture are experimental
   and may change without warning in future releases.

Output
------

The output must be an existing FIFO, otherwise the capture fails to start.
Only a FIFO is allowed because the application opens the path itself: writing
to a regular file would let a capture request create or truncate a file with
the privileges of the application.

The reader must have the FIFO open already, so that the capture thread does
not block waiting for one.

A capture runs until ``/ethdev/capture/stop`` is called,
or an error is detected such as when the reader of a FIFO goes away.

Statistics
----------

``/ethdev/capture/stats`` reports the configuration of a capture and the
following counters, summed over all queues:

``accepted``
   Packets copied for capture.

``filtered``
   Packets rejected by the filter.

``nombuf``
   Packets missed because no mbuf was available for the copy.

``ringfull``
   Packets missed because the capture thread was not keeping up.

Some of these are also mapped onto the Interface Statistics Block written at
the end of the capture: ``ifrecv`` is every packet the callbacks saw and
``ifdrop`` the ones that were lost. The block does have a field for the count
accepted by the filter, but ``rte_pcapng_write_stats()`` has no parameter for
it, so read that from the telemetry counters.

Example
-------

Normally the capture API is driven by an external capture program, but it can
be tested using ``dpdk-telemetry.py`` against a running application.

An example, capturing TCP traffic on port 0. Create the FIFO and start a
reader on it first, for example ``tshark -r /tmp/port0.fifo``, since the
capture fails to start if the FIFO has no reader::

   --> /ethdev/capture/start,0,out=/tmp/port0.fifo,snaplen=128,filter=tcp
   {"/ethdev/capture/start": {"id": 0, "status": "running"}}

   --> /ethdev/capture/stats,0
   {"/ethdev/capture/stats": {"port_id": 0, "filter": "tcp", "running": 1, \
    "snaplen": 128, "rx_queues": 4, "tx_queues": 4, "accepted": 1200, \
    "filtered": 87, "nombuf": 0, "ringfull": 0}}

   --> /ethdev/capture/stop,0
   {"/ethdev/capture/stop": {"status": "stopped"}}

Using Wireshark
---------------

The ``dpdk-wireshark-extcap`` program presents the ports of a running DPDK
application as Wireshark capture interfaces, using these telemetry commands
with a FIFO created by Wireshark as the output.
See :doc:`../tools/wireshark_extcap`.

Limitations
-----------

* Only the primary process can start and stop a capture. Packets handled by a
  secondary are included, and its counters appear in the statistics, but a
  secondary started after the capture began is missed until it is restarted.

* Each capture covers a single port. Capturing several ports means starting
  several captures.

* Captured packets are those seen by the ethdev layer, so packets dropped by
  the hardware or the driver do not appear.

* Only threads known to EAL are captured: lcores, threads registered with
  ``rte_thread_register()``, and the interrupt thread. Traffic from a plain
  application thread that calls the ethdev burst API without registering is
  not captured, because the read-side protection needs a per-thread slot.
