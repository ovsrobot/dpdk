..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

Packet Capture Library
======================

The capture library records packets going in and out of the Ethernet ports of a
running DPDK primary process, and writes them in pcapng format to a file or a
FIFO.

Unlike the older pdump library, no secondary process is involved and the
application needs no source changes and no additional EAL arguments. The
library registers itself at load time and is driven entirely over the
:doc:`telemetry <telemetry_lib>` socket, so capture can be started on an
already running application, including a sealed vendor appliance.

Any telemetry client can drive it; see :doc:`../howto/telemetry` for the
``dpdk-telemetry.py`` script used in the examples below.

Operation
---------

When a capture is started the library installs Rx and Tx callbacks on the
requested queues of the port. Each callback copies matching packets into a
new mbuf already formatted as a pcapng Enhanced Packet Block
(``rte_pcapng_copy``) and enqueues it on a ring. A dedicated capture thread
drains that ring and writes the blocks to the output.
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
   Required. Path of the output, which must already exist and be either a FIFO
   or an empty regular file.

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

The output file or FIFO must exist otherwise the capture fails to start.
If it is a regular file, it must be empty. A pcapng file begins with a
section header and an interface description block,
which the library writes before the first packet;
therefore it is not valid to append to an existing file.

If the output is a FIFO the reader must have already opened it.
This is to prevent capture thread blocking waiting for reader.

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

The same values are mapped onto the Interface Statistics Block written at the
end of the capture: ``ifrecv`` is the number of packets seen, ``filteraccept``
the subset that passed the filter, and ``ifdrop`` the packets that were lost.

Example
-------

Normally, the capture API is intended to be used by the Wireshark
external capture script, but it can be tested using ``dpdk-telemetry.py``
against a running application.

An example, capturing TCP traffic on port 0 into a file::

   --> /ethdev/capture/start,0,out=/tmp/port0.pcapng,snaplen=128,filter=tcp
   {"/ethdev/capture/start": {"id": 0, "status": "running"}}

   --> /ethdev/capture/stats,0
   {"/ethdev/capture/stats": {"port_id": 0, "filter": "tcp", "running": 1, \
    "snaplen": 128, "rx_queues": 4, "tx_queues": 4, "accepted": 1200, \
    "filtered": 87, "nombuf": 0, "ringfull": 0}}

   --> /ethdev/capture/stop,0
   {"/ethdev/capture/stop": {"status": "stopped"}}

Using Wireshark
---------------

The ``dpdk-wireshark-extcap.py`` script presents the ports of a running DPDK
application as Wireshark capture interfaces, using these telemetry commands
with a FIFO created by Wireshark as the output.
See :doc:`../tools/wireshark_extcap`.

Limitations
-----------

* Only the primary process can capture; packets handled by a secondary process
  are not seen.

* Each capture covers a single port. Capturing several ports means starting
  several captures.

* Captured packets are those seen by the ethdev layer, so packets dropped by
  the hardware or the driver do not appear.
