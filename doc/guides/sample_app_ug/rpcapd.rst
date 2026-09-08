..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026

.. _rpcapd_app:

dpdk-rpcapd Sample Application
==============================

The ``dpdk-rpcapd`` sample application is a Data Plane Development Kit
(DPDK) implementation of the remote packet capture daemon protocol
(``rpcap``) used by libpcap.  It runs as a DPDK secondary process and
allows libpcap-aware tools such as ``tcpdump`` and Wireshark to capture
packets from a DPDK primary process live, without writing to an
intermediate file.

The ``dpdk-rpcapd`` tool implements a subset of the protocol spoken by
the libpcap project's ``rpcapd``.  See
https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd for the
reference implementation.  Clients connect to ``dpdk-rpcapd`` using a
``rpcap://`` URL, request the list of available interfaces (which are
the ports of the DPDK primary), open one, and stream packets from it.

The intended workflow is one-step capture: start the primary, start
``dpdk-rpcapd``, and point a familiar tool at it.  No intermediate files,
no separate post-processing step.

.. warning::

   ``dpdk-rpcapd`` listens on an unauthenticated, unencrypted TCP port
   (default 2002, bound to ``127.0.0.1``).  Any local user able to
   reach the port can list DPDK ports and capture all traffic flowing
   through them.  This is a sample application intended for
   development, debugging, and demonstration use only.  **Do not run
   ``dpdk-rpcapd`` on a production system.**

   The default bind address is ``127.0.0.1`` so the listener is not
   reachable from other hosts.  An operator may override this with
   ``--bind <addr>`` but should expect that the resulting deployment
   exposes captured traffic to anyone who can reach that address; do
   not do this on an untrusted network.


.. note::

   * The ``dpdk-rpcapd`` tool can only be used in conjunction with a
     primary application that has the packet capture framework
     initialized already.  In DPDK, only ``dpdk-testpmd`` is modified to
     initialize the packet capture framework; other applications must
     be modified to call ``rte_pdump_init()`` if they are to be
     capturable.

   * ``dpdk-rpcapd`` does not replace ``dpdk-dumpcap``.  ``dpdk-dumpcap``
     produces pcapng files; ``dpdk-rpcapd`` produces a live rpcap
     stream.  The two tools serve different workflows and may be used
     in parallel.

   * For Wireshark users specifically, the Wireshark ``extcap`` plugin
     interface is the preferred live-capture path; see :doc:`extcap`.
     ``extcap`` integrates directly with Wireshark and is simpler to
     deploy.  ``dpdk-rpcapd`` is intended for users who want to use
     ``tcpdump`` or other rpcap-aware libpcap clients, where ``extcap``
     does not apply.


Running the Application
-----------------------

The application has a small set of command-line options:

*   ``-p <port>``, ``--port <port>``

    TCP port to listen on.  Default is 2002, the IANA-assigned rpcap
    port.

*   ``-b <addr>``, ``--bind <addr>``

    IPv4 address to bind the listener to.  Default is ``127.0.0.1``
    (loopback only).  Setting any other address exposes captured
    traffic to the network and should not be done on untrusted
    networks.

*   ``-N <ring_size>``

    Size of the per-session capture ring in packets.  Default is 2048.

*   ``-h``, ``--help``

    Print usage and exit.

EAL options are supplied automatically; the application runs as a
secondary process and does not need EAL options on its command line for
typical use.


Client Setup
------------

Most Linux distributions ship libpcap built without ``rpcap`` support
because the libpcap project leaves ``--enable-remote`` off by default.
To use ``dpdk-rpcapd`` from ``tcpdump`` or Wireshark on Linux, libpcap
must be rebuilt with remote support enabled.  Approximate steps:

.. code-block:: console

    wget https://www.tcpdump.org/release/libpcap-1.10.6.tar.xz
    tar xf libpcap-1.10.6.tar.xz
    cd libpcap-1.10.6
    ./configure --enable-remote
    make
    sudo make install
    sudo ldconfig

To verify that the resulting library has rpcap support:

.. code-block:: console

    nm -D /usr/local/lib/libpcap.so | grep ' T pcap_open$'

The symbol ``pcap_open`` should be present.  If not, the ``--enable-remote``
flag did not take effect.

``tcpdump`` rebuilt against this libpcap can be used as a client without
further changes.  Wireshark on Windows and macOS ships with rpcap support
enabled by default.


Example
-------

Start a primary application with the packet capture framework
initialized.  ``dpdk-testpmd`` is the simplest:

.. code-block:: console

    sudo ./<build_dir>/app/dpdk-testpmd -- --no-mlockall --vdev=net_tap0

In another window, start ``dpdk-rpcapd``:

.. code-block:: console

    sudo ./<build_dir>/app/dpdk-rpcapd
    RPCAPD: listening on TCP port 2002

In a third window, list available interfaces using a libpcap-based
``tcpdump`` rebuilt with remote support:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump --list-remote-interfaces=rpcap://localhost:2002/
    rpcap://localhost:2002/net_tap0  Network adapter 'DPDK port' on remote node localhost

Capture live from a port:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump -i rpcap://localhost:2002/net_tap0 -nn -c 20

Or save to a file readable by any pcap consumer:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump -i rpcap://localhost:2002/net_tap0 -w /tmp/capture.pcap


Limitations
-----------

The following limitations apply to this initial version of
``dpdk-rpcapd`` and are expected to be addressed in subsequent patches:

*   **Single client.** Only one client may be connected at a time.
    Subsequent clients are queued by the listening socket but not
    serviced until the first disconnects.  Multi-client support
    requires an event-driven main loop (planned).

*   **No BPF filter support.** ``UPDATEFILTER`` requests are
    acknowledged and ignored.  Capture-side filtering requires an
    extension to ``rte_pdump`` to support filter updates on an active
    callback.

*   **No authentication.** ``AUTH`` requests are acknowledged with an
    empty reply (libpcap "version 0, null auth" semantics).  This
    sample application does not implement password authentication.

*   **TCP transport only; not for production use.** The rpcap protocol
    over TCP is unauthenticated and unencrypted; any client that can
    reach the listening port has full access to captured traffic.
    Binding to ``127.0.0.1`` by default mitigates remote exposure but
    does not address local users on a shared host.  See the warning at
    the top of this document.

*   **Microsecond timestamp resolution.** The rpcap protocol carries
    timestamps at microsecond resolution.


See Also
--------

*   :doc:`extcap` -- Wireshark ``extcap`` plugin for direct integration
    with Wireshark, without going through the rpcap protocol.

*   :doc:`../tools/dumpcap` -- file-based capture writing pcapng
    output.

*   The libpcap project's ``rpcapd`` reference implementation:
    https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
