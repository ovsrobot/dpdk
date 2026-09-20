..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

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
the libpcap project's ``rpcapd``.
See
https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd for the
reference implementation.
Clients connect to ``dpdk-rpcapd`` using a ``rpcap://`` URL,
request the list of available interfaces(which are the ports of the DPDK primary),
open one, and stream packets from it.

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

   * ``dpdk-rpcapd`` is experimental and provided for demonstration purposes only.
     It may change or be removed without notice, and it is not intended to be relied upon.


Running the Application
-----------------------

The application has a small set of command-line options:

*   ``-p <port>``, ``--port <port>``

    TCP port to listen on.  Default is 2002, the IANA-assigned rpcap
    port.

*   ``-b <addr>``, ``--bind <addr>``

    Numeric IPv4 or IPv6 address to bind the listener to.  Default is
    ``127.0.0.1`` (loopback only).  Setting any other address exposes
    captured traffic to the network and should not be done on untrusted
    networks.

*   ``-4``

    Use only IPv4; an IPv6 argument to ``-b`` is rejected.

*   ``-N <ring_size>``

    Size of the per-session capture ring in packets.  Default is 2048.
    Rounded up to a power of two if necessary.

*   ``-D``, ``--debug``

    Increase log verbosity.  By default only notices, warnings and
    errors are printed.  A single ``-D`` adds session-level messages
    (client connected, capture started and stopped); ``-DD`` adds
    per-request protocol detail.

*   ``--debug-file <file>``

    Append log output to ``<file>`` instead of writing it to standard
    error.

*   ``--lcore <core>``

    CPU core to run on.  By default the daemon runs as an ordinary
    process on any non-isolated CPU.

*   ``--file-prefix <prefix>``

    EAL file prefix of the primary process to attach to.  Needed when
    the primary was started with a non-default prefix.

*   ``--version``

    Print the version and exit.

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

    wget https://www.tcpdump.org/release/libpcap-1.10.7.tar.xz
    tar xf libpcap-1.10.7.tar.xz
    cd libpcap-1.10.7
    ./configure --enable-remote
    make
    sudo make install

Only the client side of ``rpcap`` is used for ``dpdk-rpcapd``.
Do not run libpcap's version of ``rpcapd``.

``tcpdump`` rebuilt against this libpcap can be used as a client without
further changes.  Wireshark on Windows and macOS ships with rpcap support
enabled by default.


Example
-------

Start a primary application with the packet capture framework
initialized.  ``dpdk-testpmd`` is the simplest:

.. code-block:: console

    sudo ./<build_dir>/app/dpdk-testpmd --vdev=net_tap0 -- -i

In another window, start ``dpdk-rpcapd``:

.. code-block:: console

    sudo ./<build_dir>/examples/dpdk-rpcapd
    RPCAPD: open_listen_socket(): listening on 127.0.0.1 port 2002

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

*   **Original length of truncated packets is not reported.** The
    capture framework in the primary process copies only the snaplen
    worth of bytes and does not carry the original frame length across
    to the secondary, so a truncated packet is reported to the client
    with its on-the-wire length equal to its captured length.  A frame
    longer than the snaplen therefore appears to the client as a short
    frame rather than as a truncated long one.


See Also
--------

*   :doc:`../tools/dumpcap` -- file-based capture writing pcapng
    output.

*   The libpcap project's ``rpcapd`` reference implementation:
    https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
