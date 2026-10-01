..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

.. _rpcapd_tool:

dpdk-rpcapd Application
=======================

The ``dpdk-rpcapd`` application is a Data Plane Development Kit
(DPDK) implementation of the remote packet capture daemon protocol
(``rpcap``) used by libpcap.  It runs as a DPDK secondary process and
allows libpcap-aware tools such as ``tcpdump`` and Wireshark to capture
packets from a DPDK primary process live, without writing to an
intermediate file.

The ``dpdk-rpcapd`` tool implements a subset of the protocol spoken by
the libpcap project's ``rpcapd``.
See
https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
for the reference implementation.
Clients connect to ``dpdk-rpcapd`` using a ``rpcap://`` URL,
request the list of available interfaces(which are the ports of the DPDK primary),
open one, and stream packets from it.

.. warning::

   ``dpdk-rpcapd`` listens on an unauthenticated, unencrypted TCP port
   (default 2002).  Anyone able to reach the port can list DPDK ports
   and capture all traffic flowing through them.  The default bind
   address is ``127.0.0.1``, so the listener is not reachable from
   other hosts; overriding this with ``--bind`` exposes captured
   traffic to anyone who can reach that address.  **Do not run
   ``dpdk-rpcapd`` on a production system.**


Running the Application
-----------------------

The application has a small set of command-line options:

*   ``-p <port>``, ``--port <port>``

    TCP port to listen on.  Default is 2002, the IANA-assigned rpcap
    port.

*   ``-b <addr>``, ``--bind <addr>``

    Numeric IPv4 or IPv6 address to bind the listener to.  Default is
    ``127.0.0.1``, or ``::1`` when ``-6`` is given (loopback only).
    See the warning above before using any other address.

*   ``-4``

    Use only IPv4; an IPv6 argument to ``-b`` is rejected.

*   ``-6``

    Use only IPv6; an IPv4 argument to ``-b`` is rejected.  The default
    bind address becomes ``::1``.

*   ``-N <ring_size>``

    Size of the per-session capture ring in packets.  Default is 2048.
    Rounded up to a power of two if necessary.

*   ``-D``, ``--debug``

    Increase log verbosity.  A single ``-D`` adds informational
    messages; ``-DD`` adds per-request protocol detail.

*   ``--debug-file <file>``

    Append log output to ``<file>`` instead of writing it to standard
    error.

*   ``--send-timeout <seconds>``

    How long a send on the data connection may block before the client
    is treated as dead and the capture stopped.  Default is 10 seconds;
    zero waits forever.

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

Most Linux distributions ship libpcap built without ``rpcap`` support,
since ``--enable-remote`` is off by default.  To use ``dpdk-rpcapd``
from ``tcpdump`` or Wireshark on Linux, rebuild libpcap with it:

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

    sudo ./<build_dir>/app/dpdk-rpcapd
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

The following features of the reference ``rpcapd`` are not implemented
in this initial version:

*   **Single client.** Only one client may be connected at a time.
    Subsequent clients are queued by the listening socket but not
    serviced until the first disconnects.

*   **No authentication.** Password authentication is refused with
    ``PCAP_ERR_AUTH_TYPE_NOTSUP``; clients must connect without
    credentials, which is what a ``rpcap://`` URL with no userinfo does.
    With the default loopback bind, reaching the port already requires
    an account on the host.

*   **No TLS.** The ``-S`` option of the reference ``rpcapd`` is not
    implemented, so the connection is always in the clear.  This is
    reasonable for the default loopback bind, where the traffic never
    leaves the host, but means ``--bind`` to any other address sends
    captured packets over the network unencrypted.

*   **TCP data transport only.** A client requesting UDP is refused.


See Also
--------

*   :doc:`dumpcap` -- file-based capture writing pcapng
    output.

*   The libpcap project's ``rpcapd`` reference implementation:
    https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
