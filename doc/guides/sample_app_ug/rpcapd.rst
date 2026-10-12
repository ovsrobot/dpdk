..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

.. _rpcapd_example:

Remote Packet Capture Daemon Sample Application
===============================================

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
request the list of available interfaces (which are the ports of the DPDK
primary),
open one, and stream packets from it.

This is an example, not a supported application, for three reasons:

*   ``rpcap`` is not a secure protocol.  See `Security`_ below.

*   Clients need rebuilding.  ``--enable-remote`` is off by default in
    libpcap, so the ``tcpdump`` and libpcap that distributions ship
    cannot speak ``rpcap`` at all.  See `Client Setup`_.

*   Linux only.  Capturing from a running application means attaching to
    it as a DPDK secondary process, and multi-process support only works
    on Linux.


Security
--------

The protocol has no authentication and no encryption, so the listener is
bound to the loopback addresses only and is never reachable from another
host.

A connection grants read access to all traffic of the primary
process.  Any client can list its ports and capture from any of them,
including traffic belonging to other users of that application, and
can turn on promiscuous mode on a port the primary owns.

The listener is reachable by every user on the host.  Since
``dpdk-rpcapd`` normally runs as root, starting it gives any local
user that access.  Running this on a production system is not
advisable.


Running the Application
-----------------------

The application has a small set of command-line options:

*   ``-p <port>``, ``--port <port>``

    TCP port to listen on.  Default is 2002, the IANA-assigned rpcap
    port.

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
from ``tcpdump`` or Wireshark on Linux, rebuild libpcap with it.
The ``rpcap`` client was added in libpcap 1.9.0, so any release from
that one on will do:

.. code-block:: console

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
    RPCAPD: open_listen_sockets(): listening on 127.0.0.1 port 2002

In a third window, list available interfaces using a libpcap-based
``tcpdump`` rebuilt with remote support:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump --list-remote-interfaces=rpcap://127.0.0.1:2002/
    rpcap://127.0.0.1:2002/net_tap0  Network adapter 'DPDK port' on remote node 127.0.0.1

Capture live from a port:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump -i rpcap://127.0.0.1:2002/net_tap0 -nn -c 20

Or save to a file readable by any pcap consumer:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump -i rpcap://127.0.0.1:2002/net_tap0 -w /tmp/capture.pcap


Limitations
-----------

The following features of the reference ``rpcapd`` are not implemented
in this initial version:

*   **Single client.** Only one client may be connected at a time.
    Subsequent clients are queued by the listening socket but not
    serviced until the first disconnects.

*   **No TLS and no password authentication.** See `Security`_ above.
    A password is refused with ``PCAP_ERR_AUTH_TYPE_NOTSUP``; clients
    must connect without credentials, which is what a ``rpcap://`` URL
    with no userinfo does.

*   **TCP data transport only.** A client requesting UDP is refused.

*   **Approximate timestamps.** Packets are stamped when sent
    to the client, not when the port received them.

See Also
--------

*   :doc:`../tools/dumpcap` -- file-based capture writing pcapng
    output.

*   The libpcap project's ``rpcapd`` reference implementation:
    https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
