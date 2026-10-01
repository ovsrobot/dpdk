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
Clients connect to ``dpdk-rpcapd`` using a ``rpcap://`` URL, or
``rpcaps://`` for a TLS-encrypted connection,
request the list of available interfaces(which are the ports of the DPDK primary),
open one, and stream packets from it.

.. warning::

   Anyone who can authenticate to ``dpdk-rpcapd`` can capture all
   traffic flowing through the ports of the DPDK primary process.  The
   default bind address is ``127.0.0.1``, so the listener is not
   reachable from other hosts.  A client on the loopback address may
   connect without credentials; a client from any other address must
   authenticate with a system username and password and must use TLS to
   send it, unless ``-n`` was given.  See `Authentication`_ and `TLS`_.
   **Do not run ``dpdk-rpcapd`` on a production system.**


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

*   ``-l <host_list>``, ``--hosts <host_list>``

    Only allow the hosts in ``<host_list>`` to connect.  The list is
    host names or addresses separated by commas, semicolons or spaces,
    and includes loopback, so ``127.0.0.1`` must be listed for a local
    client.  Names are resolved at startup.  By default any host that
    can reach the port may connect.

*   ``-N <ring_size>``

    Size of the per-session capture ring in packets.  Default is 2048.
    Rounded up to a power of two if necessary.

*   ``-S``, ``--tls``

    Encrypt both the control and the data connection with TLS.  Clients
    must then use a ``rpcaps://`` URL.  Requires ``-X`` and ``-K``.
    Available only when DPDK was built with OpenSSL.

*   ``-X <file>``, ``--cert <file>``

    Server certificate chain in PEM format.  Only meaningful with
    ``-S``, and required by it.

*   ``-K <file>``, ``--key <file>``

    Server private key in PEM format.  Required with ``-S``; there is
    no default.

*   ``-n``, ``--null-auth``

    Permit null authentication from any address, not just loopback.
    Usually used with ``-l``.

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


Authentication
--------------

A client on the loopback address may connect without credentials, which
is what a ``rpcap://`` URL with no userinfo does.

A client from any other address must supply a system username and
password, checked against the host password database as the reference
``rpcapd`` does.  Accounts without a usable password hash, such as
locked accounts, are refused.

A password is only accepted over an encrypted connection, so remote
password authentication requires ``-S`` as well.  A password sent in
the clear is refused without being checked.

Credentials are checked but no privileges are dropped, so this
authenticates a client without authorising it: any account that can log
in has the same access to every port of the primary process.

``-n`` waives the check and lets any client connect unauthenticated,
from any address.


TLS
---

``-S`` encrypts both the control and the data connection, and is
available only when DPDK was built with OpenSSL.

TLS is not negotiated in the rpcap protocol: the client decides from
its URL scheme and the daemon from ``-S``, so the two have to be
configured to agree.  A mismatch is reported rather than left to fail
as a protocol error.

A certificate and key can be generated for testing with:

.. code-block:: console

    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout key.pem -out cert.pem -subj /CN=localhost

Start the daemon with them:

.. code-block:: console

    sudo ./<build_dir>/app/dpdk-rpcapd -S -X cert.pem -K key.pem

Then connect with a ``rpcaps://`` URL:

.. code-block:: console

    sudo /usr/local/sbin/tcpdump -i rpcaps://localhost:2002/net_tap0 -nn -c 20

A client does not validate a self-signed certificate unless told to
trust it, so the connection is encrypted but the server is not
authenticated.


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

*   **TLS needs OpenSSL.** ``-S`` is only available when DPDK was built
    with OpenSSL support.

*   **Authentication does not restrict access.** Credentials are
    checked, but the daemon keeps the root privileges it needs for
    ``pdump`` instead of dropping to the authenticated user, so every
    account that can log in has the same access to every port.

*   **No client certificates.** TLS authenticates the server to the
    client and encrypts the connection; the client is identified only
    by its password.

*   **TCP data transport only.** A client requesting UDP is refused.


See Also
--------

*   :doc:`dumpcap` -- file-based capture writing pcapng
    output.

*   The libpcap project's ``rpcapd`` reference implementation:
    https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
