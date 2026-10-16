..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

Wireshark Extcap Plugin
=======================

The ``dpdk-wireshark-extcap`` program is an external capture (extcap)
plugin that enables Wireshark capture of live traffic from
the Ethernet ports of a DPDK application.
Each DPDK port appears as a capture interface in the Wireshark interface list,
alongside the host's own network interfaces.

The plugin uses the DPDK telemetry API to query and start capture.
The work is done by the :doc:`capture library <../prog_guide/capture_lib>`
in the application.
It passes the path of the fifo file that Wireshark created to the DPDK application,
which opens the file itself and writes pcapng packets straight into it;
the plugin never touches packet data.
Wireshark signals the plugin on exit and that results in closing
the capture session.


Requirements
------------

* A DPDK application built with the
  :doc:`capture library <../prog_guide/capture_lib>` and with telemetry
  enabled. Telemetry is enabled by default.

* Since the plugin is started by Wireshark, Wireshark must be able to reach
  the telemetry socket of the DPDK application. See `Permissions`_.

The plugin is a standalone C program that speaks the telemetry protocol
directly and links against nothing from DPDK. It is built and installed with
the other DPDK tools, except on Windows. Building with ``libcap`` allows the
capability install described under `Permissions`_.


Installation
------------

For Wireshark to discover the plugin it must be present in an extcap
directory. The configured locations are listed in Wireshark under
*Help > About Wireshark > Folders*. Symbolically link the program into the
personal extcap directory, naming it ``dpdkdump`` to match the convention of
the other programs there::

    ln -s /usr/local/bin/dpdk-wireshark-extcap \
        ~/.local/lib/wireshark/extcap/dpdkdump

Or from a build tree::

    ln -s $(pwd)/build/usertools/dpdk-wireshark-extcap \
        ~/.local/lib/wireshark/extcap/dpdkdump

The DPDK ports then appear in the interface list the next time the capture
options dialog is opened.


Permissions
-----------

The DPDK runtime directory is created mode ``0700``, so only the user that
started the DPDK application can reach its telemetry socket. No privilege
beyond access to that socket is required: if you can run ``dpdk-dumpcap``
against an application, you can capture from it with this plugin.

Running Wireshark as that same user needs nothing more, and a DPDK
application need not run as root. A containerized one has its own runtime
directory, which can be made readable by the Wireshark user. Run as a
different user the interface list is empty, and ``--extcap-interfaces``
prints the permission failure to standard error.

The rest of this section applies only to capturing from a root application as
an ordinary user. Install set-user-ID to the user running the application,
root here, and restrict who may execute it::

    chown root:wireshark dpdk-wireshark-extcap
    chmod 4750 dpdk-wireshark-extcap

Set-group-ID is not enough: the runtime directory is mode ``0700``, so the
group bits grant nothing. This is unlike ``dumpcap``, which is set-group-ID
because the ``/dev/bpf`` devices it needs are group accessible.

On Linux a capability grants less and is preferred where available::

    chown root:wireshark dpdk-wireshark-extcap
    chmod 0750 dpdk-wireshark-extcap
    setcap cap_dac_override+ep dpdk-wireshark-extcap

This needs a build with ``libcap``; without it a file capability cannot be
dropped and the plugin refuses to run. ``cap_dac_override`` rather than
``cap_dac_read_search`` because connecting to the socket needs write
permission. FreeBSD has no file capabilities, so set-user-ID is the only
option there.

Whoever runs Wireshark must be in the group named above, or the plugin cannot
be executed and no DPDK interfaces appear. Link the extcap entry to the
installed program; copying does not preserve set-user-ID or capabilities.

Privilege is used only for the connect, then dropped permanently before the
banner is read, before any reply is parsed, and before the FIFO is opened.
The drop is verified and privilege is never raised again, following
``dumpcap``. Nothing after the connect needs privilege, so unlike ``dumpcap``
none is retained.

After a privileged start the plugin is more restrictive: the environment is
ignored, only ``/var/run/dpdk`` is searched, and the output must be a FIFO.


Usage
-----

In normal use the plugin is not run by hand; Wireshark invokes it.
The ports of a running DPDK application appear in the interface list as
``DPDK <name>``, where ``<name>`` is the device name reported by
DPDK ethdev, such as ``net_tap0``.

The plugin can also be run directly, which is useful for confirming that a
DPDK application is reachable::

    $ dpdk-wireshark-extcap --extcap-interfaces
    extcap {version=0.1}{display=DPDK telemetry capture}
    interface {value=dpdk:0}{display=DPDK net_tap0}

When no interfaces are listed the reason is printed to standard error, which
the Wireshark GUI does not show. ``--help`` lists the options.


Capture options
---------------

The following options are offered in the Wireshark capture options dialog for
a DPDK interface:

Snapshot length
    Number of bytes captured from each packet. ``0`` captures the whole
    packet. The default is 262144.

Queue
    Capture a single hardware queue, or all queues (the default). The choices
    are bounded to the port's configured queue count. If the queue count
    cannot be read the option is omitted and capture uses all queues.

Capture filter
    A libpcap filter expression, applied by the DPDK application to the
    captured traffic.


Selecting a DPDK application
----------------------------

A host usually runs a single DPDK application, started with the default
file-prefix (``rte``), and no configuration is needed: its ports appear
automatically as ``DPDK <name>``.

Running several DPDK applications on one host is also supported. In that case
each application is started with a distinct ``--file-prefix`` so that its
runtime state is kept separate. The plugin lists the ports of *all* running
applications at once, so the application is chosen from the interface list
rather than before Wireshark is launched. There is no environment variable to
select one.

Ports of the default prefix are shown plainly, as ``DPDK <name>`` with the
interface value ``dpdk:<port>``. Ports of any other prefix are qualified with
the prefix, shown as ``DPDK <name>@<prefix>`` with the interface value
``dpdk:<prefix>:<port>``, so applications with colliding port numbers stay
distinct in the list.


Environment variables
----------------------

The runtime directory location depends on the user the DPDK application runs
as, not on who runs the plugin, so both are searched: ``/var/run/dpdk`` for an
application started by root, and ``$XDG_RUNTIME_DIR/dpdk``, or ``/tmp/dpdk``
if that is unset, for one started by an ordinary user. Ports found in either
are listed together.

``DPDK_EXTCAP_PATH``
    Search this base directory instead, for a runtime directory in a
    non-standard location. Ignored, along with ``XDG_RUNTIME_DIR``, after a
    privileged start; see `Permissions`_.


Troubleshooting
---------------

The DPDK ports do not appear in Wireshark
    Confirm the application is running and was built with the capture library
    and telemetry. Confirm Wireshark runs as the same user as the application,
    or that the plugin is installed with privilege; see `Permissions`_. An
    application started with a non-default ``--file-prefix`` is listed with
    its ports qualified as ``DPDK <name>@<prefix>``; see
    `Selecting a DPDK application`_.

    Running ``--extcap-interfaces`` by hand prints diagnostics to standard
    error that the Wireshark GUI hides.

A port is listed as ``portN`` instead of a device name
    The port was reported but its details could not be read, usually because
    the application stopped in between. A capture against it will fail;
    restart the application.
