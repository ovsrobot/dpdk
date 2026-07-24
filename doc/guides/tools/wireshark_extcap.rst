..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

Wireshark Extcap Plugin
=======================

The ``dpdk-wireshark-extcap.py`` script is an external capture (extcap)
plugin that lets Wireshark capture live traffic from the Ethernet ports of a
running DPDK application.
Each DPDK port appears as a capture interface in the Wireshark interface list,
alongside the host's own network interfaces.

The plugin uses the DPDK telemetry API to query and start capture.
It passes the path of the fifo file that Wireshark created to the DPDK application,
which opens the file itself and writes pcapng packets straight into it;
the plugin never touches packet data.
Wireshark signals the plugin on exit and that results in closing
the capture session.


Requirements
------------

* A DPDK application built with the capture library and with telemetry enabled.
  Telemetry is enabled by default.

* Since the plugin is started by Wireshark, Wireshark and the DPDK application
  must have the same permissions. See `Permissions`_.


Installation
------------

For Wireshark to discover the plugin it must be present in an extcap
directory. The configured locations are listed in Wireshark under
*Help > About Wireshark > Folders*. Copy or symbolically link the script into
the personal extcap directory, for example::

    ln -s $RTE_SDK/usertools/dpdk-wireshark-extcap.py \
        ~/.local/lib/wireshark/extcap/

The DPDK ports then appear in the interface list the next time the capture
options dialog is opened.


Usage
-----

In normal use the plugin is not run by hand; Wireshark invokes it.
The ports of a running DPDK application appear in the interface list as
``DPDK <name>``, where ``<name>`` is the device name reported by
DPDK ethdev, such as ``net_tap0``.

The plugin can also be run directly, which is useful for confirming that a
DPDK application is reachable::

    $ usertools/dpdk-wireshark-extcap.py --extcap-interfaces
    extcap {version=0.1}{display=DPDK telemetry capture}
    interface {value=dpdk:0}{display=DPDK net_tap0}


Capture options
---------------

The following options are offered in the Wireshark capture options dialog for
a DPDK interface:

Snapshot length
    Number of bytes captured from each packet. ``0`` captures the whole
    packet. The default is 262144.

Queue
    Capture a single hardware queue, or all queues (the default). The choices
    are bounded to the port's configured queue count.

Capture filter
    A libpcap filter expression, applied by the DPDK application to the
    captured traffic.


Permissions
-----------

The DPDK runtime directory is created mode ``0700``, so only the user that
started the DPDK application can reach its telemetry socket.
Wireshark, and the plugin it launches, must run as that same user. If run as a
different user, the interface list is simply empty; running the plugin directly
with ``--extcap-interfaces`` prints a diagnostic to standard error explaining
the permission failure.

No privilege beyond access to the telemetry socket is required: if you can
run ``dpdk-dumpcap`` against an application, you can capture from it with this
plugin.


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

``DPDK_EXTCAP_PATH``
    Overrides the base DPDK runtime directory that holds the per-prefix
    subdirectories. Use it when the runtime directory is in a non-standard
    location. It gives the base directory that holds the per-prefix
    subdirectories, one of which is scanned for each running application.


Troubleshooting
---------------

The DPDK ports do not appear in Wireshark
    Confirm the application is running and was built with the capture library
    and telemetry. Confirm Wireshark runs as the same user as the application;
    see `Permissions`_. An application started with a non-default
    ``--file-prefix`` is listed with its ports qualified as
    ``DPDK <name>@<prefix>``; see `Selecting a DPDK application`_.

    Running the plugin directly with ``--extcap-interfaces`` prints
    diagnostics to standard error that the Wireshark GUI does not surface.

A port is listed as ``portN`` instead of a device name
    The port was reported by the application, but its details could not be
    read, usually because the application stopped between listing and naming
    its ports. A capture started against it will fail; restart the
    application.
