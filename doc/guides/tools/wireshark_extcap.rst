..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Stephen Hemminger

Wireshark Extcap Plugin
=======================

The ``dpdk-wireshark-extcap.py`` script is an external capture (extcap)
plugin that lets Wireshark capture live traffic from the Ethernet ports of a
running DPDK application. Each DPDK port appears as a capture interface in the
Wireshark interface list, alongside the host's own network interfaces.

The plugin does not attach to the DPDK application as a secondary process and
never touches packet data itself. It connects to the application's telemetry
socket, asks it to start capturing, and hands Wireshark's capture pipe to the
application over that socket. The DPDK capture library writes pcapng packets
directly into the pipe; the plugin only sets the capture up and tears it down
when Wireshark closes the pipe.


Requirements
------------

* A DPDK application built with the capture library and with telemetry
  enabled. Telemetry is enabled by default.

* Wireshark with extcap support.

* The plugin, and therefore Wireshark, must run as the same user as the DPDK
  application. See `Permissions`_.


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

In normal use the plugin is not run by hand; Wireshark invokes it. The ports
of a running DPDK application appear in the interface list as
``DPDK <name> (port <N>)``, where ``<name>`` is the device name reported by
the application, such as ``net_tap0``. Selecting a port and starting the
capture is all that is required.

The plugin can also be run directly, which is useful for confirming that a
DPDK application is reachable::

    $ usertools/dpdk-wireshark-extcap.py --extcap-interfaces
    extcap {version=0.1}{display=DPDK telemetry capture}
    interface {value=dpdk:0}{display=DPDK net_tap0 (port 0)}


Capture options
---------------

The following options are offered in the Wireshark capture options dialog for
a DPDK interface:

Snapshot length
    Number of bytes captured from each packet. ``0`` captures the whole
    packet. The default is 262144.

Capture filter
    A libpcap filter expression, applied by the DPDK application to the
    captured traffic.


Permissions
-----------

The DPDK runtime directory is created mode ``0700``, so only the user that
started the DPDK application can reach its telemetry socket. Wireshark, and
the plugin it launches, must run as that same user. Run as a different user,
the interface list is simply empty; running the plugin directly with
``--extcap-interfaces`` prints a diagnostic to standard error explaining the
permission failure.

No privilege beyond access to the telemetry socket is required: if you can
run ``dpdk-dumpcap`` against an application, you can capture from it with this
plugin.


Selecting a DPDK application
----------------------------

A host usually runs a single DPDK application, started with the default
file-prefix, and no configuration is needed: its ports appear automatically.

Running several DPDK applications on one host is uncommon. Each primary
process needs its own dedicated cores, memory, and network ports, so it is
generally done only on large hosts deliberately partitioned for the purpose.
In that case each application is started with a distinct ``--file-prefix`` so
that its runtime state is kept separate.

Each file-prefix is an independent namespace, much like a network namespace.
The plugin operates within exactly one of them at a time and lists only the
ports of the application using that prefix. The prefix is selected by the
``DPDK_EXTCAP_FILE_PREFIX`` environment variable, which corresponds to the EAL
``--file-prefix`` option and defaults to ``rte`` (the EAL default). It must be
present in the environment that Wireshark inherits, so it has to be set before
Wireshark is launched, not from within the capture dialog::

    DPDK_EXTCAP_FILE_PREFIX=myapp wireshark

The prefix cannot be chosen per capture from the Wireshark GUI, by design.
Wireshark builds the interface list once, before any interface or its options
are selected, so the prefix must be known at enumeration time. It is also
deliberately not a per-interface option: the device names in the list are
resolved against one application, and a per-capture override would let the
name shown disagree with the port actually captured.


Environment variables
----------------------

``DPDK_EXTCAP_FILE_PREFIX``
    Selects which DPDK application, by EAL file-prefix, the plugin operates
    on. Defaults to ``rte``. See `Selecting a DPDK application`_.

``DPDK_EXTCAP_PATH``
    Overrides the base DPDK runtime directory that holds the per-prefix
    subdirectories. Use it when the runtime directory is in a non-standard
    location. It composes with ``DPDK_EXTCAP_FILE_PREFIX``: this variable
    gives the base directory, the prefix selects the subdirectory within it.


Troubleshooting
---------------

The DPDK ports do not appear in Wireshark
    Confirm the application is running and was built with the capture library
    and telemetry. Confirm Wireshark runs as the same user as the application;
    see `Permissions`_. If the application was started with a non-default
    ``--file-prefix``, set ``DPDK_EXTCAP_FILE_PREFIX`` to match before
    launching Wireshark; see `Selecting a DPDK application`_.

    Running the plugin directly with ``--extcap-interfaces`` prints
    diagnostics to standard error that the Wireshark GUI does not surface.

A port is listed as ``portN`` instead of a device name
    The port was reported by the application, but its details could not be
    read, usually because the application stopped between listing and naming
    its ports. A capture started against it will fail; restart the
    application.
