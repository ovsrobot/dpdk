#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-or-later
# Copyright(c) 2026 Stephen Hemminger

"""
Wireshark extcap plugin for live capture from DPDK ethdev ports.

Capture path: this plugin opens the FIFO that Wireshark hands it, then passes
that file descriptor to the DPDK primary process over the telemetry socket
(via SCM_RIGHTS). The DPDK 'capture' library writes pcapng straight into the
FIFO; this plugin never touches packet data. Teardown is implicit: when
Wireshark closes the read end, both the DPDK writer and this plugin see the
hangup.

Interface values are encoded as 'dpdk:<port>'. The DPDK file-prefix is
ambient, not part of the interface value: it comes from
DPDK_EXTCAP_FILE_PREFIX (default 'rte') in the environment Wireshark inherits,
so one invocation is scoped to a single primary like a namespace. See
doc/guides/tools/wireshark_extcap.rst for the rationale and the multi-prefix
case.
"""

import argparse
import array
import json
import os
import select
import signal
import socket
import sys

EXTCAP_VERSION = "0.1"
TELEMETRY_SOCKET = "dpdk_telemetry.v2"
CAPTURE_CMD = "/ethdev/capture/start"
ETHDEV_LIST = "/ethdev/list"
ETHDEV_INFO = "/ethdev/info"
DEFAULT_SNAPLEN = 262144
DEFAULT_PREFIX = "rte"  # EAL HUGEFILE_PREFIX_DEFAULT
DLT_EN10MB = 1


# --- DPDK runtime directory / socket discovery ---------------------------


def dpdk_dir():
    """Directory holding the per-file-prefix runtime subdirectories."""
    override = os.environ.get("DPDK_EXTCAP_PATH")
    if override:
        return override
    if os.geteuid() == 0:
        base = "/var/run"
    else:
        base = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return os.path.join(base, "dpdk")


def file_prefix():
    """The EAL file-prefix to operate on; see the module docstring."""
    return os.environ.get("DPDK_EXTCAP_FILE_PREFIX", DEFAULT_PREFIX)


def socket_path():
    return os.path.join(dpdk_dir(), file_prefix(), TELEMETRY_SOCKET)


# --- Telemetry transport -------------------------------------------------


class Telemetry:
    """Minimal client for the DPDK v2 telemetry socket (SOCK_SEQPACKET)."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.connect(path)
        info = json.loads(self.sock.recv(1024).decode())
        self.max_output_len = info.get("max_output_len", 16384)
        self.pid = info.get("pid")
        self.version = info.get("version")

    def command(self, cmd, fds=None):
        """Send a command, optionally with file descriptors as ancillary data.

        Returns the decoded JSON reply, or None if the peer sent nothing.
        """
        if fds:
            fd_arr = array.array("i", fds)
            self.sock.sendmsg(
                [cmd.encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd_arr)]
            )
        else:
            self.sock.send(cmd.encode())

        reply = self.sock.recv(self.max_output_len)
        if not reply:
            return None
        return json.loads(reply.decode())

    def close(self):
        self.sock.close()


# --- extcap query operations --------------------------------------------


def port_name(tel, port):
    """Device name for a port via /ethdev/info, or 'port<N>' if unreadable."""
    try:
        reply = tel.command(f"{ETHDEV_INFO},{port}")
    except OSError:
        reply = None
    info = (reply or {}).get(ETHDEV_INFO) or {}
    return info.get("name") or f"port{port}"


def cmd_interfaces():
    print(f"extcap {{version={EXTCAP_VERSION}}}{{display=DPDK telemetry capture}}")
    path = socket_path()
    try:
        tel = Telemetry(path)
    except FileNotFoundError:
        # No telemetry socket -> no DPDK primary with this file-prefix.
        return
    except PermissionError:
        # The runtime dir is mode 0700; a different user cannot traverse it.
        sys.stderr.write(
            f"cannot access {path}: permission denied. The DPDK runtime "
            "directory is created mode 0700, so capture must run as the same "
            "user as the DPDK application (or set DPDK_EXTCAP_PATH / "
            "DPDK_EXTCAP_FILE_PREFIX).\n"
        )
        return

    # One connection for the whole enumeration: list the ports, then name
    # each over the same socket (each telemetry connection costs the primary
    # a handler thread).
    try:
        reply = tel.command(ETHDEV_LIST)
        ports = (reply or {}).get(ETHDEV_LIST) or []
        for port in ports:
            name = port_name(tel, port)
            print(
                f"interface {{value=dpdk:{port}}}"
                f"{{display=DPDK {name} (port {port})}}"
            )
    except OSError as e:
        sys.stderr.write(f"cannot query {path}: {e}\n")
    finally:
        tel.close()


def cmd_dlts(_iface):
    print(f"dlt {{number={DLT_EN10MB}}}{{name=EN10MB}}{{display=Ethernet}}")


def cmd_config(_iface):
    print(
        f"arg {{number=0}}{{call=--snaplen}}{{display=Snapshot length}}"
        f"{{tooltip=Bytes captured per packet (0 = whole packet)}}"
        f"{{type=integer}}{{range=0,{DEFAULT_SNAPLEN}}}"
        f"{{default={DEFAULT_SNAPLEN}}}{{group=Capture}}"
    )


# --- capture -------------------------------------------------------------


def parse_iface(iface):
    """Return the port number from a 'dpdk:<port>' interface value."""
    scheme, sep, port = iface.partition(":")
    if scheme != "dpdk" or not sep:
        raise SystemExit(f"unsupported interface '{iface}'")
    try:
        return int(port)
    except ValueError:
        raise SystemExit(f"malformed interface '{iface}'")


def wait_for_stop(fifo_fd):
    """Block until Wireshark stops us: either it closes the FIFO read end
    (POLLERR on our write fd) or it sends SIGINT/SIGTERM."""
    rd, wr = os.pipe()
    os.set_blocking(wr, False)
    signal.set_wakeup_fd(wr)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: None)

    poller = select.poll()
    poller.register(fifo_fd, select.POLLERR)
    poller.register(rd, select.POLLIN)
    poller.poll()

    signal.set_wakeup_fd(-1)
    os.close(rd)
    os.close(wr)


def cmd_capture(iface, fifo, snaplen, cfilter):
    port = parse_iface(iface)
    path = socket_path()

    # Open the FIFO Wireshark created; this blocks until it has the read end.
    fifo_fd = os.open(fifo, os.O_WRONLY)

    try:
        tel = Telemetry(path)
    except OSError as e:
        os.close(fifo_fd)
        raise SystemExit(f"cannot connect to DPDK telemetry at {path}: {e}")

    params = [str(port)]
    if snaplen is not None:
        params.append(f"snaplen={snaplen}")
    if cfilter:
        params.append(f"filter={cfilter}")
    cmd = CAPTURE_CMD + "," + ",".join(params)

    try:
        tel.command(cmd, fds=[fifo_fd])
    except OSError as e:
        os.close(fifo_fd)
        tel.close()
        raise SystemExit(f"capture start failed: {e}")

    # DPDK now holds its own dup of the FIFO write end. We keep ours only as a
    # hangup sentinel: when Wireshark closes the read end we get POLLERR, the
    # same event that stops the DPDK-side writer.
    wait_for_stop(fifo_fd)

    os.close(fifo_fd)
    tel.close()


# --- entry point ---------------------------------------------------------


def main():
    p = argparse.ArgumentParser(
        prog="dpdk-wireshark-extcap.py",
        allow_abbrev=False,
        description="Wireshark extcap plugin for live packet capture from the "
        "Ethernet ports of a running DPDK application. Normally "
        "invoked by Wireshark; see the DPDK Wireshark extcap guide.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {EXTCAP_VERSION}")

    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--extcap-interface")
    p.add_argument("--fifo")
    p.add_argument("--extcap-capture-filter")
    p.add_argument("--extcap-version")
    p.add_argument("--snaplen", type=int)
    args, _ = p.parse_known_args()

    if args.extcap_interfaces:
        cmd_interfaces()
    elif args.extcap_dlts:
        cmd_dlts(args.extcap_interface)
    elif args.extcap_config:
        cmd_config(args.extcap_interface)
    elif args.capture:
        if not args.extcap_interface or not args.fifo:
            raise SystemExit("--capture requires --extcap-interface and --fifo")
        cmd_capture(
            args.extcap_interface, args.fifo, args.snaplen, args.extcap_capture_filter
        )
    else:
        raise SystemExit("no extcap operation specified")


if __name__ == "__main__":
    main()
