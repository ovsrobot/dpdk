#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-or-later
# Copyright(c) 2026 Stephen Hemminger

"""
Wireshark extcap plugin for live capture from DPDK ethdev ports.

Capture path: Wireshark creates a FIFO and hands this plugin its path. The
plugin opens the FIFO -- which rendezvous with Wireshark's read end -- and then
passes the FIFO *path* to the DPDK primary process over the telemetry socket as
the 'out=' parameter. DPDK opens the FIFO itself and writes pcapng straight into
it; this plugin never touches packet data.

Stopping: Wireshark stops a capture by closing the FIFO read end and/or sending
SIGTERM. On either, this plugin asks DPDK to stop (/ethdev/capture/stop,<id>) so
it can flush the trailing packets and the closing interface statistics block
while a reader is still attached. If the read end is already gone, DPDK detects
the same hangup and stops on its own; the explicit stop is then a harmless
no-op. Note that when stopped from the Wireshark GUI the read-end close usually
precedes the signal, so the statistics block is delivered reliably only for
standalone (Ctrl+C) runs and for file output.

Interface values: 'dpdk:<port>' for the default file-prefix ('rte'), and
'dpdk:<prefix>:<port>' for any other primary. The default prefix is left
implicit so the common single-instance case stays unadorned.
"""

import argparse
import json
import os
import select
import signal
import socket
import sys

EXTCAP_VERSION = "0.1"
TELEMETRY_SOCKET = "dpdk_telemetry.v2"
CAPTURE_START_CMD = "/ethdev/capture/start"
CAPTURE_STOP_CMD = "/ethdev/capture/stop"
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


def socket_path(prefix):
    return os.path.join(dpdk_dir(), prefix, TELEMETRY_SOCKET)


def list_prefixes():
    """Yield (prefix, path) for each DPDK telemetry socket found."""
    root = dpdk_dir()
    try:
        entries = os.listdir(root)
    except FileNotFoundError:
        # No DPDK runtime dir -> no DPDK application is running.
        return
    except PermissionError:
        # The runtime dir is mode 0700; a different user can see nothing.
        sys.stderr.write(
            f"cannot read {root}: permission denied. The DPDK runtime "
            "directory is created mode 0700, so capture must run as the same "
            "user as the DPDK application, or set DPDK_EXTCAP_PATH.\n"
        )
        return

    for prefix in sorted(entries):
        path = os.path.join(root, prefix, TELEMETRY_SOCKET)
        if os.path.exists(path):
            yield prefix, path


def iface_value(prefix, port):
    """Interface value for a (prefix, port). The default prefix is left
    implicit so a single default-prefix instance shows 'dpdk:<port>'; any
    other primary is spelled out as 'dpdk:<prefix>:<port>'."""
    if prefix == DEFAULT_PREFIX:
        return f"dpdk:{port}"
    return f"dpdk:{prefix}:{port}"


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

    def command(self, cmd):
        """Send a command, return the decoded JSON reply, or None if empty."""
        self.sock.send(cmd.encode())
        reply = self.sock.recv(self.max_output_len)
        if not reply:
            return None
        return json.loads(reply.decode())

    def close(self):
        self.sock.close()


def port_queue_count(tel, port):
    """Max of the rx/tx queue counts for a port, 0 if unknown."""
    try:
        reply = tel.command(f"{ETHDEV_INFO},{port}")
    except OSError:
        reply = None
    info = (reply or {}).get(ETHDEV_INFO) or {}
    return max(info.get("nb_rx_queues", 0), info.get("nb_tx_queues", 0))


# --- extcap query operations --------------------------------------------


def port_name(tel, port):
    """Device name for a port via /ethdev/info, or 'port<N>' if unreadable.
    For a physical port this is the PCI address (0000:c1:00.0); for a vdev it
    is the vdev name (net_tap0). Reuses the caller's open connection."""
    try:
        reply = tel.command(f"{ETHDEV_INFO},{port}")
    except OSError:
        reply = None
    info = (reply or {}).get(ETHDEV_INFO) or {}
    return info.get("name") or f"port{port}"


def cmd_interfaces():
    print(f"extcap {{version={EXTCAP_VERSION}}}{{display=DPDK telemetry capture}}")
    for prefix, path in list_prefixes():
        try:
            tel = Telemetry(path)
        except OSError as e:
            sys.stderr.write(f"cannot query {path}: {e}\n")
            continue
        # One connection per prefix for the whole enumeration: list the ports,
        # then name each over the same socket (each connection costs the
        # primary a handler thread).
        try:
            ports = (tel.command(ETHDEV_LIST) or {}).get(ETHDEV_LIST) or []
            for port in ports:
                name = port_name(tel, port)
                # Name the prefix in the label only when it is not the default.
                if prefix == DEFAULT_PREFIX:
                    display = f"DPDK {name}"
                else:
                    display = f"DPDK {name}@{prefix}"
                print(
                    f"interface {{value={iface_value(prefix, port)}}}"
                    f"{{display={display}}}"
                )
        except OSError as e:
            sys.stderr.write(f"cannot query {path}: {e}\n")
        finally:
            tel.close()


def cmd_dlts(_iface):
    print(f"dlt {{number={DLT_EN10MB}}}{{name=EN10MB}}{{display=Ethernet}}")


def cmd_config(iface):
    print(
        f"arg {{number=0}}{{call=--snaplen}}{{display=Snapshot length}}"
        f"{{tooltip=Bytes captured per packet (0 = whole packet)}}"
        f"{{type=integer}}{{range=0,{DEFAULT_SNAPLEN}}}"
        f"{{default={DEFAULT_SNAPLEN}}}{{group=Capture}}"
    )

    # Bound the queue dropdown to the port's actual queue count. If the primary
    # is unreachable, just omit the selector -- capture still defaults to all.
    nqueues = 0
    if iface:
        prefix, port = parse_iface(iface)
        try:
            tel = Telemetry(socket_path(prefix))
        except OSError:
            tel = None
        if tel is not None:
            try:
                nqueues = port_queue_count(tel, port)
            finally:
                tel.close()

    if nqueues > 0:
        print(
            f"arg {{number=1}}{{call=--queue}}{{display=Queue}}"
            f"{{tooltip=Capture a single hardware queue}}"
            f"{{type=selector}}{{group=Capture}}"
        )
        print("value {arg=1}{value=-1}{display=All queues}{default=true}")
        for q in range(nqueues):
            print(f"value {{arg=1}}{{value={q}}}{{display=Queue {q}}}")


# --- capture -------------------------------------------------------------


def parse_iface(iface):
    """Inverse of iface_value: accept 'dpdk:<port>' (default prefix) or
    'dpdk:<prefix>:<port>'."""
    parts = iface.split(":")
    if parts[0] != "dpdk":
        raise SystemExit(f"unsupported interface scheme in '{iface}'")
    if len(parts) == 2:
        prefix, port = DEFAULT_PREFIX, parts[1]
    elif len(parts) == 3:
        prefix, port = parts[1], parts[2]
    else:
        raise SystemExit(f"malformed interface '{iface}'")
    try:
        port = int(port)
    except ValueError:
        raise SystemExit(f"malformed interface '{iface}'")
    return prefix, port


def wait_for_stop(fifo_fd):
    """Block until Wireshark stops us: either it closes the FIFO read end
    (POLLERR on our write fd) or it sends SIGINT/SIGTERM. Watching the fd as
    well as the signal matters because the signal may be missed -- Wireshark's
    reliable stop is closing the pipe."""
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


def cmd_capture(iface, fifo, snaplen, queue, cfilter):
    prefix, port = parse_iface(iface)
    path = socket_path(prefix)

    # Blocking open of the FIFO Wireshark created. This rendezvous guarantees a
    # reader is attached before we ask DPDK to open the write end (DPDK opens
    # O_WRONLY|O_NONBLOCK and would fail with ENXIO if no reader were present).
    # We then hold this fd for the whole session: it keeps the pipe from
    # EOF-ing in the window before the DPDK capture thread opens its own write
    # end, and it is our reliable stop signal -- POLLERR here means Wireshark
    # closed the read end.
    fifo_fd = os.open(fifo, os.O_WRONLY)

    try:
        tel = Telemetry(path)
    except OSError as e:
        os.close(fifo_fd)
        raise SystemExit(f"cannot connect to DPDK telemetry at {path}: {e}")

    params = [str(port), f"out={fifo}"]
    if snaplen is not None:
        params.append(f"snaplen={snaplen}")
    if queue is not None and queue >= 0:
        params.append(f"queue={queue}")
    if cfilter:
        params.append(f"filter={cfilter}")
    cmd = CAPTURE_START_CMD + "," + ",".join(params)

    try:
        reply = tel.command(cmd)
    except OSError as e:
        os.close(fifo_fd)
        tel.close()
        raise SystemExit(f"capture start failed: {e}")

    result = (reply or {}).get(CAPTURE_START_CMD) or {}
    if "error" in result:
        os.close(fifo_fd)
        tel.close()
        raise SystemExit(f"capture start failed: {result['error']}")

    cap_id = result.get("id")

    # Run until Wireshark stops us (signal or read-end close). DPDK now holds
    # its own write end, so closing ours below won't EOF the reader prematurely.
    wait_for_stop(fifo_fd)

    # Ask DPDK to stop while we still hold the write end, so if the reader is
    # still attached it drains the tail and writes the statistics block before
    # the final EOF. If the read end is already gone DPDK has already stopped
    # on the same hangup and this is a no-op.
    if cap_id is not None:
        try:
            tel.command(f"{CAPTURE_STOP_CMD},{cap_id}")
        except OSError:
            pass

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
    p.add_argument("--extcap-version", nargs="?")
    p.add_argument("--snaplen", type=int)
    p.add_argument("--queue", type=int)
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
            args.extcap_interface,
            args.fifo,
            args.snaplen,
            args.queue,
            args.extcap_capture_filter,
        )
    elif args.extcap_capture_filter:
        # Wireshark validates a capture filter by invoking the extcap with the
        # filter but without --capture (see doc/extcap_example.py upstream). We
        # accept it: Wireshark already syntax-checks it with libpcap against our
        # DLT (EN10MB), and DPDK compiles it again at capture start. Exiting 0
        # with no output means "accepted"; printing a line would mark it invalid.
        pass
    else:
        raise SystemExit("no extcap operation specified")


if __name__ == "__main__":
    main()
