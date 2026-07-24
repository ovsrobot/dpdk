#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
dpdk-dumpcap: capture packets from a running DPDK primary process.

A tcpdump/dumpcap-style front end for the DPDK 'capture' library. Unlike the
legacy secondary-process dpdk-dumpcap (which used pdump and required the primary
to initialise the capture framework), this drives the primary directly over its
telemetry socket: the primary opens the output file itself and writes pcapng
into it. It works with any primary that links lib/capture; no application
changes are needed.

Examples:
    dpdk-dumpcap --list-interfaces
    dpdk-dumpcap -i 0 -w /tmp/port0.pcapng
    dpdk-dumpcap -i 0 -c 100 -f 'tcp port 80'
"""

import argparse
import json
import os
import signal
import socket
import sys
import tempfile
import time

TELEMETRY_SOCKET = "dpdk_telemetry.v2"
CAPTURE_START_CMD = "/ethdev/capture/start"
CAPTURE_STOP_CMD = "/ethdev/capture/stop"
CAPTURE_STATS_CMD = "/ethdev/capture/stats"
ETHDEV_LIST = "/ethdev/list"
ETHDEV_INFO = "/ethdev/info"
DEFAULT_SNAPLEN = 262144
COUNT_POLL_INTERVAL = 0.1  # fast stats poll cadence when -c is set
POLL_TICK = 0.5  # loop wake granularity; bounds Ctrl-C latency when idle
DEFAULT_STATS_INTERVAL = 0.5  # seconds between liveness updates


# --- DPDK runtime directory / socket discovery ---------------------------


def dpdk_dir():
    override = os.environ.get("DPDK_EXTCAP_PATH")
    if override:
        return override
    base = (
        "/var/run" if os.geteuid() == 0 else os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    )
    return os.path.join(base, "dpdk")


def socket_path(prefix):
    return os.path.join(dpdk_dir(), prefix, TELEMETRY_SOCKET)


def list_prefixes():
    """Yield (prefix, path) for each DPDK telemetry socket found."""
    root = dpdk_dir()
    try:
        entries = os.listdir(root)
    except FileNotFoundError:
        return
    except PermissionError:
        sys.stderr.write(
            f"cannot read {root}: permission denied. The DPDK runtime directory "
            "is mode 0700, so capture must run as the same user as the DPDK "
            "application, or set DPDK_EXTCAP_PATH.\n"
        )
        return
    for prefix in sorted(entries):
        path = os.path.join(root, prefix, TELEMETRY_SOCKET)
        if os.path.exists(path):
            yield prefix, path


def resolve_prefix(requested):
    """Pick the file-prefix to talk to. If one was requested, use it; else use
    the sole running prefix, or error if there are zero or several."""
    prefixes = [p for p, _ in list_prefixes()]
    if requested is not None:
        if requested not in prefixes:
            raise SystemExit(f"no DPDK process with file-prefix '{requested}'")
        return requested
    if not prefixes:
        raise SystemExit("no running DPDK process found")
    if len(prefixes) > 1:
        raise SystemExit(
            "multiple DPDK processes running; select one with --file-prefix: "
            + ", ".join(prefixes)
        )
    return prefixes[0]


# --- Telemetry transport -------------------------------------------------


class Telemetry:
    """Minimal client for the DPDK v2 telemetry socket (SOCK_SEQPACKET)."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.connect(path)
        info = json.loads(self.sock.recv(1024).decode())
        self.max_output_len = info.get("max_output_len", 16384)

    def command(self, cmd):
        self.sock.send(cmd.encode())
        reply = self.sock.recv(self.max_output_len)
        if not reply:
            return None
        return json.loads(reply.decode())

    def close(self):
        self.sock.close()


# --- operations ----------------------------------------------------------


def port_name(tel, port):
    """Device name for a port via /ethdev/info, or 'port<N>' if unreadable.
    For a physical port this is the PCI address; for a vdev, the vdev name."""
    try:
        reply = tel.command(f"{ETHDEV_INFO},{port}")
    except OSError:
        reply = None
    info = (reply or {}).get(ETHDEV_INFO) or {}
    return info.get("name") or f"port{port}"


def list_interfaces():
    """List ports as '<port>. <name>', matching Wireshark/C dpdk-dumpcap -D.
    Port ids are per-primary; if several primaries run, capture disambiguates
    with --file-prefix (see resolve_prefix)."""
    any_found = False
    for _prefix, path in list_prefixes():
        try:
            tel = Telemetry(path)
        except OSError as e:
            sys.stderr.write(f"cannot query {path}: {e}\n")
            continue
        try:
            ports = (tel.command(ETHDEV_LIST) or {}).get(ETHDEV_LIST) or []
            for port in ports:
                any_found = True
                print(f"{port}. {port_name(tel, port)}")
        except OSError as e:
            sys.stderr.write(f"cannot query {path}: {e}\n")
        finally:
            tel.close()
    if not any_found:
        sys.stderr.write("no DPDK interfaces available for capture\n")


def resolve_interface(tel, spec):
    """Port id to capture on the connected primary. spec None selects the first
    interface (like Wireshark and the C dpdk-dumpcap); otherwise it is a port id
    or a device name as shown by --list-interfaces."""
    ports = (tel.command(ETHDEV_LIST) or {}).get(ETHDEV_LIST) or []
    if not ports:
        raise SystemExit("no interfaces on this DPDK process")
    if spec is None:
        return ports[0]
    try:
        port = int(spec)
    except ValueError:
        port = None
    if port is not None:
        if port in ports:
            return port
        raise SystemExit(f"no port {port} on this DPDK process")
    for port in ports:
        if port_name(tel, port) == spec:
            return port
    raise SystemExit(f"no interface '{spec}' on this DPDK process")


def default_output(name):
    r"""Auto-named output in the temp dir, matching how current Wireshark
    dumpcap names its default file: '<tool>_<iface><unique>.pcapng', with a
    random unique suffix and no timestamp.
    basename() strips any path-like parts of the device name, as Wireshark does;
    mkstemp pre-creates the file empty, which is what the capture library wants."""
    basename = os.path.basename(name)
    fd, path = tempfile.mkstemp(prefix=f"dpdk-dumpcap_{basename}", suffix=".pcapng")
    os.close(fd)
    return path


def read_stats(tel, cap_id):
    """Return the stats dict, or None if the telemetry peer has closed (the
    primary exited). An empty reply from a SEQPACKET socket is EOF."""
    reply = tel.command(f"{CAPTURE_STATS_CMD},{cap_id}")
    if reply is None:
        return None
    return reply.get(CAPTURE_STATS_CMD) or {}


def print_progress(stats):
    """Live packet counter, overwritten in place (carriage return, no newline)
    like Wireshark: the running line reads 'Packets:', and print_summary
    finalises it as 'Packets captured:' with a trailing newline."""
    captured = stats.get("accepted", 0) - stats.get("ringfull", 0)
    sys.stderr.write(f"\rPackets: {captured} ")
    sys.stderr.flush()


def print_summary(stats, name):
    r"""dumpcap-style end-of-capture summary on stderr. The leading '\r'
    finalises the in-place live counter (same line, overwritten). Counters map
    onto the pcapng ISB the primary writes, so this agrees with the file trailer:
        received (ifrecv) = accepted + filtered + nombuf   -- true total seen
        dropped  (ifdrop) = nombuf + ringfull
        captured          = accepted - ringfull            -- written to file
    The percentage is 'fraction not dropped', off the true total (ifrecv already
    includes the drops). An empty capture prints 0.0%, as dumpcap does."""
    accepted = stats.get("accepted", 0)
    filtered = stats.get("filtered", 0)
    nombuf = stats.get("nombuf", 0)
    ringfull = stats.get("ringfull", 0)

    captured = accepted - ringfull
    received = accepted + filtered + nombuf
    dropped = nombuf + ringfull
    pct = 100.0 * (received - dropped) / received if received else 0.0

    print(f"\rPackets captured: {captured}", file=sys.stderr)
    print(
        f"Packets received/dropped on interface '{name}': "
        f"{received}/{dropped} ({pct:.1f}%)",
        file=sys.stderr,
    )


def capture(args):
    prefix = resolve_prefix(args.file_prefix)
    path = socket_path(prefix)

    try:
        tel = Telemetry(path)
    except OSError as e:
        raise SystemExit(f"cannot connect to DPDK telemetry at {path}: {e}")

    port = resolve_interface(tel, args.interface)
    name = port_name(tel, port)

    output = args.write or default_output(name)

    # The capture library opens the output O_WRONLY|O_NOFOLLOW without O_CREAT
    # and rejects a non-empty file, so create/truncate it to an empty regular
    # file here before handing over the path.
    try:
        open(output, "wb").close()
    except OSError as e:
        tel.close()
        raise SystemExit(f"cannot create output {output}: {e}")

    params = [str(port), f"out={output}"]
    if args.snaplen is not None:
        params.append(f"snaplen={args.snaplen}")
    if args.queue is not None and args.queue >= 0:
        params.append(f"queue={args.queue}")
    if args.filter:
        params.append(f"filter={args.filter}")
    cmd = CAPTURE_START_CMD + "," + ",".join(params)

    result = (tel.command(cmd) or {}).get(CAPTURE_START_CMD) or {}
    if "error" in result:
        tel.close()
        raise SystemExit(f"capture start failed: {result['error']}")
    cap_id = result.get("id")
    if cap_id is None:
        tel.close()
        raise SystemExit("capture start did not return an id")

    qnote = "" if args.queue is None or args.queue < 0 else f" queue {args.queue}"
    print(f"File: {output}", file=sys.stderr)
    print(f"Capturing on '{name}'{qnote}", file=sys.stderr)

    # Stop on Ctrl-C/SIGTERM; the handler flips a flag the loop checks.
    stop = {"now": False}
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.update(now=True))

    interval = args.stats_interval
    # Wake on a short tick so a signal stops us promptly; poll fast when -c must
    # bound overshoot, otherwise just often enough to notice the signal. Stats
    # are read only when -c is set or a heartbeat is due, so an idle capture
    # barely touches the telemetry socket.
    tick = COUNT_POLL_INTERVAL if args.count is not None else POLL_TICK
    next_beat = time.monotonic() + interval if interval > 0 else None

    stats = {}
    try:
        while not stop["now"]:
            time.sleep(tick)
            now = time.monotonic()
            due = next_beat is not None and now >= next_beat
            if args.count is not None or due:
                # The stats round-trip is itself the liveness check: if the
                # primary has exited, the telemetry socket errors or returns
                # EOF, and the capture (and its half-written pcapng) is gone.
                try:
                    latest = read_stats(tel, cap_id)
                except OSError:
                    latest = None
                if latest is None:
                    print(
                        "\nDPDK telemetry connection lost; capture stopped",
                        file=sys.stderr,
                    )
                    break
                if "error" in latest:
                    break  # capture instance no longer present
                if latest:
                    stats = latest
                if args.count is not None and stats.get("accepted", 0) >= args.count:
                    break
            if due:
                print_progress(stats)
                next_beat = now + interval
        # snapshot final counters while the instance is still alive, then stop:
        # after stop the primary tears the instance down and stats disappear.
        try:
            latest = read_stats(tel, cap_id)
            if latest and "error" not in latest:
                stats = latest
        except OSError:
            pass
    finally:
        try:
            tel.command(f"{CAPTURE_STOP_CMD},{cap_id}")
        except OSError:
            pass

    print_summary(stats, name)
    tel.close()


# --- entry point ---------------------------------------------------------


def main():
    p = argparse.ArgumentParser(
        prog="dpdk-dumpcap",
        description="Capture packets from a running DPDK primary process.",
    )
    p.add_argument(
        "-D",
        "--list-interfaces",
        action="store_true",
        help="list available DPDK interfaces and exit",
    )
    p.add_argument(
        "-i",
        "--interface",
        metavar="IFACE",
        help="port id or device name to capture from "
        "(default: first interface; see --list-interfaces)",
    )
    p.add_argument(
        "--file-prefix",
        help="EAL file-prefix of the target primary "
        "(required only if several are running)",
    )
    p.add_argument(
        "-w", "--write", metavar="FILE", help="output pcapng file (default: auto-named)"
    )
    p.add_argument(
        "-s",
        "--snapshot-length",
        dest="snaplen",
        type=int,
        metavar="LEN",
        help="bytes to capture per packet (0 = all)",
    )
    p.add_argument(
        "--queue",
        type=int,
        metavar="ID",
        help="capture a single hardware queue (default: all queues)",
    )
    p.add_argument(
        "-c",
        "--packet-count",
        dest="count",
        type=int,
        metavar="N",
        help="stop after roughly N packets",
    )
    p.add_argument(
        "--stats-interval",
        type=float,
        metavar="SECS",
        default=DEFAULT_STATS_INTERVAL,
        help="seconds between liveness updates "
        f"(0 to disable; default {DEFAULT_STATS_INTERVAL})",
    )
    p.add_argument(
        "-f",
        "--filter",
        dest="filter",
        metavar="EXPR",
        help="capture filter in libpcap syntax",
    )
    p.add_argument(
        "filter_args", nargs="*", help="capture filter (if not given with -f)"
    )
    args = p.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    # tcpdump-style trailing filter expression, if -f was not used.
    if not args.filter and args.filter_args:
        args.filter = " ".join(args.filter_args)

    capture(args)


if __name__ == "__main__":
    main()
