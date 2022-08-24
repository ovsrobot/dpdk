#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Intel Corporation

"""
Script to be used with V2 Telemetry.
Allows the user to view various key telemetry metrics using a Terminal User Interface (TUI).
"""


# Import the required standard modules.
import argparse
import atexit
from datetime import datetime
import importlib
import os
import socket
import sys
from time import sleep


# Import dpdk-telemetry.py to prevent code duplication
# Python modules cannot be hyphenated, importlib has been used to avoid this issue
dpdk_telemetry = importlib.import_module("dpdk-telemetry")


# Try to import the required rich components which are needed to create the
# Terminal User Interface. The app will be unable to continue without it.
try:
    from rich import box as rich_box
    from rich.align import Align as rich_align
    from rich.layout import Layout as rich_layout
    from rich.panel import Panel as rich_panel
    from rich.text import Text as rich_text
    from rich.table import Table as rich_table
    from rich.ansi import AnsiDecoder as rich_ansi_decoder
    from rich.console import RenderGroup as rich_render_group
    from rich.jupyter import JupyterMixin as rich_jupyter_mixin
    from rich.live import Live as rich_live
except ImportError:
    print(
        "ERROR: The python module 'rich' must be installed "
        "to use this script - 'pip install rich'"
    )
    sys.exit(1)


# Try to import plotext.
# The app is able to run without plotext but the live graph will be hidden.
try:
    import plotext as plt
except ImportError:
    plt = None


# Global Telemetry Constants.
TELEMETRY_VERSION = "v2"
SOCKET_NAME = f"dpdk_telemetry.{TELEMETRY_VERSION}"
DEFAULT_PREFIX = "rte"


# Constants.
MINIMUM_CONSOLE = 80
MILLION = 1000000
GIGA = 1000000000
MAX_PORTS = 8


class Socket:
    """ Helper class for using DPDK sockets. """

    def __init__(self, path):
        """ Setup the socket for telemetry. """
        # To ensure that the socket is always closed correctly on exit the socket
        # must be made global.
        self.telem_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.buf_len = 1024
        try:
            self.telem_socket.connect(path)
        except OSError as err:
            raise OSError(f'Error connecting to {path}') from err
        json_reply = self.read()
        self.buf_len = json_reply["max_output_len"]

    def send(self, cmd):
        """ Send a command to the socket. """
        self.telem_socket.send(str(cmd).encode())

    def read(self):
        """ Read from the socket. """
        return dpdk_telemetry.read_socket(self.telem_socket, self.buf_len, False)

    def query(self, path):
        """ Query an item from the socket. """
        self.send(path)
        try:
            # Remove everything after the comma to get the key to return
            return self.read()[path.rsplit(',', maxsplit=1)[0]]
        except KeyError as err:
            raise OSError(f'Could not find the item {path} returned from socket') from err

    def close(self):
        """ Close the telemetry socket. """
        self.telem_socket.close()
        print("DPDK socket closed . . .")


def args_parse():
    """ Parse the arguments passed to the script. """
    parser = argparse.ArgumentParser(
        description=(
            "This is a tool for viewing statistics from the DPDK "
            "telemetry socket.\nMinimum supported console "
            f"width: {MINIMUM_CONSOLE}"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--time",
        type=int,
        dest="time",
        help="Set the time span for stats calculations, " "default: 60",
        default=60,
    )
    parser.add_argument(
        "-f",
        "--file-prefix",
        type=str,
        dest="fileprefix",
        default=DEFAULT_PREFIX,
        help="Provide file-prefix for DPDK runtime directory",
    )
    parser.add_argument(
        "-i",
        "--instance",
        default="0",
        type=int,
        dest="instance",
        help="Provide instance number for DPDK application",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        dest="list",
        default=False,
        help="List all possible file-prefixes and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        dest="quiet",
        help="Quiet mode which will hide some warnings such as the warning about"
        "if the console is below the supported minimum",
        default=False,
    )
    return parser.parse_args()


def make_layout(ports) -> rich_layout:
    """ Setup the rich layout. """
    stats_layout = rich_layout(name="main")
    # Create the rows.
    stats_layout.split(
        rich_layout(name="header", size=3),
        rich_layout(name="width", size=5),
        rich_layout(name="app", size=12),
        rich_layout(name="ports", ratio=2),
        rich_layout(name="data", ratio=2),
        rich_layout(name="footer", size=1),
    )
    # Split top row for EAL and app info.
    stats_layout["app"].split_row(
        rich_layout(name="info", ratio=1), rich_layout(name="eal", ratio=3)
    )
    # Create 8 port columns and an all column.
    stats_layout["ports"].split_row(
        rich_layout(name="0"),
        rich_layout(name="1"),
        rich_layout(name="2"),
        rich_layout(name="3"),
        rich_layout(name="4"),
        rich_layout(name="5"),
        rich_layout(name="6"),
        rich_layout(name="7"),
        rich_layout(name="all"),
    )
    # Disable any unused port columns.
    if len(ports) < 8:
        for i in range(len(ports), 8, 1):
            stats_layout[f"{i}"].visible = False
    # Disable width warning.
    stats_layout["width"].visible = False
    # Split data row into 3 for graph, totals and pkt info.
    stats_layout["data"].split_row(
        rich_layout(name="through", ratio=2),
        rich_layout(name="totals", ratio=1),
        rich_layout(name="history", ratio=1),
    )
    return stats_layout


def gen_header() -> rich_panel:
    """ Generate the apps header. """
    header_grid = rich_table.grid(expand=True)
    header_grid.add_column(justify="center", ratio=1)
    header_grid.add_column(justify="right")
    header_grid.add_row(
        "DPDK TUI Stats Viewer", datetime.now().ctime().replace(":", "[blink]:[/]")
    )
    return rich_panel(header_grid, padding=(0, 0), style="white on blue")


def width_warning(width) -> rich_panel:
    """ Generate the minimum width warning. """
    width_text = rich_text(
        "Your console is below the required minimum "
        f"width of {MINIMUM_CONSOLE}.\nCurrent console "
        f"width: {width}",
        style="white on red",
        justify="center",
    )
    return rich_panel(
        rich_align.center(width_text, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(0, 1),
        title="Warning",
        style="white on red",
        border_style="white",
    )


def app_info(args, info_resp, run_time) -> rich_panel:
    """ Generate the app info section. """
    app_grid = rich_table.grid(padding=1)
    app_grid.add_column(style="blue", justify="left")
    app_grid.add_column()
    app_grid.add_row(
        "App", f'{dpdk_telemetry.get_app_name(info_resp["pid"])} ({args.fileprefix})'
    )
    app_grid.add_row("Version", f'{info_resp["version"]}')
    app_grid.add_row("PID", f'{info_resp["pid"]}')
    app_grid.add_row("Avgs Over:", f"{args.time} seconds")
    if run_time < 60:
        app_grid.add_row("Time:", f"{run_time} seconds")
    else:
        app_grid.add_row("Time:", f"{int(run_time / 60)}:{(run_time % 60):02}")

    return rich_panel(
        rich_align.left(app_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]App Info",
        border_style="blue",
    )


def eal_info(eal_resp, app_resp) -> rich_panel:
    """ Generate the EAL info section. """
    eal_grid = rich_table.grid(padding=1)
    eal_grid.add_column(style="blue", justify="left")
    eal_grid.add_column()
    eal_grid.add_row("EAL", " ".join(eal_resp))
    eal_grid.add_row("App", " ".join(app_resp))

    return rich_panel(
        rich_align.left(eal_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]EAL Info",
        border_style="blue",
    )


def gen_ports(port, sock, port_stats_last, port_stats_delta) -> rich_panel:
    """ Generate each port section depending on the port number. """
    # Get the link status.
    link = sock.query(f'/ethdev/link_status,{port}')

    # Get the port status.
    latest_stats = sock.query(f'/ethdev/stats,{port}')

    port_stats_delta[port]["status"] = link["status"]
    # Only do calculations if port is up.
    if link["status"] == "UP":
        # Get the speed the NIC is capable of to 1 decimal place.
        port_stats_delta[port]["speed"] = round(link["speed"] / 1000, 1)
        # Get the RX Packets since last read (1 second ago => pps) Mpps.
        port_stats_delta[port]["ipackets"] = (
            latest_stats["ipackets"] - port_stats_last[port]["ipackets"]
        ) / MILLION
        # Get the TX Packets since last read.
        port_stats_delta[port]["opackets"] = (
            latest_stats["opackets"] - port_stats_last[port]["opackets"]
        ) / MILLION
        # Get the RX bytes since last read (1 second ago => Bps) Gbps.
        port_stats_delta[port]["ibytes"] = (
            (latest_stats["ibytes"] - port_stats_last[port]["ibytes"]) * 8 / GIGA
        )
        # Get the TX bytes since last read.
        port_stats_delta[port]["obytes"] = (
            (latest_stats["obytes"] - port_stats_last[port]["obytes"]) * 8 / GIGA
        )

        port_grid = rich_table.grid(padding=1)
        port_grid.add_column(no_wrap=True, style="blue", justify="left")
        port_grid.add_column()
        port_grid.add_row("Status", link["status"])
        port_grid.add_row("Speed", f'{port_stats_delta[port]["speed"]:.1f} Gbps')
        port_grid.add_row(
            "Packets RX", f'{port_stats_delta[port]["ipackets"]:.2f} Mpps'
        )
        port_grid.add_row(
            "Packets TX", f'{port_stats_delta[port]["opackets"]:.2f} Mpps'
        )
        port_grid.add_row("Bytes RX", f'{port_stats_delta[port]["ibytes"]:.2f} Gbps')
        port_grid.add_row("Bytes TX", f'{port_stats_delta[port]["obytes"]:.2f} Gbps')
        # The NIC drops are shown as totals over whole run.
        port_grid.add_row("NIC drops", f'{latest_stats["imissed"]:,} pkts')
    # If the port is down tell the user but do no calculations.
    else:
        port_grid = rich_table.grid(padding=1)
        port_grid.add_column(no_wrap=True, style="blue", justify="left")
        port_grid.add_column()
        port_grid.add_row("Status", link["status"])

    # Update the last read stats.
    port_stats_last[port] = latest_stats

    return rich_panel(
        rich_align.center(port_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title=f"[b blue]Port {port}",
        border_style="blue",
    )


def gen_all_ports(
        ports, port_stats_last, port_stats_delta, through_bytes, through_pkts
    ) -> rich_panel:
    """ Generate the section with totals for all ports. """
    links_up = 0
    speed = 0
    ipackets = 0
    opackets = 0
    ibytes = 0
    obytes = 0
    nic_drops = 0

    # Sum the total per second info for all ports
    for i in ports:
        if port_stats_delta[i]["status"] == "UP":
            links_up += 1
            speed += port_stats_delta[i]["speed"]
            ipackets += port_stats_delta[i]["ipackets"]
            opackets += port_stats_delta[i]["opackets"]
            ibytes += port_stats_delta[i]["ibytes"]
            obytes += port_stats_delta[i]["obytes"]
            # The NIC drops are shown as totals over whole run.
            nic_drops += port_stats_last[i]["imissed"]

    # Store the totals for the live graph.
    through_bytes.append(obytes)
    through_pkts.append(opackets)

    all_port_grid = rich_table.grid(padding=1)
    all_port_grid.add_column(no_wrap=True, style="blue", justify="left")
    all_port_grid.add_column()
    all_port_grid.add_row("Ports UP", f"{links_up}")
    all_port_grid.add_row("Speed", f"{speed:.1f} Gbps")
    all_port_grid.add_row("Packets RX", f"{ipackets:.2f} Mpps")
    all_port_grid.add_row("Packets TX", f"{opackets:.2f} Mpps")
    all_port_grid.add_row("Bytes RX", f"{ibytes:.2f} Gbps")
    all_port_grid.add_row("Bytes TX", f"{obytes:.2f} Gbps")
    all_port_grid.add_row("NIC drops", f"{nic_drops:,} pkts")

    return rich_panel(
        rich_align.center(all_port_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]Port Totals",
        border_style="blue",
    )


def make_through_plot(args, width, height, through_bytes, through_pkts):
    """ Generate the plotext terminal chart. """
    plt.clf()
    plt.scatter(through_bytes[-args.time :], label="Gbps", marker="small")
    plt.scatter(through_pkts[-args.time :], label="Mpps", marker="small")
    plt.ylim(0, max(max(through_bytes[-args.time :]), max(through_pkts[-args.time :])))
    plt.plotsize(width, height)
    plt.canvas_color("none")
    plt.axes_color("none")
    plt.ticks_color("white")
    plt.show(hide=True)
    return plt.get_canvas()


class plotext_mixin_throughput(rich_jupyter_mixin):
    """ Class to calculate the sizing info and help render plotext into rich. """

    def __init__(self, args, through_bytes, through_pkts):
        self.decoder = rich_ansi_decoder()
        self.args = args
        self.through_bytes = through_bytes
        self.through_pkts = through_pkts
        # Ensure that all required variables are defined within __init__
        self.width = 0
        self.height = 0
        self.rich_canvas = rich_render_group()

    def __rich_console__(self, console, options):
        self.width = options.max_width or console.width
        self.height = options.height or console.height
        canvas = make_through_plot(
            self.args, self.width, self.height, self.through_bytes, self.through_pkts
        )
        self.rich_canvas = rich_render_group(*self.decoder.decode(canvas))
        yield self.rich_canvas


def gen_throughput(args, through_bytes, through_pkts):
    """ Generate the panel for the throughput section. """
    return rich_panel(
        plotext_mixin_throughput(args, through_bytes, through_pkts),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]Total Throughput (TX)",
        border_style="blue",
    )


def gen_throughput_disabled():
    """
    Generate the panel for the throughput section when plotext is not
    available.
    """
    throughput_grid = rich_table.grid(padding=1)
    throughput_grid.add_column(style="red", justify="center")
    throughput_grid.add_row("Graphing disabled, plotext module required" "for graphing")
    return rich_panel(
        rich_align.center(throughput_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]Total Throughput (TX)",
        border_style="blue",
    )


def gen_pkt_sizes(ports, sock, width) -> rich_panel:
    """ Generate the packet size info section. """
    pkt_names = [
        "64",
        "65-127",
        "128-255",
        "256-511",
        "512-1023",
        "1024-1522",
        "1523-Max",
    ]
    pkt_size_counts = [0 for _ in pkt_names]

    # Get packet size distribution for all ports
    try:
        for i in ports:
            xstats = sock.query(f'/ethdev/xstats,{i}')
            pkt_size_counts[0] += xstats["tx_size_64_packets"]
            pkt_size_counts[1] += xstats["tx_size_65_to_127_packets"]
            pkt_size_counts[2] += xstats["tx_size_128_to_255_packets"]
            pkt_size_counts[3] += xstats["tx_size_256_to_511_packets"]
            pkt_size_counts[4] += xstats["tx_size_512_to_1023_packets"]
            pkt_size_counts[5] += xstats["tx_size_1024_to_1522_packets"]
            pkt_size_counts[6] += xstats["tx_size_1523_to_max_packets"]
    except KeyError:
        pkt_error_grid = rich_table.grid(padding=1)
        pkt_error_grid.add_column(style="red", justify="center")
        pkt_error_grid.add_row(
            "Packet Sizes Unavailable, app or ethernet device may not support these metrics!"
        )
        return rich_panel(
            rich_align.center(pkt_error_grid, vertical="middle"),
            box=rich_box.ROUNDED,
            padding=(1, 2),
            title="[b blue]Packet Sizes",
            border_style="blue",
        )

    # Normalize the packet size data for the bar charts
    pkt_size_counts_normalized = [
        round(float(i) / sum(pkt_size_counts), 3) for i in pkt_size_counts
    ]

    pkt_grid = rich_table.grid(padding=1)
    pkt_grid.add_column(style="blue", justify="left", no_wrap=True)
    pkt_grid.add_column()

    # Set a scale for the bars depending on the terminal width
    bar_scaler = 5
    if 125 < width < 165:
        bar_scaler = 10
    elif 105 < width <= 125:
        bar_scaler = 15
    # Below 105 console width divide by 1000 to hide bar
    elif width <= 105:
        bar_scaler = 1000

    # Generate a bar and show a percentage for each packet size
    for i, name in enumerate(pkt_names):
        progress_bar = ""
        bar_width = int(pkt_size_counts_normalized[i] * 100 / bar_scaler)
        while bar_width:
            progress_bar = f"{progress_bar}\u2588"
            if len(progress_bar) is bar_width:
                break
        pkt_grid.add_row(
            name, f"{pkt_size_counts_normalized[i] * 100:3.0f}%" f" {progress_bar}"
        )

    return rich_panel(
        rich_align.center(pkt_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]Packet Sizes",
        border_style="blue",
    )


def gen_totals(args, through_bytes, through_pkts) -> rich_panel:
    """ Generate the totals panel. """
    # Get bytes and packets for last X seconds
    current_bytes = through_bytes[-args.time :]
    current_pkts = through_pkts[-args.time :]

    totals_grid = rich_table.grid(padding=1)
    totals_grid.add_column(no_wrap=True, style="blue", justify="left")
    totals_grid.add_column()
    totals_grid.add_column()
    totals_grid.add_row("", "[b blue]Bytes", "[b blue]Pkts")
    totals_grid.add_row(
        "Avg",
        f"{sum(current_bytes) / len(current_bytes):.2f} Gbps",
        f"{sum(current_pkts) / len(current_pkts):.2f} Mpps",
    )
    totals_grid.add_row(
        "Min", f"{min(current_bytes):.2f} Gbps", f"{min(current_pkts):.2f} Mpps"
    )
    totals_grid.add_row(
        "Max", f"{max(current_bytes):.2f} Gbps", f"{max(current_pkts):.2f} Mpps"
    )

    return rich_panel(
        rich_align.center(totals_grid, vertical="middle"),
        box=rich_box.ROUNDED,
        padding=(1, 2),
        title="[b blue]Stats Totals (TX)",
        border_style="blue",
    )


def gen_footer() -> rich_panel:
    """ Generate the applications footer. """
    return rich_text(
        f"Copyright {datetime.now().year}, Intel Corporation. All rights reserved.",
        style="white on blue",
        justify="center",
    )


def gen_body(
        sock, args, main_layout, info_resp, eal_resp, app_resp, run_time, ports,
        port_stats_last, port_stats_delta, through_bytes, through_pkts,
    ) -> rich_panel:
    """ Generate and update the body. """
    main_layout["header"].update(gen_header())
    # Get the width of the console.
    width = os.get_terminal_size().columns
    # If the console width is below the minimum warn the user.
    if width < MINIMUM_CONSOLE and not args.quiet:
        main_layout["width"].update(width_warning(width))
        main_layout["width"].visible = True
    else:
        main_layout["width"].visible = False
    main_layout["eal"].update(eal_info(eal_resp, app_resp))
    main_layout["info"].update(app_info(args, info_resp, run_time))
    for i in range(0, len(ports), 1):
        main_layout[f"{i}"].update(gen_ports(i, sock, port_stats_last, port_stats_delta))
    main_layout["all"].update(
        gen_all_ports(
            ports, port_stats_last, port_stats_delta, through_bytes, through_pkts
        )
    )
    # Only try to generate the plot if the plotext module is available.
    if plt:
        main_layout["through"].update(gen_throughput(args, through_bytes, through_pkts))
    else:
        main_layout["through"].update(gen_throughput_disabled())
    main_layout["totals"].update(gen_totals(args, through_bytes, through_pkts))
    main_layout["history"].update(gen_pkt_sizes(ports, sock, width))
    main_layout["footer"].update(gen_footer())


def main():
    """ Main function for the script. """

    # Parse arguments.
    args = args_parse()

    run_time = 0

    # If user just requested app list.
    if args.list:
        dpdk_telemetry.list_fp()
        sys.exit(0)

    # Check if requested app is available if not print app list.
    path_lst = [dpdk_telemetry.get_dpdk_runtime_dir(args.fileprefix), SOCKET_NAME]
    path_lst = list(map(str, path_lst))
    path = os.path.join(*path_lst)
    # Append the instance number if it's an in-memory app
    if args.instance:
        path += f":{args.instance}"
    if not os.path.exists(path):
        print(path)
        print(f"\nNo valid sockets found for {args.fileprefix}\n")
        dpdk_telemetry.list_fp()
        sys.exit(1)


    # Setup telemetry socket.
    try:
        sock = Socket(path)
    except OSError as err:
        print(err)
        sys.exit(1)

    # Register safe exit for sock
    atexit.register(sock.close)

    # Get a port list.
    ports = sock.query("/ethdev/list")

    # Check that the requested app has the supported number of ports or less
    if len(ports) > MAX_PORTS:
        print(f'The maximum number of supported ports is {MAX_PORTS}, Exiting . . .')
        sys.exit(1)

    # Get app info.
    info_resp = sock.query("/info")

    # Get EAL info.
    eal_resp = sock.query("/eal/params")

    # Get app params.
    app_resp = sock.query("/eal/app_params")

    port_stats_last = []
    port_stats_delta = []
    through_pkts = []
    through_bytes = []

    # Get port stats.
    ports = list(range(len(ports)))
    port_stats_last = [sock.query(f'/ethdev/stats,{i}') for i in ports]
    port_stats_delta = [{} for _ in ports]

    # Setup and populate the rich layout.
    main_layout = make_layout(ports)
    # Render the body initially before entering the loop so the user never sees the empty layout
    gen_body(
        sock, args, main_layout, info_resp, eal_resp, app_resp, run_time, ports,
        port_stats_last, port_stats_delta, through_bytes, through_pkts,
    )

    # Continually update the body until exiting
    with rich_live(main_layout, refresh_per_second=10, screen=True):
        while True:
            gen_body(
                sock, args, main_layout, info_resp, eal_resp, app_resp, run_time,
                ports, port_stats_last, port_stats_delta, through_bytes,
                through_pkts,
            )
            run_time += 1
            sleep(1)


if __name__ == "__main__":
    main()
