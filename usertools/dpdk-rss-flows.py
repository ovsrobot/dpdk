#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2014 6WIND S.A.
# Copyright (c) 2023 Robin Jarry

"""
Craft IP{v6}/{TCP/UDP} traffic flows that will evenly spread over a given
number of RX queues according to the RSS algorithm.
"""

import argparse
import binascii
import ctypes
import ipaddress
import json
import struct
import typing


NO_PORT = (0,)

# fmt: off
# rss_intel_key, see drivers/net/ixgbe/ixgbe_rxtx.c
RSS_KEY_INTEL = bytes(
    (
        0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
        0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
        0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
        0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
        0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
    )
)
# rss_hash_default_key, see drivers/net/mlx5/mlx5_rxq.c
RSS_KEY_MLX = bytes(
    (
        0x2C, 0xC6, 0x81, 0xD1, 0x5B, 0xDB, 0xF4, 0xF7,
        0xFC, 0xA2, 0x83, 0x19, 0xDB, 0x1A, 0x3E, 0x94,
        0x6B, 0x9E, 0x38, 0xD9, 0x2C, 0x9C, 0x03, 0xD1,
        0xAD, 0x99, 0x44, 0xA7, 0xD9, 0x56, 0x3D, 0x59,
        0x06, 0x3C, 0x25, 0xF3, 0xFC, 0x1F, 0xDC, 0x2A,
    )
)
# fmt: on
DEFAULT_DRIVER_KEYS = {
    "intel": RSS_KEY_INTEL,
    "mlx": RSS_KEY_MLX,
}


def rss_key(value):
    if value in DEFAULT_DRIVER_KEYS:
        return DEFAULT_DRIVER_KEYS[value]
    try:
        key = binascii.unhexlify(value)
        if len(key) != 40:
            raise argparse.ArgumentTypeError("The key must be 40 bytes long")
        return key
    except (TypeError, ValueError) as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def port_range(value):
    try:
        if "-" in value:
            start, stop = value.split("-")
            res = tuple(range(int(start), int(stop)))
        else:
            res = (int(value),)
        return res or NO_PORT
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


Address = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Network = typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
PortList = typing.Iterable[int]


class Packet:
    def __init__(self, ip_src: Address, ip_dst: Address, l4_sport: int, l4_dport: int):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.l4_sport = l4_sport
        self.l4_dport = l4_dport

    def reverse(self):
        return Packet(
            ip_src=self.ip_dst,
            l4_sport=self.l4_dport,
            ip_dst=self.ip_src,
            l4_dport=self.l4_sport,
        )

    def hash_data(self, use_l4_port: bool = False) -> bytes:
        data = self.ip_src.packed + self.ip_dst.packed
        if use_l4_port:
            data += struct.pack(">H", self.l4_sport)
            data += struct.pack(">H", self.l4_dport)
        return data


class TrafficTemplate:
    def __init__(
        self,
        ip_src: Network,
        ip_dst: Network,
        l4_sport_range: PortList,
        l4_dport_range: PortList,
    ):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.l4_sport_range = l4_sport_range
        self.l4_dport_range = l4_dport_range

    def __iter__(self) -> typing.Iterator[Packet]:
        for ip_src in self.ip_src.hosts():
            for ip_dst in self.ip_dst.hosts():
                if ip_src == ip_dst:
                    continue
                for sport in self.l4_sport_range:
                    for dport in self.l4_dport_range:
                        yield Packet(ip_src, ip_dst, sport, dport)


class RSSAlgo:
    def __init__(
        self,
        queues_count: int,
        key: bytes,
        reta_size: int,
        use_l4_port: bool,
    ):
        self.queues_count = queues_count
        self.reta = tuple(i % queues_count for i in range(reta_size))
        self.key = key
        self.use_l4_port = use_l4_port

    def toeplitz_hash(self, data: bytes) -> int:
        hash_value = ctypes.c_uint32(0)

        for i, byte in enumerate(data):
            for j in range(8):
                bit = (byte >> (7 - j)) & 0x01

                if bit == 1:
                    keyword = ctypes.c_uint32(0)
                    keyword.value |= self.key[i] << 24
                    keyword.value |= self.key[i + 1] << 16
                    keyword.value |= self.key[i + 2] << 8
                    keyword.value |= self.key[i + 3]

                    if j > 0:
                        keyword.value <<= j
                        keyword.value |= self.key[i + 4] >> (8 - j)

                    hash_value.value ^= keyword.value

        return hash_value.value

    def get_queue_index(self, packet: Packet) -> int:
        bytes_to_hash = packet.hash_data(self.use_l4_port)

        # get the 32bit hash of the packet
        hash_value = self.toeplitz_hash(bytes_to_hash)

        # determine the offset in the redirection table
        offset = hash_value & (len(self.reta) - 1)

        return self.reta[offset]


def balanced_traffic(
    algo: RSSAlgo,
    traffic_template: TrafficTemplate,
    check_reverse_traffic: bool,
) -> typing.Iterator[typing.Tuple[int, int, Packet]]:
    queues = set()
    if check_reverse_traffic:
        queues_reverse = set()

    for pkt in traffic_template:

        q = algo.get_queue_index(pkt)

        # check if q is already filled
        if q in queues:
            continue

        qr = algo.get_queue_index(pkt.reverse())

        if check_reverse_traffic:
            # check if q is already filled
            if qr in queues_reverse:
                continue
            # mark this queue as matched
            queues_reverse.add(qr)

        # mark this queue as filled
        queues.add(q)

        yield q, qr, pkt

        # stop when all queues have been filled
        if len(queues) == algo.queues_count:
            break


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "rx_queues",
        metavar="RX_QUEUES",
        type=int,
        help="""
        The number of RX queues to fill.
        """,
    )
    parser.add_argument(
        "ip_src",
        metavar="SRC",
        type=ipaddress.ip_network,
        help="""
        The source IP network/address.
        """,
    )
    parser.add_argument(
        "ip_dst",
        metavar="DST",
        type=ipaddress.ip_network,
        help="""
        The destination IP network/address.
        """,
    )
    parser.add_argument(
        "-s",
        "--sport-range",
        type=port_range,
        default=NO_PORT,
        help="""
        The layer 4 (TCP/UDP) source port range.
        Can be a single fixed value or a range <start>-<end>.
        """,
    )
    parser.add_argument(
        "-d",
        "--dport-range",
        type=port_range,
        default=NO_PORT,
        help="""
        The layer 4 (TCP/UDP) destination port range.
        Can be a single fixed value or a range <start>-<end>.
        """,
    )
    parser.add_argument(
        "-r",
        "--check-reverse-traffic",
        default=False,
        action="store_true",
        help="""
        The reversed traffic (source <-> dest) should also be evenly balanced
        in the queues.
        """,
    )
    parser.add_argument(
        "-k",
        "--rss-key",
        default=RSS_KEY_INTEL,
        type=rss_key,
        help="""
        The random 40-bytes key used to compute the RSS hash. This option
        supports either a well-known name or the hex value of the key
        (well-known names: "intel", "mlx", default: "intel").
        """,
    )
    parser.add_argument(
        "-t",
        "--reta-size",
        default=128,
        type=int,
        help="""
        Size of the redirection table or "RETA" (default: 128).
        """,
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="""
        Output in parseable JSON format.
        """,
    )

    args = parser.parse_args()

    if args.ip_src.version != args.ip_dst.version:
        parser.error(
            f"{args.ip_src} and {args.ip_dst} don't have the same protocol version"
        )
    if args.reta_size < args.rx_queues:
        parser.error("RETA_SIZE must be greater than or equal to RX_QUEUES")

    return args


def main():
    args = parse_args()
    use_l4_port = args.sport_range != NO_PORT or args.dport_range != NO_PORT

    algo = RSSAlgo(
        queues_count=args.rx_queues,
        key=args.rss_key,
        reta_size=args.reta_size,
        use_l4_port=use_l4_port,
    )
    template = TrafficTemplate(
        args.ip_src,
        args.ip_dst,
        args.sport_range,
        args.dport_range,
    )

    results = balanced_traffic(algo, template, args.check_reverse_traffic)

    if args.json:
        flows = []
        for q, qr, pkt in results:
            flows.append(
                {
                    "queue": q,
                    "queue_reverse": qr,
                    "src_ip": str(pkt.ip_src),
                    "dst_ip": str(pkt.ip_dst),
                    "src_port": pkt.l4_sport,
                    "dst_port": pkt.l4_dport,
                }
            )
        print(json.dumps(flows, indent=2))
        return

    if use_l4_port:
        header = ["SRC_IP", "SPORT", "DST_IP", "DPORT", "QUEUE"]
    else:
        header = ["SRC_IP", "DST_IP", "QUEUE"]
    if args.check_reverse_traffic:
        header.append("QUEUE_REVERSE")

    rows = [tuple(header)]
    widths = [len(h) for h in header]

    for q, qr, pkt in results:
        if use_l4_port:
            row = [pkt.ip_src, pkt.l4_sport, pkt.ip_dst, pkt.l4_dport, q]
        else:
            row = [pkt.ip_src, pkt.ip_dst, q]
        if args.check_reverse_traffic:
            row.append(qr)
        cells = []
        for i, r in enumerate(row):
            r = str(r)
            if len(r) > widths[i]:
                widths[i] = len(r)
            cells.append(r)
        rows.append(tuple(cells))

    fmt = [f"%-{w}s" for w in widths]
    fmt[-1] = "%s"  # avoid trailing whitespace
    fmt = "    ".join(fmt)
    for row in rows:
        print(fmt % row)


if __name__ == "__main__":
    main()
