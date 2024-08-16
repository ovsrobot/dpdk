#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2017 Cavium, Inc. All rights reserved.

from typing import List, Set, Dict, Tuple
import glob


def _range_expand(rstr: str) -> List[int]:
    """Expand a range string into a list of integers."""
    # 0,1-3 => [0, 1-3]
    ranges = rstr.split(",")
    valset: List[int] = []
    for r in ranges:
        # 1-3 => [1, 2, 3]
        if "-" in r:
            start, end = r.split("-")
            valset.extend(range(int(start), int(end) + 1))
        else:
            valset.append(int(r))
    return valset


def _read_sysfs(path: str) -> str:
    with open(path, encoding="utf-8") as fd:
        return fd.read().strip()


def _read_numa_node(base: str) -> int:
    node_glob = f"{base}/node*"
    node_dirs = glob.glob(node_glob)
    if not node_dirs:
        return 0  # default to node 0
    return int(node_dirs[0].split("node")[1])


def _print_row(row: Tuple[str, ...], col_widths: List[int]) -> None:
    first, *rest = row
    w_first, *w_rest = col_widths
    first_end = " " * 4
    rest_end = " " * 4

    print(first.ljust(w_first), end=first_end)
    for cell, width in zip(rest, w_rest):
        print(cell.rjust(width), end=rest_end)
    print()


def _print_section(heading: str) -> None:
    sep = "=" * len(heading)
    print(sep)
    print(heading)
    print(sep)
    print()


def _main() -> None:
    sockets_s: Set[int] = set()
    cores_s: Set[int] = set()
    core_map: Dict[Tuple[int, int], List[int]] = {}
    numa_map: Dict[int, int] = {}
    base_path = "/sys/devices/system/cpu"

    cpus = _range_expand(_read_sysfs(f"{base_path}/online"))

    for cpu in cpus:
        lcore_base = f"{base_path}/cpu{cpu}"
        core = int(_read_sysfs(f"{lcore_base}/topology/core_id"))
        socket = int(_read_sysfs(f"{lcore_base}/topology/physical_package_id"))
        node = _read_numa_node(lcore_base)

        cores_s.add(core)
        sockets_s.add(socket)
        key = (socket, core)
        core_map.setdefault(key, [])
        core_map[key].append(cpu)
        numa_map[cpu] = node

    cores = sorted(cores_s)
    sockets = sorted(sockets_s)

    _print_section("Core and Socket Information "
                   f"(as reported by '{base_path}')")

    print("cores = ", cores)
    print("sockets = ", sockets)
    print("numa = ", sorted(set(numa_map.values())))
    print()

    # Core, [NUMA, Socket, NUMA, Socket, ...]
    heading_strs = "", *[v for s in sockets for v in ("", f"Socket {s}")]
    sep_strs = tuple("-" * len(hstr) for hstr in heading_strs)
    rows: List[Tuple[str, ...]] = []

    prev_numa = None
    for c in cores:
        # Core,
        row: Tuple[str, ...] = (f"Core {c}",)

        # assume NUMA changes symmetrically
        first_lcore = core_map[(0, c)][0]
        cur_numa = numa_map[first_lcore]
        numa_changed = prev_numa != cur_numa
        prev_numa = cur_numa

        # [NUMA, lcores, NUMA, lcores, ...]
        for s in sockets:
            try:
                lcores = core_map[(s, c)]
                numa = numa_map[lcores[0]]
                if numa_changed:
                    row += (f"NUMA {numa}",)
                else:
                    row += ("",)
                row += (str(lcores),)
            except KeyError:
                row += ("", "")
        rows += [row]

    # find max widths for each column, including header and rows
    col_widths = [
        max([len(tup[col_idx]) for tup in rows + [heading_strs]])
        for col_idx in range(len(heading_strs))
    ]

    # print out table taking row widths into account
    _print_row(heading_strs, col_widths)
    _print_row(sep_strs, col_widths)
    for row in rows:
        _print_row(row, col_widths)


if __name__ == "__main__":
    _main()
