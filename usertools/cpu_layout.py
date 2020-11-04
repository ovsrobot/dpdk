#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2017 Cavium, Inc. All rights reserved.
"""
Show CPU layout
"""
SYS_DEVICES_CPU = "/sys/devices/system/cpu"


def print_coremap(sockets, cores, core_map):
    '''print core, thread, socket mapping'''
    max_processor_len = len(str(len(cores) * len(sockets) * 2 - 1))
    max_thread_count = len(list(core_map.values())[0])
    max_core_map_len = (max_processor_len * max_thread_count)  \
                      + len(", ") * (max_thread_count - 1) \
                      + len('[]') + len('Socket ')

    max_core_id_len = len(str(max(cores)))

    output = " ".ljust(max_core_id_len + len('Core '))
    for socket in sockets:
        output += " Socket %s" % str(socket).ljust(max_core_map_len -
                                                   len('Socket '))
    print(output)

    output = " ".ljust(max_core_id_len + len('Core '))
    for socket in sockets:
        output += " --------".ljust(max_core_map_len)
        output += " "
    print(output)

    for core in cores:
        output = "Core %s" % str(core).ljust(max_core_id_len)
        for socket in sockets:
            if (socket, core) in core_map:
                output += " " + str(core_map[(socket,
                                              core)]).ljust(max_core_map_len)
            else:
                output += " " * (max_core_map_len + 1)
        print(output)


def print_header(sockets, cores):
    '''print the core socket information header'''
    header_len = 47 + len(SYS_DEVICES_CPU)
    print(format("=" * header_len))
    print("Core and Socket Information (as reported by '{}')".format(
        SYS_DEVICES_CPU))
    print("{}\n".format("=" * header_len))
    print("cores = ", cores)
    print("sockets = ", sockets)
    print("")


def main():
    '''program main function'''

    with open("{}/kernel_max".format(SYS_DEVICES_CPU)) as kernel_max:
        max_cpus = int(kernel_max.read())

    core_map = {}
    sockets = []
    cores = []

    for cpu in range(max_cpus + 1):
        topo_path = "{}/cpu{}/topology/".format(SYS_DEVICES_CPU, cpu)
        try:
            with open(topo_path + "core_id") as core_id:
                core = int(core_id.read())
        except FileNotFoundError:
            break
        except IOError:
            continue

        with open(topo_path + "physical_package_id") as package_id:
            socket = int(package_id.read())

        if core not in cores:
            cores.append(core)
        if socket not in sockets:
            sockets.append(socket)
        key = (socket, core)
        if key not in core_map:
            core_map[key] = []
        core_map[key].append(cpu)

    print_header(sockets, cores)
    print_coremap(sockets, cores, core_map)


if __name__ == "__main__":
    main()
