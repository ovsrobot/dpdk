#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2023 Intel Corporation
# Copyright(c) 2017 Cavium, Inc. All rights reserved.

sockets = []
dies = []
cores = []
module_id = []
core_map = {}
core_p_e = {}
title_len = 47
die_len = 8
module_no = 0
base_path = "/sys/devices/system/cpu"
fd = open("{}/kernel_max".format(base_path))
max_cpus = int(fd.read())
fd.close()
for cpu in range(max_cpus + 1):
    try:
        fd = open("{}/cpu{}/topology/core_id".format(base_path, cpu))
    except IOError:
        continue
    core = int(fd.read())
    fd.close()
    fd = open("{}/cpu{}/topology/physical_package_id".format(base_path, cpu))
    socket = int(fd.read())
    fd.close()
    fd = open("{}/cpu{}/topology/die_id".format(base_path, cpu))
    die = int(fd.read())
    fd.close()
    fd = open("{}/cpu{}/topology/thread_siblings_list".format(base_path, cpu))
    threads_share = str(fd.read())
    fd.close()
    fd = open("{}/cpu{}/cache/index2/shared_cpu_list".format(base_path, cpu))
    l2_cache_share = str(fd.read())
    fd.close()
    if (threads_share == l2_cache_share):
        p_e = '-P'
        module_id.append(-1)
    else:
        module_tmp = []
        p_e = '-E'
        for i in l2_cache_share:
            if not i.isdigit():
                break
            module_tmp.append(i)
        if (cpu == int("".join(module_tmp))):
            module_id.append(module_no)
            module_no += 1
        else:
            module_id.append(-1)
    if core not in cores:
        cores.append(core)
    if die not in dies:
        dies.append(die)
    if socket not in sockets:
        sockets.append(socket)
    key = (socket, die, core)
    key_p_e = (die, core)
    if key not in core_map:
        core_map[key] = []
    if key_p_e not in core_p_e:
        core_p_e[key_p_e] = p_e
    core_map[key].append(cpu)

print(format("=" * (title_len + len(base_path))))
print("Core and Socket Information (as reported by '{}')".format(base_path))
print("{}\n".format("=" * (title_len + len(base_path))))
print("cores = ", cores)
meaningful_module = []
for i in module_id:
    if (i != -1):
        meaningful_module.append(i)
print("modules = ", meaningful_module)
print("dies = ", dies)
print("sockets = ", sockets)
print("")

max_processor_len = len(str(len(cores) * len(sockets) * 2 - 1))
max_thread_count = len(list(core_map.values())[0])
max_core_map_len = (max_processor_len * max_thread_count)  \
                      + len(", ") * (max_thread_count - 1) \
                      + len('[]') + len('Socket ')
max_core_id_len = len(str(max(cores)))

socket_space_len = max_core_id_len + len('Core ') + die_len + len('-P')
output = " ".ljust(socket_space_len)
for s in sockets:
    output += " Socket %s" % str(s).ljust(max_core_map_len - len('Socket '))
print(output)

output = " ".ljust(socket_space_len)
for s in sockets:
    output += " --------".ljust(max_core_map_len)
    output += " "
print(output)

for d in dies:
    print("Die", die)
    for c in cores:
        if (module_id[core_map[(sockets[0], d, c)][0]] != -1):
            print("    Module", module_id[core_map[(sockets[0], d, c)][0]])
        output = " ".ljust(die_len)
        output += "Core"
        output += core_p_e[(d, c)]
        output += " %s" % str(c).ljust(max_core_id_len)
        for s in sockets:
            if (s, d, c) in core_map:
                output += " " + str(core_map[(s, d, c)]).ljust(max_core_map_len)
            else:
                output += " " * (max_core_map_len + 1)
        print(output)
