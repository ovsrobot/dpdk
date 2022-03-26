#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2017 Cavium, Inc. All rights reserved.

import glob
import os

sockets = []
cores = []
numaNodes = []
core_map = {}
numa_map = {}
node_path = "/sys/devices/system/node"
base_path = "/sys/devices/system/cpu"
max_cpus = 0

if os.path.isdir(base_path):
    temp_maxCpu = glob.glob(base_path + '/cpu[0-9]*')
    max_cpus = len(temp_maxCpu)

if os.path.isdir(node_path):
    temp_numaNodes = glob.glob(node_path + '/node*')
    for numaId in range(0, int(os.path.basename(temp_numaNodes[-1])[4:]) + 1):
        numaNodes.append(numaId)

for cpu in range(max_cpus + 1):
    try:
        fd = open("{}/cpu{}/topology/core_id".format(base_path, cpu))
    except IOError:
        continue
    core = int(fd.read())
    fd.close()

    tempGet_cpuNuma = glob.glob("{}/cpu{}/node*".format(base_path, cpu))
    temp_cpuNuma = tempGet_cpuNuma[-1].split("{}/cpu{}/".format(base_path, cpu))[-1]
    numa = temp_cpuNuma.split("node")[-1]

    fd = open("{}/cpu{}/topology/physical_package_id".format(base_path, cpu))
    socket = int(fd.read())
    fd.close()

    if core not in cores:
        cores.append(core)

    if socket not in sockets:
        sockets.append(socket)

    key = (socket, core)
    if key not in core_map:
        core_map[key] = []
    core_map[key].append(cpu)

    key = (socket, numa)
    if key not in numa_map:
        numa_map[key] = []

    if (core_map[(socket, core)] not in numa_map[key]):
        numa_map[key].append(core_map[(socket, core)])

print(format("=" * (47 + len(base_path))))
print("Core and Socket Information (as reported by '{}')".format(base_path))
print("{}\n".format("=" * (47 + len(base_path))))
print("cores = ", cores)
print("numa nodes per socket = ", numaNodes)
print("sockets = ", sockets)
print("")

for keys in numa_map:
  print ("")
  socket,numa = keys

  output = " Socket " + str(socket).ljust(3, ' ') + " Numa " + str(numa).zfill(1) + " "
  #output = " Socket " + str(socket).zfill(1) + " Numa " + str(numa).zfill(1) + " "
  print(output)
  print(format("-" * len(output)))

  for index,coreSibling in enumerate(numa_map[keys]):
      print ("Core " + str(index).ljust(3, ' ') + "    " + str(coreSibling))
      #print ("Core " + str(index).zfill(3) + "    " + str(coreSibling))
print("")

