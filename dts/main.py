#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

"""
A test framework for testing DPDK.
"""

import argparse

from framework import dts

# Read cmd-line args
parser = argparse.ArgumentParser(description="DPDK test framework.")

parser.add_argument(
    "--config-file",
    default="execution.cfg",
    help="configuration file that describes the test " + "cases, SUTs and targets",
)

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="enable verbose output, all message output on screen",
)

args = parser.parse_args()

# Main program begins here
dts.run_all(
    args.config_file,
    args.verbose,
)
