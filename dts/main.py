#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

"""
A test framework for testing DPDK.
"""

import argparse
import logging

from framework import dts
from framework.settings import DEFAULT_CONFIG_FILE_PATH


def main() -> None:
    # Read cmd-line args
    parser = argparse.ArgumentParser(description="DPDK test framework.")

    parser.add_argument(
        "--config-file",
        default=DEFAULT_CONFIG_FILE_PATH,
        help="configuration file that describes the test cases, SUTs and targets",
    )

    parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="enable verbose output, all message output on screen",
)

    args = parser.parse_args()

    dts.run_all(
        args.config_file,
        args.verbose,
    )


# Main program begins here
if __name__ == "__main__":
    logging.raiseExceptions = True
    main()
