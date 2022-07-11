# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2019 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import sys
from typing import Iterable, Optional

import framework.logger as logger

from .config import Configuration, load_config
from .logger import getLogger
from .node import Node
from .utils import check_dts_python_version, create_parallel_locks

log_handler: Optional[logger.DTSLOG] = None


def dts_nodes_exit(nodes: Iterable[Node]) -> None:
    """
    Call SUT and TG exit function after execution finished
    """
    for node in nodes:
        node.node_exit()


def run_all(
    config_file,
    verbose,
) -> None:
    """
    Main process of DTS, it will run all test suites in the config file.
    """

    global log_handler

    # check the python version of the server that run dts
    check_dts_python_version()

    # init log_handler handler
    if verbose is True:
        logger.set_verbose()

    log_handler = getLogger("dts")

    # parse input config file
    config: Configuration = load_config(config_file)

    # init global lock
    create_parallel_locks(len(config.nodes))

    nodes = []
    try:
        nodes = [
            Node(node_config, sut_id=i)
            for i, node_config in enumerate(config.nodes)
        ]
        dts_nodes_exit(nodes)
    finally:
        quit_execution(nodes)


def quit_execution(nodes: Iterable[Node]) -> None:
    """
    Close session to SUT and TG before quit.
    Return exit status when failure occurred.
    """
    for node in nodes:
        # close all session
        node.node_exit()

    if log_handler is not None:
        log_handler.info("DTS ended")

    sys.exit(0)
