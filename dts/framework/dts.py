# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2019 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import sys
from typing import Iterable, Optional

import framework.logger as logger

from .config import CONFIGURATION
from .logger import getLogger
from .node import Node
from .settings import SETTINGS
from .utils import check_dts_python_version

log_handler: Optional[logger.DTSLOG] = None


def run_all() -> None:
    """
    Main process of DTS, it will run all test suites in the config file.
    """

    global log_handler

    # check the python version of the server that run dts
    check_dts_python_version()

    # init log_handler handler
    if SETTINGS.verbose is True:
        logger.set_verbose()

    log_handler = getLogger("dts")

    nodes = {}
    # This try/finally block means "Run the try block, if there is an exception,
    # run the finally block before passing it upward. If there is not an exception,
    # run the finally block after the try block is finished." This helps avoid the
    # problem of python's interpreter exit context, which essentially prevents you
    # from making certain system calls. This makes cleaning up resources difficult,
    # since most of the resources in DTS are network-based, which is restricted.
    #
    # An except block SHOULD NOT be added to this. A failure at this level should
    # deliver a full stack trace for debugging, since the only place that exceptions
    # should be caught and handled is in the testing code.
    try:
        # for all Execution sections
        for execution in CONFIGURATION.executions:
            sut_config = execution.system_under_test
            if sut_config.name not in nodes:
                nodes[sut_config.name] = Node(sut_config)

    finally:
        quit_execution(nodes.values())


def quit_execution(sut_nodes: Iterable[Node]) -> None:
    """
    Close session to SUT and TG before quit.
    Return exit status when failure occurred.
    """
    for sut_node in sut_nodes:
        # close all session
        sut_node.node_exit()

    if log_handler is not None:
        log_handler.info("DTS ended")
    sys.exit(0)
