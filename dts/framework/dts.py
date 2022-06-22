# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2019 Intel Corporation
#

import atexit  # register callback when exit
import configparser  # config parse module
import os  # operation system module
import sys

import framework.logger as logger
import framework.settings as settings  # dts settings

from .config import TopologyConf
from .exception import ConfigParseException
from .logger import getLogger
from .node import Node
from .utils import check_dts_python_version, create_parallel_locks

log_handler = None


def dts_parse_config(config, section):
    """
    Parse execution file configuration.
    """
    sut_nodes = [sut_.strip() for sut_ in config.get(section, "sut").split(",")]

    return sut_nodes


def dts_nodes_init(nodeInsts):
    """
    Create dts SUT/TG instance and initialize them.
    """
    sut_nodes = []

    sut_id = 0
    for nodeInst in nodeInsts:
        sut_node = Node(nodeInst, sut_id)
        sut_nodes.append(sut_node)
        sut_id += 1

    return sut_nodes


def dts_nodes_exit(sut_nodes):
    """
    Call SUT and TG exit function after execution finished
    """
    for sut_node in sut_nodes:
        sut_node.node_exit()


def run_all(
    config_file,
    verbose,
):
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

    # Read config file
    dts_cfg_folder = settings.load_global_setting(settings.DTS_CFG_FOLDER)
    if dts_cfg_folder != "":
        config_file = dts_cfg_folder + os.sep + config_file

    config = configparser.SafeConfigParser()
    load_cfg = config.read(config_file)
    if len(load_cfg) == 0:
        raise ConfigParseException(config_file)

    topo_conf = TopologyConf()
    nodes = topo_conf.load_topo_config()

    # for all Execution sections
    for section in config.sections():
        nodeInsts = list()

        # verify if the delimiter is good if the lists are vertical
        sut_nodes = dts_parse_config(config, section)
        for sut in sut_nodes:
            log_handler.info("\nSUT " + sut)

        # look up in nodes - to find the matching IP
        for sut in sut_nodes:
            for node in nodes:
                if node["section"] == sut:
                    nodeInsts.append(node)
                    break

        # only run on the SUT in known nodes
        if len(nodeInsts) == 0:
            log_handler.error(" SKIP UNKNOWN NODE")
            continue

        # init global lock
        create_parallel_locks(len(sut_nodes))

        # init SUT, TG node
        sut_nodes = dts_nodes_init(nodeInsts)
        # register exit action
        atexit.register(quit_execution, sut_nodes)

        dts_nodes_exit(sut_nodes)


def quit_execution(sut_nodes):
    """
    Close session to SUT and TG before quit.
    Return exit status when failure occurred.
    """
    for sut_node in sut_nodes:
        # close all session
        sut_node.node_exit()

    log_handler.info("DTS ended")
    sys.exit(0)
