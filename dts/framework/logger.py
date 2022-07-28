# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import logging
import os.path
from typing import TypedDict

"""
DTS logger module with several log level. DTS framework and TestSuite log
will saved into different log files.
"""
verbose = False
date_fmt = "%d/%m/%Y %H:%M:%S"
stream_fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class LoggerDictType(TypedDict):
    logger: "DTSLOG"
    name: str
    node: str


# List for saving all using loggers
global Loggers
Loggers: list[LoggerDictType] = []


def set_verbose() -> None:
    global verbose
    verbose = True


class DTSLOG(logging.LoggerAdapter):
    """
    DTS log class for framework and testsuite.
    """

    node: str
    logger: logging.Logger
    sh: logging.StreamHandler
    fh: logging.FileHandler
    verbose_handler: logging.FileHandler

    def __init__(self, logger: logging.Logger, node: str = "suite"):
        global log_dir

        self.logger = logger
        self.logger.setLevel(1)  # 1 means log everything

        self.node = node

        # add handler to emit to stdout
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter(stream_fmt, date_fmt))

        sh.setLevel(logging.DEBUG)  # file handler default level
        global verbose
        if verbose is True:
            sh.setLevel(logging.DEBUG)
        else:
            sh.setLevel(logging.INFO)  # console handler defaultlevel

        self.logger.addHandler(sh)
        self.sh = sh

        if not os.path.exists("output"):
            os.mkdir("output")

        fh = logging.FileHandler(f"output/{node}.log")
        fh.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt=date_fmt,
            )
        )

        fh.setLevel(1)  # We want all the logs we can get in the file
        self.logger.addHandler(fh)
        self.fh = fh

        # This outputs EVERYTHING, intended for post-mortem debugging
        # Also optimized for processing via AWK (awk -F '|' ...)
        verbose_handler = logging.FileHandler(f"output/{node}.verbose.log")
        verbose_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s|%(name)s|%(levelname)s|%(pathname)s|%(lineno)d|%(funcName)s|"
                "%(process)d|%(thread)d|%(threadName)s|%(message)s",
                datefmt=date_fmt,
            )
        )

        verbose_handler.setLevel(1)  # We want all the logs we can get in the file
        self.logger.addHandler(verbose_handler)
        self.verbose_handler = verbose_handler

        super(DTSLOG, self).__init__(self.logger, dict(node=self.node))

    def logger_exit(self) -> None:
        """
        Remove stream handler and logfile handler.
        """
        for handler in (self.sh, self.fh, self.verbose_handler):
            handler.flush()
            self.logger.removeHandler(handler)


def getLogger(name: str, node: str = "suite") -> DTSLOG:
    """
    Get logger handler and if there's no handler for specified Node will create one.
    """
    global Loggers
    # return saved logger
    logger: LoggerDictType
    for logger in Loggers:
        if logger["name"] == name and logger["node"] == node:
            return logger["logger"]

    # return new logger
    dts_logger: DTSLOG = DTSLOG(logging.getLogger(name), node)
    Loggers.append({"logger": dts_logger, "name": name, "node": node})
    return dts_logger
