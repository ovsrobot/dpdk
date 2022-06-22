# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

import logging

"""
DTS logger module with several log level. DTS framework and TestSuite log
will saved into different log files.
"""
verbose = False
date_fmt = "%d/%m/%Y %H:%M:%S"
stream_fmt = "%(name)30s: %(message)s"

# List for saving all using loggers
global Loggers
Loggers = []


def set_verbose():
    global verbose
    verbose = True


class DTSLOG(logging.LoggerAdapter):
    """
    DTS log class for framework and testsuite.
    """

    def __init__(self, logger, node="suite"):
        global log_dir

        self.logger = logger
        self.logger.setLevel(logging.DEBUG)

        self.node = node
        super(DTSLOG, self).__init__(self.logger, dict(node=self.node))

        self.sh = None

        # add handler to emit to stdout
        sh = logging.StreamHandler()
        self.__log_handler(sh)

    def __log_handler(self, sh):
        """
        Config stream handler and file handler.
        """
        sh.setFormatter(logging.Formatter(stream_fmt, date_fmt))

        sh.setLevel(logging.DEBUG)  # file handler default level
        global verbose
        if verbose is True:
            sh.setLevel(logging.DEBUG)
        else:
            sh.setLevel(logging.INFO)  # console handler default level

        self.logger.addHandler(sh)

        if self.sh is not None:
            self.logger.removeHandler(self.sh)

        self.sh = sh

    def logger_exit(self):
        """
        Remove stream handler and logfile handler.
        """
        if self.sh is not None:
            self.logger.removeHandler(self.sh)


def getLogger(name, node="suite"):
    """
    Get logger handler and if there's no handler for specified Node will create one.
    """
    global Loggers
    # return saved logger
    for logger in Loggers:
        if logger["name"] == name and logger["node"] == node:
            return logger["logger"]

    # return new logger
    logger = DTSLOG(logging.getLogger(name), node)
    Loggers.append({"logger": logger, "name": name, "node": node})
    return logger
