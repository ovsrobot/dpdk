# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

"""
User-defined exceptions used across the framework.
"""


class ConfigParseException(Exception):
    """
    Configuration file parse failure exception.
    """

    config: str

    def __init__(self, conf_file: str):
        self.config = conf_file

    def __str__(self) -> str:
        return f"Failed to parse config file [{self.config}]"
