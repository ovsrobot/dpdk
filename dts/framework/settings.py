# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import os
import re

DEFAULT_CONFIG_FILE_PATH: str = "./conf.yaml"

# DTS global environment variables
DTS_ENV_PAT: str = r"DTS_*"
DTS_CFG_FILE: str = "DTS_CFG_FILE"


def load_global_setting(key: str) -> str:
    """
    Load DTS global setting
    """
    if re.match(DTS_ENV_PAT, key):
        env_key = key
    else:
        env_key = "DTS_" + key

    return os.environ.get(env_key, "")


def get_config_file_path(conf_file_path: str) -> str:
    """
    The root path of framework configs.
    """
    if conf_file_path == DEFAULT_CONFIG_FILE_PATH:
        # if the user didn't specify a path on cmdline, they could've specified
        # it in the env variable
        conf_file_path = load_global_setting(DTS_CFG_FILE)
        if conf_file_path == "":
            conf_file_path = DEFAULT_CONFIG_FILE_PATH

    return conf_file_path
