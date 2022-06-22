# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
#

"""
Generic port and topology nodes configuration file load function
"""
import configparser  # config parse module

from .exception import ConfigParseException
from .settings import CONFIG_ROOT_PATH

TOPOCONF = "%s/topology.cfg" % CONFIG_ROOT_PATH


class UserConf:
    def __init__(self, config):
        self.conf = configparser.SafeConfigParser()
        load_files = self.conf.read(config)
        if load_files == []:
            self.conf = None
            raise ConfigParseException(config)

    def get_sections(self):
        if self.conf is None:
            return []

        return self.conf.sections()

    def load_section(self, section):
        if self.conf is None:
            return None

        items = None
        for conf_sect in self.conf.sections():
            if conf_sect == section:
                items = self.conf.items(section)

        return items


class TopologyConf(UserConf):
    TOPO_DEFAULTS = {
        "IP": "",
        "user": "",
        "pass": "",
    }

    def __init__(self, topo_conf=TOPOCONF):
        self.config_file = topo_conf
        self.nodes = []
        try:
            self.topo_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.topo_conf = None
            raise ConfigParseException

    def load_topo_config(self):
        sections = self.topo_conf.get_sections()
        if not sections:
            return self.nodes

        for node_name in sections:
            node = self.TOPO_DEFAULTS.copy()
            node["section"] = node_name
            node_conf = self.topo_conf.load_section(node_name)
            if not node_conf:
                continue

            # convert file configuration to dts node configuration
            for key, value in node_conf:
                if key == "sut_ip":
                    node["IP"] = value
                elif key == "sut_user":
                    node["user"] = value
                elif key == "sut_passwd":
                    node["pass"] = value

            self.nodes.append(node)
        return self.nodes

