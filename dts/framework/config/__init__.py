# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022 University of New Hampshire
#

"""
Generic port and topology nodes configuration file load function
"""
import json
import os.path
import pathlib
from dataclasses import dataclass
from enum import Enum, auto, unique
from typing import Any, Optional

import warlock
import yaml

from framework.settings import get_config_file_path


class StrEnum(Enum):
    @staticmethod
    def _generate_next_value_(
        name: str, start: int, count: int, last_values: object
    ) -> str:
        return name


@unique
class NodeType(StrEnum):
    physical = auto()
    virtual = auto()


# Slots enables some optimizations, by pre-allocating space for the defined
# attributes in the underlying data structure.
#
# Frozen makes the object immutable. This enables further optimizations,
# and makes it thread safe should we every want to move in that direction.
@dataclass(slots=True, frozen=True)
class NodeConfiguration:
    name: str
    hostname: str
    user: str
    password: Optional[str]

    @staticmethod
    def from_dict(d: dict) -> "NodeConfiguration":
        return NodeConfiguration(
            name=d["name"],
            hostname=d["hostname"],
            user=d["user"],
            password=d.get("password"),
        )


@dataclass(slots=True, frozen=True)
class ExecutionConfiguration:
    system_under_test: str

    @staticmethod
    def from_dict(d: dict) -> "ExecutionConfiguration":
        return ExecutionConfiguration(
            system_under_test=d["system_under_test"],
        )


@dataclass(slots=True, frozen=True)
class Configuration:
    executions: list[ExecutionConfiguration]
    nodes: list[NodeConfiguration]

    @staticmethod
    def from_dict(d: dict) -> "Configuration":
        executions: list[ExecutionConfiguration] = list(
            map(ExecutionConfiguration.from_dict, d["executions"])
        )
        nodes: list[NodeConfiguration] = list(
            map(NodeConfiguration.from_dict, d["nodes"])
        )
        assert len(nodes) > 0, "There must be a node to test"

        for i, n1 in enumerate(nodes):
            for j, n2 in enumerate(nodes):
                if i != j:
                    assert n1.name == n2.name, "Duplicate node names are not allowed"

        node_names = {node.name for node in nodes}
        for execution in executions:
            assert (
                execution.system_under_test in node_names
            ), f"Unknown SUT {execution.system_under_test} in execution"

        return Configuration(executions=executions, nodes=nodes)


def load_config(conf_file_path: str) -> Configuration:
    """
    Loads the configuration file and the configuration file schema,
    validates the configuration file, and creates a configuration object.
    """
    conf_file_path: str = get_config_file_path(conf_file_path)
    with open(conf_file_path, "r") as f:
        config_data = yaml.safe_load(f)
    schema_path = os.path.join(
        pathlib.Path(__file__).parent.resolve(), "conf_yaml_schema.json"
    )

    with open(schema_path, "r") as f:
        schema = json.load(f)
    config: dict[str, Any] = warlock.model_factory(schema, name="_Config")(
        config_data
    )
    config_obj: Configuration = Configuration.from_dict(dict(config))
    return config_obj
