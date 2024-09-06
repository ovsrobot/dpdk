#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""JSON schema generation script."""

import json
import os

from pydantic.json_schema import GenerateJsonSchema

from framework.config import ConfigurationType, TestSuitesConfigs

DTS_DIR = os.path.dirname(os.path.realpath(__file__))
RELATIVE_PATH_TO_SCHEMA = "framework/config/conf_yaml_schema.json"


class GenerateSchemaWithDialect(GenerateJsonSchema):
    """Custom schema generator which adds the schema dialect."""

    def generate(self, schema, mode="validation"):
        """Generate JSON schema."""
        json_schema = super().generate(schema, mode=mode)
        json_schema["$schema"] = self.schema_dialect
        return json_schema


try:
    TestSuitesConfigs.fix_custom_config_annotations()

    path = os.path.join(DTS_DIR, RELATIVE_PATH_TO_SCHEMA)

    with open(path, "w") as schema_file:
        schema_dict = ConfigurationType.json_schema(schema_generator=GenerateSchemaWithDialect)
        schema_json = json.dumps(schema_dict, indent=2)
        schema_file.write(schema_json)

    print("Schema generated successfully!")
except Exception as e:
    raise Exception("failed to generate schema") from e
