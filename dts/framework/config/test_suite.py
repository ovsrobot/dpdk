# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""Test suites configuration module.

Test suites can inherit :class:`TestSuiteConfig` to create their own custom configuration.
By doing so, the test suite class must also override the annotation of the field
`~framework.test_suite.TestSuite.config` to use their custom configuration type.
"""

from typing import TYPE_CHECKING, Any, Iterable

from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator
from pydantic.config import JsonDict
from typing_extensions import Self

if TYPE_CHECKING:
    from framework.test_suite import TestSuiteSpec


def make_parsable_schema(schema: JsonDict):
    """Updates a model's JSON schema to make a string representation a valid alternative.

    This utility function is required to be used with models that can be represented and validated
    as a string instead of an object mapping. Normally the generated JSON schema will just show
    the object mapping. This function wraps the mapping under an anyOf property sequenced with a
    string type.

    This function is a valid `Callable` for the `json_schema_extra` attribute of
    `~pydantic.config.ConfigDict`.
    """
    inner_schema = schema.copy()

    fields_to_preserve = ["title", "description"]
    extracted_fields = {k: v for k in fields_to_preserve if (v := inner_schema.get(k))}
    for field in extracted_fields:
        del inner_schema[field]

    schema.clear()
    schema.update(extracted_fields)
    schema["anyOf"] = [inner_schema, {"type": "string"}]


class TestSuiteConfig(BaseModel, extra="forbid", json_schema_extra=make_parsable_schema):
    """Test suite configuration base model.

    By default the configuration of a generic test suite does not contain any attributes. Any test
    suite should inherit this class to create their own custom configuration. Finally override the
    type of the :attr:`~TestSuite.config` to use the newly created one.

    Attributes:
        test_cases_names: The names of test cases from this test suite to execute. If empty, all
            test cases will be executed.
    """

    _test_suite_spec: "TestSuiteSpec"

    test_cases_names: list[str] = Field(default_factory=list, alias="test_cases")

    @property
    def test_suite_name(self) -> str:
        """The name of the test suite module without the starting ``TestSuite_``."""
        return self._test_suite_spec.name

    @property
    def test_suite_spec(self) -> "TestSuiteSpec":
        """The specification of the requested test suite."""
        return self._test_suite_spec

    @model_validator(mode="before")
    @classmethod
    def convert_from_string(cls, data: Any) -> Any:
        """Validator which allows to select a test suite by string instead of a mapping."""
        if isinstance(data, str):
            test_cases = [] if data == "all" else data.split()
            return dict(test_cases=test_cases)
        return data

    @classmethod
    def make(cls, test_suite_name: str, *test_cases_names: str, **kwargs) -> Self:
        """Make a configuration for the requested test suite.

        Args:
            test_suite_name: The name of the test suite.
            test_cases_names: The test cases to select, if empty all are selected.
            **kwargs: Any other configuration field.

        Raises:
            AssertionError: If the requested test suite or test cases do not exist.
            ValidationError: If the configuration fields were not filled correctly.
        """
        from framework.test_suite import find_by_name

        test_suite_spec = find_by_name(test_suite_name)
        assert test_suite_spec is not None, f"Could not find test suite '{test_suite_name}'."
        test_suite_spec.validate_test_cases(test_cases_names)

        config = cls.model_validate({"test_cases": test_cases_names, **kwargs})
        config._test_suite_spec = test_suite_spec
        return config


class BaseTestSuitesConfigs(BaseModel, extra="forbid"):
    """Base class for test suites configs."""

    def __contains__(self, key) -> bool:
        """Check if the provided test suite name has been selected and/or configured."""
        return key in self.model_fields_set

    def __getitem__(self, key) -> TestSuiteConfig:
        """Get test suite configuration."""
        return self.__getattribute__(key)

    def get_configs(self) -> Iterable[TestSuiteConfig]:
        """Get all the test suite configurations."""
        return map(lambda t: self[t], self.model_fields_set)

    @classmethod
    def available_test_suites(cls) -> Iterable[str]:
        """List all the available test suites."""
        return cls.model_fields.keys()

    @field_validator("*")
    @classmethod
    def validate_test_suite_config(
        cls, config: type[TestSuiteConfig], info: ValidationInfo
    ) -> type[TestSuiteConfig]:
        """Validate the provided test cases and link the test suite spec to the configuration."""
        from framework.test_suite import find_by_name

        test_suite_name = info.field_name
        assert test_suite_name is not None

        test_suite_spec = find_by_name(test_suite_name)
        assert test_suite_spec is not None

        config._test_suite_spec = test_suite_spec

        test_suite_spec.validate_test_cases(config.test_cases_names)
        return config
