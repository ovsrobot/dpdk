# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""Parameter manipulation module.

This module provides :class:`~Params` which can be used to model any data structure
that is meant to represent any command parameters.
"""

from dataclasses import dataclass, field, fields
from typing import Any, Callable, Literal, Reversible, TypeVar, Iterable
from enum import Flag


T = TypeVar("T")
#: Type for a Mixin.
Mixin = Callable[[Any], str]
#: Type for an option parameter.
Option = Literal[True, None]
#: Type for a yes/no option parameter.
BooleanOption = Literal[True, False, None]

META_VALUE_ONLY = "value_only"
META_OPTIONS_END = "options_end"
META_SHORT_NAME = "short_name"
META_LONG_NAME = "long_name"
META_MULTIPLE = "multiple"
META_MIXINS = "mixins"


def value_only(metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Injects the value of the attribute as-is without flag. Metadata modifier for :func:`dataclasses.field`."""
    return {**metadata, META_VALUE_ONLY: True}


def short(name: str, metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Overrides any parameter name with the given short option. Metadata modifier for :func:`dataclasses.field`.

    .. code:: python

        logical_cores: str | None = field(default="1-4", metadata=short("l"))

    will render as ``-l=1-4`` instead of ``--logical-cores=1-4``.
    """
    return {**metadata, META_SHORT_NAME: name}


def long(name: str, metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Overrides the inferred parameter name to the specified one. Metadata modifier for :func:`dataclasses.field`.

    .. code:: python

        x_name: str | None = field(default="y", metadata=long("x"))

    will render as ``--x=y``, but the field is accessed and modified through ``x_name``.
    """
    return {**metadata, META_LONG_NAME: name}


def options_end(metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Precedes the value with an options end delimiter (``--``). Metadata modifier for :func:`dataclasses.field`."""
    return {**metadata, META_OPTIONS_END: True}


def multiple(metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Specifies that this parameter is set multiple times. Must be a list. Metadata modifier for :func:`dataclasses.field`.

    .. code:: python

        ports: list[int] | None = field(default_factory=lambda: [0, 1, 2], metadata=multiple(param_name("port")))

    will render as ``--port=0 --port=1 --port=2``. Note that modifiers can be chained like in this example.
    """
    return {**metadata, META_MULTIPLE: True}


def field_mixins(*mixins: Mixin, metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """Takes in a variable number of mixins to manipulate the value's rendering. Metadata modifier for :func:`dataclasses.field`.

    The ``metadata`` keyword argument can be used to chain metadata modifiers together.

    Mixins can be chained together, executed from right to left in the arguments list order.

    Example:

    .. code:: python

        hex_bitmask: int | None = field(default=0b1101, metadata=field_mixins(hex, metadata=param_name("mask")))

    will render as ``--mask=0xd``. The :func:`hex` built-in can be used as a mixin turning a valid integer into a hexadecimal representation.
    """
    return {**metadata, META_MIXINS: mixins}


def _reduce_mixins(mixins: Reversible[Mixin], value: Any) -> str:
    for mixin in reversed(mixins):
        value = mixin(value)
    return value


def str_mixins(*mixins: Mixin):
    """Decorator which modifies the ``__str__`` method, enabling support for mixins.

    Mixins can be chained together, executed from right to left in the arguments list order.

    Example:

    .. code:: python

        @str_mixins(hex_from_flag_value)
        class BitMask(enum.Flag):
            A = auto()
            B = auto()

    will allow ``BitMask`` to render as a hexadecimal value.
    """

    def _class_decorator(original_class):
        original_class.__str__ = lambda self: _reduce_mixins(mixins, self)
        return original_class

    return _class_decorator


def comma_separated(values: Iterable[T]) -> str:
    """Mixin which renders an iterable in a comma-separated string."""
    return ",".join([str(value).strip() for value in values if value is not None])


def bracketed(value: str) -> str:
    """Mixin which adds round brackets to the input."""
    return f"({value})"


def str_from_flag_value(flag: Flag) -> str:
    """Mixin which returns the value from a :class:`enum.Flag` as a string."""
    return str(flag.value)


def hex_from_flag_value(flag: Flag) -> str:
    """Mixin which turns a :class:`enum.Flag` value into hexadecimal."""
    return hex(flag.value)


def _make_option(param_name: str, short: bool = False, no: bool = False) -> str:
    param_name = param_name.replace("_", "-")
    return f"{'-' if short else '--'}{'no-' if no else ''}{param_name}"


@dataclass
class Params:
    """Helper abstract dataclass that renders its fields into command line arguments.

    The parameter name is taken from the field name by default. The following:

    .. code:: python

        name: str | None = "value"

    is rendered as ``--name=value``.
    Through :func:`dataclasses.field` the resulting parameter can be manipulated by applying
    appropriate metadata. This class can be used with the following metadata modifiers:

    * :func:`value_only`
    * :func:`options_end`
    * :func:`short`
    * :func:`long`
    * :func:`multiple`
    * :func:`field_mixins`

    To use fields as option switches set the value to ``True`` to enable them. If you
    use a yes/no option switch you can also set ``False`` which would enable an option
    prefixed with ``--no-``. Examples:

    .. code:: python

        interactive: Option = True  # renders --interactive
        numa: BooleanOption = False # renders --no-numa

    Setting ``None`` will disable any option. The :attr:`~Option` type alias is provided for
    regular option switches, whereas :attr:`~BooleanOption` is offered for yes/no ones.

    An instance of a dataclass inheriting ``Params`` can also be assigned to an attribute, this helps with grouping parameters
    together. The attribute holding the dataclass will be ignored and the latter will just be rendered as expected.
    """

    def __str__(self) -> str:
        arguments: list[str] = []

        for field in fields(self):
            value = getattr(self, field.name)

            if value is None:
                continue

            options_end = field.metadata.get(META_OPTIONS_END, False)
            if options_end:
                arguments.append("--")

            value_only = field.metadata.get(META_VALUE_ONLY, False)
            if isinstance(value, Params) or value_only or options_end:
                arguments.append(str(value))
                continue

            # take "short_name" metadata, or "long_name" metadata, or infer from field name
            option_name = field.metadata.get(
                META_SHORT_NAME, field.metadata.get(META_LONG_NAME, field.name)
            )
            is_short = META_SHORT_NAME in field.metadata

            if isinstance(value, bool):
                arguments.append(_make_option(option_name, short=is_short, no=(not value)))
                continue

            option = _make_option(option_name, short=is_short)
            separator = " " if is_short else "="
            str_mixins = field.metadata.get(META_MIXINS, [])
            multiple = field.metadata.get(META_MULTIPLE, False)

            values = value if multiple else [value]
            for entry_value in values:
                entry_value = _reduce_mixins(str_mixins, entry_value)
                arguments.append(f"{option}{separator}{entry_value}")

        return " ".join(arguments)


@dataclass
class StrParams(Params):
    """A drop-in replacement for parameters passed as a string."""

    value: str = field(metadata=value_only())
