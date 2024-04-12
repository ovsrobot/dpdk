# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""Parsing utility module.

This module provides :class:`~TextParser` which can be used to model any data structure
that can parse a block of text.
"""

from dataclasses import dataclass, fields, MISSING
import re
from typing import TypeVar
from typing_extensions import Self

T = TypeVar("T")


META_PARSERS = "parsers"


def chain(parser, metadata):
    """Chain a parser function.

    The parser function can take and return a single argument of any type. It is
    up to the user to ensure that the chained functions have compatible types.

    Args:
        parser: the parser function pointer
        metadata: pre-existing metadata to chain if any
    """
    parsers = metadata.get(META_PARSERS) or []
    parsers.append(parser)
    return {**metadata, META_PARSERS: parsers}


def to_int(metadata={}, base=0):
    """Converts a string to an integer.

    Args:
        metadata: pre-existing metadata to chain if any
        base: argument passed to the constructor of ``int``
    """
    return chain(lambda v: int(v, base), metadata)


def eq(v2, metadata={}):
    """Compares two values and returns a boolean.

    Args:
        v2: value to compare with the incoming value
        metadata: pre-existing metadata to chain if any
    """
    return chain(lambda v1: v1 == v2, metadata)


def to_bool(metadata={}):
    """Evaluates a string into a boolean.

    The following case-insensitive words yield ``True``: on, yes, enabled, true.

    Args:
        metadata: pre-existing metadata to chain if any
    """
    return chain(lambda s: s.lower() in ["on", "yes", "enabled", "true"], metadata)


def regex(
    pattern: str | re.Pattern[str],
    flags: re.RegexFlag = re.RegexFlag(0),
    named: bool = False,
    metadata={},
):
    """Searches for a regular expression in a text.

    If there is only one capture group, its value is returned, otherwise a tuple containing all the
    capture groups values is returned instead.

    Args:
        pattern: the regular expression pattern
        flags: the regular expression flags
        named: if set to True only the named capture groups will be returned as a dictionary
        metadata: pre-existing metadata to chain if any
    """
    pattern = re.compile(pattern, flags)

    def regex_parser(text: str):
        m = pattern.search(text)
        if m is None:
            return m

        if named:
            return m.groupdict()

        matches = m.groups()
        if len(matches) == 1:
            return matches[0]

        return matches

    return chain(regex_parser, metadata)


@dataclass
class TextParser:
    """Helper abstract dataclass that parses a text according to the fields' rules.

    This class is accompanied by a selection of parser functions and a generic chaining function,
    that are to be set to the fields' metadata, to enable parsing. If a field metadata is not set with
    any parser function, this is skipped.
    """

    @classmethod
    def parse(cls, text: str) -> Self:
        """The parsing class method.

        This function loops through every field that has any parser function associated with it and runs
        each parser chain to the supplied text. If a parser function returns None, it expects that parsing
        has failed and continues to the next field.

        Args:
            text: the text to parse
        Raises:
            RuntimeError: if the parser did not find a match and the field does not have a default value
                          or default factory.
        """
        fields_values = {}
        for field in fields(cls):
            parsers = field.metadata.get(META_PARSERS)
            if parsers is None:
                continue

            field_value = text
            for parser_fn in parsers:
                field_value = parser_fn(field_value)
                if field_value is None:
                    # nothing was actually parsed, move on
                    break

            if field_value is None:
                if field.default is MISSING and field.default_factory is MISSING:
                    raise RuntimeError(
                        f"parsers for field {field.name} returned None, but the field has no default"
                    )
            else:
                fields_values[field.name] = field_value

        return cls(**fields_values)
