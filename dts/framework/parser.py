# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

r"""Parsing utility module.

This module provides :class:`~TextParser` which can be used to model any dataclass to a block of
text.

Usage example::
..code:: python

    from dataclasses import dataclass, field
    from enum import Enum
    from framework.parser import TextParser

    class Colour(Enum):
        BLACK = 1
        WHITE = 2

        @classmethod
        def from_str(cls, text: str):
            match text:
                case "black":
                    return cls.BLACK
                case "white":
                    return cls.WHITE
                case _:
                    return None # unsupported colour

        @classmethod
        def make_parser(cls):
            # make a parser function that finds a match and
            # then makes it a Colour object through Colour.from_str
            return TextParser.compose(cls.from_str, TextParser.find(r"is a (\w+)"))

    @dataclass
    class Animal(TextParser):
        kind: str = field(metadata=TextParser.find(r"is a \w+ (\w+)"))
        name: str = field(metadata=TextParser.find(r"^(\w+)"))
        colour: Colour = field(metadata=Colour.make_parser())
        age: int = field(metadata=TextParser.find_int(r"aged (\d+)"))

    steph = Animal.parse("Stephanie is a white cat aged 10")
    print(steph) # Animal(kind='cat', name='Stephanie', colour=<Colour.WHITE: 2>, age=10)
"""

import re
from abc import ABC
from dataclasses import MISSING, dataclass, fields
from functools import partial
from typing import Any, Callable, TypedDict, cast

from typing_extensions import Self


class ParserFn(TypedDict):
    """Parser function in a dict compatible with the :func:`dataclasses.field` metadata param."""

    #:
    TextParser_fn: Callable[[str], Any]


@dataclass
class TextParser(ABC):
    """Helper abstract dataclass that parses a text according to the fields' rules.

    This class provides a selection of parser functions and a function to compose generic functions
    with parser functions. Parser functions are designed to be passed to the fields' metadata param
    to enable parsing.
    """

    """============ BEGIN PARSER FUNCTIONS ============"""

    @staticmethod
    def compose(f: Callable, parser_fn: ParserFn) -> ParserFn:
        """Makes a composite parser function.

        The parser function is run and if a non-None value was returned, f is called with it.
        Otherwise the function returns early with None.

        Metadata modifier for :func:`dataclasses.field`.

        Args:
            f: the function to apply to the parser's result
            parser_fn: the dictionary storing the parser function
        """
        g = parser_fn["TextParser_fn"]

        def _composite_parser_fn(text: str) -> Any:
            intermediate_value = g(text)
            if intermediate_value is None:
                return None
            return f(intermediate_value)

        return ParserFn(TextParser_fn=_composite_parser_fn)

    @staticmethod
    def find(
        pattern: str | re.Pattern[str],
        flags: re.RegexFlag = re.RegexFlag(0),
        named: bool = False,
    ) -> ParserFn:
        """Makes a parser function that finds a regular expression match in the text.

        If the pattern has capturing groups, it returns None if no match was found. If the pattern
        has only one capturing group and a match was found, its value is returned. If the pattern
        has no capturing groups then either True or False is returned if the pattern had a match or
        not.

        Metadata modifier for :func:`dataclasses.field`.

        Args:
            pattern: the regular expression pattern
            flags: the regular expression flags. Not used if the given pattern is already compiled
            named: if set to True only the named capture groups will be returned as a dictionary
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern, flags)

        def _find(text: str) -> Any:
            m = pattern.search(text)
            if m is None:
                return None if pattern.groups > 0 else False

            if pattern.groups == 0:
                return True

            if named:
                return m.groupdict()

            matches = m.groups()
            if len(matches) == 1:
                return matches[0]

            return matches

        return ParserFn(TextParser_fn=_find)

    @classmethod
    def find_int(
        cls,
        pattern: str | re.Pattern[str],
        flags: re.RegexFlag = re.RegexFlag(0),
        int_base: int = 0,
    ) -> ParserFn:
        """Makes a parser function that converts the match of :meth:`~find` to int.

        This function is compatible only with a pattern containing one capturing group.

        Metadata modifier for :func:`dataclasses.field`.

        Args:
            pattern: the regular expression pattern
            flags: the regular expression flags
            int_base: the base of the number to convert from
        Raises:
            RuntimeError: if the pattern does not have exactly one capturing group
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern, flags)

        if pattern.groups != 1:
            raise RuntimeError("only one capturing group is allowed with this parser function")

        return cls.compose(partial(int, base=int_base), cls.find(pattern))

    """============ END PARSER FUNCTIONS ============"""

    @classmethod
    def parse(cls, text: str) -> Self:
        """Creates a new instance of the class from the given text.

        A new class instance is created with all the fields that have a parser function in their
        metadata. Fields without one are ignored and are expected to have a default value, otherwise
        the class initialization will fail.

        A field is populated with the value returned by its corresponding parser function.

        Args:
            text: the text to parse
        Raises:
            RuntimeError: if the parser did not find a match and the field does not have a default
                          value or default factory.
        """
        fields_values = {}
        for field in fields(cls):
            parse = cast(ParserFn, field.metadata).get("TextParser_fn")
            if parse is None:
                continue

            value = parse(text)
            if value is not None:
                fields_values[field.name] = value
            elif field.default is MISSING and field.default_factory is MISSING:
                raise RuntimeError(
                    f"parser for field {field.name} returned None, but the field has no default"
                )

        return cls(**fields_values)
