#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
# Copyright(c) 2022 PANTHEON.tech s.r.o.
#

function main() {
    # The directory to work on is either passed in as argument 1,
    # or is the current working directory
    DIRECTORY=${1:-$(pwd)}
    LINE_LENGTH=88

    BLACK_VERSION=$(awk '/\[tool.poetry.dev-dependencies\]/,/$^/' pyproject.toml |\
                    grep black | grep -o '[0-9][^"]*')

    PYTHON_VERSION=$(awk '/\[tool.poetry.dependencies\]/,/$^/' pyproject.toml |\
                    grep python | grep -o '[0-9][^"]*' | tr -d '.')

    isort \
      --overwrite-in-place \
      --profile black \
      -j "$(nproc)" \
      --line-length $LINE_LENGTH \
      --python-version auto \
      "$DIRECTORY"

    black \
      --line-length $LINE_LENGTH \
      --required-version "${BLACK_VERSION}" \
      --target-version "py${PYTHON_VERSION}" \
      --safe \
      "$DIRECTORY"
}

function help() {
  echo "usage: format.sh <directory>"
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  help
  exit 0
fi

main "$1"

