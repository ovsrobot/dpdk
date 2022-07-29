# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
#

FROM ubuntu:22.04 AS base

RUN apt-get -y update && apt-get -y upgrade && \
    apt-get -y install --no-install-recommends \
        python3 \
        python3-pip \
        python3-pexpect \
        python3-poetry \
        python3-cachecontrol \
        openssh-client


FROM base AS runner

# This container is intended to be used as the base for automated systems.
# It bakes DTS into the container during the build.

RUN mkdir /dts
COPY ./pyproject.toml /dts/pyproject.toml
COPY ./poetry.lock /dts/poetry.lock
WORKDIR /dts
RUN poetry install --no-dev
COPY . /dts

CMD ["poetry", "run", "python", "main.py"]

FROM base AS dev

# This container is intended to be used as a development environment.

RUN apt-get -y install --no-install-recommends \
        vim emacs git

WORKDIR /dts
