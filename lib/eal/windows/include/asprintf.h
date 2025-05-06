/* SPDX-License-Identifier: MIT
 * Copyright(C) 2023 - 2025 Neved4
 * https://github.com/Neved4/asprintf/tree/main
 */

/**
 * @file
 * asprintf compat.
 *
 * This module provides asprintf() and vasprintf().
 */

#pragma once

#include <stdarg.h>

#ifndef RTE_TOOLCHAIN_GCC
int vasprintf(char **strp, const char *fmt, va_list ap);

int asprintf(char **s, const char *fmt, ...);
#endif
