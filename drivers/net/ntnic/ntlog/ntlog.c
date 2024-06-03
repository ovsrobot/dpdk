/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <rte_string_fns.h>

#define NTLOG_HELPER_STR_SIZE_MAX (1024)

static struct nt_log_impl *user_impl;

int nt_log_init(struct nt_log_impl *impl)
{
	user_impl = impl;
	return user_impl->init();
}

static char *last_trailing_eol(char *s)
{
	int i = strlen(s) - 1;

	/* Skip spaces */
	while (i > 0 && s[i] == ' ')
		--i;

	if (s[i] != '\n')
		return NULL;

	/*
	 * Find the last trailing EOL "hello_world\n\n\n"
	 *                                         ^
	 */
	while (i > 1 && s[i] == '\n' && s[i - 1] == '\n')
		--i;

	return &s[i];
}

/* Always terminates the NT_LOG statement with a !!!single!!! EOL. */
int nt_log(enum nt_log_level level, uint32_t module, const char *format, ...)
{
	int rv = -1;
	va_list args;

	if (user_impl == NULL)
		return rv;

	char *actual_format = ntlog_helper_str_alloc(format);
	char *eol = last_trailing_eol(actual_format);

	if (!eol)	/* If log line is not terminated with '\n' we add it. */
		strncat(actual_format, "\n", NTLOG_HELPER_STR_SIZE_MAX - strlen(actual_format));

	else	/* If multiple trailing EOLs, then keep just one of them. */
		*(eol + 1) = '\0';

	va_start(args, format);
	rv = user_impl->log(level, module, actual_format, args);
	va_end(args);

	ntlog_helper_str_free(actual_format);
	return rv;
}

int nt_log_is_debug(uint32_t module)
{
	return user_impl->is_debug(module);
}

char *ntlog_helper_str_alloc(const char *sinit)
{
	char *s = malloc(NTLOG_HELPER_STR_SIZE_MAX);

	if (!s)
		return NULL;

	if (sinit)
		snprintf(s, NTLOG_HELPER_STR_SIZE_MAX, "%s", sinit);

	else
		s[0] = '\0';

	return s;
}

__rte_format_printf(2, 0)
void ntlog_helper_str_add(char *s, const char *format, ...)
{
	if (!s)
		return;

	va_list args;
	va_start(args, format);
	int len = strlen(s);
	vsnprintf(&s[len], (NTLOG_HELPER_STR_SIZE_MAX - 1 - len), format, args);
	va_end(args);
}

void ntlog_helper_str_free(char *s)
{
	free(s);
}
