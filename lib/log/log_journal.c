/* SPDX-License-Identifier: BSD-3-Clause */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>

#include "log_internal.h"
#include "log_private.h"

static enum {
	LOG_JOURNAL_NEVER = 0,	/* do not use journal */
	LOG_JOURNAL_AUTO,	/* use if stderr is set to journal */
	LOG_JOURNAL_ALWAYS,	/* always try to use journal */
} log_journal_opt = LOG_JOURNAL_AUTO;

static int log_journal_fd = -1;

int
eal_log_journal(const char *str)
{
	if (str == NULL || strcmp(str, "auto") == 0)
		log_journal_opt = LOG_JOURNAL_AUTO;
	else if (strcmp(str, "always") == 0)
		log_journal_opt = LOG_JOURNAL_ALWAYS;
	else if (strcmp(str, "never") == 0)
		log_journal_opt = LOG_JOURNAL_NEVER;
	else
		return -1;
	return 0;
}

/*
 * send structured message using journal protocol
 * See: https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
 */
static int
journal_send(const char *buf, size_t len)
{
	struct iovec iov[4];
	unsigned int n = 0;
	int priority = rte_log_cur_msg_loglevel() - 1;
	char msg[] = "MESSAGE=";
	char newline = '\n';
	char pbuf[16];	/* "PRIORITY=N\n" */

	iov[n].iov_base = msg;
	iov[n++].iov_len = strlen(msg);

	iov[n].iov_base = (char *)(uintptr_t)buf;
	iov[n++].iov_len = len;

	/* if message doesn't end with newline, one will be applied. */
	if (buf[len - 1] != '\n') {
		iov[n].iov_base = &newline;
		iov[n++].iov_len = 1;
	}

	/* priority value between 0 ("emerg") and 7 ("debug") */
	iov[n].iov_base = pbuf;
	iov[n++].iov_len = snprintf(pbuf, sizeof(pbuf),
				    "PRIORITY=%d\n", priority);

	return writev(log_journal_fd, iov, n);
}


/* wrapper for log stream to put messages into journal */
static ssize_t
journal_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	return journal_send(buf, size);
}

static int
journal_log_close(__rte_unused void *c)
{
	close(log_journal_fd);
	log_journal_fd = -1;
	return 0;
}

static cookie_io_functions_t journal_log_func = {
	.write = journal_log_write,
	.close = journal_log_close,
};

/*
 * Check if stderr is going to system journal.
 * This is the documented way to handle systemd journal
 *
 * See: https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
 *
 */
static bool
is_journal(int fd)
{
	char *jenv, *endp = NULL;
	struct stat st;
	unsigned long dev, ino;

	jenv = getenv("JOURNAL_STREAM");
	if (jenv == NULL)
		return false;

	if (fstat(fd, &st) < 0)
		return false;

	/* systemd sets colon-separated list of device and inode number */
	dev = strtoul(jenv, &endp, 10);
	if (endp == NULL || *endp != ':')
		return false;	/* missing colon */

	ino = strtoul(endp + 1, NULL, 10);

	return dev == st.st_dev && ino == st.st_ino;
}

/* Connect to systemd's journal service */
static int
open_journal(void)
{
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
		.sun_path = "/run/systemd/journal/socket",
	};
	int s;

	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		perror("connect");
		close(s);
		return -1;
	}

	return s;
}

bool log_journal_enabled(void)
{
	if (log_journal_opt == LOG_JOURNAL_NEVER)
		return false;

	if (log_journal_opt == LOG_JOURNAL_AUTO &&
	    !is_journal(STDERR_FILENO))
		return false;

	log_journal_fd = open_journal();
	if (log_journal_fd < 0)
		return false;

	return true;
}

void log_journal_open(const char *id)
{
	FILE *log_stream;
	char *syslog_id = NULL;
	ssize_t len;

	/* Send identifier as first message */
	len = asprintf(&syslog_id, "SYSLOG_IDENTIFIER=%s\nSYSLOG_PID=%u",
		       id, getpid());
	if (len == 0)
		goto error;

	if (write(log_journal_fd, syslog_id, len) != len) {
		perror("write");
		goto error;
	}

	free(syslog_id);

	/* redirect other log messages to journal */
	log_stream = fopencookie(NULL, "w", journal_log_func);
	if (log_stream != NULL) {
		rte_openlog_stream(log_stream);
		return;
	}

error:
	free(syslog_id);
	close(log_journal_fd);
	log_journal_fd = -1;
}
