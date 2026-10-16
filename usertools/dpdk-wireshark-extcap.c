/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-or-later
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Wireshark extcap plugin for live capture from DPDK ethdev ports.
 *
 * Wireshark creates a FIFO, this program opens it and passes the path to the
 * DPDK application as out= in /ethdev/capture/start. The application writes
 * pcapng straight into the FIFO; packet data never passes through here.
 * Capture stops when the read end closes or on SIGINT/SIGTERM, then
 * /ethdev/capture/stop is sent so the application can flush.
 *
 * Interface values are 'dpdk:<port>' for the default file-prefix and
 * 'dpdk:<prefix>:<port>' otherwise.
 *
 * May be installed with elevated privilege to reach the runtime directory of
 * an application running as another user. Privilege is used only to connect
 * to the telemetry socket and is dropped permanently after that; see
 * doc/guides/tools/wireshark_extcap.rst.
 *
 * The runtime directory location depends on the user the application runs as,
 * not on who runs this, so every candidate is searched; see dpdk_dirs().
 *
 * Build:
 *   cc -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
 *      -fPIE -pie -Wl,-z,relro,-z,now -o dpdk-wireshark-extcap \
 *      dpdk-wireshark-extcap.c
 */

/* The DPDK build passes this; keep the standalone build above working too. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/auxv.h>
#endif
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#define PROG_NAME		"dpdk-wireshark-extcap"
#define EXTCAP_VERSION		"0.1"
#define TELEMETRY_SOCKET	"dpdk_telemetry.v2"
#define CAPTURE_START_CMD	"/ethdev/capture/start"
#define CAPTURE_STOP_CMD	"/ethdev/capture/stop"
#define ETHDEV_LIST		"/ethdev/list"
#define ETHDEV_INFO		"/ethdev/info"
#define DEFAULT_SNAPLEN		262144
#define DEFAULT_PREFIX		"rte"
#define DLT_EN10MB		1

#define SECURE_DIR		"/var/run/dpdk"
#define ARRAY_SIZE(a)		((int)(sizeof(a) / sizeof((a)[0])))
#define MAX_PREFIXES		64
#define PREFIX_MAX		64
#define MAX_PORTS		256
#define MAX_QUEUES		1024
#define PARAMS_MAX		1024	/* primary limit (CAP_CMD_MAX) */
#define CMD_BUF			(PARAMS_MAX + 128)
#define REPLY_TIMEOUT_SEC	30
#define MIN_REPLY_LEN		1024
#define MAX_REPLY_LEN		(1 << 20)

/* One connected primary. */
struct source {
	char prefix[PREFIX_MAX];
	int fd;
};

static uid_t ruid, euid;
static gid_t rgid, egid;
static bool privileged_exec;

/* --- privilege handling -------------------------------------------- */

/*
 * True when the kernel raised our privilege at exec: setuid, setgid or file
 * capabilities. This is the same test the C library uses to decide whether to
 * trust the environment. dumpcap compares uids instead, which misses the
 * capability-only install where ruid == euid throughout, and counts a plain
 * root invocation as privileged, which this does not.
 */
static bool
exec_was_privileged(void)
{
#if defined(__linux__)
	return getauxval(AT_SECURE) != 0;
#elif defined(__FreeBSD__)
	return issetugid();
#else
	return getuid() != geteuid() || getgid() != getegid();
#endif
}

static void
priv_init(void)
{
	ruid = getuid();
	rgid = getgid();
	euid = geteuid();
	egid = getegid();
	privileged_exec = exec_was_privileged();
}

/*
 * Give up privilege permanently, then prove it cannot be taken back.
 *
 * Effective uid goes last: changing it is what takes away the right to change
 * anything else. Capabilities are cleared whether or not this process has any,
 * as in dumpcap's relinquish_all_capabilities().
 */
static void
priv_drop(void)
{
	if (setresgid(rgid, rgid, rgid) != 0)
		err(1, "setresgid");
	if (setresuid(ruid, ruid, ruid) != 0)
		err(1, "setresuid");

	if (getuid() != ruid || geteuid() != ruid ||
	    getgid() != rgid || getegid() != rgid)
		errx(1, "privilege drop failed");
	if (euid != ruid && seteuid(euid) == 0)
		errx(1, "privilege drop failed");
	if (egid != rgid && setegid(egid) == 0)
		errx(1, "privilege drop failed");

#ifdef HAVE_LIBCAP
	/* A file-capability install changes no id above, so this is the drop. */
	cap_t caps = cap_init();	/* all capabilities off */

	if (caps == NULL)
		err(1, "cap_init");
	if (cap_set_proc(caps) != 0)
		err(1, "cap_set_proc");
	cap_free(caps);
#else
	if (privileged_exec && ruid == euid && rgid == egid)
		errx(1, "built without libcap, cannot drop a file capability");
#endif
}

/* Make sure fds 0-2 are open so later opens cannot land on them. */
static void
std_fds(void)
{
	for (int fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
			int n = open("/dev/null", O_RDWR);

			if (n != fd)
				_exit(1);
		}
	}
}

/* --- minimal JSON scanner ------------------------------------------ */

static const char *
skip_ws(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	return p;
}

/* Return pointer to the value following "key": or NULL. */
static const char *
json_value(const char *json, const char *key)
{
	char pat[96];
	const char *p = json;
	int n = snprintf(pat, sizeof(pat), "\"%s\"", key);

	if (n < 0 || (size_t)n >= sizeof(pat))
		return NULL;

	while ((p = strstr(p, pat)) != NULL) {
		const char *v = skip_ws(p + n);

		if (*v == ':')
			return skip_ws(v + 1);
		p += n;
	}
	return NULL;
}

static bool
json_int(const char *json, const char *key, long long *val)
{
	const char *v = json_value(json, key);
	char *end;
	long long x;

	if (v == NULL || !((*v >= '0' && *v <= '9') || *v == '-'))
		return false;
	errno = 0;
	x = strtoll(v, &end, 10);
	if (errno != 0 || end == v)
		return false;
	*val = x;
	return true;
}

/* Copy a string value, replacing non printable characters with '_'. */
static bool
json_str(const char *json, const char *key, char *out, size_t outsz)
{
	const char *v = json_value(json, key);
	size_t n = 0;

	if (v == NULL || *v != '"')
		return false;
	for (v++; *v != '"'; v++) {
		unsigned char c = *v;

		if (c == '\0')
			return false;
		if (c == '\\') {
			c = '_';
			if (v[1] == '\0')
				return false;
			v++;
		}
		if (c < 0x20 || c > 0x7e)
			c = '_';
		if (n + 1 < outsz)
			out[n++] = c;
	}
	out[n] = '\0';
	return true;
}

static int
json_int_array(const char *json, const char *key, long long *out, int max)
{
	const char *v = json_value(json, key);
	int n = 0;

	if (v == NULL || *v != '[')
		return 0;
	v = skip_ws(v + 1);
	while (*v != '\0' && *v != ']') {
		char *end;
		long long x;

		errno = 0;
		x = strtoll(v, &end, 10);
		if (end == v || errno != 0)
			break;
		if (n < max)
			out[n++] = x;
		v = skip_ws(end);
		if (*v != ',')
			break;
		v = skip_ws(v + 1);
	}
	return n;
}

/* Names go into extcap sentences, keep them to a safe alphabet. */
static void
sanitize_label(char *s)
{
	for (; *s != '\0'; s++) {
		char c = *s;

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == ':' || c == '-'))
			*s = '_';
	}
}

/*
 * Why this string cannot be handed to the primary, or NULL if it can.
 * Telemetry parameters are a comma separated list with no escaping.
 */
static const char *
param_problem(const char *s)
{
	if (strchr(s, ',') != NULL)
		return "must not contain a comma";

	for (; *s != '\0'; s++) {
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return "must not contain control characters";
	}
	return NULL;
}

/* --- DPDK runtime directory / socket discovery ---------------------- */

static char dirbuf[PATH_MAX];

/*
 * Directories that may hold the per-prefix runtime subdirectories.
 *
 * Where the primary put them depends on the user it runs as, not on the user
 * running this program: a root primary uses /var/run/dpdk whether or not the
 * capture tool is root. So rather than guess from our own uid, return every
 * candidate and let the caller look in each.
 *
 * DPDK_EXTCAP_PATH overrides the search. It is ignored after a privileged
 * exec, where the environment is not trusted.
 */
static int
dpdk_dirs(const char *dirs[], int max)
{
	const char *env, *xdg;
	int n = 0;

	if (!privileged_exec) {
		env = getenv("DPDK_EXTCAP_PATH");
		if (env != NULL && *env != '\0') {
			dirs[n++] = env;
			return n;
		}
	}

	/* where a root primary puts it */
	if (n < max)
		dirs[n++] = SECURE_DIR;

	/* where a primary running as an ordinary user puts it */
	if (!privileged_exec) {
		xdg = getenv("XDG_RUNTIME_DIR");
		if (xdg == NULL || *xdg == '\0')
			xdg = "/tmp";
		if ((size_t)snprintf(dirbuf, sizeof(dirbuf), "%s/dpdk", xdg) >= sizeof(dirbuf))
			errx(1, "runtime directory path too long");
		if (n < max)
			dirs[n++] = dirbuf;
	}

	return n;
}

static bool
valid_prefix(const char *s)
{
	size_t len = strlen(s);

	if (len == 0 || len >= PREFIX_MAX)
		return false;
	if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
		return false;
	for (; *s != '\0'; s++) {
		char c = *s;

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return false;
	}
	return true;
}

static void
socket_path(const char *dir, const char *prefix, char *out, size_t sz)
{
	if ((size_t)snprintf(out, sz, "%s/%s/%s", dir, prefix,
			     TELEMETRY_SOCKET) >= sz)
		errx(1, "socket path too long");
}

/* --- telemetry transport -------------------------------------------- */

struct telemetry {
	int fd;
	size_t max_len;
	char *buf;	/* last reply, always NUL terminated */
};

/*
 * Connect to a telemetry socket. This is the only call that needs privilege,
 * so it is also the only thing done before priv_drop().
 */
static int
tel_connect(const char *path)
{
	struct sockaddr_un sa;
	size_t len = strlen(path);
	int fd, save;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	if (len >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(sa.sun_path, path, len);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		save = errno;
		close(fd);
		errno = save;
		return -1;
	}
	return fd;
}

/*
 * Read the banner and size the reply buffer. Runs unprivileged: this is the
 * first point at which the primary gets to send us anything. Takes ownership
 * of fd and closes it on failure.
 */
static int
tel_handshake(struct telemetry *t, int fd)
{
	struct timeval tv = { .tv_sec = REPLY_TIMEOUT_SEC };
	char banner[1025];
	long long maxlen;
	ssize_t n;
	int save;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	do {
		n = recv(fd, banner, sizeof(banner) - 1, 0);
	} while (n < 0 && errno == EINTR);
	if (n <= 0) {
		save = n < 0 ? errno : ECONNRESET;
		close(fd);
		errno = save;
		return -1;
	}
	banner[n] = '\0';

	if (!json_int(banner, "max_output_len", &maxlen))
		maxlen = 16384;
	if (maxlen < MIN_REPLY_LEN)
		maxlen = MIN_REPLY_LEN;
	if (maxlen > MAX_REPLY_LEN)
		maxlen = MAX_REPLY_LEN;

	t->buf = malloc(maxlen + 1);
	if (t->buf == NULL) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}
	t->fd = fd;
	t->max_len = maxlen;
	return 0;
}

/* Send a command; reply lands in t->buf (empty string if no reply). */
static int
tel_command(struct telemetry *t, const char *cmd)
{
	size_t len = strlen(cmd);
	ssize_t n;

	do {
		n = send(t->fd, cmd, len, 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -1;

	do {
		n = recv(t->fd, t->buf, t->max_len, 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -1;
	t->buf[n] = '\0';
	return 0;
}

static void
tel_close(struct telemetry *t)
{
	close(t->fd);
	free(t->buf);
	t->buf = NULL;
}

static long
port_queue_count(struct telemetry *t, long port)
{
	char cmd[64];
	long long rx = 0, tx = 0;

	snprintf(cmd, sizeof(cmd), ETHDEV_INFO ",%ld", port);
	if (tel_command(t, cmd) < 0)
		return 0;
	json_int(t->buf, "nb_rx_queues", &rx);
	json_int(t->buf, "nb_tx_queues", &tx);
	return rx > tx ? (long)rx : (long)tx;
}

/* Device name via /ethdev/info, or "port<N>" if unreadable. */
static void
port_name(struct telemetry *t, long port, char *out, size_t sz)
{
	char cmd[64];

	snprintf(cmd, sizeof(cmd), ETHDEV_INFO ",%ld", port);
	if (tel_command(t, cmd) < 0 || !json_str(t->buf, "name", out, sz) ||
	    out[0] == '\0')
		snprintf(out, sz, "port%ld", port);
	sanitize_label(out);
}

/* --- interface naming ---------------------------------------------- */

static void
iface_value(const char *prefix, long port, char *out, size_t sz)
{
	if (strcmp(prefix, DEFAULT_PREFIX) == 0)
		snprintf(out, sz, "dpdk:%ld", port);
	else
		snprintf(out, sz, "dpdk:%.*s:%ld", PREFIX_MAX - 1, prefix, port);
}

/* Inverse of iface_value. */
static void
parse_iface(const char *iface, char *prefix, size_t prefix_sz, long *port)
{
	const char *p, *c1, *c2, *num;
	char *end;
	unsigned long v;

	c1 = strchr(iface, ':');
	if (c1 == NULL || (size_t)(c1 - iface) != 4 || strncmp(iface, "dpdk", 4) != 0)
		errx(1, "unsupported interface scheme in '%s'", iface);

	p = c1 + 1;
	c2 = strchr(p, ':');
	if (c2 == NULL) {
		snprintf(prefix, prefix_sz, "%s", DEFAULT_PREFIX);
		num = p;
	} else {
		size_t len = c2 - p;

		if (strchr(c2 + 1, ':') != NULL)
			errx(1, "malformed interface '%s'", iface);
		if (len == 0 || len >= prefix_sz)
			errx(1, "malformed interface '%s'", iface);
		memcpy(prefix, p, len);
		prefix[len] = '\0';
		num = c2 + 1;
	}

	if (!valid_prefix(prefix))
		errx(1, "malformed interface '%s'", iface);
	if (!(*num >= '0' && *num <= '9'))
		errx(1, "malformed interface '%s'", iface);
	errno = 0;
	v = strtoul(num, &end, 10);
	if (errno != 0 || *end != '\0' || v > UINT16_MAX)
		errx(1, "malformed interface '%s'", iface);
	*port = v;
}

/* --- privileged phase ----------------------------------------------- */

static int
cmp_source(const void *a, const void *b)
{
	const struct source *x = a, *y = b;

	return strcmp(x->prefix, y->prefix);
}

/*
 * Connect to every primary under the runtime directory.
 *
 * All of it happens before the drop, as dumpcap opens all of its capture
 * devices before relinquishing. Nothing is read from these sockets here.
 */
static int
connect_dir(const char *root, struct source *src, int n, int max, bool *looked,
	    bool *complained)
{
	struct dirent *de;
	DIR *d;

	d = opendir(root);
	if (d == NULL) {
		/*
		 * A directory that is simply not there is not worth a word: the
		 * other candidate is probably the live one. Anything else means
		 * a primary is likely there but out of reach, which is worth
		 * saying even if another directory works out.
		 */
		if (errno == EACCES) {
			*looked = true;
			*complained = true;
			warnx("cannot read %s: permission denied. The DPDK runtime "
			      "directory is created mode 0700, so capture must run "
			      "as the same user as the DPDK application, or be "
			      "installed with privilege", root);
		} else if (errno != ENOENT) {
			*looked = true;
			*complained = true;
			warn("cannot read %s", root);
		}
		return n;
	}
	*looked = true;

	while (n < max && (de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		struct stat st;
		int fd;

		if (!valid_prefix(de->d_name))
			continue;
		socket_path(root, de->d_name, path, sizeof(path));
		if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode))
			continue;

		fd = tel_connect(path);
		if (fd < 0) {
			warn("cannot connect to %s", path);
			continue;
		}
		/* valid_prefix() bounded the length */
		memcpy(src[n].prefix, de->d_name, strlen(de->d_name) + 1);
		src[n].fd = fd;
		n++;
	}
	closedir(d);

	return n;
}

/*
 * Connect to one named prefix, trying each candidate directory. The path tried
 * last is left in out[] for the caller's error message.
 */
static int
connect_prefix(const char *prefix, char *out, size_t outsz)
{
	const char *dirs[4];
	int ndirs = dpdk_dirs(dirs, ARRAY_SIZE(dirs));

	for (int i = 0; i < ndirs; i++) {
		int fd;

		socket_path(dirs[i], prefix, out, outsz);
		fd = tel_connect(out);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int
connect_all(struct source *src, int max)
{
	const char *dirs[4];
	bool looked = false, complained = false;
	int ndirs, n = 0;

	ndirs = dpdk_dirs(dirs, ARRAY_SIZE(dirs));
	for (int i = 0; i < ndirs && n < max; i++)
		n = connect_dir(dirs[i], src, n, max, &looked, &complained);

	/* a reason was already given for an unreadable directory */
	if (n == 0 && !complained) {
		if (looked)
			warnx("no DPDK telemetry socket found. Is a DPDK "
			      "application running with telemetry enabled?");
		else
			warnx("no DPDK runtime directory. Either no DPDK "
			      "application is running, or it runs as a different "
			      "user and this program was installed without privilege");
	}

	qsort(src, n, sizeof(*src), cmp_source);
	return n;
}

/* --- extcap query operations --------------------------------------- */

static void
cmd_interfaces(struct source *src, int nsrc)
{
	printf("extcap {version=%s}{display=DPDK telemetry capture}\n", EXTCAP_VERSION);

	for (int i = 0; i < nsrc; i++) {
		long long ports[MAX_PORTS];
		struct telemetry t;
		int nports = 0;

		if (tel_handshake(&t, src[i].fd) < 0) {
			warn("no banner from %s", src[i].prefix);
			continue;
		}

		if (tel_command(&t, ETHDEV_LIST) == 0)
			nports = json_int_array(t.buf, ETHDEV_LIST, ports, MAX_PORTS);
		else
			warn("cannot query %s", src[i].prefix);

		for (int j = 0; j < nports; j++) {
			char name[128], value[160], display[256];

			if (ports[j] < 0 || ports[j] > UINT16_MAX)
				continue;
			port_name(&t, ports[j], name, sizeof(name));
			iface_value(src[i].prefix, ports[j], value, sizeof(value));
			if (strcmp(src[i].prefix, DEFAULT_PREFIX) == 0)
				snprintf(display, sizeof(display), "DPDK %.127s", name);
			else
				snprintf(display, sizeof(display), "DPDK %.127s@%.63s",
					 name, src[i].prefix);
			printf("interface {value=%s}{display=%s}\n", value, display);
		}
		tel_close(&t);
	}
}

static void
cmd_dlts(void)
{
	printf("dlt {number=%d}{name=EN10MB}{display=Ethernet}\n", DLT_EN10MB);
}

static void
cmd_config(int fd, long port)
{
	long nqueues = 0;

	printf("arg {number=0}{call=--snaplen}{display=Snapshot length}"
	       "{tooltip=Bytes captured per packet (0 = whole packet)}"
	       "{type=integer}{range=0,%d}{default=%d}{group=Capture}\n",
	       DEFAULT_SNAPLEN, DEFAULT_SNAPLEN);

	/*
	 * Bound the queue dropdown to the port's queue count. If the primary
	 * is unreachable just omit it, capture defaults to all queues.
	 */
	if (fd >= 0) {
		struct telemetry t;

		if (tel_handshake(&t, fd) == 0) {
			nqueues = port_queue_count(&t, port);
			tel_close(&t);
		}
	}

	if (nqueues > MAX_QUEUES)
		nqueues = MAX_QUEUES;
	if (nqueues > 0) {
		printf("arg {number=1}{call=--queue}{display=Queue}"
		       "{tooltip=Capture a single hardware queue}"
		       "{type=selector}{group=Capture}\n");
		printf("value {arg=1}{value=-1}{display=All queues}{default=true}\n");
		for (long q = 0; q < nqueues; q++)
			printf("value {arg=1}{value=%ld}{display=Queue %ld}\n", q, q);
	}
}

/* --- capture -------------------------------------------------------- */

static void
cmd_append(char *cmd, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void
cmd_append(char *cmd, const char *fmt, ...)
{
	size_t len = strlen(cmd);
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(cmd + len, CMD_BUF - len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= CMD_BUF - len)
		errx(1, "capture parameters too long");
}

static int stop_pipe[2] = { -1, -1 };

static void
on_stop_signal(int sig)
{
	int saved = errno;
	ssize_t r;

	(void)sig;
	r = write(stop_pipe[1], "x", 1);
	(void)r;
	errno = saved;
}

/*
 * Block until Wireshark stops us: it closes the FIFO read end (error/hangup
 * on our write fd) or sends SIGINT/SIGTERM. Handlers are restored before
 * returning so a second signal terminates us the usual way.
 */
static void
wait_for_stop(int fifo_fd)
{
	struct sigaction sa, old_int, old_term;
	struct pollfd pfd[2];

	if (pipe2(stop_pipe, O_CLOEXEC | O_NONBLOCK) != 0)
		err(1, "pipe2");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_stop_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, &old_int);
	sigaction(SIGTERM, &sa, &old_term);

	pfd[0].fd = fifo_fd;
	pfd[0].events = POLLERR;
	pfd[1].fd = stop_pipe[0];
	pfd[1].events = POLLIN;
	for (;;) {
		int r = poll(pfd, 2, -1);

		if (r > 0 || (r < 0 && errno != EINTR))
			break;
	}

	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
	close(stop_pipe[0]);
	close(stop_pipe[1]);
}

static void
cmd_capture(int fd, long port, const char *fifo, long snaplen, long queue,
	    const char *cfilter)
{
	char cmd[CMD_BUF];
	char errmsg[256];
	struct telemetry t;
	struct stat sb;
	long long cap_id;
	int fifo_fd;

	snprintf(cmd, sizeof(cmd), CAPTURE_START_CMD ",%ld,out=%s", port, fifo);
	if (snaplen >= 0)
		cmd_append(cmd, ",snaplen=%ld", snaplen);
	if (queue >= 0)
		cmd_append(cmd, ",queue=%ld", queue);
	if (cfilter != NULL && *cfilter != '\0')
		cmd_append(cmd, ",filter=%s", cfilter);
	if (strlen(cmd) - sizeof(CAPTURE_START_CMD) >= PARAMS_MAX)
		errx(1, "capture parameters too long");

	/*
	 * Blocking open of the FIFO Wireshark created, unprivileged, which is
	 * where dumpcap opens its output too.
	 *
	 * Rendezvous: a reader is attached before the primary opens the write
	 * end (it uses O_NONBLOCK and fails with ENXIO without a reader). We
	 * hold this fd for the whole session: it keeps the pipe from EOF-ing
	 * before the primary has its own write end, and it is the reliable stop
	 * signal (error here means Wireshark closed the read end).
	 */
	fifo_fd = open(fifo, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fifo_fd < 0)
		err(1, "cannot open fifo %s", fifo);
	if (fstat(fifo_fd, &sb) != 0 || !S_ISFIFO(sb.st_mode))
		errx(1, "%s is not a fifo", fifo);

	if (tel_handshake(&t, fd) < 0)
		err(1, "no banner from DPDK telemetry");

	if (tel_command(&t, cmd) < 0)
		err(1, "capture start failed");

	if (json_str(t.buf, "error", errmsg, sizeof(errmsg)))
		errx(1, "capture start failed: %s", errmsg);
	if (!json_int(t.buf, "id", &cap_id) || cap_id < 0)
		errx(1, "capture start failed: unexpected reply from primary");

	/*
	 * Run until Wireshark stops us. The primary holds its own write end,
	 * so closing ours below does not EOF the reader prematurely.
	 */
	wait_for_stop(fifo_fd);

	/*
	 * Ask the primary to stop while we still hold the write end, so a
	 * still attached reader gets the tail and the statistics block before
	 * the final EOF. If the read end is gone the primary already stopped
	 * on the same hangup and this is a no-op.
	 */
	snprintf(cmd, sizeof(cmd), CAPTURE_STOP_CMD ",%lld", cap_id);
	tel_command(&t, cmd);

	close(fifo_fd);
	tel_close(&t);
}

/* --- entry point ---------------------------------------------------- */

struct options {
	bool interfaces, dlts, config, capture, version, help;
	const char *iface, *fifo, *cfilter;
	long snaplen, queue;
};

static void
usage(FILE *f)
{
	fprintf(f,
		"Usage: %s [options]\n"
		"\n"
		"Wireshark external capture (extcap) plugin for DPDK ports.\n"
		"Normally run by Wireshark, not by hand.\n"
		"\n"
		"Extcap operations:\n"
		"  --extcap-interfaces          list the ports of every running DPDK application\n"
		"  --extcap-dlts                list link types of an interface\n"
		"  --extcap-config              list capture options of an interface\n"
		"  --capture                    start a capture, needs --fifo\n"
		"  --extcap-version[=<ver>]     version of the calling Wireshark\n"
		"  --extcap-interface <iface>   interface to act on, as listed above\n"
		"\n"
		"Capture options:\n"
		"  --fifo <path>                where to write pcapng, created by Wireshark\n"
		"  --extcap-capture-filter <f>  pcap filter expression\n"
		"  --snaplen <n>                bytes to capture per packet, 0 for all\n"
		"  --queue <n>                  capture one queue, -1 for all\n"
		"\n"
		"  -h, --help                   this text\n"
		"  --version                    program version\n"
		"\n"
		"Environment:\n"
		"  DPDK_EXTCAP_PATH             base DPDK runtime directory to search\n"
		"                               (ignored if installed with privilege)\n",
		PROG_NAME);
}

/* Match --name, --name=value or --name value. Returns 1 on match. */
static int
opt_value(int argc, char **argv, int *i, const char *name, const char **val,
	  bool optional)
{
	const char *a = argv[*i];
	size_t len = strlen(name);

	if (strncmp(a, name, len) != 0)
		return 0;
	if (a[len] == '=') {
		*val = a + len + 1;
		return 1;
	}
	if (a[len] != '\0')
		return 0;
	if (*i + 1 < argc && (!optional || argv[*i + 1][0] != '-')) {
		*val = argv[++*i];
		return 1;
	}
	if (optional) {
		*val = NULL;
		return 1;
	}
	errx(1, "%s requires a value", name);
}

static long
parse_long(const char *name, const char *s, long lo, long hi)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi)
		errx(1, "invalid %s '%s'", name, s);
	return v;
}

static void
parse_args(int argc, char **argv, struct options *o)
{
	const char *val;

	memset(o, 0, sizeof(*o));
	o->snaplen = -1;
	o->queue = -1;

	/* Unknown options are ignored, Wireshark passes several extras. */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
			o->help = true;
		else if (strcmp(argv[i], "--version") == 0)
			o->version = true;
		else if (strcmp(argv[i], "--extcap-interfaces") == 0)
			o->interfaces = true;
		else if (strcmp(argv[i], "--extcap-dlts") == 0)
			o->dlts = true;
		else if (strcmp(argv[i], "--extcap-config") == 0)
			o->config = true;
		else if (strcmp(argv[i], "--capture") == 0)
			o->capture = true;
		else if (opt_value(argc, argv, &i, "--extcap-interface", &val, false))
			o->iface = val;
		else if (opt_value(argc, argv, &i, "--fifo", &val, false))
			o->fifo = val;
		else if (opt_value(argc, argv, &i, "--extcap-capture-filter", &val, false))
			o->cfilter = val;
		else if (opt_value(argc, argv, &i, "--extcap-version", &val, true))
			continue;
		else if (opt_value(argc, argv, &i, "--snaplen", &val, false))
			o->snaplen = parse_long("--snaplen", val, 0, INT32_MAX);
		else if (opt_value(argc, argv, &i, "--queue", &val, false))
			o->queue = parse_long("--queue", val, -1, UINT16_MAX);
	}
}

int
main(int argc, char **argv)
{
	struct source src[MAX_PREFIXES];
	struct options o;
	const char *why;
	long port = -1;
	int nsrc = 0;

	std_fds();
	priv_init();
	signal(SIGPIPE, SIG_IGN);
	parse_args(argc, argv, &o);

	/* Needs no privilege and no primary, so answer before anything else. */
	if (o.help) {
		usage(stdout);
		return 0;
	}

	/*
	 * Privileged phase. Only the connect needs privilege, so it is the
	 * only thing here, and everything it needs from argv is checked first.
	 */
	if (o.interfaces) {
		nsrc = connect_all(src, MAX_PREFIXES);
	} else if (o.config || o.capture) {
		char path[PATH_MAX];

		if (o.iface == NULL)
			errx(1, "missing --extcap-interface");
		if (o.capture) {
			struct stat sb;

			if (o.fifo == NULL)
				errx(1, "--capture requires --fifo");
			why = param_problem(o.fifo);
			if (why != NULL)
				errx(1, "fifo path %s", why);
			if (o.cfilter != NULL) {
				why = param_problem(o.cfilter);
				if (why != NULL)
					errx(1, "capture filter %s", why);
			}

			/*
			 * Advisory: fail before costing the primary a connection
			 * and a handler thread. lstat() to match the O_NOFOLLOW
			 * open, which is the check that counts.
			 */
			if (lstat(o.fifo, &sb) != 0)
				err(1, "%s", o.fifo);
			if (!S_ISFIFO(sb.st_mode))
				errx(1, "%s is not a fifo", o.fifo);
		}

		parse_iface(o.iface, src[0].prefix, PREFIX_MAX, &port);
		src[0].fd = connect_prefix(src[0].prefix, path, sizeof(path));
		if (src[0].fd < 0 && o.capture)
			err(1, "cannot connect to DPDK telemetry at %s", path);
		nsrc = 1;
	}

	/* Nothing below this point runs with privilege. */
	priv_drop();

	if (o.version)
		printf("%s %s\n", PROG_NAME, EXTCAP_VERSION);
	else if (o.interfaces)
		cmd_interfaces(src, nsrc);
	else if (o.dlts)
		cmd_dlts();
	else if (o.config)
		cmd_config(src[0].fd, port);
	else if (o.capture)
		cmd_capture(src[0].fd, port, o.fifo, o.snaplen, o.queue, o.cfilter);
	else if (o.cfilter != NULL) {
		/*
		 * Wireshark validates a capture filter by running the extcap
		 * with the filter but without --capture. No output means
		 * accepted, any output marks it invalid. Exit status must stay
		 * 0 or Wireshark reports the filter as unknown. Only reject
		 * what the telemetry encoding cannot carry.
		 */
		why = param_problem(o.cfilter);
		if (why != NULL)
			printf("capture filter %s\n", why);
	} else {
		warnx("no extcap operation specified");
		usage(stderr);
		return 1;
	}

	return 0;
}
