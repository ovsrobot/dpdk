/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "nt_util.h"
#include "ntconnect.h"
#include "ntconnect_api.h"
#include "ntlog.h"

/* clang-format off */
ntconn_err_t ntconn_err[] = {
	{NTCONN_ERR_CODE_NONE, "Success"},
	{NTCONN_ERR_CODE_INTERNAL_ERROR, "Internal error"},
	{NTCONN_ERR_CODE_INTERNAL_REPLY_ERROR, "Internal error in reply from module"},
	{NTCONN_ERR_CODE_NO_DATA, "No data found"},
	{NTCONN_ERR_CODE_INVALID_REQUEST, "Invalid request"},
	{NTCONN_ERR_CODE_NOT_YET_IMPLEMENTED, "Function not yet implemented"},
	{NTCONN_ERR_CODE_INTERNAL_FUNC_ERROR, "Internal error in function call list"},
	{NTCONN_ERR_CODE_MISSING_INVALID_PARAM, "Missing or invalid parameter"},
	{NTCONN_ERR_CODE_FUNCTION_PARAM_INCOMPLETE, "Function parameter is incomplete"},
	{NTCONN_ERR_CODE_FUNC_PARAM_NOT_RECOGNIZED,
		"Function or parameter not recognized/supported"},
	{-1, NULL}
};

/* clang-format on */

static ntconn_mod_t *ntcmod_base;
static pthread_t tid;
static pthread_t ctid;
static struct ntconn_server_s ntconn_serv;

const ntconn_err_t *get_ntconn_error(enum ntconn_err_e err_code)
{
	int idx = 0;

	while (ntconn_err[idx].err_code != (uint32_t)-1 &&
			ntconn_err[idx].err_code != err_code)
		idx++;
	if (ntconn_err[idx].err_code == (uint32_t)-1)
		idx = 1;

	return &ntconn_err[idx];
}

int register_ntconn_mod(const struct rte_pci_addr *addr, void *hdl,
			const ntconnapi_t *op)
{
	/* Verify and check module name is unique */
#ifdef DEBUG
	NT_LOG(DBG, NTCONNECT,
	       "Registering pci: %04x:%02x:%02x.%x, module %s\n", addr->domain,
	       addr->bus, addr->devid, addr->function, op->module);
#endif

	ntconn_mod_t *ntcmod = (ntconn_mod_t *)malloc(sizeof(ntconn_mod_t));

	if (!ntcmod) {
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return -1;
	}
	ntcmod->addr.domain = addr->domain;
	ntcmod->addr.bus = addr->bus;
	ntcmod->addr.devid = addr->devid;
	ntcmod->addr.function = addr->function;
	ntcmod->addr.pad = 0;

	ntcmod->hdl = hdl;
	ntcmod->op = op;
	pthread_mutex_init(&ntcmod->mutex, NULL);

	ntcmod->next = ntcmod_base;
	ntcmod_base = ntcmod;

	if (ntcmod->addr.pci_id) { /* Avoid server fake pci_id */
		int i;

		for (i = 0; i < MAX_PCI_IDS; i++) {
			if (ntconn_serv.pci_id_list[i].pci_id == 0) {
				NT_LOG(DBG, NTCONNECT,
				       "insert at index %i PCI ID %" PRIX64 "\n", i,
				       ntcmod->addr.pci_id);
				ntconn_serv.pci_id_list[i].pci_id =
					ntcmod->addr.pci_id;
				break;
			} else if (ntconn_serv.pci_id_list[i].pci_id ==
					ntcmod->addr.pci_id)
				break;
		}
	}

	return 0;
}

static int unix_build_address(const char *path, struct sockaddr_un *addr)
{
	if (addr == NULL || path == NULL)
		return -1;
	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_UNIX;
	if (strlen(path) < sizeof(addr->sun_path)) {
		rte_strscpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
		return 0;
	}
	return -1;
}

#define STATUS_OK 0
#define STATUS_INTERNAL_ERROR -1
#define STATUS_TRYAGAIN -2
#define STATUS_INVALID_PARAMETER -3
#define STATUS_CONNECTION_CLOSED -4
#define STATUS_CONNECTION_INVALID -5
#define STATUS_TIMEOUT -6

static int read_data(int fd, size_t len, uint8_t *data, size_t *recv_len,
		     int timeout)
{
	struct pollfd pfd;
	ssize_t ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	ret = poll(&pfd, 1, timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return STATUS_TRYAGAIN; /* Caught signal before timeout */
		if (errno == EINVAL)
			return STATUS_INVALID_PARAMETER; /* Timeout is negative */
		if (errno == EFAULT)
			return STATUS_INVALID_PARAMETER; /* Fds argument is illegal */
		/* else */
		assert(0);
		return STATUS_INTERNAL_ERROR;
	}

	if (ret == 0)
		return STATUS_TIMEOUT;

	if (pfd.revents == 0) {
		assert(ret == 1);
		assert(0); /* Revents cannot be zero when NtSocket_Poll returns 1 */
		return STATUS_TRYAGAIN;
	}

	if ((pfd.revents & POLLIN) &&
			((pfd.revents & (POLLERR | POLLNVAL)) == 0)) {
		ret = recv(pfd.fd, data, len, 0);
		if (ret < 0) {
			int lerrno = errno;

			if (lerrno == EWOULDBLOCK || lerrno == EAGAIN) {
				/*
				 * We have data but if the very first read turns out to return
				 * EWOULDBLOCK or EAGAIN it means that the remote  end has dropped
				 * the connection
				 */
				NT_LOG(DBG, NTCONNECT,
				       "The socket with fd %d has been closed by remote end. %d [%s]\n",
				       pfd.fd, lerrno, strerror(lerrno));
				return STATUS_CONNECTION_CLOSED;
			}
			if (lerrno != EINTR) {
				NT_LOG(ERR, NTCONNECT,
				       "recv() from fd %d received errno %d [%s]\n",
				       pfd.fd, lerrno, strerror(lerrno));
				return STATUS_CONNECTION_INVALID;
			}
			/* EINTR */
			return STATUS_TRYAGAIN;
		}
		if (ret == 0) {
			if (pfd.revents & POLLHUP) {
				/* This means that we have read all data and the remote end has
				 * HUP
				 */
#ifdef DEBUG
				NT_LOG(DBG, NTCONNECT,
				       "The remote end has terminated the session\n");
#endif
				return STATUS_CONNECTION_CLOSED;
			}
			return STATUS_TRYAGAIN;
		}

		/* Ret can only be positive at this point */
		 *recv_len = (size_t)ret;
		return STATUS_OK;
	}

	if ((pfd.revents & POLLHUP) == POLLHUP) {
		/* this means that the remote end has HUP */
		NT_LOG(DBG, NTCONNECT,
		       "The remote end has terminated the session\n");
		return STATUS_CONNECTION_CLOSED;
	}

	NT_LOG(ERR, NTCONNECT,
	       "poll() returned 0x%x. Invalidating the connection\n",
	       pfd.revents);
	return STATUS_CONNECTION_INVALID;
}

static int read_all(int clfd, uint8_t *data, size_t length)
{
	size_t recv_len = 0;
	size_t left = length;
	size_t pos = 0;

	while (left > 0) {
		int ret = read_data(clfd, left, &data[pos], &recv_len, -1);

		if (ret == STATUS_OK) {
			pos += recv_len;
			left -= recv_len;
		} else {
			if (ret == STATUS_CONNECTION_CLOSED || ret == STATUS_TIMEOUT) {
				/* Silently return status */
				return ret;
			}
			if (ret != STATUS_TRYAGAIN) {
				NT_LOG(ERR, NTCONNECT,
				       "Failed getting packet. Error code: 0x%X\n",
				       ret);
				return ret;
			}
		}
		/* Try again */
	}
	return STATUS_OK;
}

static int write_all(int fd, const uint8_t *data, size_t size)
{
	size_t len = 0;

	while (len < size) {
		ssize_t res = write(fd, (const void *)&data[len], size - len);

		if (res < 0) {
			NT_LOG(ERR, NTCONNECT, "write to socket failed!");
			return STATUS_INTERNAL_ERROR;
		}
		len += res;
	}
	return 0;
}

static int read_request(int clfd, char **rdata)
{
	uint8_t *data = malloc(MESSAGE_BUFFER * sizeof(uint8_t));

	if (!data) {
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return STATUS_INTERNAL_ERROR;
	}

	size_t recv_len = 0;
	int ret = read_data(clfd, MESSAGE_BUFFER, data, &recv_len, -1);

	if (ret) {
		free(data);
		return ret;
	}

	struct ntconn_header_s hdr;

	memcpy(&hdr, data, NTCMOD_HDR_LEN);
	size_t length = (hdr.len + hdr.blob_len) * sizeof(uint8_t);

	if (length > MESSAGE_BUFFER) {
		uint8_t *new_data = realloc(data, length);

		if (!new_data) {
			NT_LOG(ERR, NTCONNECT, "memory reallocation failed");
			free(data);
			return STATUS_INTERNAL_ERROR;
		}
		data = new_data;
		ret = read_all(clfd, &data[recv_len], length - recv_len);
		if (ret) {
			free(data);
			return ret;
		}
	}

	*rdata = (char *)data;
	return STATUS_OK;
}

static ntconn_mod_t *ntconnect_interpret_request(int clfd,
		struct ntconn_header_s *hdr,
		char **get_req _unused,
		char **module_cmd, int *status)
{
	char pci_id[32];
	char module[64];
	ntconn_mod_t *result_ntcmod = NULL;
	char *request = NULL;

	int ret = read_request(clfd, &request);
	*status = ret;
	*get_req = request;

	if (ret == STATUS_OK && request) {
		*hdr = *(struct ntconn_header_s *)request;

		if (!hdr) {
			NT_LOG(ERR, NTCONNECT, "hdr returned NULL\n");
			*status = STATUS_INTERNAL_ERROR;
			return NULL;
		}

		switch (hdr->tag) {
		case NTCONN_TAG_REQUEST: {
			unsigned long idx = NTCMOD_HDR_LEN;
			char *saveptr;
			char *req = &request[idx];

			uint32_t domain = 0xffffffff;
			uint8_t bus = 0xff;
			uint8_t devid = 0xff;
			uint8_t function = 0xff;

			char *tok = strtok_r(req, ";", &saveptr);

			idx += strlen(tok) + 1;
			if (!tok)
				goto err_out;
			rte_strscpy(pci_id, tok, 31);

			tok = strtok_r(NULL, ";", &saveptr);
			idx += strlen(tok) + 1;
			if (!tok)
				goto err_out;
			rte_strscpy(module, tok, 63);

			tok = strtok_r(NULL, "", &saveptr);
			hdr->len -= idx;
			if (tok)
				*module_cmd = &request[idx];

			tok = strtok_r(pci_id, ":.", &saveptr);
			if (!tok)
				goto err_out;
			domain = (uint32_t)strtol(tok, NULL, 16);
			tok = strtok_r(NULL, ":.", &saveptr);
			if (!tok)
				goto err_out;
			bus = (uint8_t)strtol(tok, NULL, 16);

			tok = strtok_r(NULL, ":.", &saveptr);
			if (!tok)
				goto err_out;
			devid = (uint8_t)strtol(tok, NULL, 16);
			tok = strtok_r(NULL, "", &saveptr);
			if (!tok)
				goto err_out;
			function = (uint8_t)strtol(tok, NULL, 16);

			/* Search for module registered as <pci_id:module> */
			ntconn_mod_t *ntcmod = ntcmod_base;

			while (ntcmod) {
				if (domain == ntcmod->addr.domain &&
						bus == ntcmod->addr.bus &&
						devid == ntcmod->addr.devid &&
						function == ntcmod->addr.function &&
						strcmp(ntcmod->op->module, module) == 0) {
					result_ntcmod = ntcmod;
					break;
				}
				ntcmod = ntcmod->next;
			}
		}
		break;

		default:
			break;
		}
	}

err_out:

	return result_ntcmod;
}

static int send_reply(int clfd, uint16_t reply_tag, const void *data,
		      uint32_t size)
{
	struct ntconn_header_s hdr;

	hdr.tag = reply_tag;
	hdr.len = NTCMOD_HDR_LEN + size;
	hdr.blob_len = 0;
	uint8_t *message = malloc(hdr.len * sizeof(uint8_t));

	if (!message) {
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return STATUS_INTERNAL_ERROR;
	}
	memcpy(message, (void *)&hdr, NTCMOD_HDR_LEN);
	memcpy(&message[NTCMOD_HDR_LEN], data, size);
	int res = write_all(clfd, message, hdr.len);

	free(message);
	if (res)
		return res;

	return 0;
}

static int send_reply_free_data(int clfd, ntconn_mod_t *cmod,
				uint16_t reply_tag, void *data, uint32_t size)
{
	int res = send_reply(clfd, reply_tag, data, size);

	if (size) {
		pthread_mutex_lock(&cmod->mutex);
		cmod->op->free_data(cmod->hdl, data);
		pthread_mutex_unlock(&cmod->mutex);
	}

	return res;
}

static int ntconnect_send_error(int clfd, enum ntconn_err_e err_code)
{
	char err_buf[MAX_ERR_MESSAGE_LENGTH];
	const ntconn_err_t *ntcerr = get_ntconn_error(err_code);

	sprintf(err_buf, "----connect:%s", ntcerr->err_text);
	unsigned int len = strlen(err_buf);
	*(uint32_t *)err_buf = (uint32_t)ntcerr->err_code;

	return send_reply(clfd, NTCONN_TAG_ERROR, err_buf, len);
}

static void *ntconnect_worker(void *arg)
{
	int status;
	int clfd = (int)(uint64_t)arg;
	char *module_cmd = NULL;
	char *request = NULL;
	struct ntconn_header_s hdr;

	do {
		ntconn_mod_t *cmod = ntconnect_interpret_request(clfd, &hdr,
								 &request,
								 &module_cmd,
								 &status);

		if (cmod && module_cmd && status == 0) {
			int len;
			char *data;

			/*
			 * Handle general module commands
			 */
			if (strcmp(module_cmd, "version") == 0) {
				uint64_t version =
					((uint64_t)cmod->op->version_major
					 << 32) +
					(cmod->op->version_minor);

				if (send_reply(clfd, NTCONN_TAG_REPLY,
						(void *)&version,
						sizeof(uint64_t)))
					break;

			} else {
				/*
				 * Call module for execution of command
				 */
				data = NULL;
				pthread_mutex_lock(&cmod->mutex);
				int repl = cmod->op->request(cmod->hdl, clfd,
							     &hdr, module_cmd,
							     &data, &len);
				pthread_mutex_unlock(&cmod->mutex);

				if (repl == REQUEST_OK && len >= 0) {
					if (send_reply_free_data(clfd, cmod,
								 NTCONN_TAG_REPLY,
								 (void *)data,
								 (uint32_t)len))
						break;

				} else if (repl == REQUEST_ERR && len >= 0) {
					if (send_reply_free_data(clfd, cmod,
								 NTCONN_TAG_ERROR,
								 (void *)data,
								 (uint32_t)len))
						break;
				} else {
					NT_LOG(ERR, NTCONNECT,
					       "Invalid result from module request function: module %s, result %i\n",
					       cmod->op->module, repl);
					if (ntconnect_send_error(clfd,
						NTCONN_ERR_CODE_INTERNAL_REPLY_ERROR))
						break;
				}
			}

		} else if (status == STATUS_TIMEOUT) {
			/* Other end is dead */
			NT_LOG(WRN, NTCONNECT,
			       "Client must be dead - timeout\n");
			break;
		} else if (status == STATUS_CONNECTION_CLOSED) {
			break; /* silently break out */
		}
		/* Error - send error back */
		if (ntconnect_send_error(clfd, NTCONN_ERR_CODE_INVALID_REQUEST))
			break;
		if (request)
			free(request);
	} while (1); /* while still connected */

	close(clfd);

	/* call module cleanup callback function for client_id */
	ntconn_mod_t *ntcmod = ntcmod_base;

	while (ntcmod) {
		if (ntcmod->op->client_cleanup) {
			pthread_mutex_lock(&ntcmod->mutex);
			ntcmod->op->client_cleanup(ntcmod->hdl, clfd);
			pthread_mutex_unlock(&ntcmod->mutex);
		}

		ntcmod = ntcmod->next;
	}
	pthread_exit(NULL);
	return NULL;
}

static void *ntconnect_server(void *arg)
{
	struct ntconn_server_s *ntcserv = (struct ntconn_server_s *)arg;

	ntcserv->running = 1;

#ifdef DEBUG
	NT_LOG(DBG, NTCONNECT, "Running NT Connection Server fd %i\n",
	       ntcserv->serv_fd);
#endif

	if (listen(ntcserv->serv_fd, 5) < 0) {
		NT_LOG(ERR, NTCONNECT,
		       "Server failed on listen(), stopping thread. err: %s\n",
		       strerror(errno));
		pthread_exit(NULL);
		return NULL;
	}

	while (ntcserv->running) {
		int clfd = accept(ntcserv->serv_fd, NULL, NULL);

		if (clfd < 0) {
			NT_LOG(ERR, NTCONNECT,
			       "ERROR from accept(), stopping thread. err: %s\n",
			       strerror(errno));
			break;
		}
		pthread_create(&ctid, NULL, ntconnect_worker,
			       (void *)(uint64_t)clfd);
		pthread_setaffinity_np(ctid, sizeof(cpu_set_t),
				       &ntcserv->cpuset);
		/* Detach immediately. We will never join this thread */
		pthread_detach(ctid);
	}

	pthread_exit(NULL);
	return NULL;
}

int ntconnect_init(const char *sockname, cpu_set_t cpuset)
{
	if (ntcmod_base) {
		/* Make sure the socket directory exists */
		char *sockname_copy = strdup(sockname);
		char *sockname_dir = dirname(sockname_copy);

		if (mkdir(sockname_dir, 0755) < 0 && errno != EEXIST) {
			NT_LOG(ERR, NTCONNECT,
			       "Can't create socket directory: %s",
			       sockname_dir);
			free(sockname_copy);
			return -1;
		}
		free(sockname_copy);

		/* Add server to module list - cannot work without */
		ntconn_server_register(&ntconn_serv);

		/* Start named socket server */
		struct sockaddr_un addr;

		unix_build_address(sockname, &addr);

		ntconn_serv.serv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		ntconn_serv.cpuset = cpuset;
		if (ntconn_serv.serv_fd == -1)
			return -1;

		/* Make sure the node in filesystem is deleted otherwise bind will fail */
		unlink(sockname);

		if (bind(ntconn_serv.serv_fd, (struct sockaddr *)&addr,
				sizeof(struct sockaddr_un)) == -1) {
			close(ntconn_serv.serv_fd);
			return -1;
		}

		/* Run ntconnect service */
		pthread_create(&tid, NULL, ntconnect_server, &ntconn_serv);
		pthread_setaffinity_np(tid, sizeof(cpu_set_t),
				       &ntconn_serv.cpuset);
	}

	return 0;
}
