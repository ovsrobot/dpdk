/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#include "idpf_osdep.h"

int idpf_compl_event_init(struct completion *completion)
{
	int poll_fd;

	poll_fd = epoll_create(1);
	if (poll_fd < 0) {
		perror("epoll create failed\n");
		return EPERM;
	}
	completion->poll_fd = poll_fd;

	return 0;
}

int idpf_compl_event_reinit(struct completion *completion)
{
	struct epoll_event event;
	int fd, ret;

	fd = eventfd(0,0);
	if (fd < 0) {
		perror("Eventfd open failed\n");
		return EPERM;
	}
	completion->event_fd = fd;
	event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	event.data.fd = fd;
	ret = epoll_ctl(completion->poll_fd, EPOLL_CTL_ADD, fd, &event);
	if (ret < 0) {
		perror("Eventfd open failed\n");
		close(fd);
		return EPERM;
	}
	return 0;
}

int idpf_compl_event_sig(struct completion *completion, uint64_t status)
{
	int ret;

	ret = write(completion->event_fd, &status, sizeof(status));

	return (ret > 0 ? 0 : 1);
}

int idpf_compl_event_wait(struct completion *completion, int timeout)
{
	struct epoll_event event = { 0 };
	uint64_t status;
	int ret;

	ret = epoll_wait(completion->poll_fd, &event, 1, timeout);
	if (ret > 0) {
		printf("Command Completed successfully\n");
		ret = read(completion->event_fd, &status, sizeof(status));
	}
	close(completion->event_fd);

	return (ret > 0 ? 0 : 1);
}

void idpf_compl_event_deinit(struct completion *completion)
{
	close(completion->poll_fd);
}
