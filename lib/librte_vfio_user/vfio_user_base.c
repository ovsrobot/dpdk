/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

#include "vfio_user_base.h"

int vfio_user_log_level;

const char *vfio_user_msg_str[VFIO_USER_MAX] = {
	[VFIO_USER_NONE] = "VFIO_USER_NONE",
	[VFIO_USER_VERSION] = "VFIO_USER_VERSION",
};

void
vfio_user_close_msg_fds(struct vfio_user_msg *msg)
{
	int i;

	for (i = 0; i < msg->fd_num; i++)
		close(msg->fds[i]);
}

int
vfio_user_check_msg_fdnum(struct vfio_user_msg *msg, int expected_fds)
{
	if (msg->fd_num == expected_fds)
		return 0;

	VFIO_USER_LOG(ERR, "Expect %d FDs for request %s, received %d\n",
		expected_fds, vfio_user_msg_str[msg->cmd], msg->fd_num);

	vfio_user_close_msg_fds(msg);

	return -1;
}

static int
vfio_user_recv_fd_msg(int sockfd, char *buf, int buflen, int *fds,
	int max_fds, int *fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	char control[CMSG_SPACE(max_fds * sizeof(int))];
	struct cmsghdr *cmsg;
	int fd_sz, got_fds = 0;
	int ret, i;

	*fd_num = 0;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len  = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = control;
	msgh.msg_controllen = sizeof(control);

	ret = recvmsg(sockfd, &msgh, 0);
	if (ret <= 0) {
		if (ret)
			VFIO_USER_LOG(DEBUG, "recvmsg failed\n");
		return ret;
	}

	if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		VFIO_USER_LOG(ERR, "Message is truncated\n");
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
		cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if ((cmsg->cmsg_level == SOL_SOCKET) &&
			(cmsg->cmsg_type == SCM_RIGHTS)) {
			fd_sz = cmsg->cmsg_len - CMSG_LEN(0);
			got_fds = fd_sz / sizeof(int);
			if (got_fds >= max_fds) {
				/* Invalid message, close fds */
				int *close_fd = (int *)CMSG_DATA(cmsg);
				for (i = 0; i < got_fds; i++) {
					close_fd += i;
					close(*close_fd);
				}
				VFIO_USER_LOG(ERR, "fd num exceeds max "
					"in vfio-user msg\n");
				return -1;
			}
			*fd_num = got_fds;
			memcpy(fds, CMSG_DATA(cmsg), got_fds * sizeof(int));
			break;
		}
	}

	/* Make unused file descriptors invalid */
	while (got_fds < max_fds)
		fds[got_fds++] = -1;

	return ret;
}

int
vfio_user_recv_msg(int sockfd, struct vfio_user_msg *msg)
{
	int ret;

	ret = vfio_user_recv_fd_msg(sockfd, (char *)msg, VFIO_USER_MSG_HDR_SIZE,
		msg->fds, VFIO_USER_MAX_FD, &msg->fd_num);
	if (ret <= 0) {
		return ret;
	} else if (ret != VFIO_USER_MSG_HDR_SIZE) {
		VFIO_USER_LOG(ERR, "Read unexpected header size\n");
		ret = -1;
		goto err;
	}

	if (msg->size > VFIO_USER_MSG_HDR_SIZE) {
		if (msg->size > (sizeof(msg->payload) +
			VFIO_USER_MSG_HDR_SIZE)) {
			VFIO_USER_LOG(ERR, "Read invalid msg size: %d\n",
				msg->size);
			ret = -1;
			goto err;
		}

		ret = read(sockfd, &msg->payload,
			msg->size - VFIO_USER_MSG_HDR_SIZE);
		if (ret <= 0)
			goto err;
		if (ret != (int)(msg->size - VFIO_USER_MSG_HDR_SIZE)) {
			VFIO_USER_LOG(ERR, "Read payload failed\n");
			ret = -1;
			goto err;
		}
	}

	return ret;
err:
	vfio_user_close_msg_fds(msg);
	return ret;
}

static int
vfio_user_send_fd_msg(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{

	struct iovec iov;
	struct msghdr msgh;
	size_t fdsize = fd_num * sizeof(int);
	char control[CMSG_SPACE(fdsize)];
	struct cmsghdr *cmsg;
	int ret;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	if (fds && fd_num > 0) {
		msgh.msg_control = control;
		msgh.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_len = CMSG_LEN(fdsize);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, fdsize);
	} else {
		msgh.msg_control = NULL;
		msgh.msg_controllen = 0;
	}

	do {
		ret = sendmsg(sockfd, &msgh, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		VFIO_USER_LOG(ERR, "sendmsg error\n");
		return ret;
	}

	return ret;
}

int
vfio_user_send_msg(int sockfd, struct vfio_user_msg *msg)
{
	if (!msg)
		return 0;

	return vfio_user_send_fd_msg(sockfd, (char *)msg,
		msg->size, msg->fds, msg->fd_num);
}

int
vfio_user_reply_msg(int sockfd, struct vfio_user_msg *msg)
{
	if (!msg)
		return 0;

	msg->flags |= VFIO_USER_NEED_NO_RP;
	msg->flags |= VFIO_USER_TYPE_REPLY;

	return vfio_user_send_msg(sockfd, msg);
}

RTE_LOG_REGISTER(vfio_user_log_level, lib.vfio, INFO);
