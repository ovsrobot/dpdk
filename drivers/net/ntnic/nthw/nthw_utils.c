/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>	/* isprint */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* inet_addr */
#include <string.h>	/* memset */

#include "nthw_utils.h"
#include "nthw_helper.h"

int socket_loopback_setup(uint16_t port)
{
	int res = 0;
	struct sockaddr_in serv_addr;
	int sockfd;
	int sockval;

	/* socket create and verification */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
		NT_LOG(ERR, NTHW, "socket creation failed...\n");
		res = -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &sockval, sizeof(sockval));

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serv_addr.sin_port = htons(port);

	if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) != 0) {
		NT_LOG(ERR, NTHW, "socket bind failed...\n");
		res = -1;
	}

	/* Now server is ready to listen and verification */
	if ((listen(sockfd, 5)) != 0) {
		NT_LOG(ERR, NTHW, "Listen failed...\n");
		res = -1;
	}

	return res == 0 ? sockfd : res;
}
