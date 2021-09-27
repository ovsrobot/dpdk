/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 6WIND S.A.
 * Copyright 2015 Mellanox Technologies, Ltd
 */

#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <net/if_media.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdalign.h>
#include <sys/un.h>
#include <time.h>

#include <ethdev_driver.h>
#include <rte_bus_pci.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_rwlock.h>
#include <rte_cycles.h>

#include <mlx5_glue.h>
#include <mlx5_devx_cmds.h>
#include <mlx5_common.h>
#include <mlx5_malloc.h>

#include "mlx5.h"
#include "mlx5_rxtx.h"
#include "mlx5_utils.h"

static unsigned int xstats_n;

/**
 * Get interface name from private structure.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] ifname
 *   Interface name output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_ifname(const struct rte_eth_dev *dev, char (*ifname)[MLX5_NAMESIZE])
{
	struct mlx5_priv *priv = dev->data->dev_private;

	MLX5_ASSERT(priv);
	MLX5_ASSERT(priv->sh);
	return mlx5_get_ifname_sysfs(priv->sh->ibdev_path, *ifname);
}

/**
 * Perform ifreq ioctl() on associated netdev ifname.
 *
 * @param[in] ifname
 *   Pointer to netdev name.
 * @param req
 *   Request number to pass to ioctl().
 * @param[out] ifr
 *   Interface request structure output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_ifreq_by_ifname(const char *ifname, int req, struct ifreq *ifr)
{
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	int ret = 0;

	if (sock == -1) {
		rte_errno = errno;
		return -rte_errno;
	}
	rte_strscpy(ifr->ifr_name, ifname, sizeof(ifr->ifr_name));
	ret = ioctl(sock, req, ifr);
	if (ret == -1) {
		rte_errno = errno;
		goto error;
	}
	close(sock);
	return 0;
error:
	close(sock);
	return -rte_errno;
}

/**
 * Perform ifreq ioctl() on associated Ethernet device.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param req
 *   Request number to pass to ioctl().
 * @param[out] ifr
 *   Interface request structure output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_ifreq(const struct rte_eth_dev *dev, int req, struct ifreq *ifr)
{
	char ifname[sizeof(ifr->ifr_name)];
	int ret;

	ret = mlx5_get_ifname(dev, &ifname);
	if (ret)
		return -rte_errno;
	return mlx5_ifreq_by_ifname(ifname, req, ifr);
}

/**
 * Get device MTU.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[out] mtu
 *   MTU value output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_mtu(struct rte_eth_dev *dev, uint16_t *mtu)
{
	struct ifreq request;
	int ret = mlx5_ifreq(dev, SIOCGIFMTU, &request);

	if (ret)
		return ret;
	*mtu = request.ifr_mtu;
	return 0;
}

/**
 * Set device MTU.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param mtu
 *   MTU value to set.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct ifreq request = { .ifr_mtu = mtu, };

	return mlx5_ifreq(dev, SIOCSIFMTU, &request);
}

/**
 * Set device flags.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param keep
 *   Bitmask for flags that must remain untouched.
 * @param flags
 *   Bitmask for flags to modify.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_set_flags(struct rte_eth_dev *dev, unsigned int keep, unsigned int flags)
{
	struct ifreq request;
	int ret = mlx5_ifreq(dev, SIOCGIFFLAGS, &request);

	if (ret)
		return ret;
	request.ifr_flags &= keep;
	request.ifr_flags |= flags & ~keep;
	return mlx5_ifreq(dev, SIOCSIFFLAGS, &request);
}

/**
 * Get device current raw clock counter
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] time
 *   Current raw clock counter of the device.
 *
 * @return
 *   0 if the clock has correctly been read
 *   The value of errno in case of error
 */
int
mlx5_read_clock(struct rte_eth_dev *dev, uint64_t *clock)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct ibv_context *ctx = priv->sh->ctx;
	struct ibv_values_ex values;
	int err = 0;

	values.comp_mask = IBV_VALUES_MASK_RAW_CLOCK;
	err = mlx5_glue->query_rt_values_ex(ctx, &values);
	if (err != 0) {
		DRV_LOG(WARNING, "Could not query the clock !");
		return err;
	}
	*clock = values.raw_clock.tv_nsec;
	return 0;
}

static const struct ifmedia_baudrate ifmedia_baudrate_desc[] =
	IFM_BAUDRATE_DESCRIPTIONS;

static uint64_t
mlx5_ifmedia_baudrate(int mword)
{
	int i;

	for (i = 0; ifmedia_baudrate_desc[i].ifmb_word != 0; i++) {
		if (IFM_TYPE_MATCH(mword, ifmedia_baudrate_desc[i].ifmb_word))
			return (ifmedia_baudrate_desc[i].ifmb_baudrate);
	}

	return (0);
}

static int
mlx5_link_update_bsd(struct rte_eth_dev *dev,
		     struct rte_eth_link *link)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_eth_link dev_link;
	int link_speed = 0, sock;
	struct ifmediareq ifmr;
	char ifname[IF_NAMESIZE];
	int *media_list;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		DRV_LOG(ERR,
			"port %u CANT OPEN SOCKET FOR MEDIA REQUEST on FREEBSD: %s",
			dev->data->port_id, strerror(rte_errno));
		return sock;
	}

	mlx5_get_ifname(dev, &ifname);
	memset(&ifmr, 0, sizeof(struct ifmediareq));
	strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	if (ioctl(sock, SIOCGIFXMEDIA, (caddr_t)&ifmr) < 0) {
		DRV_LOG(ERR,
			"ioctl(SIOCGIFMEDIA) on %s: %s",
			ifname, strerror(errno));
		close(sock);
		return errno;
	}

	media_list = (int *)malloc(ifmr.ifm_count * sizeof(int));
	ifmr.ifm_ulist = media_list;

	if (ioctl(sock, SIOCGIFXMEDIA, (caddr_t)&ifmr) < 0) {
		DRV_LOG(ERR,
			"ioctl(SIOCGIFMEDIA) on %s: %s",
			ifname, strerror(errno));
		close(sock);
		return errno;
	}

	if (ifmr.ifm_status == (IFM_AVALID | IFM_ACTIVE))
		dev_link.link_status = ETH_LINK_UP;
	else
		dev_link.link_status = ETH_LINK_DOWN;

	link_speed = ifmr.ifm_status & IFM_AVALID ?
			mlx5_ifmedia_baudrate(ifmr.ifm_active) / (1000 * 1000) : 0;

	if (link_speed == 0)
		dev_link.link_speed = ETH_SPEED_NUM_NONE;
	else
		dev_link.link_speed = link_speed;

	priv->link_speed_capa = 0;
	/* Add support for duplex types */
	dev_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	/* FreeBSD automatically negotiates speed,
	 * so it is displayed in its capabilities.
	 */
	priv->link_speed_capa |= ETH_LINK_SPEED_AUTONEG;

	for (int i = 1; i < ifmr.ifm_count; i += 2) {
		switch (mlx5_ifmedia_baudrate(media_list[i]) / (1000 * 1000)) {
		case 100000:
			priv->link_speed_capa |= ETH_LINK_SPEED_100G;
			break;
		case 56000:
			priv->link_speed_capa |= ETH_LINK_SPEED_56G;
			break;
		case 50000:
			priv->link_speed_capa |= ETH_LINK_SPEED_50G;
			break;
		case 40000:
			priv->link_speed_capa |= ETH_LINK_SPEED_40G;
			break;
		case 25000:
			priv->link_speed_capa |= ETH_LINK_SPEED_25G;
			break;
		case 10000:
			priv->link_speed_capa |= ETH_LINK_SPEED_10G;
			break;
		case 2500:
			priv->link_speed_capa |= ETH_LINK_SPEED_2_5G;
			break;
		case 1000:
			priv->link_speed_capa |= ETH_LINK_SPEED_1G;
			break;
		case 100:
			priv->link_speed_capa |= (dev_link.link_duplex ==
						ETH_LINK_FULL_DUPLEX) ?
						ETH_LINK_SPEED_100M :
						ETH_LINK_SPEED_100M_HD;
			break;
		case 10:
			priv->link_speed_capa |= (dev_link.link_duplex ==
						ETH_LINK_FULL_DUPLEX) ?
						ETH_LINK_SPEED_10M :
						ETH_LINK_SPEED_10M_HD;
			break;
		case 0:
		default:
			break;
		}
	}
	dev_link.link_autoneg = !(dev->data->dev_conf.link_speeds &
				ETH_LINK_SPEED_FIXED);
	free(media_list);
	*link = dev_link;
	close(sock);
	return 0;
}

/**
 * DPDK callback to retrieve physical link information.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param wait_to_complete
 *   Wait for request completion.
 *
 * @return
 *   0 if link status was not updated, positive if it was, a negative errno
 *   value otherwise and rte_errno is set.
 */
int
mlx5_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	int ret;
	struct rte_eth_link dev_link;
	time_t start_time = time(NULL);
	int retry = MLX5_GET_LINK_STATUS_RETRY_COUNT;

	do {
		ret = mlx5_link_update_bsd(dev, &dev_link);
		if (ret == 0)
			break;
		/* Handle wait to complete situation. */
		if ((wait_to_complete || retry) && ret == -EAGAIN) {
			if (abs((int)difftime(time(NULL), start_time)) <
			    MLX5_LINK_STATUS_TIMEOUT) {
				usleep(0);
				continue;
			} else {
				rte_errno = EBUSY;
				return -rte_errno;
			}
		} else if (ret < 0) {
			return ret;
		}
	} while (wait_to_complete || retry-- > 0);
	ret = !!memcmp(&dev->data->dev_link, &dev_link,
		       sizeof(struct rte_eth_link));
	dev->data->dev_link = dev_link;
	return ret;
}

/**
 * DPDK callback to get flow control status.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] fc_conf
 *   Flow control output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_get_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	RTE_SET_USED(fc_conf);
	DRV_LOG(WARNING,
		"port %u can not get flow control status. Operation not supported in FreeBSD",
		dev->data->port_id);

	return -EOPNOTSUPP;
}

/**
 * DPDK callback to modify flow control parameters.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[in] fc_conf
 *   Flow control parameters.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_dev_set_flow_ctrl(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	RTE_SET_USED(fc_conf);
	DRV_LOG(WARNING,
		"port %u can not modify flow control. Operation not supported in FreeBSD",
		dev->data->port_id);

	return -EOPNOTSUPP;
}

/**
 * Handle asynchronous removal event for entire multiport device.
 *
 * @param sh
 *   Infiniband device shared context.
 */
static void
mlx5_dev_interrupt_device_fatal(struct mlx5_dev_ctx_shared *sh)
{
	uint32_t i;

	for (i = 0; i < sh->max_port; ++i) {
		struct rte_eth_dev *dev;

		if (sh->port[i].ih_port_id >= RTE_MAX_ETHPORTS) {
			/*
			 * Or not existing port either no
			 * handler installed for this port.
			 */
			continue;
		}
		dev = &rte_eth_devices[sh->port[i].ih_port_id];
		MLX5_ASSERT(dev);
		if (dev->data->dev_conf.intr_conf.rmv)
			rte_eth_dev_callback_process
				(dev, RTE_ETH_EVENT_INTR_RMV, NULL);
	}
}

/**
 * Handle shared asynchronous events the NIC (removal event
 * and link status change). Supports multiport IB device.
 *
 * @param cb_arg
 *   Callback argument.
 */
void
mlx5_dev_interrupt_handler(void *cb_arg)
{
	struct mlx5_dev_ctx_shared *sh = cb_arg;
	struct ibv_async_event event;

	/* Read all message from the IB device and acknowledge them. */
	for (;;) {
		struct rte_eth_dev *dev;
		uint32_t tmp;

		if (mlx5_glue->get_async_event(sh->ctx, &event))
			break;
		/* Retrieve and check IB port index. */
		tmp = (uint32_t)event.element.port_num;
		if (!tmp && event.event_type == IBV_EVENT_DEVICE_FATAL) {
			/*
			 * The DEVICE_FATAL event is called once for
			 * entire device without port specifying.
			 * We should notify all existing ports.
			 */
			mlx5_glue->ack_async_event(&event);
			mlx5_dev_interrupt_device_fatal(sh);
			continue;
		}
		MLX5_ASSERT(tmp && (tmp <= sh->max_port));
		if (!tmp) {
			/* Unsupported device level event. */
			mlx5_glue->ack_async_event(&event);
			DRV_LOG(DEBUG,
				"unsupported common event (type %d)",
				event.event_type);
			continue;
		}
		if (tmp > sh->max_port) {
			/* Invalid IB port index. */
			mlx5_glue->ack_async_event(&event);
			DRV_LOG(DEBUG,
				"cannot handle an event (type %d)"
				"due to invalid IB port index (%u)",
				event.event_type, tmp);
			continue;
		}
		if (sh->port[tmp - 1].ih_port_id >= RTE_MAX_ETHPORTS) {
			/* No handler installed. */
			mlx5_glue->ack_async_event(&event);
			DRV_LOG(DEBUG,
				"cannot handle an event (type %d)"
				"due to no handler installed for port %u",
				event.event_type, tmp);
			continue;
		}
		/* Retrieve ethernet device descriptor. */
		tmp = sh->port[tmp - 1].ih_port_id;
		dev = &rte_eth_devices[tmp];
		MLX5_ASSERT(dev);
		if ((event.event_type == IBV_EVENT_PORT_ACTIVE ||
		     event.event_type == IBV_EVENT_PORT_ERR) &&
			dev->data->dev_conf.intr_conf.lsc) {
			mlx5_glue->ack_async_event(&event);
			if (mlx5_link_update(dev, 0) == -EAGAIN) {
				usleep(0);
				continue;
			}
			rte_eth_dev_callback_process
				(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
			continue;
		}
		DRV_LOG(DEBUG,
			"port %u cannot handle an unknown event (type %d)",
			dev->data->port_id, event.event_type);
		mlx5_glue->ack_async_event(&event);
	}
}

/*
 * Unregister callback handler safely. The handler may be active
 * while we are trying to unregister it, in this case code -EAGAIN
 * is returned by rte_intr_callback_unregister(). This routine checks
 * the return code and tries to unregister handler again.
 *
 * @param handle
 *   interrupt handle
 * @param cb_fn
 *   pointer to callback routine
 * @cb_arg
 *   opaque callback parameter
 */
void
mlx5_intr_callback_unregister(const struct rte_intr_handle *handle,
			      rte_intr_callback_fn cb_fn, void *cb_arg)
{
	/*
	 * Try to reduce timeout management overhead by not calling
	 * the timer related routines on the first iteration. If the
	 * unregistering succeeds on first call there will be no
	 * timer calls at all.
	 */
	uint64_t twait = 0;
	uint64_t start = 0;

	do {
		int ret;

		ret = rte_intr_callback_unregister(handle, cb_fn, cb_arg);
		if (ret >= 0)
			return;
		if (ret != -EAGAIN) {
			DRV_LOG(INFO, "failed to unregister interrupt"
				      " handler (error: %d)", ret);
			MLX5_ASSERT(false);
			return;
		}
		if (twait) {
			struct timespec onems;

			/* Wait one millisecond and try again. */
			onems.tv_sec = 0;
			onems.tv_nsec = NS_PER_S / MS_PER_S;
			nanosleep(&onems, 0);
			/* Check whether one second elapsed. */
			if ((rte_get_timer_cycles() - start) <= twait)
				continue;
		} else {
			/*
			 * We get the amount of timer ticks for one second.
			 * If this amount elapsed it means we spent one
			 * second in waiting. This branch is executed once
			 * on first iteration.
			 */
			twait = rte_get_timer_hz();
			MLX5_ASSERT(twait);
		}
		/*
		 * Timeout elapsed, show message (once a second) and retry.
		 * We have no other acceptable option here, if we ignore
		 * the unregistering return code the handler will not
		 * be unregistered, fd will be closed and we may get the
		 * crush. Hanging and messaging in the loop seems not to be
		 * the worst choice.
		 */
		DRV_LOG(INFO, "Retrying to unregister interrupt handler");
		start = rte_get_timer_cycles();
	} while (true);
}

/**
 * Handle DEVX interrupts from the NIC.
 * This function is probably called from the DPDK host thread.
 *
 * @param cb_arg
 *   Callback argument.
 */
void
mlx5_dev_interrupt_handler_devx(void *cb_arg)
{
#ifndef HAVE_IBV_DEVX_ASYNC
	(void)cb_arg;
	return;
#else
	struct mlx5_dev_ctx_shared *sh = cb_arg;
	union {
		struct mlx5dv_devx_async_cmd_hdr cmd_resp;
		uint8_t buf[MLX5_ST_SZ_BYTES(query_flow_counter_out) +
			    MLX5_ST_SZ_BYTES(traffic_counter) +
			    sizeof(struct mlx5dv_devx_async_cmd_hdr)];
	} out;
	uint8_t *buf = out.buf + sizeof(out.cmd_resp);

	while (!mlx5_glue->devx_get_async_cmd_comp(sh->devx_comp,
						   &out.cmd_resp,
						   sizeof(out.buf)))
		mlx5_flow_async_pool_query_handle
			(sh, (uint64_t)out.cmd_resp.wr_id,
			 mlx5_devx_get_out_command_status(buf));
#endif /* HAVE_IBV_DEVX_ASYNC */
}

/**
 * DPDK callback to bring the link DOWN.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_link_down(struct rte_eth_dev *dev)
{
	return mlx5_set_flags(dev, ~IFF_UP, ~IFF_UP);
}

/**
 * DPDK callback to bring the link UP.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_set_link_up(struct rte_eth_dev *dev)
{
	return mlx5_set_flags(dev, ~IFF_UP, IFF_UP);
}

/**
 * Check if mlx5 device was removed.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   1 when device is removed, otherwise 0.
 */
int
mlx5_is_removed(struct rte_eth_dev *dev)
{
	struct ibv_device_attr device_attr;
	struct mlx5_priv *priv = dev->data->dev_private;

	if (mlx5_glue->query_device(priv->sh->ctx, &device_attr) == EIO)
		return 1;
	return 0;
}

/**
 * Analyze gathered port parameters via sysfs to recognize master
 * and representor devices for E-Switch configuration.
 *
 * @param[in] device_dir
 *   flag of presence of "device" directory under port device key.
 * @param[inout] switch_info
 *   Port information, including port name as a number and port name
 *   type if recognized
 *
 * @return
 *   master and representor flags are set in switch_info according to
 *   recognized parameters (if any).
 */
static void
mlx5_sysfs_check_switch_info(bool device_dir,
			     struct mlx5_switch_info *switch_info)
{
	switch (switch_info->name_type) {
	case MLX5_PHYS_PORT_NAME_TYPE_UNKNOWN:
		/*
		 * Name is not recognized, assume the master,
		 * check the device directory presence.
		 */
		switch_info->master = device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_NOTSET:
		/*
		 * Name is not set, this assumes the legacy naming
		 * schema for master, just check if there is
		 * a device directory.
		 */
		switch_info->master = device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_UPLINK:
		/* New uplink naming schema recognized. */
		switch_info->master = 1;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_LEGACY:
		/* Legacy representors naming schema. */
		switch_info->representor = !device_dir;
		break;
	case MLX5_PHYS_PORT_NAME_TYPE_PFHPF:
		/* Fallthrough */
	case MLX5_PHYS_PORT_NAME_TYPE_PFVF:
		/* Fallthrough */
	case MLX5_PHYS_PORT_NAME_TYPE_PFSF:
		/* New representors naming schema. */
		switch_info->representor = 1;
		break;
	default:
		switch_info->master = device_dir;
		break;
	}
}

/**
 * Get switch information associated with network interface.
 *
 * @param ifindex
 *   Network interface index.
 * @param[out] info
 *   Switch information object, populated in case of success.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_sysfs_switch_info(unsigned int ifindex, struct mlx5_switch_info *info)
{
	char ifname[IF_NAMESIZE];
	char port_name[IF_NAMESIZE];
	FILE *file;
	struct mlx5_switch_info data = {
		.master = 0,
		.representor = 0,
		.name_type = MLX5_PHYS_PORT_NAME_TYPE_NOTSET,
		.port_name = 0,
		.switch_id = 0,
	};
	DIR *dir;
	bool port_switch_id_set = false;
	bool device_dir = false;
	char c;
	int ret;

	if (!if_indextoname(ifindex, ifname)) {
		rte_errno = errno;
		return -rte_errno;
	}

	MKSTR(phys_port_name, "/sys/class/net/%s/phys_port_name",
	      ifname);
	MKSTR(phys_switch_id, "/sys/class/net/%s/phys_switch_id",
	      ifname);
	MKSTR(pci_device, "/sys/class/net/%s/device",
	      ifname);

	file = fopen(phys_port_name, "rb");
	if (file != NULL) {
		ret = fscanf(file, "%" RTE_STR(IF_NAMESIZE) "s", port_name);
		fclose(file);
		if (ret == 1)
			mlx5_translate_port_name(port_name, &data);
	}
	file = fopen(phys_switch_id, "rb");
	if (file == NULL) {
		rte_errno = errno;
		return -rte_errno;
	}
	port_switch_id_set =
		fscanf(file, "%" SCNx64 "%c", &data.switch_id, &c) == 2 &&
		c == '\n';
	fclose(file);
	dir = opendir(pci_device);
	if (dir != NULL) {
		closedir(dir);
		device_dir = true;
	}
	if (port_switch_id_set) {
		/* We have some E-Switch configuration. */
		mlx5_sysfs_check_switch_info(device_dir, &data);
	}
	*info = data;
	MLX5_ASSERT(!(data.master && data.representor));
	if (data.master && data.representor) {
		DRV_LOG(ERR, "ifindex %u device is recognized as master"
			     " and as representor", ifindex);
		rte_errno = ENODEV;
		return -rte_errno;
	}
	return 0;
}

/**
 * Get bond information associated with network interface.
 *
 * @param pf_ifindex
 *   Network interface index of bond slave interface
 * @param[out] ifindex
 *   Pointer to bond ifindex.
 * @param[out] ifname
 *   Pointer to bond ifname.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_sysfs_bond_info(unsigned int pf_ifindex, unsigned int *ifindex,
		     char *ifname)
{
	char name[IF_NAMESIZE];
	FILE *file;
	unsigned int index;
	int ret;

	if (!if_indextoname(pf_ifindex, name) || !strlen(name)) {
		rte_errno = errno;
		return -rte_errno;
	}
	MKSTR(bond_if, "/sys/class/net/%s/master/ifindex", name);
	/* read bond ifindex */
	file = fopen(bond_if, "rb");
	if (file == NULL) {
		rte_errno = errno;
		return -rte_errno;
	}
	ret = fscanf(file, "%u", &index);
	fclose(file);
	if (ret <= 0) {
		rte_errno = errno;
		return -rte_errno;
	}
	if (ifindex)
		*ifindex = index;

	/* read bond device name from symbol link */
	if (ifname) {
		if (!if_indextoname(index, ifname)) {
			rte_errno = errno;
			return -rte_errno;
		}
	}
	return 0;
}

/**
 * DPDK callback to retrieve plug-in module EEPROM information (type and size).
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] modinfo
 *   Storage for plug-in module EEPROM information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_module_info(struct rte_eth_dev *dev,
		     struct rte_eth_dev_module_info *modinfo)
{
	struct ethtool_modinfo info = {
		.cmd = ETHTOOL_GMODULEINFO,
	};
	struct ifreq ifr = (struct ifreq) {
		.ifr_data = (void *)&info,
	};
	int ret = 0;

	if (!dev) {
		DRV_LOG(WARNING, "missing argument, cannot get module info");
		rte_errno = EINVAL;
		return -rte_errno;
	}
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret) {
		DRV_LOG(WARNING, "port %u ioctl(SIOCETHTOOL) failed: %s",
			dev->data->port_id, strerror(rte_errno));
		return ret;
	}
	modinfo->type = info.type;
	modinfo->eeprom_len = info.eeprom_len;
	return ret;
}

/**
 * DPDK callback to retrieve plug-in module EEPROM data.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param[out] info
 *   Storage for plug-in module EEPROM data.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int mlx5_get_module_eeprom(struct rte_eth_dev *dev,
			   struct rte_dev_eeprom_info *info)
{
	struct ethtool_eeprom *eeprom;
	struct ifreq ifr;
	int ret = 0;

	if (!dev) {
		DRV_LOG(WARNING, "missing argument, cannot get module eeprom");
		rte_errno = EINVAL;
		return -rte_errno;
	}
	eeprom = mlx5_malloc(MLX5_MEM_ZERO,
			     (sizeof(struct ethtool_eeprom) + info->length), 0,
			     SOCKET_ID_ANY);
	if (!eeprom) {
		DRV_LOG(WARNING, "port %u cannot allocate memory for "
			"eeprom data", dev->data->port_id);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	eeprom->cmd = ETHTOOL_GMODULEEEPROM;
	eeprom->offset = info->offset;
	eeprom->len = info->length;
	ifr = (struct ifreq) {
		.ifr_data = (void *)eeprom,
	};
	ret = mlx5_ifreq(dev, SIOCETHTOOL, &ifr);
	if (ret)
		DRV_LOG(WARNING, "port %u ioctl(SIOCETHTOOL) failed: %s",
			dev->data->port_id, strerror(rte_errno));
	else
		rte_memcpy(info->data, eeprom->data, info->length);
	mlx5_free(eeprom);
	return ret;
}

/**
 * Read device counters table.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[in] pf
 *   PF index in case of bonding device, -1 otherwise
 * @param[out] stats
 *   Counters table output buffer.
 */
static void
_mlx5_os_read_dev_counters(struct rte_eth_dev *dev, uint64_t *stats)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_xstats_ctrl *xstats_ctrl = &priv->xstats_ctrl;
	char stat_key[RTE_ETH_XSTATS_NAME_SIZE + 16];
	unsigned int i;
	size_t len = sizeof(uint64_t);
	uint64_t val;
	int ibvindex, ret;

	ibvindex = mlx5_get_ibvindex(priv->sh->ibdev_path);

	for (i = 0; i != xstats_ctrl->mlx5_stats_n; ++i) {
		snprintf(stat_key, sizeof(stat_key), "dev.mce.%d.%s",
			 ibvindex, xstats_ctrl->info[i].ctr_name);
		ret = sysctlbyname(stat_key, &val, &len, NULL, 0);
		if (ret == -1) {
			DRV_LOG(WARNING, "port %u failed to get statistics: %s",
				dev->data->port_id, strerror(errno));
			continue;
		}
		stats[i] += val;
	}
}

/**
 * Read device counters.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param[out] stats
 *   Counters table output buffer.
 *
 * @return
 *   0 on success and stats is filled, negative errno value otherwise and
 *   rte_errno is set.
 */
int
mlx5_os_read_dev_counters(struct rte_eth_dev *dev, uint64_t *stats)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_xstats_ctrl *xstats_ctrl = &priv->xstats_ctrl;
	int ret = 0, i;

	memset(stats, 0, sizeof(*stats) * xstats_ctrl->mlx5_stats_n);
	_mlx5_os_read_dev_counters(dev, stats);

	/* Read IB counters. */
	for (i = 0; i != xstats_ctrl->mlx5_stats_n; ++i) {
		if (!xstats_ctrl->info[i].dev)
			continue;
		ret = mlx5_os_read_dev_stat(priv, xstats_ctrl->info[i].ctr_name,
					    &stats[i]);
		/* return last xstats counter if fail to read. */
		if (ret != 0)
			xstats_ctrl->xstats[i] = stats[i];
		else
			stats[i] = xstats_ctrl->xstats[i];
	}
	return ret;
}

/**
 * Query the number of statistics.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Number of statistics on success.
 */
int
mlx5_os_get_stats_n(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return xstats_n;
}

static const struct mlx5_counter_ctrl mlx5_counters_init[] = {
	{
		.dpdk_name = "rx_port_unicast_bytes",
		.ctr_name = "vstats.rx_unicast_bytes",
	},
	{
		.dpdk_name = "rx_port_multicast_bytes",
		.ctr_name = "vstats.rx_multicast_bytes",
	},
	{
		.dpdk_name = "rx_port_broadcast_bytes",
		.ctr_name = "vstats.rx_broadcast_bytes",
	},
	{
		.dpdk_name = "rx_port_unicast_packets",
		.ctr_name = "vstats.rx_unicast_packets",
	},
	{
		.dpdk_name = "rx_port_multicast_packets",
		.ctr_name = "vstats.rx_multicast_packets",
	},
	{
		.dpdk_name = "rx_port_broadcast_packets",
		.ctr_name = "vstats.rx_broadcast_packets",
	},
	{
		.dpdk_name = "tx_port_unicast_bytes",
		.ctr_name = "vstats.tx_unicast_bytes",
	},
	{
		.dpdk_name = "tx_port_multicast_bytes",
		.ctr_name = "vstats.tx_multicast_bytes",
	},
	{
		.dpdk_name = "tx_port_broadcast_bytes",
		.ctr_name = "vstats.tx_broadcast_bytes",
	},
	{
		.dpdk_name = "tx_port_unicast_packets",
		.ctr_name = "vstats.tx_unicast_packets",
	},
	{
		.dpdk_name = "tx_port_multicast_packets",
		.ctr_name = "vstats.tx_multicast_packets",
	},
	{
		.dpdk_name = "tx_port_broadcast_packets",
		.ctr_name = "vstats.tx_broadcast_packets",
	},
	{
		.dpdk_name = "rx_wqe_err",
		.ctr_name = "vstats.rx_wqe_err",
	},
	{
		.dpdk_name = "rx_crc_align_errors",
		.ctr_name = "pstats.crc_align_errors",
	},
	{
		.dpdk_name = "rx_in_range_len_errors",
		.ctr_name = "pstats.in_range_len_errors",
	},
	{
		.dpdk_name = "rx_symbol_err",
		.ctr_name = "pstats.symbol_err",
	},
	{
		.dpdk_name = "tx_errors_packets",
		.ctr_name = "vstats.tx_error_packets",
	},
	{
		.dpdk_name = "rx_out_of_buffer",
		.ctr_name = "vstats.rx_out_of_buffer",
	},
	{
		.dpdk_name = "lro_bytes",
		.ctr_name = "vstats.lro_bytes",
	},
	{
		.dpdk_name = "lro_packets",
		.ctr_name = "vstats.lro_packets",
	},
	{
		.dpdk_name = "tso_bytes",
		.ctr_name = "vstats.tso_bytes",
	},
	{
		.dpdk_name = "tso_packets",
		.ctr_name = "vstats.tso_packets",
	},
	/* Representor only */
	{
		.dpdk_name = "rx_packets",
		.ctr_name = "vstats.rx_packets",
	},
	{
		.dpdk_name = "rx_bytes",
		.ctr_name = "vstats.rx_bytes",
	},
	{
		.dpdk_name = "tx_packets",
		.ctr_name = "vstats.tx_packets",
	},
	{
		.dpdk_name = "tx_bytes",
		.ctr_name = "vstats.tx_bytes",
	},
};

/**
 * Init the structures to read device counters.
 *
 * @param dev
 *   Pointer to Ethernet device.
 */
void
mlx5_os_stats_init(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_xstats_ctrl *xstats_ctrl = &priv->xstats_ctrl;
	struct mlx5_stats_ctrl *stats_ctrl = &priv->stats_ctrl;

	xstats_n = RTE_DIM(mlx5_counters_init);
	xstats_ctrl->mlx5_stats_n = 0;

	for (unsigned int i = 0; i != xstats_n; ++i) {
		unsigned int idx = xstats_ctrl->mlx5_stats_n++;

		xstats_ctrl->dev_table_idx[idx] = i;
		xstats_ctrl->info[idx] = mlx5_counters_init[i];
	}
	xstats_ctrl->stats_n = xstats_n;
	int ret = mlx5_os_read_dev_counters(dev, xstats_ctrl->base);

	if (ret)
		DRV_LOG(ERR, "port %u cannot read device counters: %s",
			dev->data->port_id, strerror(rte_errno));
	mlx5_os_read_dev_stat(priv, "out_of_buffer", &stats_ctrl->imissed_base);
	stats_ctrl->imissed = 0;
}

/**
 * Get MAC address by querying netdevice.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[out] mac
 *   MAC address output buffer.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_get_mac(struct rte_eth_dev *dev, uint8_t (*mac)[RTE_ETHER_ADDR_LEN])
{
	struct ifreq request;
	int ret;

	ret = mlx5_ifreq(dev, SIOCGHWADDR, &request);
	if (ret)
		return ret;
	memcpy(mac, request.ifr_addr.sa_data, RTE_ETHER_ADDR_LEN);
	return 0;
}
