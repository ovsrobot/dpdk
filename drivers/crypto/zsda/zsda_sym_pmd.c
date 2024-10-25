/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <rte_cryptodev.h>

#include "cryptodev_pmd.h"
#include "zsda_logs.h"
#include "zsda_sym.h"
#include "zsda_sym_pmd.h"
#include "zsda_sym_session.h"
#include "zsda_sym_capabilities.h"

uint8_t zsda_sym_driver_id;

static int
zsda_sym_dev_config(__rte_unused struct rte_cryptodev *dev,
		    __rte_unused struct rte_cryptodev_config *config)
{
	return ZSDA_SUCCESS;
}

static int
zsda_sym_dev_start(struct rte_cryptodev *dev)
{
	struct zsda_sym_dev_private *sym_dev = dev->data->dev_private;
	int ret;

	ret = zsda_queue_start(sym_dev->zsda_pci_dev->pci_dev);

	if (ret)
		ZSDA_LOG(ERR, E_START_Q);
	return ret;
}

static void
zsda_sym_dev_stop(struct rte_cryptodev *dev)
{
	struct zsda_sym_dev_private *sym_dev = dev->data->dev_private;

	zsda_queue_stop(sym_dev->zsda_pci_dev->pci_dev);
}

static int
zsda_sym_qp_release(struct rte_cryptodev *dev, uint16_t queue_pair_id)
{
	ZSDA_LOG(DEBUG, "Release sym qp %u on device %d", queue_pair_id,
		 dev->data->dev_id);

	return zsda_queue_pair_release(
		(struct zsda_qp **)&(dev->data->queue_pairs[queue_pair_id]));
}

static int
zsda_sym_dev_close(struct rte_cryptodev *dev)
{
	int ret = ZSDA_SUCCESS;
	uint16_t i;

	for (i = 0; i < dev->data->nb_queue_pairs; i++)
		ret |= zsda_sym_qp_release(dev, i);

	return ret;
}

static uint16_t
zsda_sym_max_nb_qps(void)
{
	uint16_t encrypt = zsda_nb_qps.encrypt;
	uint16_t decrypt = zsda_nb_qps.decrypt;
	uint16_t hash = zsda_nb_qps.hash;
	uint16_t min = 0;

	if ((encrypt == MAX_QPS_ON_FUNCTION) ||
		(decrypt == MAX_QPS_ON_FUNCTION) ||
	    (hash == MAX_QPS_ON_FUNCTION))
		min = MAX_QPS_ON_FUNCTION;
	else {
		min = (encrypt < decrypt) ? encrypt : decrypt;
		min = (min < hash) ? min : hash;
	}

	if (min == 0)
		return MAX_QPS_ON_FUNCTION;
	return min;
}


static void
zsda_sym_dev_info_get(struct rte_cryptodev *dev,
		      struct rte_cryptodev_info *info)
{
	struct zsda_sym_dev_private *sym_priv = dev->data->dev_private;

	if (info != NULL) {
		info->max_nb_queue_pairs = zsda_sym_max_nb_qps();
		info->feature_flags = dev->feature_flags;
		info->capabilities = sym_priv->zsda_dev_capabilities;
		info->driver_id = zsda_sym_driver_id;
		info->sym.max_nb_sessions = 0;
	}
}

static void
zsda_sym_stats_get(struct rte_cryptodev *dev, struct rte_cryptodev_stats *stats)
{
	struct zsda_common_stat comm = {0};

	zsda_stats_get(dev->data->queue_pairs, dev->data->nb_queue_pairs,
		       &comm);
	stats->enqueued_count = comm.enqueued_count;
	stats->dequeued_count = comm.dequeued_count;
	stats->enqueue_err_count = comm.enqueue_err_count;
	stats->dequeue_err_count = comm.dequeue_err_count;
}

static void
zsda_sym_stats_reset(struct rte_cryptodev *dev)
{
	zsda_stats_reset(dev->data->queue_pairs, dev->data->nb_queue_pairs);
}

static int
zsda_setup_encrypto_queue(struct zsda_pci_device *zsda_pci_dev, uint16_t qp_id,
		     struct zsda_qp *qp, uint32_t nb_des, int socket_id)
{
	enum zsda_service_type type = ZSDA_SERVICE_SYMMETRIC_ENCRYPT;
	struct zsda_qp_config conf;
	int ret;
	struct zsda_qp_hw *qp_hw;

	qp_hw = zsda_qps_hw_per_service(zsda_pci_dev, type);
	conf.hw = qp_hw->data + qp_id;
	conf.service_type = type;
	conf.cookie_size = sizeof(struct zsda_op_cookie);
	conf.nb_descriptors = nb_des;
	conf.socket_id = socket_id;
	conf.service_str = "sym_encrypt";

	ret = zsda_common_setup_qp(zsda_pci_dev->zsda_dev_id, &qp, qp_id, &conf);
	qp->srv[type].rx_cb = zsda_crypto_callback;
	qp->srv[type].tx_cb = zsda_build_cipher_request;
	qp->srv[type].match = zsda_encry_match;

	return ret;
}

static int
zsda_setup_decrypto_queue(struct zsda_pci_device *zsda_pci_dev, uint16_t qp_id,
		     struct zsda_qp *qp, uint32_t nb_des, int socket_id)
{
	enum zsda_service_type type = ZSDA_SERVICE_SYMMETRIC_DECRYPT;
	struct zsda_qp_config conf;
	int ret;
	struct zsda_qp_hw *qp_hw;

	qp_hw = zsda_qps_hw_per_service(zsda_pci_dev, type);
	conf.hw = qp_hw->data + qp_id;
	conf.service_type = type;

	conf.cookie_size = sizeof(struct zsda_op_cookie);
	conf.nb_descriptors = nb_des;
	conf.socket_id = socket_id;
	conf.service_str = "sym_decrypt";

	ret = zsda_common_setup_qp(zsda_pci_dev->zsda_dev_id, &qp, qp_id, &conf);
	qp->srv[type].rx_cb = zsda_crypto_callback;
	qp->srv[type].tx_cb = zsda_build_cipher_request;
	qp->srv[type].match = zsda_decry_match;

	return ret;
}

static int
zsda_setup_hash_queue(struct zsda_pci_device *zsda_pci_dev, uint16_t qp_id,
		 struct zsda_qp *qp, uint32_t nb_des, int socket_id)
{
	enum zsda_service_type type = ZSDA_SERVICE_HASH_ENCODE;
	struct zsda_qp_config conf;
	int ret;
	struct zsda_qp_hw *qp_hw;

	qp_hw = zsda_qps_hw_per_service(zsda_pci_dev, type);
	conf.hw = qp_hw->data + qp_id;
	conf.service_type = type;
	conf.cookie_size = sizeof(struct zsda_op_cookie);
	conf.nb_descriptors = nb_des;
	conf.socket_id = socket_id;
	conf.service_str = "sym_hash";

	ret = zsda_common_setup_qp(zsda_pci_dev->zsda_dev_id, &qp, qp_id, &conf);
	qp->srv[type].rx_cb = zsda_crypto_callback;
	qp->srv[type].tx_cb = zsda_build_hash_request;
	qp->srv[type].match = zsda_hash_match;

	return ret;
}

static int
zsda_sym_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
		  const struct rte_cryptodev_qp_conf *qp_conf,
		  int socket_id)
{
	int ret = ZSDA_SUCCESS;
	struct zsda_qp *qp_new;
	struct zsda_qp **qp_addr =
		(struct zsda_qp **)&(dev->data->queue_pairs[qp_id]);
	struct zsda_sym_dev_private *sym_priv = dev->data->dev_private;
	struct zsda_pci_device *zsda_pci_dev = sym_priv->zsda_pci_dev;
	uint16_t num_qps_encrypt = zsda_nb_qps.encrypt;
	uint16_t num_qps_decrypt = zsda_nb_qps.decrypt;
	uint16_t num_qps_hash = zsda_nb_qps.hash;
	uint32_t nb_des = qp_conf->nb_descriptors;

	nb_des = (nb_des == NB_DES) ? nb_des : NB_DES;

	if (*qp_addr != NULL) {
		ret = zsda_sym_qp_release(dev, qp_id);
		if (ret)
			return ret;
	}

	qp_new = rte_zmalloc_socket("zsda PMD qp metadata", sizeof(*qp_new),
				    RTE_CACHE_LINE_SIZE, socket_id);
	if (qp_new == NULL) {
		ZSDA_LOG(ERR, "Failed to alloc mem for qp struct");
		return -ENOMEM;
	}

	if (num_qps_encrypt == MAX_QPS_ON_FUNCTION)
		ret = zsda_setup_encrypto_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					    socket_id);
	else if (num_qps_decrypt == MAX_QPS_ON_FUNCTION)
		ret = zsda_setup_decrypto_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					    socket_id);
	else if (num_qps_hash == MAX_QPS_ON_FUNCTION)
		ret = zsda_setup_hash_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					socket_id);
	else {
		ret = zsda_setup_encrypto_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					    socket_id);
		ret |= zsda_setup_decrypto_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					    socket_id);
		ret |= zsda_setup_hash_queue(zsda_pci_dev, qp_id, qp_new, nb_des,
					socket_id);
	}

	if (ret) {
		rte_free(qp_new);
		return ret;
	}

	*qp_addr = qp_new;

	return ret;
}

static unsigned int
zsda_sym_session_get_private_size(struct rte_cryptodev *dev __rte_unused)
{
	return RTE_ALIGN_CEIL(sizeof(struct zsda_sym_session), 8);
}

static int
zsda_sym_session_configure(struct rte_cryptodev *dev __rte_unused,
			   struct rte_crypto_sym_xform *xform,
			   struct rte_cryptodev_sym_session *sess)
{
	void *sess_private_data;
	int ret;

	if (unlikely(sess == NULL)) {
		ZSDA_LOG(ERR, "Invalid session struct");
		return -EINVAL;
	}

	sess_private_data = CRYPTODEV_GET_SYM_SESS_PRIV(sess);

	ret = zsda_crypto_set_session_parameters(
			sess_private_data, xform);

	if (ret != ZSDA_SUCCESS)
		ZSDA_LOG(ERR, "Failed configure session parameters");

	return ret;
}

static void
zsda_sym_session_clear(struct rte_cryptodev *dev __rte_unused,
			struct rte_cryptodev_sym_session  *sess __rte_unused)
{}

static struct rte_cryptodev_ops crypto_zsda_ops = {

	.dev_configure = zsda_sym_dev_config,
	.dev_start = zsda_sym_dev_start,
	.dev_stop = zsda_sym_dev_stop,
	.dev_close = zsda_sym_dev_close,
	.dev_infos_get = zsda_sym_dev_info_get,

	.stats_get = zsda_sym_stats_get,
	.stats_reset = zsda_sym_stats_reset,
	.queue_pair_setup = zsda_sym_qp_setup,
	.queue_pair_release = zsda_sym_qp_release,

	.sym_session_get_size = zsda_sym_session_get_private_size,
	.sym_session_configure = zsda_sym_session_configure,
	.sym_session_clear = zsda_sym_session_clear,
};
