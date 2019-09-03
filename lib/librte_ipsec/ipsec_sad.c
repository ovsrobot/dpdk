/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_rwlock.h>
#include <rte_tailq.h>

#include "rte_ipsec_sad.h"

#define IPSEC_SAD_NAMESIZE	64
#define SAD_PREFIX		"SAD_"
/* "SAD_<name>" */
#define SAD_FORMAT		SAD_PREFIX "%s"

#define DEFAULT_HASH_FUNC	rte_jhash

struct hash_cnt {
	uint32_t cnt_2;
	uint32_t cnt_3;
};

struct rte_ipsec_sad {
	char name[IPSEC_SAD_NAMESIZE];
	struct rte_hash	*hash[RTE_IPSEC_SAD_KEY_TYPE_MASK];
	__extension__ struct hash_cnt cnt_arr[];
};

TAILQ_HEAD(rte_ipsec_sad_list, rte_tailq_entry);
static struct rte_tailq_elem rte_ipsec_sad_tailq = {
	.name = "RTE_IPSEC_SAD",
};
EAL_REGISTER_TAILQ(rte_ipsec_sad_tailq)

int
rte_ipsec_sad_add(__rte_unused struct rte_ipsec_sad *sad,
		__rte_unused union rte_ipsec_sad_key *key,
		__rte_unused int key_type, __rte_unused void *sa)
{
	return -ENOTSUP;
}

int
rte_ipsec_sad_del(__rte_unused struct rte_ipsec_sad *sad,
		__rte_unused union rte_ipsec_sad_key *key,
		__rte_unused int key_type)
{
	return -ENOTSUP;
}

struct rte_ipsec_sad *
rte_ipsec_sad_create(const char *name, struct rte_ipsec_sad_conf *conf)
{
	char hash_name[RTE_HASH_NAMESIZE];
	struct rte_tailq_entry *te;
	struct rte_ipsec_sad_list *sad_list;
	struct rte_ipsec_sad *sad, *tmp_sad = NULL;
	struct rte_hash_parameters hash_params = {0};
	int ret;
	uint32_t sa_sum;

	RTE_BUILD_BUG_ON(RTE_IPSEC_SAD_KEY_TYPE_MASK != 3);

	if ((name == NULL) || (conf == NULL) ||
			(conf->max_sa[RTE_IPSEC_SAD_SPI_ONLY] == 0) ||
			(conf->max_sa[RTE_IPSEC_SAD_SPI_DIP] == 0) ||
			(conf->max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] == 0) ||
			/* check that either IPv4 or IPv6 type flags
			 * are configured
			 */
			((!!(conf->flags & RTE_IPSEC_SAD_FLAG_IPV4) ^
			!!(conf->flags & RTE_IPSEC_SAD_FLAG_IPV6)) == 0)) {
		rte_errno = EINVAL;
		return NULL;
	}

	/** Init SAD*/
	sa_sum = conf->max_sa[RTE_IPSEC_SAD_SPI_ONLY] +
		conf->max_sa[RTE_IPSEC_SAD_SPI_DIP] +
		conf->max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP];
	sad = rte_zmalloc_socket(NULL, sizeof(*sad) +
		(sizeof(struct hash_cnt) * sa_sum),
		RTE_CACHE_LINE_SIZE, conf->socket_id);
	if (sad == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	ret = snprintf(sad->name, sizeof(sad->name), SAD_FORMAT, name);
	if (ret < 0 || ret >= (int)sizeof(sad->name)) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	hash_params.hash_func = DEFAULT_HASH_FUNC;
	hash_params.hash_func_init_val = rte_rand();
	hash_params.socket_id = conf->socket_id;
	hash_params.name = hash_name;
	if (conf->flags & RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY)
		hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;

	/** Init hash[RTE_IPSEC_SAD_SPI_ONLY] for SPI only */
	ret = snprintf(hash_name, sizeof(hash_name),
		"sad_%p_1", sad);
	if (ret < 0 || ret >= (int)sizeof(hash_name)) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}
	hash_params.key_len = sizeof(((struct rte_ipsec_sadv4_key *)0)->spi);
	hash_params.entries = sa_sum;
	sad->hash[RTE_IPSEC_SAD_SPI_ONLY] = rte_hash_create(&hash_params);
	if (sad->hash[RTE_IPSEC_SAD_SPI_ONLY] == NULL) {
		rte_ipsec_sad_free(sad);
		return NULL;
	}

	/** Init hash_2 for SPI + DIP */
	ret = snprintf(hash_name, sizeof(hash_name),
		"sad_%p_2", sad);
	if (ret < 0 || ret >= (int)sizeof(hash_name)) {
		rte_errno = ENAMETOOLONG;
		rte_ipsec_sad_free(sad);
		return NULL;
	}
	if (conf->flags & RTE_IPSEC_SAD_FLAG_IPV4)
		hash_params.key_len +=
			sizeof(((struct rte_ipsec_sadv4_key *)0)->dip);
	else
		hash_params.key_len +=
			sizeof(((struct rte_ipsec_sadv6_key *)0)->dip);
	hash_params.entries = conf->max_sa[RTE_IPSEC_SAD_SPI_DIP];
	sad->hash[RTE_IPSEC_SAD_SPI_DIP] = rte_hash_create(&hash_params);
	if (sad->hash[RTE_IPSEC_SAD_SPI_DIP] == NULL) {
		rte_ipsec_sad_free(sad);
		return NULL;
	}

	/** Init hash_3 for SPI + DIP + SIP */
	ret = snprintf(hash_name, sizeof(hash_name),
		"sad_%p_3", name);
	if (ret < 0 || ret >= (int)sizeof(hash_name)) {
		rte_errno = ENAMETOOLONG;
		rte_ipsec_sad_free(sad);
		return NULL;
	}
	if (conf->flags & RTE_IPSEC_SAD_FLAG_IPV4)
		hash_params.key_len +=
			sizeof(((struct rte_ipsec_sadv4_key *)0)->sip);
	else
		hash_params.key_len +=
			sizeof(((struct rte_ipsec_sadv6_key *)0)->sip);
	hash_params.entries = conf->max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP];
	sad->hash[RTE_IPSEC_SAD_SPI_DIP_SIP] = rte_hash_create(&hash_params);
	if (sad->hash[RTE_IPSEC_SAD_SPI_DIP_SIP] == NULL) {
		rte_ipsec_sad_free(sad);
		return NULL;
	}

	sad_list = RTE_TAILQ_CAST(rte_ipsec_sad_tailq.head,
			rte_ipsec_sad_list);
	rte_mcfg_tailq_write_lock();
	/* guarantee there's no existing */
	TAILQ_FOREACH(te, sad_list, next) {
		tmp_sad = (struct rte_ipsec_sad *)te->data;
		if (strncmp(name, tmp_sad->name, IPSEC_SAD_NAMESIZE) == 0)
			break;
	}
	if (te != NULL) {
		rte_mcfg_tailq_write_unlock();
		rte_errno = EEXIST;
		rte_ipsec_sad_free(sad);
		return NULL;
	}

	/* allocate tailq entry */
	te = rte_zmalloc("IPSEC_SAD_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		rte_mcfg_tailq_write_unlock();
		rte_errno = ENOMEM;
		rte_ipsec_sad_free(sad);
		return NULL;
	}

	te->data = (void *)sad;
	TAILQ_INSERT_TAIL(sad_list, te, next);
	rte_mcfg_tailq_write_unlock();
	return sad;
}

struct rte_ipsec_sad *
rte_ipsec_sad_find_existing(const char *name)
{
	struct rte_ipsec_sad *sad = NULL;
	struct rte_tailq_entry *te;
	struct rte_ipsec_sad_list *sad_list;


	sad_list = RTE_TAILQ_CAST(rte_ipsec_sad_tailq.head,
		rte_ipsec_sad_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, sad_list, next) {
		sad = (struct rte_ipsec_sad *) te->data;
		if (strncmp(name, sad->name, IPSEC_SAD_NAMESIZE) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}

	return sad;
}

void
rte_ipsec_sad_free(struct rte_ipsec_sad *sad)
{
	struct rte_tailq_entry *te;
	struct rte_ipsec_sad_list *sad_list;

	if (sad == NULL)
		return;

	sad_list = RTE_TAILQ_CAST(rte_ipsec_sad_tailq.head,
			rte_ipsec_sad_list);
	rte_mcfg_tailq_write_lock();
	TAILQ_FOREACH(te, sad_list, next) {
		if (te->data == (void *)sad)
			break;
	}
	if (te != NULL)
		TAILQ_REMOVE(sad_list, te, next);

	rte_mcfg_tailq_write_unlock();

	rte_hash_free(sad->hash[RTE_IPSEC_SAD_SPI_ONLY]);
	rte_hash_free(sad->hash[RTE_IPSEC_SAD_SPI_DIP]);
	rte_hash_free(sad->hash[RTE_IPSEC_SAD_SPI_DIP_SIP]);
	rte_free(sad);
	if (te != NULL)
		rte_free(te);
}

int
rte_ipsec_sad_lookup(__rte_unused const struct rte_ipsec_sad *sad,
		__rte_unused const union rte_ipsec_sad_key *keys[],
		__rte_unused uint32_t n, __rte_unused void *sa[])
{
	return -ENOTSUP;
}
