/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright(c) 2019 Intel Corporation
 */

#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <eal_export.h>
#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_tailq.h>

#include <rte_debug.h>
#include <rte_rib.h>
#include <rte_fib.h>

#include "dir24_8.h"
#include "fib_log.h"

#define FIB_MAX_LOOKUP_BULK 64U

RTE_LOG_REGISTER_DEFAULT(fib_logtype, INFO);

TAILQ_HEAD(rte_fib_list, rte_tailq_entry);
static struct rte_tailq_elem rte_fib_tailq = {
	.name = "RTE_FIB",
};
EAL_REGISTER_TAILQ(rte_fib_tailq)

#if defined(RTE_LIBRTE_FIB_DEBUG)
#define FIB_RETURN_IF_TRUE(cond, retval) do {		\
	if (cond)					\
		return retval;				\
} while (0)
#else
#define FIB_RETURN_IF_TRUE(cond, retval)
#endif

struct rte_fib {
	char			name[RTE_FIB_NAMESIZE];
	enum rte_fib_type	type;	/**< Type of FIB struct */
	uint16_t flags;			/**< Flags */
	uint16_t		num_vrfs;/**< Number of VRFs */
	struct rte_rib		**ribs;	/**< RIB helper datastructures per VRF */
	void			*dp;	/**< pointer to the dataplane struct*/
	rte_fib_lookup_fn_t	lookup;	/**< FIB lookup function */
	rte_fib_modify_fn_t	modify; /**< modify FIB datastructure */
	uint64_t		*def_nh;/**< Per-VRF default next hop array */
};

static void
dummy_lookup(void *fib_p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	unsigned int i;
	struct rte_fib *fib = fib_p;
	struct rte_rib_node *node;
	struct rte_rib *rib;

	for (i = 0; i < n; i++) {
		RTE_ASSERT(vrf_ids[i] < fib->num_vrfs);
		rib = rte_fib_vrf_get_rib(fib, vrf_ids[i]);
		node = rte_rib_lookup(rib, ips[i]);
		if (node != NULL)
			rte_rib_get_nh(node, &next_hops[i]);
		else
			next_hops[i] = fib->def_nh[vrf_ids[i]];
	}
}

static int
dummy_modify(struct rte_fib *fib, uint16_t vrf_id, uint32_t ip,
	uint8_t depth, uint64_t next_hop, int op)
{
	struct rte_rib_node *node;
	struct rte_rib *rib;
	if ((fib == NULL) || (depth > RTE_FIB_MAXDEPTH))
		return -EINVAL;

	rib = rte_fib_vrf_get_rib(fib, vrf_id);
	if (rib == NULL)
		return -EINVAL;

	node = rte_rib_lookup_exact(rib, ip, depth);

	switch (op) {
	case RTE_FIB_ADD:
		if (node == NULL)
			node = rte_rib_insert(rib, ip, depth);
		if (node == NULL)
			return -rte_errno;
		return rte_rib_set_nh(node, next_hop);
	case RTE_FIB_DEL:
		if (node == NULL)
			return -ENOENT;
		rte_rib_remove(rib, ip, depth);
		return 0;
	}
	return -EINVAL;
}

static int
init_dataplane(struct rte_fib *fib, __rte_unused int socket_id,
	struct rte_fib_conf *conf)
{
	char dp_name[sizeof(void *)];

	snprintf(dp_name, sizeof(dp_name), "%p", fib);
	switch (conf->type) {
	case RTE_FIB_DUMMY:
		fib->dp = fib;
		fib->lookup = dummy_lookup;
		fib->modify = dummy_modify;
		return 0;
	case RTE_FIB_DIR24_8:
		fib->dp = dir24_8_create(dp_name, socket_id, conf);
		if (fib->dp == NULL)
			return -rte_errno;
		fib->lookup = dir24_8_get_lookup_fn(fib->dp,
			RTE_FIB_LOOKUP_DEFAULT, !!(fib->flags & RTE_FIB_F_LOOKUP_NETWORK_ORDER));
		fib->modify = dir24_8_modify;
		return 0;
	default:
		return -EINVAL;
	}
	return 0;
}

RTE_EXPORT_SYMBOL(rte_fib_add)
int
rte_fib_add(struct rte_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop)
{
	if ((fib == NULL) || (fib->modify == NULL) ||
			(depth > RTE_FIB_MAXDEPTH))
		return -EINVAL;
	return fib->modify(fib, 0, ip, depth, next_hop, RTE_FIB_ADD);
}

RTE_EXPORT_SYMBOL(rte_fib_delete)
int
rte_fib_delete(struct rte_fib *fib, uint32_t ip, uint8_t depth)
{
	if ((fib == NULL) || (fib->modify == NULL) ||
			(depth > RTE_FIB_MAXDEPTH))
		return -EINVAL;
	return fib->modify(fib, 0, ip, depth, 0, RTE_FIB_DEL);
}

RTE_EXPORT_SYMBOL(rte_fib_lookup_bulk)
int
rte_fib_lookup_bulk(struct rte_fib *fib, uint32_t *ips,
	uint64_t *next_hops, int n)
{
	static const uint16_t zero_vrf_ids[FIB_MAX_LOOKUP_BULK];
	unsigned int off = 0;
	unsigned int total = (unsigned int)n;

	FIB_RETURN_IF_TRUE(((fib == NULL) || (ips == NULL) ||
		(next_hops == NULL) || (fib->lookup == NULL)), -EINVAL);

	while (off < total) {
		unsigned int chunk = RTE_MIN(total - off,
			FIB_MAX_LOOKUP_BULK);
		fib->lookup(fib->dp, zero_vrf_ids, ips + off,
			next_hops + off, chunk);
		off += chunk;
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_vrf_lookup_bulk, 26.07)
int
rte_fib_vrf_lookup_bulk(struct rte_fib *fib, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, int n)
{
	FIB_RETURN_IF_TRUE(((fib == NULL) || (vrf_ids == NULL) ||
		(ips == NULL) || (next_hops == NULL) ||
		(fib->lookup == NULL)), -EINVAL);

	fib->lookup(fib->dp, vrf_ids, ips, next_hops, (unsigned int)n);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_vrf_add, 26.07)
int
rte_fib_vrf_add(struct rte_fib *fib, uint16_t vrf_id, uint32_t ip,
	uint8_t depth, uint64_t next_hop)
{
	if ((fib == NULL) || (fib->modify == NULL) ||
			(depth > RTE_FIB_MAXDEPTH))
		return -EINVAL;
	return fib->modify(fib, vrf_id, ip, depth, next_hop, RTE_FIB_ADD);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_vrf_delete, 26.07)
int
rte_fib_vrf_delete(struct rte_fib *fib, uint16_t vrf_id, uint32_t ip,
	uint8_t depth)
{
	if ((fib == NULL) || (fib->modify == NULL) ||
			(depth > RTE_FIB_MAXDEPTH))
		return -EINVAL;
	return fib->modify(fib, vrf_id, ip, depth, 0, RTE_FIB_DEL);
}

RTE_EXPORT_SYMBOL(rte_fib_create)
struct rte_fib *
rte_fib_create(const char *name, int socket_id, struct rte_fib_conf *conf)
{
	char mem_name[RTE_FIB_NAMESIZE];
	char rib_name[RTE_FIB_NAMESIZE];
	int ret;
	struct rte_fib *fib = NULL;
	struct rte_rib *rib = NULL;
	struct rte_tailq_entry *te;
	struct rte_fib_list *fib_list;
	struct rte_rib_conf rib_conf;
	uint16_t num_vrfs;
	uint16_t vrf;

	/* Check user arguments. */
	if ((name == NULL) || (conf == NULL) ||	(conf->max_routes < 0) ||
			(conf->flags & ~RTE_FIB_ALLOWED_FLAGS) ||
			(conf->type > RTE_FIB_DIR24_8)) {
		rte_errno = EINVAL;
		return NULL;
	}

	num_vrfs = (conf->max_vrfs == 0) ? 1 : conf->max_vrfs;
	rib_conf.ext_sz = conf->rib_ext_sz;
	rib_conf.max_nodes = conf->max_routes * 2;

	struct rte_rib **ribs = rte_zmalloc_socket("FIB_RIBS",
		num_vrfs * sizeof(*fib->ribs), RTE_CACHE_LINE_SIZE, socket_id);
	if (ribs == NULL) {
		FIB_LOG(ERR, "FIB %s RIB array allocation failed", name);
		rte_errno = ENOMEM;
		return NULL;
	}

	uint64_t *def_nh = rte_zmalloc_socket("FIB_DEF_NH",
		num_vrfs * sizeof(*def_nh), RTE_CACHE_LINE_SIZE, socket_id);
	if (def_nh == NULL) {
		FIB_LOG(ERR, "FIB %s default nexthop array allocation failed", name);
		rte_errno = ENOMEM;
		rte_free(ribs);
		return NULL;
	}

	for (vrf = 0; vrf < num_vrfs; vrf++) {
		if (num_vrfs == 1)
			snprintf(rib_name, sizeof(rib_name), "%s", name);
		else
			snprintf(rib_name, sizeof(rib_name), "%s_vrf%u", name, vrf);
		rib = rte_rib_create(rib_name, socket_id, &rib_conf);
		if (rib == NULL) {
			FIB_LOG(ERR, "Can not allocate RIB %s", rib_name);
			goto free_ribs;
		}
		ribs[vrf] = rib;
		def_nh[vrf] = (conf->vrf_default_nh != NULL) ?
			conf->vrf_default_nh[vrf] : conf->default_nh;
	}

	snprintf(mem_name, sizeof(mem_name), "FIB_%s", name);
	fib_list = RTE_TAILQ_CAST(rte_fib_tailq.head, rte_fib_list);

	rte_mcfg_tailq_write_lock();

	/* guarantee there's no existing */
	TAILQ_FOREACH(te, fib_list, next) {
		fib = (struct rte_fib *)te->data;
		if (strncmp(name, fib->name, RTE_FIB_NAMESIZE) == 0)
			break;
	}
	fib = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		goto exit;
	}

	/* allocate tailq entry */
	te = rte_zmalloc("FIB_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		FIB_LOG(ERR,
			"Can not allocate tailq entry for FIB %s", name);
		rte_errno = ENOMEM;
		goto exit;
	}

	/* Allocate memory to store the FIB data structures. */
	fib = rte_zmalloc_socket(mem_name,
		sizeof(struct rte_fib),	RTE_CACHE_LINE_SIZE, socket_id);
	if (fib == NULL) {
		FIB_LOG(ERR, "FIB %s memory allocation failed", name);
		rte_errno = ENOMEM;
		goto free_te;
	}

	fib->num_vrfs = num_vrfs;
	fib->ribs = ribs;
	fib->def_nh = def_nh;

	rte_strlcpy(fib->name, name, sizeof(fib->name));
	fib->type = conf->type;
	fib->flags = conf->flags;
	ret = init_dataplane(fib, socket_id, conf);
	if (ret < 0) {
		FIB_LOG(ERR,
			"FIB dataplane struct %s memory allocation failed "
			"with err %d", name, ret);
		rte_errno = -ret;
		goto free_fib;
	}

	te->data = (void *)fib;
	TAILQ_INSERT_TAIL(fib_list, te, next);

	rte_mcfg_tailq_write_unlock();

	return fib;

free_fib:
	rte_free(fib);
free_te:
	rte_free(te);
exit:
	rte_mcfg_tailq_write_unlock();
free_ribs:
	for (vrf = 0; vrf < num_vrfs; vrf++)
		rte_rib_free(ribs[vrf]);

	rte_free(def_nh);
	rte_free(ribs);
	return NULL;
}

RTE_EXPORT_SYMBOL(rte_fib_find_existing)
struct rte_fib *
rte_fib_find_existing(const char *name)
{
	struct rte_fib *fib = NULL;
	struct rte_tailq_entry *te;
	struct rte_fib_list *fib_list;

	fib_list = RTE_TAILQ_CAST(rte_fib_tailq.head, rte_fib_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, fib_list, next) {
		fib = (struct rte_fib *) te->data;
		if (strncmp(name, fib->name, RTE_FIB_NAMESIZE) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}

	return fib;
}

static void
free_dataplane(struct rte_fib *fib)
{
	switch (fib->type) {
	case RTE_FIB_DUMMY:
		return;
	case RTE_FIB_DIR24_8:
		dir24_8_free(fib->dp);
	default:
		return;
	}
}

RTE_EXPORT_SYMBOL(rte_fib_free)
void
rte_fib_free(struct rte_fib *fib)
{
	struct rte_tailq_entry *te;
	struct rte_fib_list *fib_list;

	if (fib == NULL)
		return;

	fib_list = RTE_TAILQ_CAST(rte_fib_tailq.head, rte_fib_list);

	rte_mcfg_tailq_write_lock();

	/* find our tailq entry */
	TAILQ_FOREACH(te, fib_list, next) {
		if (te->data == (void *)fib)
			break;
	}
	if (te != NULL)
		TAILQ_REMOVE(fib_list, te, next);

	rte_mcfg_tailq_write_unlock();

	free_dataplane(fib);
	if (fib->ribs != NULL) {
		uint16_t vrf;
		for (vrf = 0; vrf < fib->num_vrfs; vrf++)
			rte_rib_free(fib->ribs[vrf]);
	}
	rte_free(fib->ribs);
	rte_free(fib->def_nh);
	rte_free(fib);
	rte_free(te);
}

RTE_EXPORT_SYMBOL(rte_fib_get_dp)
void *
rte_fib_get_dp(struct rte_fib *fib)
{
	return (fib == NULL) ? NULL : fib->dp;
}

RTE_EXPORT_SYMBOL(rte_fib_get_rib)
struct rte_rib *
rte_fib_get_rib(struct rte_fib *fib)
{
	return (fib == NULL || fib->ribs == NULL) ? NULL : fib->ribs[0];
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_vrf_get_rib, 26.07)
struct rte_rib *
rte_fib_vrf_get_rib(struct rte_fib *fib, uint16_t vrf_id)
{
	if (fib == NULL || fib->ribs == NULL)
		return NULL;
	if (vrf_id >= fib->num_vrfs)
		return NULL;
	return fib->ribs[vrf_id];
}

RTE_EXPORT_SYMBOL(rte_fib_select_lookup)
int
rte_fib_select_lookup(struct rte_fib *fib,
	enum rte_fib_lookup_type type)
{
	rte_fib_lookup_fn_t fn;

	switch (fib->type) {
	case RTE_FIB_DIR24_8:
		fn = dir24_8_get_lookup_fn(fib->dp, type,
			!!(fib->flags & RTE_FIB_F_LOOKUP_NETWORK_ORDER));
		if (fn == NULL)
			return -EINVAL;
		fib->lookup = fn;
		return 0;
	default:
		return -EINVAL;
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_rcu_qsbr_add, 24.11)
int
rte_fib_rcu_qsbr_add(struct rte_fib *fib, struct rte_fib_rcu_config *cfg)
{
	if (fib == NULL)
		return -EINVAL;

	switch (fib->type) {
	case RTE_FIB_DIR24_8:
		return dir24_8_rcu_qsbr_add(fib->dp, cfg, fib->name);
	default:
		return -ENOTSUP;
	}
}
