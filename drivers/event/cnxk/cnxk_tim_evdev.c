/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cnxk_eventdev.h"
#include "cnxk_tim_evdev.h"

static struct event_timer_adapter_ops cnxk_tim_ops;

static int
cnxk_tim_chnk_pool_create(struct cnxk_tim_ring *tim_ring,
			  struct rte_event_timer_adapter_conf *rcfg)
{
	unsigned int cache_sz = (tim_ring->nb_chunks / 1.5);
	unsigned int mp_flags = 0;
	char pool_name[25];
	int rc;

	cache_sz /= rte_lcore_count();
	/* Create chunk pool. */
	if (rcfg->flags & RTE_EVENT_TIMER_ADAPTER_F_SP_PUT) {
		mp_flags = MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET;
		plt_tim_dbg("Using single producer mode");
		tim_ring->prod_type_sp = true;
	}

	snprintf(pool_name, sizeof(pool_name), "cnxk_tim_chunk_pool%d",
		 tim_ring->ring_id);

	if (cache_sz > RTE_MEMPOOL_CACHE_MAX_SIZE)
		cache_sz = RTE_MEMPOOL_CACHE_MAX_SIZE;
	cache_sz = cache_sz != 0 ? cache_sz : 2;
	tim_ring->nb_chunks += (cache_sz * rte_lcore_count());
	if (!tim_ring->disable_npa) {
		tim_ring->chunk_pool = rte_mempool_create_empty(
			pool_name, tim_ring->nb_chunks, tim_ring->chunk_sz,
			cache_sz, 0, rte_socket_id(), mp_flags);

		if (tim_ring->chunk_pool == NULL) {
			plt_err("Unable to create chunkpool.");
			return -ENOMEM;
		}

		rc = rte_mempool_set_ops_byname(tim_ring->chunk_pool,
						rte_mbuf_platform_mempool_ops(),
						NULL);
		if (rc < 0) {
			plt_err("Unable to set chunkpool ops");
			goto free;
		}

		rc = rte_mempool_populate_default(tim_ring->chunk_pool);
		if (rc < 0) {
			plt_err("Unable to set populate chunkpool.");
			goto free;
		}
		tim_ring->aura = roc_npa_aura_handle_to_aura(
			tim_ring->chunk_pool->pool_id);
		tim_ring->ena_dfb = 0;
	} else {
		tim_ring->chunk_pool = rte_mempool_create(
			pool_name, tim_ring->nb_chunks, tim_ring->chunk_sz,
			cache_sz, 0, NULL, NULL, NULL, NULL, rte_socket_id(),
			mp_flags);
		if (tim_ring->chunk_pool == NULL) {
			plt_err("Unable to create chunkpool.");
			return -ENOMEM;
		}
		tim_ring->ena_dfb = 1;
	}

	return 0;

free:
	rte_mempool_free(tim_ring->chunk_pool);
	return rc;
}

static void
cnxk_tim_set_fp_ops(struct cnxk_tim_ring *tim_ring)
{
	uint8_t prod_flag = !tim_ring->prod_type_sp;

	/* [STATS] [DFB/FB] [SP][MP]*/
	const rte_event_timer_arm_burst_t arm_burst[2][2][2] = {
#define FP(_name, _f3, _f2, _f1, flags)                                        \
	[_f3][_f2][_f1] = cnxk_tim_arm_burst_##_name,
		TIM_ARM_FASTPATH_MODES
#undef FP
	};

	const rte_event_timer_arm_tmo_tick_burst_t arm_tmo_burst[2][2] = {
#define FP(_name, _f2, _f1, flags)                                             \
	[_f2][_f1] = cnxk_tim_arm_tmo_tick_burst_##_name,
		TIM_ARM_TMO_FASTPATH_MODES
#undef FP
	};

	cnxk_tim_ops.arm_burst =
		arm_burst[tim_ring->enable_stats][tim_ring->ena_dfb][prod_flag];
	cnxk_tim_ops.arm_tmo_tick_burst =
		arm_tmo_burst[tim_ring->enable_stats][tim_ring->ena_dfb];
	cnxk_tim_ops.cancel_burst = cnxk_tim_timer_cancel_burst;
}

static void
cnxk_tim_ring_info_get(const struct rte_event_timer_adapter *adptr,
		       struct rte_event_timer_adapter_info *adptr_info)
{
	struct cnxk_tim_ring *tim_ring = adptr->data->adapter_priv;

	adptr_info->max_tmo_ns = tim_ring->max_tout;
	adptr_info->min_resolution_ns = tim_ring->tck_nsec;
	rte_memcpy(&adptr_info->conf, &adptr->data->conf,
		   sizeof(struct rte_event_timer_adapter_conf));
}

static int
cnxk_tim_ring_create(struct rte_event_timer_adapter *adptr)
{
	struct rte_event_timer_adapter_conf *rcfg = &adptr->data->conf;
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();
	struct cnxk_tim_ring *tim_ring;
	int i, rc;

	if (dev == NULL)
		return -ENODEV;

	if (adptr->data->id >= dev->nb_rings)
		return -ENODEV;

	tim_ring = rte_zmalloc("cnxk_tim_prv", sizeof(struct cnxk_tim_ring), 0);
	if (tim_ring == NULL)
		return -ENOMEM;

	rc = roc_tim_lf_alloc(&dev->tim, adptr->data->id, NULL);
	if (rc < 0) {
		plt_err("Failed to create timer ring");
		goto tim_ring_free;
	}

	if (NSEC2TICK(RTE_ALIGN_MUL_CEIL(
			      rcfg->timer_tick_ns,
			      cnxk_tim_min_resolution_ns(cnxk_tim_cntfrq())),
		      cnxk_tim_cntfrq()) <
	    cnxk_tim_min_tmo_ticks(cnxk_tim_cntfrq())) {
		if (rcfg->flags & RTE_EVENT_TIMER_ADAPTER_F_ADJUST_RES)
			rcfg->timer_tick_ns = TICK2NSEC(
				cnxk_tim_min_tmo_ticks(cnxk_tim_cntfrq()),
				cnxk_tim_cntfrq());
		else {
			rc = -ERANGE;
			goto tim_hw_free;
		}
	}
	tim_ring->ring_id = adptr->data->id;
	tim_ring->clk_src = (int)rcfg->clk_src;
	tim_ring->tck_nsec = RTE_ALIGN_MUL_CEIL(
		rcfg->timer_tick_ns,
		cnxk_tim_min_resolution_ns(cnxk_tim_cntfrq()));
	tim_ring->max_tout = rcfg->max_tmo_ns;
	tim_ring->nb_bkts = (tim_ring->max_tout / tim_ring->tck_nsec);
	tim_ring->nb_timers = rcfg->nb_timers;
	tim_ring->chunk_sz = dev->chunk_sz;
	tim_ring->disable_npa = dev->disable_npa;
	tim_ring->enable_stats = dev->enable_stats;

	for (i = 0; i < dev->ring_ctl_cnt; i++) {
		struct cnxk_tim_ctl *ring_ctl = &dev->ring_ctl_data[i];

		if (ring_ctl->ring == tim_ring->ring_id) {
			tim_ring->chunk_sz =
				ring_ctl->chunk_slots ?
					((uint32_t)(ring_ctl->chunk_slots + 1) *
					 CNXK_TIM_CHUNK_ALIGNMENT) :
					      tim_ring->chunk_sz;
			tim_ring->enable_stats = ring_ctl->enable_stats;
			tim_ring->disable_npa = ring_ctl->disable_npa;
		}
	}

	if (tim_ring->disable_npa) {
		tim_ring->nb_chunks =
			tim_ring->nb_timers /
			CNXK_TIM_NB_CHUNK_SLOTS(tim_ring->chunk_sz);
		tim_ring->nb_chunks = tim_ring->nb_chunks * tim_ring->nb_bkts;
	} else {
		tim_ring->nb_chunks = tim_ring->nb_timers;
	}

	tim_ring->nb_chunk_slots = CNXK_TIM_NB_CHUNK_SLOTS(tim_ring->chunk_sz);
	/* Create buckets. */
	tim_ring->bkt =
		rte_zmalloc("cnxk_tim_bucket",
			    (tim_ring->nb_bkts) * sizeof(struct cnxk_tim_bkt),
			    RTE_CACHE_LINE_SIZE);
	if (tim_ring->bkt == NULL)
		goto tim_hw_free;

	rc = cnxk_tim_chnk_pool_create(tim_ring, rcfg);
	if (rc < 0)
		goto tim_bkt_free;

	rc = roc_tim_lf_config(
		&dev->tim, tim_ring->ring_id,
		cnxk_tim_convert_clk_src(tim_ring->clk_src), 0, 0,
		tim_ring->nb_bkts, tim_ring->chunk_sz,
		NSEC2TICK(tim_ring->tck_nsec, cnxk_tim_cntfrq()));
	if (rc < 0) {
		plt_err("Failed to configure timer ring");
		goto tim_chnk_free;
	}

	tim_ring->base = roc_tim_lf_base_get(&dev->tim, tim_ring->ring_id);
	plt_write64((uint64_t)tim_ring->bkt, tim_ring->base + TIM_LF_RING_BASE);
	plt_write64(tim_ring->aura, tim_ring->base + TIM_LF_RING_AURA);

	/* Set fastpath ops. */
	cnxk_tim_set_fp_ops(tim_ring);

	/* Update SSO xae count. */
	cnxk_sso_updt_xae_cnt(cnxk_sso_pmd_priv(dev->event_dev), tim_ring,
			      RTE_EVENT_TYPE_TIMER);
	cnxk_sso_xae_reconfigure(dev->event_dev);

	plt_tim_dbg(
		"Total memory used %" PRIu64 "MB\n",
		(uint64_t)(((tim_ring->nb_chunks * tim_ring->chunk_sz) +
			    (tim_ring->nb_bkts * sizeof(struct cnxk_tim_bkt))) /
			   BIT_ULL(20)));

	adptr->data->adapter_priv = tim_ring;
	return rc;

tim_chnk_free:
	rte_mempool_free(tim_ring->chunk_pool);
tim_bkt_free:
	rte_free(tim_ring->bkt);
tim_hw_free:
	roc_tim_lf_free(&dev->tim, tim_ring->ring_id);
tim_ring_free:
	rte_free(tim_ring);
	return rc;
}

static int
cnxk_tim_ring_free(struct rte_event_timer_adapter *adptr)
{
	struct cnxk_tim_ring *tim_ring = adptr->data->adapter_priv;
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();

	if (dev == NULL)
		return -ENODEV;

	roc_tim_lf_free(&dev->tim, tim_ring->ring_id);
	rte_free(tim_ring->bkt);
	rte_mempool_free(tim_ring->chunk_pool);
	rte_free(tim_ring);

	return 0;
}

static void
cnxk_tim_calibrate_start_tsc(struct cnxk_tim_ring *tim_ring)
{
#define CNXK_TIM_CALIB_ITER 1E6
	uint32_t real_bkt, bucket;
	int icount, ecount = 0;
	uint64_t bkt_cyc;

	for (icount = 0; icount < CNXK_TIM_CALIB_ITER; icount++) {
		real_bkt = plt_read64(tim_ring->base + TIM_LF_RING_REL) >> 44;
		bkt_cyc = cnxk_tim_cntvct();
		bucket = (bkt_cyc - tim_ring->ring_start_cyc) /
			 tim_ring->tck_int;
		bucket = bucket % (tim_ring->nb_bkts);
		tim_ring->ring_start_cyc =
			bkt_cyc - (real_bkt * tim_ring->tck_int);
		if (bucket != real_bkt)
			ecount++;
	}
	tim_ring->last_updt_cyc = bkt_cyc;
	plt_tim_dbg("Bucket mispredict %3.2f distance %d\n",
		    100 - (((double)(icount - ecount) / (double)icount) * 100),
		    bucket - real_bkt);
}

static int
cnxk_tim_ring_start(const struct rte_event_timer_adapter *adptr)
{
	struct cnxk_tim_ring *tim_ring = adptr->data->adapter_priv;
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();
	int rc;

	if (dev == NULL)
		return -ENODEV;

	rc = roc_tim_lf_enable(&dev->tim, tim_ring->ring_id,
			       &tim_ring->ring_start_cyc, NULL);
	if (rc < 0)
		return rc;

	tim_ring->tck_int = NSEC2TICK(tim_ring->tck_nsec, cnxk_tim_cntfrq());
	tim_ring->tot_int = tim_ring->tck_int * tim_ring->nb_bkts;
	tim_ring->fast_div = rte_reciprocal_value_u64(tim_ring->tck_int);
	tim_ring->fast_bkt = rte_reciprocal_value_u64(tim_ring->nb_bkts);

	cnxk_tim_calibrate_start_tsc(tim_ring);

	return rc;
}

static int
cnxk_tim_ring_stop(const struct rte_event_timer_adapter *adptr)
{
	struct cnxk_tim_ring *tim_ring = adptr->data->adapter_priv;
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();
	int rc;

	if (dev == NULL)
		return -ENODEV;

	rc = roc_tim_lf_disable(&dev->tim, tim_ring->ring_id);
	if (rc < 0)
		plt_err("Failed to disable timer ring");

	return rc;
}

static int
cnxk_tim_stats_get(const struct rte_event_timer_adapter *adapter,
		   struct rte_event_timer_adapter_stats *stats)
{
	struct cnxk_tim_ring *tim_ring = adapter->data->adapter_priv;
	uint64_t bkt_cyc = cnxk_tim_cntvct() - tim_ring->ring_start_cyc;

	stats->evtim_exp_count =
		__atomic_load_n(&tim_ring->arm_cnt, __ATOMIC_RELAXED);
	stats->ev_enq_count = stats->evtim_exp_count;
	stats->adapter_tick_count =
		rte_reciprocal_divide_u64(bkt_cyc, &tim_ring->fast_div);
	return 0;
}

static int
cnxk_tim_stats_reset(const struct rte_event_timer_adapter *adapter)
{
	struct cnxk_tim_ring *tim_ring = adapter->data->adapter_priv;

	__atomic_store_n(&tim_ring->arm_cnt, 0, __ATOMIC_RELAXED);
	return 0;
}

int
cnxk_tim_caps_get(const struct rte_eventdev *evdev, uint64_t flags,
		  uint32_t *caps, const struct event_timer_adapter_ops **ops)
{
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();

	RTE_SET_USED(flags);

	if (dev == NULL)
		return -ENODEV;

	cnxk_tim_ops.init = cnxk_tim_ring_create;
	cnxk_tim_ops.uninit = cnxk_tim_ring_free;
	cnxk_tim_ops.start = cnxk_tim_ring_start;
	cnxk_tim_ops.stop = cnxk_tim_ring_stop;
	cnxk_tim_ops.get_info = cnxk_tim_ring_info_get;

	if (dev->enable_stats) {
		cnxk_tim_ops.stats_get = cnxk_tim_stats_get;
		cnxk_tim_ops.stats_reset = cnxk_tim_stats_reset;
	}

	/* Store evdev pointer for later use. */
	dev->event_dev = (struct rte_eventdev *)(uintptr_t)evdev;
	*caps = RTE_EVENT_TIMER_ADAPTER_CAP_INTERNAL_PORT;
	*ops = &cnxk_tim_ops;

	return 0;
}

static void
cnxk_tim_parse_ring_param(char *value, void *opaque)
{
	struct cnxk_tim_evdev *dev = opaque;
	struct cnxk_tim_ctl ring_ctl = {0};
	char *tok = strtok(value, "-");
	struct cnxk_tim_ctl *old_ptr;
	uint16_t *val;

	val = (uint16_t *)&ring_ctl;

	if (!strlen(value))
		return;

	while (tok != NULL) {
		*val = atoi(tok);
		tok = strtok(NULL, "-");
		val++;
	}

	if (val != (&ring_ctl.enable_stats + 1)) {
		plt_err("Invalid ring param expected [ring-chunk_sz-disable_npa-enable_stats]");
		return;
	}

	dev->ring_ctl_cnt++;
	old_ptr = dev->ring_ctl_data;
	dev->ring_ctl_data =
		rte_realloc(dev->ring_ctl_data,
			    sizeof(struct cnxk_tim_ctl) * dev->ring_ctl_cnt, 0);
	if (dev->ring_ctl_data == NULL) {
		dev->ring_ctl_data = old_ptr;
		dev->ring_ctl_cnt--;
		return;
	}

	dev->ring_ctl_data[dev->ring_ctl_cnt - 1] = ring_ctl;
}

static void
cnxk_tim_parse_ring_ctl_list(const char *value, void *opaque)
{
	char *s = strdup(value);
	char *start = NULL;
	char *end = NULL;
	char *f = s;

	while (*s) {
		if (*s == '[')
			start = s;
		else if (*s == ']')
			end = s;

		if (start && start < end) {
			*end = 0;
			cnxk_tim_parse_ring_param(start + 1, opaque);
			start = end;
			s = end;
		}
		s++;
	}

	free(f);
}

static int
cnxk_tim_parse_kvargs_dict(const char *key, const char *value, void *opaque)
{
	RTE_SET_USED(key);

	/* Dict format [ring-chunk_sz-disable_npa-enable_stats] use '-' as ','
	 * isn't allowed. 0 represents default.
	 */
	cnxk_tim_parse_ring_ctl_list(value, opaque);

	return 0;
}

static void
cnxk_tim_parse_devargs(struct rte_devargs *devargs, struct cnxk_tim_evdev *dev)
{
	struct rte_kvargs *kvlist;

	if (devargs == NULL)
		return;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return;

	rte_kvargs_process(kvlist, CNXK_TIM_DISABLE_NPA, &parse_kvargs_flag,
			   &dev->disable_npa);
	rte_kvargs_process(kvlist, CNXK_TIM_CHNK_SLOTS, &parse_kvargs_value,
			   &dev->chunk_slots);
	rte_kvargs_process(kvlist, CNXK_TIM_STATS_ENA, &parse_kvargs_flag,
			   &dev->enable_stats);
	rte_kvargs_process(kvlist, CNXK_TIM_RINGS_LMT, &parse_kvargs_value,
			   &dev->min_ring_cnt);
	rte_kvargs_process(kvlist, CNXK_TIM_RING_CTL,
			   &cnxk_tim_parse_kvargs_dict, &dev);

	rte_kvargs_free(kvlist);
}

void
cnxk_tim_init(struct roc_sso *sso)
{
	const struct rte_memzone *mz;
	struct cnxk_tim_evdev *dev;
	int rc;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;

	mz = rte_memzone_reserve(RTE_STR(CNXK_TIM_EVDEV_NAME),
				 sizeof(struct cnxk_tim_evdev), 0, 0);
	if (mz == NULL) {
		plt_tim_dbg("Unable to allocate memory for TIM Event device");
		return;
	}
	dev = mz->addr;

	cnxk_tim_parse_devargs(sso->pci_dev->device.devargs, dev);

	dev->tim.roc_sso = sso;
	dev->tim.nb_lfs = dev->min_ring_cnt;
	rc = roc_tim_init(&dev->tim);
	if (rc < 0) {
		plt_err("Failed to initialize roc tim resources");
		rte_memzone_free(mz);
		return;
	}
	dev->nb_rings = rc;

	if (dev->chunk_slots && dev->chunk_slots <= CNXK_TIM_MAX_CHUNK_SLOTS &&
	    dev->chunk_slots >= CNXK_TIM_MIN_CHUNK_SLOTS) {
		dev->chunk_sz =
			(dev->chunk_slots + 1) * CNXK_TIM_CHUNK_ALIGNMENT;
	} else {
		dev->chunk_sz = CNXK_TIM_RING_DEF_CHUNK_SZ;
	}
}

void
cnxk_tim_fini(void)
{
	struct cnxk_tim_evdev *dev = cnxk_tim_priv_get();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;

	roc_tim_fini(&dev->tim);
	rte_memzone_free(rte_memzone_lookup(RTE_STR(CNXK_TIM_EVDEV_NAME)));
}
