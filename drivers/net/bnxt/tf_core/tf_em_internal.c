/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2020 Broadcom
 * All rights reserved.
 */

#include <string.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>

#include "tf_core.h"
#include "tf_util.h"
#include "tf_common.h"
#include "tf_em.h"
#include "tf_msg.h"
#include "tfp.h"
#include "tf_ext_flow_handle.h"

#include "bnxt.h"

/**
 * EM DBs.
 */
static void *em_db[TF_DIR_MAX];

/**
 * Init flag, set on bind and cleared on unbind
 */
static uint8_t init;

/**
 * Create EM Tbl pool of memory indexes.
 *
 * [in] session
 *   Pointer to session
 * [in] dir
 *   direction
 * [in] num_entries
 *   number of entries to write
 *
 * Return:
 *  0       - Success, entry allocated - no search support
 *  -ENOMEM -EINVAL -EOPNOTSUPP
 *          - Failure, entry not allocated, out of resources
 */
static int
tf_create_em_pool(struct tf_session *session,
		  enum tf_dir dir,
		  uint32_t num_entries)
{
	struct tfp_calloc_parms parms;
	uint32_t i, j;
	int rc = 0;
	struct stack *pool = &session->em_pool[dir];

	parms.nitems = num_entries;
	parms.size = sizeof(uint32_t);
	parms.alignment = 0;

	rc = tfp_calloc(&parms);

	if (rc) {
		TFP_DRV_LOG(ERR, "EM pool allocation failure %s\n",
			    strerror(-rc));
		return rc;
	}

	/* Create empty stack
	 */
	rc = stack_init(num_entries, (uint32_t *)parms.mem_va, pool);

	if (rc) {
		TFP_DRV_LOG(ERR, "EM pool stack init failure %s\n",
			    strerror(-rc));
		goto cleanup;
	}

	/* Fill pool with indexes
	 */
	j = num_entries - 1;

	for (i = 0; i < num_entries; i++) {
		rc = stack_push(pool, j);
		if (rc) {
			TFP_DRV_LOG(ERR, "EM pool stack push failure %s\n",
				    strerror(-rc));
			goto cleanup;
		}
		j--;
	}

	if (!stack_is_full(pool)) {
		rc = -EINVAL;
		TFP_DRV_LOG(ERR, "EM pool stack failure %s\n",
			    strerror(-rc));
		goto cleanup;
	}

	return 0;
cleanup:
	tfp_free((void *)parms.mem_va);
	return rc;
}

/**
 * Create EM Tbl pool of memory indexes.
 *
 * [in] session
 *   Pointer to session
 * [in] dir
 *   direction
 *
 * Return:
 */
static void
tf_free_em_pool(struct tf_session *session,
		enum tf_dir dir)
{
	struct stack *pool = &session->em_pool[dir];
	uint32_t *ptr;

	ptr = stack_items(pool);

	if (ptr != NULL)
		tfp_free(ptr);
}

/**
 * Insert EM internal entry API
 *
 *  returns:
 *     0 - Success
 */
int
tf_em_insert_int_entry(struct tf *tfp,
		       struct tf_insert_em_entry_parms *parms)
{
	int rc;
	uint32_t gfid;
	uint16_t rptr_index = 0;
	uint8_t rptr_entry = 0;
	uint8_t num_of_entries = 0;
	struct tf_session *session =
		(struct tf_session *)(tfp->session->core_data);
	struct stack *pool = &session->em_pool[parms->dir];
	uint32_t index;

	rc = stack_pop(pool, &index);

	if (rc) {
		PMD_DRV_LOG
		  (ERR,
		   "dir:%d, EM entry index allocation failed\n",
		   parms->dir);
		return rc;
	}

	rptr_index = index * TF_SESSION_EM_ENTRY_SIZE;
	rc = tf_msg_insert_em_internal_entry(tfp,
					     parms,
					     &rptr_index,
					     &rptr_entry,
					     &num_of_entries);
	if (rc)
		return -1;

	PMD_DRV_LOG
		  (ERR,
		   "Internal entry @ Index:%d rptr_index:0x%x rptr_entry:0x%x num_of_entries:%d\n",
		   index * TF_SESSION_EM_ENTRY_SIZE,
		   rptr_index,
		   rptr_entry,
		   num_of_entries);

	TF_SET_GFID(gfid,
		    ((rptr_index << TF_EM_INTERNAL_INDEX_SHIFT) |
		     rptr_entry),
		    0); /* N/A for internal table */

	TF_SET_FLOW_ID(parms->flow_id,
		       gfid,
		       TF_GFID_TABLE_INTERNAL,
		       parms->dir);

	TF_SET_FIELDS_IN_FLOW_HANDLE(parms->flow_handle,
				     (uint32_t)num_of_entries,
				     0,
				     0,
				     rptr_index,
				     rptr_entry,
				     0);
	return 0;
}


/** Delete EM internal entry API
 *
 * returns:
 * 0
 * -EINVAL
 */
int
tf_em_delete_int_entry(struct tf *tfp,
		       struct tf_delete_em_entry_parms *parms)
{
	int rc = 0;
	struct tf_session *session =
		(struct tf_session *)(tfp->session->core_data);
	struct stack *pool = &session->em_pool[parms->dir];

	rc = tf_msg_delete_em_entry(tfp, parms);

	/* Return resource to pool */
	if (rc == 0)
		stack_push(pool, parms->index / TF_SESSION_EM_ENTRY_SIZE);

	return rc;
}

int
tf_em_int_bind(struct tf *tfp,
	       struct tf_em_cfg_parms *parms)
{
	int rc;
	int i;
	struct tf_rm_create_db_parms db_cfg = { 0 };
	struct tf_session *session;

	TF_CHECK_PARMS2(tfp, parms);

	if (init) {
		TFP_DRV_LOG(ERR,
			    "Identifier already initialized\n");
		return -EINVAL;
	}

	session = (struct tf_session *)tfp->session->core_data;

	for (i = 0; i < TF_DIR_MAX; i++) {
		tf_create_em_pool(session,
				  i,
				  TF_SESSION_EM_POOL_SIZE);
	}

	/*
	 * I'm not sure that this code is needed.
	 * leaving for now until resolved
	 */
	if (parms->num_elements) {
		db_cfg.type = TF_DEVICE_MODULE_TYPE_EM;
		db_cfg.num_elements = parms->num_elements;
		db_cfg.cfg = parms->cfg;

		for (i = 0; i < TF_DIR_MAX; i++) {
			db_cfg.dir = i;
			db_cfg.alloc_cnt = parms->resources->em_cnt[i].cnt;
			db_cfg.rm_db = &em_db[i];
			rc = tf_rm_create_db(tfp, &db_cfg);
			if (rc) {
				TFP_DRV_LOG(ERR,
					    "%s: EM DB creation failed\n",
					    tf_dir_2_str(i));

				return rc;
			}
		}
	}

	init = 1;
	return 0;
}

int
tf_em_int_unbind(struct tf *tfp)
{
	int rc;
	int i;
	struct tf_rm_free_db_parms fparms = { 0 };
	struct tf_session *session;

	TF_CHECK_PARMS1(tfp);

	/* Bail if nothing has been initialized done silent as to
	 * allow for creation cleanup.
	 */
	if (!init) {
		TFP_DRV_LOG(ERR,
			    "No EM DBs created\n");
		return -EINVAL;
	}

	session = (struct tf_session *)tfp->session->core_data;

	for (i = 0; i < TF_DIR_MAX; i++)
		tf_free_em_pool(session, i);

	for (i = 0; i < TF_DIR_MAX; i++) {
		fparms.dir = i;
		fparms.rm_db = em_db[i];
		if (em_db[i] != NULL) {
			rc = tf_rm_free_db(tfp, &fparms);
			if (rc)
				return rc;
		}

		em_db[i] = NULL;
	}

	init = 0;

	return 0;
}
