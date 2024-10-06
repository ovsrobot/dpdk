/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hw_mod_backend.h"

#define _MOD_ "QSL"
#define _VER_ be->qsl.ver

#define QSL_QEN_ENTRIES 32
#define QSL_QNMQ_ENTRIES 256

bool hw_mod_qsl_present(struct flow_api_backend_s *be)
{
	return be->iface->get_qsl_present(be->be_dev);
}

int hw_mod_qsl_alloc(struct flow_api_backend_s *be)
{
	int nb;
	_VER_ = be->iface->get_qsl_version(be->be_dev);
	NT_LOG(DBG, FILTER, "QSL MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_), VER_MINOR(_VER_));

	nb = be->iface->get_nb_qsl_categories(be->be_dev);

	if (nb <= 0)
		return COUNT_ERROR(qsl_categories);

	be->qsl.nb_rcp_categories = (uint32_t)nb;

	nb = be->iface->get_nb_qsl_qst_entries(be->be_dev);

	if (nb <= 0)
		return COUNT_ERROR(qsl_qst_entries);

	be->qsl.nb_qst_entries = (uint32_t)nb;

	switch (_VER_) {
	case 7:
		if (!callocate_mod((struct common_func_s *)&be->qsl, 4, &be->qsl.v7.rcp,
				be->qsl.nb_rcp_categories, sizeof(struct qsl_v7_rcp_s),
				&be->qsl.v7.qst, be->qsl.nb_qst_entries,
				sizeof(struct qsl_v7_qst_s), &be->qsl.v7.qen, QSL_QEN_ENTRIES,
				sizeof(struct qsl_v7_qen_s), &be->qsl.v7.unmq, QSL_QNMQ_ENTRIES,
				sizeof(struct qsl_v7_unmq_s)))
			return -1;

		break;

	/* end case 7 */
	default:
		return UNSUP_VER;
	}

	return 0;
}

void hw_mod_qsl_free(struct flow_api_backend_s *be)
{
	if (be->qsl.base) {
		free(be->qsl.base);
		be->qsl.base = NULL;
	}
}

int hw_mod_qsl_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	zero_module_cache((struct common_func_s *)(&be->qsl));

	NT_LOG(DBG, FILTER, "INIT QSL RCP\n");
	hw_mod_qsl_rcp_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL QST\n");
	hw_mod_qsl_qst_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL QEN\n");
	hw_mod_qsl_qen_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL UNMQ\n");
	be->iface->qsl_unmq_flush(be->be_dev, &be->qsl, 0, 256);

	return 0;
}

int hw_mod_qsl_rcp_flush(struct flow_api_backend_s *be, int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = be->qsl.nb_rcp_categories;

	if ((unsigned int)(start_idx + count) > be->qsl.nb_rcp_categories)
		return INDEX_TOO_LARGE;

	return be->iface->qsl_rcp_flush(be->be_dev, &be->qsl, start_idx, count);
}

int hw_mod_qsl_qst_flush(struct flow_api_backend_s *be, int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = be->qsl.nb_qst_entries;

	if ((unsigned int)(start_idx + count) > be->qsl.nb_qst_entries)
		return INDEX_TOO_LARGE;

	return be->iface->qsl_qst_flush(be->be_dev, &be->qsl, start_idx, count);
}

int hw_mod_qsl_qen_flush(struct flow_api_backend_s *be, int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = QSL_QEN_ENTRIES;

	if ((start_idx + count) > QSL_QEN_ENTRIES)
		return INDEX_TOO_LARGE;

	return be->iface->qsl_qen_flush(be->be_dev, &be->qsl, start_idx, count);
}

int hw_mod_qsl_unmq_flush(struct flow_api_backend_s *be, int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = QSL_QNMQ_ENTRIES;

	if ((start_idx + count) > QSL_QNMQ_ENTRIES)
		return INDEX_TOO_LARGE;

	return be->iface->qsl_unmq_flush(be->be_dev, &be->qsl, start_idx, count);
}

static int hw_mod_qsl_unmq_mod(struct flow_api_backend_s *be, enum hw_qsl_e field, uint32_t index,
	uint32_t *value, int get)
{
	if (index >= QSL_QNMQ_ENTRIES)
		return INDEX_TOO_LARGE;

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_QSL_UNMQ_DEST_QUEUE:
			GET_SET(be->qsl.v7.unmq[index].dest_queue, value);
			break;

		case HW_QSL_UNMQ_EN:
			GET_SET(be->qsl.v7.unmq[index].en, value);
			break;

		default:
			return UNSUP_FIELD;
		}

		break;

	/* end case 7 */
	default:
		return UNSUP_VER;
	}

	return 0;
}

int hw_mod_qsl_unmq_set(struct flow_api_backend_s *be, enum hw_qsl_e field, uint32_t index,
	uint32_t value)
{
	return hw_mod_qsl_unmq_mod(be, field, index, &value, 0);
}
