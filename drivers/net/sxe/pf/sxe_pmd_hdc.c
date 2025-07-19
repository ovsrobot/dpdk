/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include <rte_malloc.h>
#include <ethdev_driver.h>
#include "sxe_compat_version.h"
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>
#include "sxe_pmd_hdc.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe.h"
#include "sxe_msg.h"
#include "drv_msg.h"
#include "sxe_errno.h"
#include "sxe_common.h"

static sem_t g_hdc_sem;

#define SXE_SUCCESS			(0)

#define SXE_HDC_TRYLOCK_MAX		200

#define SXE_HDC_RELEASELOCK_MAX		20
#define SXE_HDC_WAIT_TIME		1000
#define SXE_HDC_BIT_1			0x1
#define ONE_DWORD_LEN			(4)

static sem_t *sxe_hdc_sema_get(void)
{
	return &g_hdc_sem;
}

void sxe_hdc_channel_init(void)
{
	s32 ret;
	ret = sem_init(sxe_hdc_sema_get(), 0, 1);
	if (ret)
		PMD_LOG_ERR(INIT, "hdc sem init failed, ret=%d", ret);

	sxe_trace_id_gen();
}

void sxe_hdc_channel_uninit(void)
{
	sem_destroy(sxe_hdc_sema_get());
	sxe_trace_id_clean();
}

static s32 sxe_fw_time_sync_process(struct sxe_hw *hw)
{
	s32 ret;
	u64 timestamp = sxe_time_get_real_ms();
	struct sxe_adapter *adapter = hw->adapter;

	LOG_DEBUG_BDF("sync time= %" SXE_PRIU64 "ms", timestamp);
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_TINE_SYNC,
				(void *)&timestamp, sizeof(timestamp),
				NULL, 0);
	if (ret)
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:time sync", ret);

	return ret;
}

s32 sxe_fw_time_sync(struct sxe_hw *hw)
{
	s32 ret = 0;
	s32 ret_v;
	u32 status;
	struct sxe_adapter *adapter = hw->adapter;

	status = sxe_hw_hdc_fw_status_get(hw);
	if (status != SXE_FW_START_STATE_FINISHED) {
		LOG_ERROR_BDF("fw[%p] status[0x%x] is not good", hw, status);
		ret = -SXE_FW_STATUS_ERR;
		goto l_ret;
	}

	ret_v = sxe_fw_time_sync_process(hw);
	if (ret_v) {
		LOG_WARN_BDF("fw time sync failed, ret_v=%d", ret_v);
		goto l_ret;
	}

l_ret:
	return ret;
}

static inline s32 sxe_hdc_lock_get(struct sxe_hw *hw)
{
	return sxe_hw_hdc_lock_get(hw, SXE_HDC_TRYLOCK_MAX);
}

static inline void sxe_hdc_lock_release(struct sxe_hw *hw)
{
	sxe_hw_hdc_lock_release(hw, SXE_HDC_RELEASELOCK_MAX);
}

static inline s32 sxe_poll_fw_ack(struct sxe_hw *hw, u32 timeout)
{
	s32 ret = 0;
	u32 i;
	bool fw_ov = false;
	struct sxe_adapter *adapter = hw->adapter;

	for (i = 0; i < timeout; i++) {
		fw_ov = sxe_hw_hdc_is_fw_over_set(hw);
		if (fw_ov)
			break;

		mdelay(10);
	}

	if (i >= timeout) {
		LOG_ERROR_BDF("poll fw_ov timeout...");
		ret = -SXE_ERR_HDC_FW_OV_TIMEOUT;
		goto l_ret;
	}

	sxe_hw_hdc_fw_ov_clear(hw);
l_ret:
	return ret;
}

static inline void hdc_channel_clear(struct sxe_hw *hw)
{
	sxe_hw_hdc_fw_ov_clear(hw);
}

static s32 hdc_packet_ack_get(struct sxe_hw *hw, u64 trace_id,
				hdc_header_u *pkt_header)
{
	s32 ret	 = 0;
	u32 timeout = SXE_HDC_WAIT_TIME;
	struct sxe_adapter *adapter = hw->adapter;
	UNUSED(trace_id);

	pkt_header->dw0 = 0;
	pkt_header->head.err_code = PKG_ERR_OTHER;

	LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " hdc cmd ack get start", trace_id);
	ret = sxe_poll_fw_ack(hw, timeout);
	if (ret) {
		LOG_ERROR_BDF("get fw ack failed, ret=%d", ret);
		goto l_out;
	}

	pkt_header->dw0 = sxe_hw_hdc_fw_ack_header_get(hw);
	if (pkt_header->head.err_code == PKG_ERR_PKG_SKIP) {
		ret = -SXE_HDC_PKG_SKIP_ERR;
		goto l_out;
	} else if (pkt_header->head.err_code != PKG_OK) {
		ret = -SXE_HDC_PKG_OTHER_ERR;
		goto l_out;
	}

l_out:
	LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " hdc cmd ack get end ret=%d", trace_id, ret);
	return ret;
}

static void hdc_packet_header_fill(hdc_header_u *pkt_header,
			u8 pkt_index, u16 total_len,
			u16 pkt_num, u8 is_read)
{
	u16 pkt_len = 0;

	pkt_header->dw0 = 0;

	pkt_header->head.pid = (is_read == 0) ? pkt_index : (pkt_index - 1);

	pkt_header->head.total_len = SXE_HDC_LEN_TO_REG(total_len);

	if (pkt_index == 0 && is_read == 0)
		pkt_header->head.start_pkg = SXE_HDC_BIT_1;

	if (pkt_index == (pkt_num - 1)) {
		pkt_header->head.end_pkg = SXE_HDC_BIT_1;
		pkt_len = total_len - (DWORD_NUM * (pkt_num - 1));
	} else {
		pkt_len = DWORD_NUM;
	}

	pkt_header->head.len  = SXE_HDC_LEN_TO_REG(pkt_len);
	pkt_header->head.is_rd = is_read;
	pkt_header->head.msi = 0;
}

static inline void hdc_packet_send_done(struct sxe_hw *hw)
{
	sxe_hw_hdc_packet_send_done(hw);
}

static inline void hdc_packet_header_send(struct sxe_hw *hw,
							u32 header)
{
	sxe_hw_hdc_packet_header_send(hw, header);
}

static inline void hdc_packet_data_dword_send(struct sxe_hw *hw,
						u16 dword_index, u32 value)
{
	sxe_hw_hdc_packet_data_dword_send(hw, dword_index, value);
}

static void hdc_packet_send(struct sxe_hw *hw, u64 trace_id,
			hdc_header_u *pkt_header, u8 *data,
			u16 data_len)
{
	u16		  dw_idx   = 0;
	u16		  pkt_len	   = 0;
	u16		  offset		= 0;
	u32		  pkg_data	  = 0;
	struct sxe_adapter *adapter = hw->adapter;
	UNUSED(trace_id);

	LOG_DEBUG_BDF("hw_addr[%p] trace_id=0x%" SXE_PRIX64 " send pkt pkg_header[0x%x], "
		"data_addr[%p], data_len[%u]",
		hw, trace_id, pkt_header->dw0, data, data_len);

	hdc_packet_header_send(hw, pkt_header->dw0);

	if (data == NULL || data_len == 0)
		goto l_send_done;

	pkt_len = SXE_HDC_LEN_FROM_REG(pkt_header->head.len);
	for (dw_idx = 0; dw_idx < pkt_len; dw_idx++) {
		pkg_data = 0;

		offset = dw_idx * 4;

		if (pkt_header->head.end_pkg == SXE_HDC_BIT_1 &&
			(dw_idx == (pkt_len - 1)) &&
			(data_len % 4 != 0)) {
			memcpy((u8 *)&pkg_data, data + offset,
					data_len % ONE_DWORD_LEN);
		} else {
			pkg_data = *(u32 *)(data + offset);
		}

		LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " send data to reg[%u] dword[0x%x]",
				trace_id, dw_idx, pkg_data);
		hdc_packet_data_dword_send(hw, dw_idx, pkg_data);
	}

l_send_done:
	hdc_channel_clear(hw);

	hdc_packet_send_done(hw);
}

static inline u32 hdc_packet_data_dword_rcv(struct sxe_hw *hw,
						u16 dword_index)
{
	return sxe_hw_hdc_packet_data_dword_rcv(hw, dword_index);
}

static void hdc_resp_data_rcv(struct sxe_hw *hw, u64 trace_id,
				hdc_header_u *pkt_header, u8 *out_data,
				u16 out_len)
{
	u16		  dw_idx	  = 0;
	u16		  dw_num	  = 0;
	u16		  offset = 0;
	u32		  pkt_data;
	struct sxe_adapter *adapter = hw->adapter;
	UNUSED(trace_id);

	dw_num = SXE_HDC_LEN_FROM_REG(pkt_header->head.len);
	for (dw_idx = 0; dw_idx < dw_num; dw_idx++) {
		pkt_data = hdc_packet_data_dword_rcv(hw, dw_idx);
		offset = dw_idx * ONE_DWORD_LEN;
		LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " get data from reg[%u] dword=0x%x",
				trace_id, dw_idx, pkt_data);

		if (pkt_header->head.end_pkg == SXE_HDC_BIT_1 &&
			(dw_idx == (dw_num - 1)) && (out_len % 4 != 0)) {
			memcpy(out_data + offset, (u8 *)&pkt_data,
					out_len % ONE_DWORD_LEN);
		} else {
			*(u32 *)(out_data + offset) = pkt_data;
		}
	}
}

static s32 hdc_req_process(struct sxe_hw *hw, u64 trace_id,
			u8 *in_data, u16 in_len)
{
	s32 ret = 0;
	u32 total_len	= 0;
	u16 pkt_num	 = 0;
	u16 index	   = 0;
	u16 offset	  = 0;
	hdc_header_u	 pkt_header;
	bool is_retry   = false;
	struct sxe_adapter *adapter = hw->adapter;

	total_len  = (in_len + ONE_DWORD_LEN - 1) / ONE_DWORD_LEN;

	pkt_num = (in_len + ONE_PACKET_LEN_MAX - 1) / ONE_PACKET_LEN_MAX;
	LOG_DEBUG_BDF("hw[%p] trace_id=0x%" SXE_PRIX64 " req in_data[%p] in_len=%u, "
			"total_len=%uDWORD, pkt_num = %u",
			hw, trace_id, in_data, in_len, total_len,
			pkt_num);

	for (index = 0; index < pkt_num; index++) {
		LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " fill pkg header[%p], pkg_index[%u], "
			"total_Len[%u], pkg_num[%u], is_read[no]",
			trace_id, &pkt_header, index, total_len, pkt_num);
		hdc_packet_header_fill(&pkt_header, index, total_len,
						pkt_num, 0);

		offset = index * DWORD_NUM * 4;
		hdc_packet_send(hw, trace_id, &pkt_header,
				in_data + offset, in_len);

		if (index == pkt_num - 1)
			break;

		ret = hdc_packet_ack_get(hw, trace_id, &pkt_header);
		if (ret == -EINTR) {
			LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " interrupted", trace_id);
			goto l_out;
		} else if (ret == -SXE_HDC_PKG_SKIP_ERR) {
			LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " req ack "
					"failed, retry", trace_id);
			if (is_retry) {
				ret = -SXE_HDC_RETRY_ERR;
				goto l_out;
			}

			index--;
			is_retry = true;
			continue;
		} else if (ret != SXE_HDC_SUCCESS) {
			LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " req ack "
					"failed, ret=%d", trace_id, ret);
			ret = -SXE_HDC_RETRY_ERR;
			goto l_out;
		}

		LOG_DEBUG_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " get req packet_index[%u]"
			" ack succeed header[0x%x]",
			trace_id, index, pkt_header.dw0);
		is_retry = false;
	}

l_out:
	return ret;
}

static s32 hdc_resp_process(struct sxe_hw *hw, u64 trace_id,
			u8 *out_data, u16 out_len)
{
	s32		  ret;
	u32		  req_dwords;
	u32		  resp_len;
	u32		  resp_dwords;
	u16		  pkt_num;
	u16		  index;
	u16		  offset;
	hdc_header_u  pkt_header;
	bool	 retry		  = false;
	struct sxe_adapter *adapter = hw->adapter;

	LOG_DEBUG_BDF("hdc trace_id=0x%" SXE_PRIX64 " req's last cmd ack get", trace_id);
	ret = hdc_packet_ack_get(hw, trace_id, &pkt_header);
	if (ret == -EINTR) {
		LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " interrupted", trace_id);
		goto l_out;
	} else if (ret) {
		LOG_ERROR_BDF("hdc trace_id=0x%" SXE_PRIX64 " ack get failed, ret=%d",
				trace_id, ret);
		ret = -SXE_HDC_RETRY_ERR;
		goto l_out;
	}

	LOG_DEBUG_BDF("hdc trace_id=0x%" SXE_PRIX64 " req's last cmd ack get "
		"succeed header[0x%x]", trace_id, pkt_header.dw0);

	if (!pkt_header.head.start_pkg) {
		ret = -SXE_HDC_RETRY_ERR;
		LOG_ERROR_BDF("trace_id=0x%" SXE_PRIX64 " ack header has error："
				"not set start bit", trace_id);
		goto l_out;
	}

	req_dwords = (out_len + ONE_DWORD_LEN - 1) / ONE_DWORD_LEN;
	resp_dwords  = SXE_HDC_LEN_FROM_REG(pkt_header.head.total_len);
	if (resp_dwords > req_dwords) {
		ret = -SXE_HDC_RETRY_ERR;
		LOG_ERROR_BDF("trace_id=0x%" SXE_PRIX64 " rsv len check failed:"
				"resp_dwords=%u, req_dwords=%u", trace_id,
				resp_dwords, req_dwords);
		goto l_out;
	}

	resp_len = resp_dwords << 2;
	LOG_DEBUG_BDF("outlen = %u bytes, resp_len = %u bytes", out_len, resp_len);
	if (resp_len > out_len)
		resp_len = out_len;

	hdc_resp_data_rcv(hw, trace_id, &pkt_header, out_data, resp_len);

	pkt_num = (resp_len + ONE_PACKET_LEN_MAX - 1) / ONE_PACKET_LEN_MAX;
	for (index = 1; index < pkt_num; index++) {
		LOG_DEBUG_BDF("trace_id=0x%" SXE_PRIX64 " fill pkg header[%p], pkg_index[%u], "
			"total_Len[%u], pkg_num[%u], is_read[yes]",
			trace_id, &pkt_header, index, resp_dwords,
			pkt_num);
		hdc_packet_header_fill(&pkt_header, index, resp_dwords,
					pkt_num, 1);

		hdc_packet_send(hw, trace_id, &pkt_header, NULL, 0);

		ret = hdc_packet_ack_get(hw, trace_id, &pkt_header);
		if (ret == -EINTR) {
			LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " interrupted", trace_id);
			goto l_out;
		} else if (ret == -SXE_HDC_PKG_SKIP_ERR) {
			LOG_ERROR_BDF("trace_id=0x%" SXE_PRIX64 " hdc resp ack polling "
					"failed, ret=%d", trace_id, ret);
			if (retry) {
				ret = -SXE_HDC_RETRY_ERR;
				goto l_out;
			}

			index--;
			retry = true;
			continue;
		} else if (ret != SXE_HDC_SUCCESS) {
			LOG_ERROR_BDF("trace_id=0x%" SXE_PRIX64 " hdc resp ack polling "
					"failed, ret=%d", trace_id, ret);
			ret = -SXE_HDC_RETRY_ERR;
			goto l_out;
		}

		LOG_DEBUG_BDF("hdc trace_id=0x%" SXE_PRIX64 " resp pkt[%u] get "
			"succeed header[0x%x]",
			trace_id, index, pkt_header.dw0);

		retry = false;

		offset = index * DWORD_NUM * 4;
		hdc_resp_data_rcv(hw, trace_id, &pkt_header,
					out_data + offset, resp_len);
	}

l_out:
	return ret;
}

static s32 sxe_hdc_packet_trans(struct sxe_hw *hw, u64 trace_id,
					struct sxe_hdc_trans_info *trans_info)
{
	s32 ret = SXE_SUCCESS;
	u32 status;
	struct sxe_adapter *adapter = hw->adapter;
	u32 channel_state;

	status = sxe_hw_hdc_fw_status_get(hw);
	if (status != SXE_FW_START_STATE_FINISHED) {
		LOG_ERROR_BDF("fw[%p] status[0x%x] is not good", hw, status);
		ret = -SXE_FW_STATUS_ERR;
		goto l_ret;
	}

	channel_state = sxe_hw_hdc_channel_state_get(hw);
	if (channel_state != SXE_FW_HDC_TRANSACTION_IDLE) {
		LOG_ERROR_BDF("hdc channel state is busy");
		ret = -SXE_HDC_RETRY_ERR;
		goto l_ret;
	}

	ret = sxe_hdc_lock_get(hw);
	if (ret) {
		LOG_ERROR_BDF("hw[%p] cmd trace_id=0x%" SXE_PRIX64 " get hdc lock fail, ret=%d",
				hw, trace_id, ret);
		ret = -SXE_HDC_RETRY_ERR;
		goto l_ret;
	}

	ret = hdc_req_process(hw, trace_id, trans_info->in.data,
				trans_info->in.len);
	if (ret) {
		LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " req process "
				"failed, ret=%d", trace_id, ret);
		goto l_hdc_lock_release;
	}

	ret = hdc_resp_process(hw, trace_id, trans_info->out.data,
				trans_info->out.len);
	if (ret) {
		LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " resp process "
				"failed, ret=%d", trace_id, ret);
	}

l_hdc_lock_release:
	sxe_hdc_lock_release(hw);
l_ret:
	return ret;
}

static s32 sxe_hdc_cmd_process(struct sxe_hw *hw, u64 trace_id,
				struct sxe_hdc_trans_info *trans_info)
{
	s32 ret;
	u8 retry_idx;
	struct sxe_adapter *adapter = hw->adapter;
	sigset_t old_mask, new_mask;
	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGINT);
	sigaddset(&new_mask, SIGTERM);
	ret = pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);
	if (ret) {
		LOG_ERROR_BDF("hdc set signal mask failed, ret=%d", ret);
		goto l_ret;
	}

	LOG_DEBUG_BDF("hw[%p] cmd trace=0x%" SXE_PRIX64 "", hw, trace_id);

	ret = sem_wait(sxe_hdc_sema_get());
	if (ret) {
		LOG_WARN_BDF("hw[%p] hdc concurrency full", hw);
		goto l_ret;
	}

	for (retry_idx = 0; retry_idx < 250; retry_idx++) {
		ret = sxe_hdc_packet_trans(hw, trace_id, trans_info);
		if (ret == SXE_SUCCESS) {
			goto l_up;
		} else if (ret == -SXE_HDC_RETRY_ERR) {
			rte_delay_ms(10);
			continue;
		} else {
			LOG_ERROR_BDF("sxe hdc packet trace_id=0x%" SXE_PRIX64
					" trans error, ret=%d", trace_id, ret);
			ret = -EFAULT;
			goto l_up;
		}
	}

l_up:
	LOG_DEBUG_BDF("hw[%p] cmd trace=0x%" SXE_PRIX64 "", hw, trace_id);
	sem_post(sxe_hdc_sema_get());
l_ret:
	ret = pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	if (ret)
		LOG_ERROR_BDF("hdc restore old signal mask failed, ret=%d", ret);

	if (ret == -SXE_HDC_RETRY_ERR)
		ret = -EFAULT;

	return ret;
}

static void sxe_cmd_hdr_init(struct sxe_hdc_cmd_hdr *cmd_hdr,
					u8 cmd_type)
{
	cmd_hdr->cmd_type = cmd_type;
	cmd_hdr->cmd_sub_type = 0;
}

static void sxe_driver_cmd_msg_init(struct sxe_hdc_drv_cmd_msg *msg,
						u16 opcode, u64 trace_id,
						void *req_data, u16 req_len)
{
	LOG_DEBUG("cmd[opcode=0x%x], trace=0x%" SXE_PRIX64 ", req_data_len=%u start init",
			opcode, trace_id, req_len);
	msg->opcode = opcode;
	msg->length.req_len = SXE_HDC_MSG_HDR_SIZE + req_len;
	msg->traceid = trace_id;

	if (req_data && req_len != 0)
		memcpy(msg->body, (u8 *)req_data, req_len);
}

static void sxe_hdc_trans_info_init(struct sxe_hdc_trans_info *trans_info,
					u8 *in_data_buf, u16 in_len,
					u8 *out_data_buf, u16 out_len)
{
	trans_info->in.data  = in_data_buf;
	trans_info->in.len   = in_len;
	trans_info->out.data = out_data_buf;
	trans_info->out.len  = out_len;
}

s32 sxe_driver_cmd_trans(struct sxe_hw *hw, u16 opcode,
					void *req_data, u16 req_len,
					void *resp_data, u16 resp_len)
{
	s32 ret = SXE_SUCCESS;
	struct sxe_hdc_cmd_hdr *cmd_hdr;
	struct sxe_hdc_drv_cmd_msg *msg;
	struct sxe_hdc_drv_cmd_msg *ack;
	struct sxe_hdc_trans_info trans_info;
	struct sxe_adapter *adapter = hw->adapter;

	u8 *in_data_buf;
	u8 *out_data_buf;
	u16 in_len;
	u16 out_len;
	u64 trace_id = 0;
	u16 ack_data_len;

	in_len = SXE_HDC_CMD_HDR_SIZE + SXE_HDC_MSG_HDR_SIZE + req_len;
	out_len = SXE_HDC_CMD_HDR_SIZE + SXE_HDC_MSG_HDR_SIZE + resp_len;

	trace_id = sxe_trace_id_get();

	in_data_buf = rte_zmalloc("pmd hdc in buffer", in_len, RTE_CACHE_LINE_SIZE);
	if (in_data_buf == NULL) {
		LOG_ERROR_BDF("cmd trace_id=0x%" SXE_PRIX64 " kzalloc indata "
				"mem len[%u] failed", trace_id, in_len);
		ret = -ENOMEM;
		goto l_ret;
	}

	out_data_buf = rte_zmalloc("pmd hdc out buffer", out_len, RTE_CACHE_LINE_SIZE);
	if (out_data_buf == NULL) {
		LOG_ERROR_BDF("cmd trace_id=0x%" SXE_PRIX64 " kzalloc out_data "
				"mem len[%u] failed", trace_id, out_len);
		ret = -ENOMEM;
		goto l_in_buf_free;
	}

	cmd_hdr = (struct sxe_hdc_cmd_hdr *)in_data_buf;
	sxe_cmd_hdr_init(cmd_hdr, SXE_CMD_TYPE_DRV);

	msg = (struct sxe_hdc_drv_cmd_msg *)((u8 *)in_data_buf + SXE_HDC_CMD_HDR_SIZE);
	sxe_driver_cmd_msg_init(msg, opcode, trace_id, req_data, req_len);

	LOG_DEBUG_BDF("trans drv cmd:trace_id=0x%" SXE_PRIX64 ", opcode[0x%x], "
			"inlen=%u, out_len=%u",
			trace_id, opcode, in_len, out_len);

	sxe_hdc_trans_info_init(&trans_info,
				in_data_buf, in_len,
				out_data_buf, out_len);

	ret = sxe_hdc_cmd_process(hw, trace_id, &trans_info);
	if (ret) {
		LOG_ERROR_BDF("hdc cmd trace_id=0x%" SXE_PRIX64 " hdc cmd process"
				" failed, ret=%d", trace_id, ret);
		goto l_out_buf_free;
	}

	ack = (struct sxe_hdc_drv_cmd_msg *)((u8 *)out_data_buf + SXE_HDC_CMD_HDR_SIZE);

	if (ack->errcode) {
		LOG_ERROR_BDF("driver get hdc ack failed trace_id=0x%" SXE_PRIX64 ", err=%d",
				trace_id, ack->errcode);
		ret = -EFAULT;
		goto l_out_buf_free;
	}

	ack_data_len = ack->length.ack_len - SXE_HDC_MSG_HDR_SIZE;
	if (resp_len != ack_data_len) {
		LOG_ERROR("ack trace_id=0x%" SXE_PRIX64 " data len[%u]"
			" and resp_len[%u] dont match",
			trace_id, ack_data_len, resp_len);
		ret = -EFAULT;
		goto l_out_buf_free;
	}

	if (resp_len != 0)
		memcpy(resp_data, ack->body, resp_len);

	LOG_DEBUG_BDF("driver get hdc ack trace_id=0x%" SXE_PRIX64 ","
			" ack_len=%u, ack_data_len=%u",
			trace_id, ack->length.ack_len, ack_data_len);

l_out_buf_free:
	rte_free(out_data_buf);
l_in_buf_free:
	rte_free(in_data_buf);
l_ret:
	return ret;
}
