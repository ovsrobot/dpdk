#ifndef __RNP_MBX_FW_H__
#define __RNP_MBX_FW_H__

struct mbx_fw_cmd_reply;
typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);
#define RNP_MAX_SHARE_MEM (8 * 8)
struct mbx_req_cookie {
	int magic;
#define COOKIE_MAGIC 0xCE
	cookie_cb cb;
	int timeout_ms;
	int errcode;

	/* wait_queue_head_t wait; */
	volatile int done;
	int priv_len;
	char priv[RNP_MAX_SHARE_MEM];
};
struct mbx_fw_cmd_reply {
} __rte_cache_aligned;

#endif /* __RNP_MBX_FW_H__*/
