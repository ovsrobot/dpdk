#include "mp_crypto.h"

/*
 * Primary process IPC handler
 */
int
mp_crypto_primary_handler(const struct rte_mp_msg *mp_msg,
		  const void *peer)
{
	(void)peer;
	if (!memcmp(SECONDARY_PROC_EXIT, (const char *)mp_msg->param,
		sizeof(SECONDARY_PROC_EXIT))) {
		RTE_LOG(ERR, USER1, "One of secondary processes exiting...");
	}
	return 0;
}

int
mp_crypto_secondary_handler(const struct rte_mp_msg *mp_msg,
		  const void *peer)
{
	(void)peer;
	if (!memcmp(PRIMARY_PROC_EXIT, (const char *)mp_msg->param,
		sizeof(PRIMARY_PROC_EXIT)))	{
		RTE_LOG(ERR, USER1, "Primary process exiting...");
		mp_crypto_exit_flag = 1;
	}
	return 0;
}
