#ifndef _IDPF_LOGS_H_
#define _IDPF_LOGS_H_

#include <rte_log.h>

extern int idpf_logtype_init;
extern int idpf_logtype_driver;

#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, idpf_logtype_init, \
		"%s(): " fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_DRV_LOG(DEBUG, " >>")

#define PMD_DRV_LOG_RAW(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, idpf_logtype_driver, \
		"%s(): " fmt "\n", __func__, ##args)

#define PMD_DRV_LOG(level, fmt, args...) \
	PMD_DRV_LOG_RAW(level, fmt "\n", ## args)

#define PMD_DRV_FUNC_TRACE() PMD_DRV_LOG(DEBUG, " >>")

#ifdef RTE_LIBRTE_IDPF_DEBUG_RX
#define PMD_RX_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_IDPF_DEBUG_TX
#define PMD_TX_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#endif /* _IDPF_LOGS_H_ */
