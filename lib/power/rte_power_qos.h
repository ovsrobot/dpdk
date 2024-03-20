/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 HiSilicon Limited
 */

#ifndef RTE_POWER_QOS_H
#define RTE_POWER_QOS_H

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file rte_power_qos.h
 *
 * PM QoS API.
 *
 * The system-wide CPU latency QoS limit has a positive impact on the idle
 * state selection in cpuidle governor.
 *
 * Linux creates a cpu_dma_latency device under '/dev' directory to obtain the
 * CPU latency QoS limit on system and send the QoS request for userspace.
 * Please see the PM QoS framework in the following link:
 * https://docs.kernel.org/power/pm_qos_interface.html?highlight=qos
 *
 * The deeper the idle state, the lower the power consumption, but the longer
 * the resume time. Some service are delay sensitive and very except the
 * low resume time, like interrupt packet receiving mode.
 *
 * So this PM QoS API make it easy to obtain the CPU latency limit on system and
 * send the CPU latency QoS request for the application that need them.
 *
 * The recommend usage method is as follows:
 * 1) an application process first creates QoS request.
 * 2) update the CPU latency request to zero when need.
 * 3) back to the default value @see PM_QOS_CPU_LATENCY_DEFAULT_VALUE when
 *    no need (this step is optional).
 * 4）release QoS request when process exit.
 */

#define QOS_USEC_PER_SEC                        1000000
#define PM_QOS_CPU_LATENCY_DEFAULT_VALUE        (2000 * QOS_USEC_PER_SEC)
#define PM_QOS_STRICT_LATENCY_VALUE             0

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create CPU latency QoS request and release this request by
 * @see rte_power_release_qos_request.
 *
 * @return
 *   0 on success. Otherwise negative value is returned.
 */
__rte_experimental
int rte_power_create_qos_request(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * release CPU latency QoS request.
 */
__rte_experimental
void rte_power_release_qos_request(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the current CPU latency QoS limit on system.
 * The default value in kernel is @see PM_QOS_CPU_LATENCY_DEFAULT_VALUE.
 *
 * @return
 *   0 on success. Otherwise negative value is returned.
 */
__rte_experimental
int rte_power_qos_get_curr_cpu_latency(int *latency);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Update the CPU latency QoS request.
 * Note: need to create QoS request first and then call this API.
 *
 * @param latency
 *   The latency should be greater than and equal to zero.
 *
 * @return
 *   0 on success. Otherwise negative value is returned.
 */
__rte_experimental
int rte_power_qos_update_request(int latency);

#ifdef __cplusplus
}
#endif

#endif /* RTE_POWER_QOS_H */
