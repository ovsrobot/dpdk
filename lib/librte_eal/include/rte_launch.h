/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_LAUNCH_H_
#define _RTE_LAUNCH_H_

/**
 * @file
 *
 * Launch tasks on other lcores
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * State of an lcore.
 */
enum rte_lcore_state_t {
	WAIT,       /**< waiting a new command */
	RUNNING,    /**< executing command */
	FINISHED,   /**< command executed */
};

/**
 * Definition of a remote launch function.
 */
typedef int (lcore_function_t)(void *);

/**
 * Launch a function on another lcore.
 *
 * To be executed on the INITIAL lcore only.
 *
 * Sends a message to a worker lcore (identified by the id) that
 * is in the WAIT state (this is true after the first call to
 * rte_eal_init()). This can be checked by first calling
 * rte_eal_wait_lcore(id).
 *
 * When the remote lcore receives the message, it switches to
 * the RUNNING state, then calls the function f with argument arg. Once the
 * execution is done, the remote lcore switches to a FINISHED state and
 * the return value of f is stored in a local variable to be read using
 * rte_eal_wait_lcore().
 *
 * The INITIAL lcore returns as soon as the message is sent and knows
 * nothing about the completion of f.
 *
 * Note: This function is not designed to offer optimum
 * performance. It is just a practical way to launch a function on
 * another lcore at initialization time.
 *
 * @param f
 *   The function to be called.
 * @param arg
 *   The argument for the function.
 * @param id
 *   The identifier of the lcore on which the function should be executed.
 * @return
 *   - 0: Success. Execution of function f started on the remote lcore.
 *   - (-EBUSY): The remote lcore is not in a WAIT state.
 */
int rte_eal_remote_launch(lcore_function_t *f, void *arg, unsigned id);

/**
 * This enum indicates whether the initial core must execute the handler
 * launched on all logical cores.
 */
enum rte_rmt_call_initial_t {
	SKIP_INITIAL = 0, /**< lcore handler not executed by initial core. */
	CALL_INITIAL,     /**< lcore handler executed by initial core. */
};

/**
 * Deprecated backward compatiable definitions
 */
#define SKIP_MASTER	SKIP_INITIAL
#define CALL_MASTER	CALL_INITIAL

/**
 * Launch a function on all lcores.
 *
 * Check that each worker lcore is in a WAIT state, then call
 * rte_eal_remote_launch() for each lcore.
 *
 * @param f
 *   The function to be called.
 * @param arg
 *   The argument for the function.
 * @param call_initial
 *   If call_initial set to SKIP_INITIAL, the INITIAL lcore does not call
 *   the function. If call_initial is set to CALL_INITIAL, the function
 *   is also called on initial before returning. In any case, the initial
 *   lcore returns as soon as it finished its job and knows nothing
 *   about the completion of f on the other lcores.
 * @return
 *   - 0: Success. Execution of function f started on all remote lcores.
 *   - (-EBUSY): At least one remote lcore is not in a WAIT state. In this
 *     case, no message is sent to any of the lcores.
 */
int rte_eal_mp_remote_launch(lcore_function_t *f, void *arg,
			     enum rte_rmt_call_initial_t call_initial);

/**
 * Get the state of the lcore identified by id.
 *
 * To be executed on the INITIAL lcore only.
 *
 * @param id
 *   The identifier of the lcore.
 * @return
 *   The state of the lcore.
 */
enum rte_lcore_state_t rte_eal_get_lcore_state(unsigned id);

/**
 * Wait until an lcore finishes its job.
 *
 * To be executed on the INITIAL lcore only.
 *
 * If the lcore identified by the id is in a FINISHED state,
 * switch to the WAIT state. If the lcore is in RUNNING state, wait until
 * the lcore finishes its job and moves to the FINISHED state.
 *
 * @param id
 *   The identifier of the lcore.
 * @return
 *   - 0: If the lcore identified by the id is in a WAIT state.
 *   - The value that was returned by the previous remote launch
 *     function call if the lcore identified by the id was in a
 *     FINISHED or RUNNING state. In this case, it changes the state
 *     of the lcore to WAIT.
 */
int rte_eal_wait_lcore(unsigned id);

/**
 * Wait until all lcores finish their jobs.
 *
 * To be executed on the INITIAL lcore only. Issue an
 * rte_eal_wait_lcore() for every lcore. The return values are
 * ignored.
 *
 * After a call to rte_eal_mp_wait_lcore(), the caller can assume
 * that all worker lcores are in a WAIT state.
 */
void rte_eal_mp_wait_lcore(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_LAUNCH_H_ */
