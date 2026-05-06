/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_ERRNO_H__
#define __SXE2_ERRNO_H__
#include <errno.h>

enum sxe2_status {

	SXE2_SUCCESS                = 0,

	SXE2_ERR_PERM               = -EPERM,
	SXE2_ERR_NOFILE             = -ENOENT,
	SXE2_ERR_NOENT              = -ENOENT,
	SXE2_ERR_SRCH               = -ESRCH,
	SXE2_ERR_INTR               = -EINTR,
	SXE2_ERR_IO                 = -EIO,
	SXE2_ERR_NXIO               = -ENXIO,
	SXE2_ERR_2BIG               = -E2BIG,
	SXE2_ERR_NOEXEC             = -ENOEXEC,
	SXE2_ERR_BADF               = -EBADF,
	SXE2_ERR_CHILD              = -ECHILD,
	SXE2_ERR_AGAIN              = -EAGAIN,
	SXE2_ERR_NOMEM              = -ENOMEM,
	SXE2_ERR_ACCES              = -EACCES,
	SXE2_ERR_FAULT              = -EFAULT,
	SXE2_ERR_BUSY               = -EBUSY,
	SXE2_ERR_EXIST              = -EEXIST,
	SXE2_ERR_XDEV               = -EXDEV,
	SXE2_ERR_NODEV              = -ENODEV,
	SXE2_ERR_NOTSUP             = -ENOTSUP,
	SXE2_ERR_NOTDIR             = -ENOTDIR,
	SXE2_ERR_ISDIR              = -EISDIR,
	SXE2_ERR_INVAL              = -EINVAL,
	SXE2_ERR_NFILE              = -ENFILE,
	SXE2_ERR_MFILE              = -EMFILE,
	SXE2_ERR_NOTTY              = -ENOTTY,
	SXE2_ERR_FBIG               = -EFBIG,
	SXE2_ERR_NOSPC              = -ENOSPC,
	SXE2_ERR_SPIPE              = -ESPIPE,
	SXE2_ERR_ROFS               = -EROFS,
	SXE2_ERR_MLINK              = -EMLINK,
	SXE2_ERR_PIPE               = -EPIPE,
	SXE2_ERR_DOM                = -EDOM,
	SXE2_ERR_RANGE              = -ERANGE,
	SXE2_ERR_DEADLOCK           = -EDEADLK,
	SXE2_ERR_DEADLK             = -EDEADLK,
	SXE2_ERR_NAMETOOLONG        = -ENAMETOOLONG,
	SXE2_ERR_NOLCK              = -ENOLCK,
	SXE2_ERR_NOSYS              = -ENOSYS,
	SXE2_ERR_NOTEMPTY           = -ENOTEMPTY,
	SXE2_ERR_ILSEQ              = -EILSEQ,
	SXE2_ERR_NODATA             = -ENODATA,
	SXE2_ERR_CANCELED           = -ECANCELED,
	SXE2_ERR_TIMEDOUT           = -ETIMEDOUT,

	SXE2_ERROR                  = -150,
	SXE2_ERR_NO_MEMORY          = -151,
	SXE2_ERR_HW_VERSION         = -152,
	SXE2_ERR_FW_VERSION         = -153,
	SXE2_ERR_FW_MODE            = -154,

	SXE2_ERR_CMD_ERROR          = -156,
	SXE2_ERR_CMD_NO_MEMORY      = -157,
	SXE2_ERR_CMD_NOT_READY      = -158,
	SXE2_ERR_CMD_TIMEOUT        = -159,
	SXE2_ERR_CMD_CANCELED       = -160,
	SXE2_ERR_CMD_RETRY          = -161,
	SXE2_ERR_CMD_HW_CRITICAL    = -162,
	SXE2_ERR_CMD_NO_DATA        = -163,
	SXE2_ERR_CMD_INVAL_SIZE     = -164,
	SXE2_ERR_CMD_INVAL_TYPE     = -165,
	SXE2_ERR_CMD_INVAL_LEN      = -165,
	SXE2_ERR_CMD_INVAL_MAGIC    = -166,
	SXE2_ERR_CMD_INVAL_HEAD     = -167,
	SXE2_ERR_CMD_INVAL_ID       = -168,

	SXE2_ERR_DESC_NO_DONE       = -171,

	SXE2_ERR_INIT_ARGS_NAME_INVAL = -181,
	SXE2_ERR_INIT_ARGS_VAL_INVAL  = -182,
	SXE2_ERR_INIT_VSI_CRITICAL    = -183,

	SXE2_ERR_CFG_FILE_PATH        = -191,
	SXE2_ERR_CFG_FILE             = -192,
	SXE2_ERR_CFG_INVALID_SIZE     = -193,
	SXE2_ERR_CFG_NO_PIPELINE_CFG  = -194,

	SXE2_ERR_RESET_TIMIEOUT       = -200,
	SXE2_ERR_VF_NOT_ACTIVE        = -201,
	SXE2_ERR_BUF_CSUM_ERR         = -202,
	SXE2_ERR_VF_DROP              = -203,

	SXE2_ERR_FLOW_PARAM           = -301,
	SXE2_ERR_FLOW_CFG             = -302,
	SXE2_ERR_FLOW_CFG_NOT_SUPPORT = -303,
	SXE2_ERR_FLOW_PROF_EXISTS      = -304,
	SXE2_ERR_FLOW_PROF_NOT_EXISTS = -305,
	SXE2_ERR_FLOW_VSIG_FULL        = -306,
	SXE2_ERR_FLOW_VSIG_INFO        = -307,
	SXE2_ERR_FLOW_VSIG_NOT_FIND    = -308,
	SXE2_ERR_FLOW_VSIG_NOT_USED    = -309,
	SXE2_ERR_FLOW_VSI_NOT_IN_VSIG    = -310,
	SXE2_ERR_FLOW_MAX_LIMIT        = -311,

	SXE2_ERR_SCHED_NEED_RECURSION  = -400,

	SXE2_ERR_BFD_SESS_FLOW_HT_COLLISION = -500,
	SXE2_ERR_BFD_SESS_FLOW_NOSPC        = -501,
};

#endif
