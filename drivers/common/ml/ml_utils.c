/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include <errno.h>
#include <stdint.h>

#include <rte_mldev.h>

#include "ml_utils.h"
#include "ml_utils_generic.h"

#if defined(__ARM_NEON__)
#include "ml_utils_neon.h"
#endif

int
ml_io_type_size_get(enum rte_ml_io_type type)
{
	switch (type) {
	case RTE_ML_IO_TYPE_UNKNOWN:
		return -EINVAL;
	case RTE_ML_IO_TYPE_INT8:
		return sizeof(int8_t);
	case RTE_ML_IO_TYPE_UINT8:
		return sizeof(uint8_t);
	case RTE_ML_IO_TYPE_INT16:
		return sizeof(int16_t);
	case RTE_ML_IO_TYPE_UINT16:
		return sizeof(uint16_t);
	case RTE_ML_IO_TYPE_INT32:
		return sizeof(int32_t);
	case RTE_ML_IO_TYPE_UINT32:
		return sizeof(uint32_t);
	case RTE_ML_IO_TYPE_FP8:
		return sizeof(uint8_t);
	case RTE_ML_IO_TYPE_FP16:
		return sizeof(uint8_t) * 2;
	case RTE_ML_IO_TYPE_FP32:
		return sizeof(uint8_t) * 4;
	case RTE_ML_IO_TYPE_BFLOAT16:
		return sizeof(uint8_t) * 2;
	default:
		return -EINVAL;
	}
}

void
ml_io_type_to_str(enum rte_ml_io_type type, char *str, int len)
{
	switch (type) {
	case RTE_ML_IO_TYPE_UNKNOWN:
		rte_strlcpy(str, "unknown", len);
		break;
	case RTE_ML_IO_TYPE_INT8:
		rte_strlcpy(str, "int8", len);
		break;
	case RTE_ML_IO_TYPE_UINT8:
		rte_strlcpy(str, "uint8", len);
		break;
	case RTE_ML_IO_TYPE_INT16:
		rte_strlcpy(str, "int16", len);
		break;
	case RTE_ML_IO_TYPE_UINT16:
		rte_strlcpy(str, "uint16", len);
		break;
	case RTE_ML_IO_TYPE_INT32:
		rte_strlcpy(str, "int32", len);
		break;
	case RTE_ML_IO_TYPE_UINT32:
		rte_strlcpy(str, "uint32", len);
		break;
	case RTE_ML_IO_TYPE_FP8:
		rte_strlcpy(str, "float8", len);
		break;
	case RTE_ML_IO_TYPE_FP16:
		rte_strlcpy(str, "float16", len);
		break;
	case RTE_ML_IO_TYPE_FP32:
		rte_strlcpy(str, "float32", len);
		break;
	case RTE_ML_IO_TYPE_BFLOAT16:
		rte_strlcpy(str, "bfloat16", len);
		break;
	default:
		rte_strlcpy(str, "invalid", len);
	}
}

void
ml_io_format_to_str(enum rte_ml_io_format format, char *str, int len)
{
	switch (format) {
	case RTE_ML_IO_FORMAT_NCHW:
		rte_strlcpy(str, "NCHW", len);
		break;
	case RTE_ML_IO_FORMAT_NHWC:
		rte_strlcpy(str, "NHWC", len);
		break;
	case RTE_ML_IO_FORMAT_CHWN:
		rte_strlcpy(str, "CHWN", len);
		break;
	case RTE_ML_IO_FORMAT_3D:
		rte_strlcpy(str, "3D", len);
		break;
	case RTE_ML_IO_FORMAT_2D:
		rte_strlcpy(str, "Matrix", len);
		break;
	case RTE_ML_IO_FORMAT_1D:
		rte_strlcpy(str, "Vector", len);
		break;
	case RTE_ML_IO_FORMAT_SCALAR:
		rte_strlcpy(str, "Scalar", len);
		break;
	default:
		rte_strlcpy(str, "invalid", len);
	}
}

int
ml_float32_to_int8(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_int8_generic(scale, nb_elements, input, output);
}

int
ml_int8_to_float32(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_int8_to_float32_generic(scale, nb_elements, input, output);
}

int
ml_float32_to_uint8(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_uint8_generic(scale, nb_elements, input, output);
}

int
ml_uint8_to_float32(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_uint8_to_float32_generic(scale, nb_elements, input, output);
}

int
ml_float32_to_int16(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_int16_generic(scale, nb_elements, input, output);
}

int
ml_int16_to_float32(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_int16_to_float32_generic(scale, nb_elements, input, output);
}

int
ml_float32_to_uint16(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_uint16_generic(scale, nb_elements, input, output);
}

int
ml_uint16_to_float32(float scale, uint64_t nb_elements, void *input, void *output)
{
	return ml_uint16_to_float32_generic(scale, nb_elements, input, output);
}

int
ml_float32_to_float16(uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_float16_generic(nb_elements, input, output);
}

int
ml_float16_to_float32(uint64_t nb_elements, void *input, void *output)
{
	return ml_float16_to_float32_generic(nb_elements, input, output);
}

int
ml_float32_to_bfloat16(uint64_t nb_elements, void *input, void *output)
{
	return ml_float32_to_bfloat16_generic(nb_elements, input, output);
}

int
ml_bfloat16_to_float32(uint64_t nb_elements, void *input, void *output)
{
	return ml_bfloat16_to_float32_generic(nb_elements, input, output);
}
