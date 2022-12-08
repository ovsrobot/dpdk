/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_UTILS_NEON_H_
#define _ML_UTILS_NEON_H_

#include <stdint.h>

int ml_float32_to_int8_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_int8_to_float32_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_float32_to_uint8_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_uint8_to_float32_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_float32_to_int16_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_int16_to_float32_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_float32_to_uint16_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_uint16_to_float32_neon(float scale, uint64_t nb_elements, void *input, void *output);
int ml_float32_to_float16_neon(uint64_t nb_elements, void *input, void *output);
int ml_float16_to_float32_neon(uint64_t nb_elements, void *input, void *output);
int ml_float32_to_bfloat16_neon(uint64_t nb_elements, void *input, void *output);
int ml_bfloat16_to_float32_neon(uint64_t nb_elements, void *input, void *output);

#endif /*_ML_UTILS_NEON_H_ */
