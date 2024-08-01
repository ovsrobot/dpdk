/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Based on code reference code licensed as CC0 and MIT.
 * Copyright (c) 2012-2022 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 */

#ifndef _RTE_SIPHASH_H
#define _RTE_SIPHASH_H

/**
 * @file
 *
 * SipHash is a family of pseudorandom functions (PRFs) optimized for speed on short messages.
 *
 * SipHash was designed in 2012 by Jean-Philippe Aumasson and Daniel J. Bernstein as a defense
 * against hash-flooding DoS attacks.
 *
 * SipHash is simpler and faster on short messages than previous cryptographic algorithms,
 * such as MACs based on universal hashing.
 * Competitive in performance with insecure non-cryptographic algorithms.
 *
 * Cryptographically secure, with no sign of weakness despite multiple cryptanalysis projects
 * by leading cryptographers.
 *
 * Battle-tested, with successful integration in OSs (Linux kernel, OpenBSD, FreeBSD, FreeRTOS),
 * languages (Perl, Python, Ruby, etc.), libraries (OpenSSL libcrypto, Sodium, etc.)
 * and applications (Wireguard, Redis, etc.).
 *
 * As a secure pseudorandom function (a.k.a. keyed hash function), SipHash can also be used as
 * a secure message authentication code (MAC). But SipHash is not a hash in the sense of
 * general-purpose key-less hash function such as BLAKE3 or SHA-3.
 * SipHash should therefore always be used with a secret key in order to be secure.
 * siphash functions.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_compat.h>

/**
 * Compute a SipHash-2-4.
 * This version is the original version described in the reference version.
 * It uses a 64 bit key; does 2 compression rounds, and 4 finalization rounds.
 *
 * @param data
 *   Data to perform hash on.
 * @param len
 *   How many bytes to use to calculate hash value.
 * @param init_vals
 *   128-bit value to initialize hash generator.
 * @return
 *   64bit calculated hash value.
 */
__rte_experimental
uint64_t
rte_siphash(const void *data, uint32_t len, const uint64_t init_vals[2]);

/**
 * Compute Siphash-1-3.
 * This is the faster version which is used by Linux and other OS's.
 * It uses a 32 bit key; does 1 compression round, and 3 finalization rounds.
 * The function can be used with in hash_parameters with rte_hash_create().
 *
 * @param data
 *   Data to perform hash on.
 * @param len
 *   How many bytes to use to calculate hash value.
 * @param init_val
 *   Value to initialize hash generator.
 * @return
 *   32bit calculated hash value.
 */
__rte_experimental
uint32_t
rte_hsiphash(const void *data, uint32_t len, uint32_t init_val);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_SIPHASH_H */
