/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2018 Intel Corporation
 */

#ifndef _QAT_SYM_FRAME_H_
#define _QAT_SYM_FRAME_H_

#include <rte_common.h>

/**
 * Get the QAT queue pair based on device id and queue pair id.
 * Checks if passed arguments are valid.
 *
 * @param dev_id
 *   cryptodev device id.
 * @param qp_id
 *   queue pair id
 * @return
 *   pointer to queue pair if passed parameters are valid.
 *   NULL pointer otherwise.
 **/
__rte_experimental
void *
qat_sym_get_qp(uint8_t devi_id, uint16_t qp_id);

/**
 * enqueue one AEAD operation into QAT queue
 *
 * @param qat_sym_qp
 *   queue pair data got from qat_sym_get_qp().
 * @param session
 *   configured cryptodev symmetric session data.
 * @param data_iova
 *   iova address of data.
 * @param cipher_ofs
 *   cipher offset start from data_iova.
 * @param cipher_len
 *   cipher total length.
 * @param sgl
 *   in case of SGL data, pointer to an array of sgl structure.
 * @param n_sgl_vecs
 *   number of SGL vectors in sgl array, 0 for non-sgl input.
 * @param iv
 *   pointer to iv data.
 * @param tag_iova
 *   Tag iova address.
 * @param aad_iova
 *   AAD iova address.
 * @param is_first
 *   1 if it is the first operation in the frame.
 *   0 otherwise.
 * @param is_last
 *   1 if the data is the last element in the frame.
 *   0 otherwise.
 * @param frame
 *   if is_first is set the frame pointer will be written in to the message.
 *
 * @return
 *   0 if operation is successful, negative value if otherwise.
 **/

__rte_experimental
int
qat_sym_enqueue_frame_aead(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		rte_iova_t data_iova, uint32_t cipher_ofs, uint32_t cipher_len,
		struct rte_crypto_vec *sgl, uint32_t n_sgl_vecs,
		uint8_t *iv, rte_iova_t tag_iova, rte_iova_t aad_iova,
		uint8_t is_first, uint8_t is_last, void *frame);

/**
 * enqueue one chaining operation (cipher and hash) into QAT queue
 *
 * @param qat_sym_qp
 *   queue pair data got from qat_sym_get_qp().
 * @param session
 *   configured cryptodev symmetric session data.
 * @param data_iova
 *   iova address of data.
 * @param cipher_ofs
 *   cipher offset start from data_iova.
 * @param cipher_len
 *   cipher total length.
 * @param sgl
 *   in case of SGL data, pointer to an array of sgl structure.
 * @param n_sgl_vecs
 *   number of SGL vectors in sgl array, 0 for non-sgl input.
 * @param iv
 *   pointer to iv data.
 * @param digest_iova
 *   Digest iova address.
 * @param is_first
 *   1 if it is the first operation in the frame so that opaque is to written
 *     into QAT queue message that can be retrieved upon dequeue.
 *   0 otherwise.
 * @param is_last
 *   1 if the data is the last element in the frame, so that QAT queue tail
 *     is kicked and the HW will start processing
 *   0 otherwise.
 * @param opaque
 *   if is_first is set opaque will be written in to the message.
 *
 * @return
 *   0 if operation is successful, negative value if otherwise.
 **/
__rte_experimental
int
qat_sym_enqueue_frame_chain(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		rte_iova_t data_iova, uint32_t cipher_ofs, uint32_t cipher_len,
		uint32_t auth_ofs, uint32_t auth_len,
		struct rte_crypto_vec *sgl, uint32_t n_sgl_vecs,
		uint8_t *iv, rte_iova_t digest_iova,
		uint8_t is_first, uint8_t is_last, void *frame);

/**
 * enqueue one cipher-only operation into QAT queue
 *
 * @param qat_sym_qp
 *   queue pair data got from qat_sym_get_qp().
 * @param session
 *   configured cryptodev symmetric session data.
 * @param data_iova
 *   iova address of data.
 * @param cipher_ofs
 *   cipher offset start from data_iova.
 * @param cipher_len
 *   cipher total length.
 * @param sgl
 *   in case of SGL data, pointer to an array of sgl structure.
 * @param n_sgl_vecs
 *   number of SGL vectors in sgl array, 0 for non-sgl input.
 * @param iv
 *   pointer to iv data.
 * @param is_first
 *   1 if it is the first operation in the frame.
 *   0 otherwise.
 * @param is_last
 *   1 if the data is the last element in the frame.
 *   0 otherwise.
 * @param frame
 *   if is_first is set the frame pointer will be written in to the message.
 *
 * @return
 *   0 if operation is successful, negative value if otherwise.
 **/

__rte_experimental
int
qat_sym_enqueue_frame_cipher(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		rte_iova_t data_iova, uint32_t cipher_ofs, uint32_t cipher_len,
		struct rte_crypto_vec *sgl, uint32_t n_sgl_vecs,
		uint8_t *iv, uint8_t is_first, uint8_t is_last, void *frame);

/**
 * enqueue one auth-only operation into QAT queue
 *
 * @param qat_sym_qp
 *   queue pair data got from qat_sym_get_qp().
 * @param session
 *   configured cryptodev symmetric session data.
 * @param data_iova
 *   iova address of data.
 * @param auth_ofs
 *   authentication offset start from data_iova.
 * @param auth_len
 *   authentication total length.
 * @param sgl
 *   in case of SGL data, pointer to an array of sgl structure.
 * @param n_sgl_vecs
 *   number of SGL vectors in sgl array, 0 for non-sgl input.
 * @param iv
 *   pointer to iv data.
 * @param digest_iova
 *   digest iova address.
 * @param is_first
 *   1 if it is the first operation in the frame.
 *   0 otherwise.
 * @param is_last
 *   1 if the data is the last element in the frame.
 *   0 otherwise.
 * @param frame
 *   if is_first is set the frame pointer will be written in to the message.
 *
 * @return
 *   0 if operation is successful, negative value if otherwise.
 **/

__rte_experimental
int
qat_sym_enqueue_frame_auth(void *qat_sym_qp,
		struct rte_cryptodev_sym_session *session,
		rte_iova_t data_iova, uint32_t auth_ofs, uint32_t auth_len,
		struct rte_crypto_vec *sgl, uint32_t n_sgl_vecs,
		uint8_t *iv, rte_iova_t digest_iova,
		uint8_t is_first, uint8_t is_last, void *frame);

/**
 * Function prototype to get the number of elements in a frame in dequeue.
 * This function should be provided by the user.
 **/
typedef uint32_t (*qat_qp_get_frame_n_element_t)(void *frame);

/**
 * Dequeue a frame from QAT queue
 *
 * @param qat_sym_qp
 *   queue pair data got from qat_sym_get_qp().
 * @param frame
 *   return the frame dequeued.
 * @param get_frame_n_elt
 *   callback function that gets opaque_data from the first processed message.
 * @param first_status_offset
 *   the offset to status field of first frame element..
 * @param element_interval
 *   the size of frame element in the frame data, used to compute next
 *   status field.
 * @param element_status_success
 *   value to set for successfully processed frame element.
 * @param element_status_error
 *   value to set for unsuccessfully processed frame element.
 *
 * @return
 *   if a frame is retrieved from the queue pair it will be written
 *   into "frame" parameter, otherwise "frame" will be written as NULL and
 *   -1 will be returned. If all elements are successful 0 will be returned.
 *   Negative number of failed elements will be returned.
 **/
__rte_experimental
int
qat_sym_dequeue_frame(void *qat_sym_qp, void **frame,
		qat_qp_get_frame_n_element_t get_frame_n_elt,
		uint32_t first_status_offset, uint32_t element_interval,
		uint8_t element_status_success, uint8_t element_status_error);

#endif /* _QAT_SYM_FRAME_H_ */
