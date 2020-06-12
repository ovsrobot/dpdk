#include "mp_crypto_vectors.h"
#include "mp_crypto.h"
#include "mp_crypto_parser.h"

int 			mp_app_driver_id;
/* Global driver id, one per mp_app */
int				mp_app_device_id;
/* For now we use only one device type, so for session
 * init only one need to be provided */
struct mp_app_dev	mp_app_devs[MP_APP_MAX_DEVS];
/* Global devices list */
uint16_t		mp_app_devs_cnt;
/* Global device counter */
uint8_t			mp_app_max_queues;
/* Per process queue counter */
const struct rte_memzone *mp_app_process_mz;
struct mp_app_process_data *mp_shared_data;
/* Data shared across processes
 * memzone name = MP_PROC_SHARED_MZ */

int mp_crypto_exit_flag;
/* Global exit flag */

struct rte_mempool *mp_crypto_session_mempool;
/* Global crypto mempool used by all processes */
struct rte_mempool *mp_crypto_session_mempool_local;
/* Local crypto mempool used by this process */
struct rte_mempool *mp_crypto_priv_session_mp;
/* Global crypto private session mempool used by all processes */
struct rte_mempool *mp_crypto_priv_session_mp_local;
/* Local crypto private session mempool used by this process */
struct rte_mempool *mp_crypto_op_pool;
/* Per process op pool */
struct rte_mempool *mp_crypto_mbuf_pool;
/* Per process mbuf pool */

struct rte_cryptodev_sym_session *mp_crypto_local_sessions[MAX_NUM_OF_SESSIONS];
/* Array of private sessions */

struct rte_crypto_op *mp_crypto_ops[MP_CRYPTO_OPS_NUM];
/* Per process set of rte crypto ops */
struct rte_crypto_op *mp_crypto_ops_ret[MP_CRYPTO_OPS_NUM];
/* Per process set of return rte crypto ops */
struct rte_mbuf *mp_crypto_mbufs[MP_CRYPTO_OPS_NUM];
/* Per process set of rte mbufs */

/* Function for creating sessions */
struct rte_cryptodev_sym_session *mp_app_create_session
			(int dev_id, const struct mp_crypto_session_vector *vector)
{
	if (vector->x_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
		return mp_app_create_aead_session(dev_id, vector);
	}
	MP_APP_LOG_2(ERR, COL_RED, "Invalid xform type");
	return NULL;
}

/* Create AEAD session */
struct rte_cryptodev_sym_session*
mp_app_create_aead_session(int dev_id, const struct mp_crypto_session_vector *vector)
{
	struct rte_cryptodev_sym_session *session;
	struct rte_crypto_sym_xform xform;
	xform.next = NULL;
	xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	xform.aead.key.length = vector->crypto_key.len;
	xform.aead.key.data = vector->crypto_key.data;
	xform.aead.algo = vector->aead_algo;
	xform.aead.digest_length = vector->digest_len;
	xform.aead.iv.length = vector->iv_len;
	xform.aead.iv.offset = IV_OFFSET;
	xform.aead.aad_length = vector->aad_len;
	xform.aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;

	session = rte_cryptodev_sym_session_create(mp_crypto_session_mempool);
	if (session == NULL) {
		MP_APP_LOG_2(ERR, COL_RED, "Failed to create session");
		return NULL;
	}
	int status = rte_cryptodev_sym_session_init(dev_id, session,
			&xform,	mp_crypto_priv_session_mp);
	if (status < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Failed to init session");
		return NULL;
	}

	return session;
}

int
mp_crypto_create_op(struct rte_crypto_op *op, struct rte_mbuf *mbuf, uint16_t vector_number,
					struct rte_cryptodev_sym_session *sess)
{
	uint8_t *plaintext;
	uint32_t aad_pad_len = RTE_ALIGN_CEIL(session_vectors[vectors[vector_number].session].aad_len, 16);

	memset(rte_pktmbuf_mtod(mbuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(mbuf));
	if (!mbuf) {
		RTE_LOG(ERR, USER1, "Error allocating\n");
		return -1;
	}
	struct rte_crypto_sym_op *sym_op = op->sym;
	sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(mbuf,
			aad_pad_len);
	sym_op->aead.aad.phys_addr =
			rte_pktmbuf_iova(mbuf);
	memcpy(sym_op->aead.aad.data, vectors[vector_number].aad.data,
			session_vectors[vectors[vector_number].session].aad_len);
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op,
			uint8_t *, IV_OFFSET);
	rte_memcpy(iv_ptr, vectors[vector_number].iv, session_vectors[vectors[vector_number].session].iv_len);

	plaintext = (uint8_t *)rte_pktmbuf_append(mbuf,
			vectors[vector_number].plaintext.len);
	rte_memcpy(plaintext, vectors[vector_number].plaintext.data, vectors[vector_number].plaintext.len);

	sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(mbuf, vectors[vector_number].plaintext.len);

	sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
			mbuf, vectors[vector_number].digest.len);

	sym_op->aead.data.length = vectors[vector_number].plaintext.len;
	sym_op->aead.data.offset = 0;

	rte_crypto_op_attach_sym_session(op, sess);
	return 0;
}