/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */
#include <stdint.h>

#include "vhost.h"

#define BYTE_SIZE 8
/* reference count offset in mbuf rearm data */
#define REFCNT_BITS_OFFSET ((offsetof(struct rte_mbuf, refcnt) - \
	offsetof(struct rte_mbuf, rearm_data)) * BYTE_SIZE)
/* segment number offset in mbuf rearm data */
#define SEG_NUM_BITS_OFFSET ((offsetof(struct rte_mbuf, nb_segs) - \
	offsetof(struct rte_mbuf, rearm_data)) * BYTE_SIZE)

/* default rearm data */
#define DEFAULT_REARM_DATA (1ULL << SEG_NUM_BITS_OFFSET | \
	1ULL << REFCNT_BITS_OFFSET)

#define DESC_FLAGS_SHORT_OFFSET (offsetof(struct vring_packed_desc, flags) / \
	sizeof(uint16_t))

#define DESC_FLAGS_SHORT_SIZE (sizeof(struct vring_packed_desc) / \
	sizeof(uint16_t))
#define BATCH_FLAGS_MASK (1 << DESC_FLAGS_SHORT_OFFSET | \
	1 << (DESC_FLAGS_SHORT_OFFSET + DESC_FLAGS_SHORT_SIZE) | \
	1 << (DESC_FLAGS_SHORT_OFFSET + DESC_FLAGS_SHORT_SIZE * 2)  | \
	1 << (DESC_FLAGS_SHORT_OFFSET + DESC_FLAGS_SHORT_SIZE * 3))

#define FLAGS_BITS_OFFSET ((offsetof(struct vring_packed_desc, flags) - \
	offsetof(struct vring_packed_desc, len)) * BYTE_SIZE)

#define PACKED_FLAGS_MASK ((0ULL | VRING_DESC_F_AVAIL | VRING_DESC_F_USED) \
	<< FLAGS_BITS_OFFSET)
#define PACKED_AVAIL_FLAG ((0ULL | VRING_DESC_F_AVAIL) << FLAGS_BITS_OFFSET)
#define PACKED_AVAIL_FLAG_WRAP ((0ULL | VRING_DESC_F_USED) << \
	FLAGS_BITS_OFFSET)
#define PACKED_WRITE_AVAIL_FLAG (PACKED_AVAIL_FLAG | \
	((0ULL | VRING_DESC_F_WRITE) << FLAGS_BITS_OFFSET))
#define PACKED_WRITE_AVAIL_FLAG_WRAP (PACKED_AVAIL_FLAG_WRAP | \
	((0ULL | VRING_DESC_F_WRITE) << FLAGS_BITS_OFFSET))

#define DESC_FLAGS_POS 0xaa
#define MBUF_LENS_POS 0x6666
#define DESC_LENS_POS 0x4444
#define DESC_LENS_FLAGS_POS 0xB0B0B0B0

int
vhost_reserve_avail_batch_packed_avx(struct virtio_net *dev,
				 struct vhost_virtqueue *vq,
				 struct rte_mempool *mbuf_pool,
				 struct rte_mbuf **pkts,
				 uint16_t avail_idx,
				 uintptr_t *desc_addrs,
				 uint16_t *ids)
{
	struct vring_packed_desc *descs = vq->desc_packed;
	uint32_t descs_status;
	void *desc_addr;
	uint16_t i;
	uint8_t cmp_low, cmp_high, cmp_result;
	uint64_t lens[PACKED_BATCH_SIZE];
	struct virtio_net_hdr *hdr;

	if (unlikely(avail_idx & PACKED_BATCH_MASK))
		return -1;
	if (unlikely((avail_idx + PACKED_BATCH_SIZE) > vq->size))
		return -1;

	/* load 4 descs */
	desc_addr = &vq->desc_packed[avail_idx];
	__m512i desc_vec = _mm512_loadu_si512(desc_addr);

	/* burst check four status */
	__m512i avail_flag_vec;
	if (vq->avail_wrap_counter)
#if defined(RTE_ARCH_I686)
		avail_flag_vec = _mm512_set4_epi64(PACKED_AVAIL_FLAG, 0x0,
					PACKED_FLAGS_MASK, 0x0);
#else
		avail_flag_vec = _mm512_maskz_set1_epi64(DESC_FLAGS_POS,
					PACKED_AVAIL_FLAG);

#endif
	else
#if defined(RTE_ARCH_I686)
		avail_flag_vec = _mm512_set4_epi64(PACKED_AVAIL_FLAG_WRAP,
					0x0, PACKED_AVAIL_FLAG_WRAP, 0x0);
#else
		avail_flag_vec = _mm512_maskz_set1_epi64(DESC_FLAGS_POS,
					PACKED_AVAIL_FLAG_WRAP);
#endif

	descs_status = _mm512_cmp_epu16_mask(desc_vec, avail_flag_vec,
		_MM_CMPINT_NE);
	if (descs_status & BATCH_FLAGS_MASK)
		return -1;

	if (dev->features & (1ULL << VIRTIO_F_IOMMU_PLATFORM)) {
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			uint64_t size = (uint64_t)descs[avail_idx + i].len;
			desc_addrs[i] = __vhost_iova_to_vva(dev, vq,
				descs[avail_idx + i].addr, &size,
				VHOST_ACCESS_RO);

			if (!desc_addrs[i])
				goto free_buf;
			lens[i] = descs[avail_idx + i].len;
			rte_prefetch0((void *)(uintptr_t)desc_addrs[i]);

			pkts[i] = virtio_dev_pktmbuf_alloc(dev, mbuf_pool,
					lens[i]);
			if (!pkts[i])
				goto free_buf;
		}
	} else {
		/* check buffer fit into one region & translate address */
		struct mem_regions_range *range = dev->regions_range;
		__m512i regions_low_addrs =
			_mm512_loadu_si512((void *)&range->regions_low_addrs);
		__m512i regions_high_addrs =
			_mm512_loadu_si512((void *)&range->regions_high_addrs);
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			uint64_t addr_low = descs[avail_idx + i].addr;
			uint64_t addr_high = addr_low +
						descs[avail_idx + i].len;
			__m512i low_addr_vec = _mm512_set1_epi64(addr_low);
			__m512i high_addr_vec = _mm512_set1_epi64(addr_high);

			cmp_low = _mm512_cmp_epi64_mask(low_addr_vec,
					regions_low_addrs, _MM_CMPINT_NLT);
			cmp_high = _mm512_cmp_epi64_mask(high_addr_vec,
					regions_high_addrs, _MM_CMPINT_LT);
			cmp_result = cmp_low & cmp_high;
			int index = __builtin_ctz(cmp_result);
			if (unlikely((uint32_t)index >= dev->mem->nregions))
				goto free_buf;

			desc_addrs[i] = addr_low +
				dev->mem->regions[index].host_user_addr -
				dev->mem->regions[index].guest_phys_addr;
			lens[i] = descs[avail_idx + i].len;
			rte_prefetch0((void *)(uintptr_t)desc_addrs[i]);

			pkts[i] = virtio_dev_pktmbuf_alloc(dev, mbuf_pool,
					lens[i]);
			if (!pkts[i])
				goto free_buf;
		}
	}

	if (virtio_net_with_host_offload(dev)) {
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			hdr = (struct virtio_net_hdr *)(desc_addrs[i]);
			vhost_dequeue_offload(hdr, pkts[i]);
		}
	}

	if (virtio_net_is_inorder(dev)) {
		ids[PACKED_BATCH_SIZE - 1] =
			descs[avail_idx + PACKED_BATCH_SIZE - 1].id;
	} else {
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
			ids[i] = descs[avail_idx + i].id;
	}

	uint64_t addrs[PACKED_BATCH_SIZE << 1];
	/* store mbuf data_len, pkt_len */
	vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		addrs[i << 1] = (uint64_t)pkts[i]->rx_descriptor_fields1;
		addrs[(i << 1) + 1] = (uint64_t)pkts[i]->rx_descriptor_fields1
					+ sizeof(uint64_t);
	}

	/* save pkt_len and data_len into mbufs */
	__m512i value_vec = _mm512_maskz_shuffle_epi32(MBUF_LENS_POS, desc_vec,
					0xAA);
	__m512i offsets_vec = _mm512_maskz_set1_epi32(MBUF_LENS_POS,
					(uint32_t)-12);
	value_vec = _mm512_add_epi32(value_vec, offsets_vec);
	__m512i vindex = _mm512_loadu_si512((void *)addrs);
	_mm512_i64scatter_epi64(0, vindex, value_vec, 1);

	return 0;
free_buf:
	for (i = 0; i < PACKED_BATCH_SIZE; i++)
		rte_pktmbuf_free(pkts[i]);

	return -1;
}

int
virtio_dev_rx_batch_packed_avx(struct virtio_net *dev,
			       struct vhost_virtqueue *vq,
			       struct rte_mbuf **pkts)
{
	struct vring_packed_desc *descs = vq->desc_packed;
	uint16_t avail_idx = vq->last_avail_idx;
	uint64_t desc_addrs[PACKED_BATCH_SIZE];
	uint32_t buf_offset = dev->vhost_hlen;
	uint32_t desc_status;
	uint64_t lens[PACKED_BATCH_SIZE];
	uint16_t i;
	void *desc_addr;
	uint8_t cmp_low, cmp_high, cmp_result;

	if (unlikely(avail_idx & PACKED_BATCH_MASK))
		return -1;
	if (unlikely((avail_idx + PACKED_BATCH_SIZE) > vq->size))
		return -1;

	/* check refcnt and nb_segs */
	__m256i mbuf_ref = _mm256_set1_epi64x(DEFAULT_REARM_DATA);

	/* load four mbufs rearm data */
	__m256i mbufs = _mm256_set_epi64x(
				*pkts[3]->rearm_data,
				*pkts[2]->rearm_data,
				*pkts[1]->rearm_data,
				*pkts[0]->rearm_data);

	uint16_t cmp = _mm256_cmpneq_epu16_mask(mbufs, mbuf_ref);
	if (cmp & MBUF_LENS_POS)
		return -1;

	/* check desc status */
	desc_addr = &vq->desc_packed[avail_idx];
	__m512i desc_vec = _mm512_loadu_si512(desc_addr);

	__m512i avail_flag_vec;
	__m512i used_flag_vec;
	if (vq->avail_wrap_counter) {
#if defined(RTE_ARCH_I686)
		avail_flag_vec = _mm512_set4_epi64(PACKED_WRITE_AVAIL_FLAG,
					0x0, PACKED_WRITE_AVAIL_FLAG, 0x0);
		used_flag_vec = _mm512_set4_epi64(PACKED_FLAGS_MASK, 0x0,
					PACKED_FLAGS_MASK, 0x0);
#else
		avail_flag_vec = _mm512_maskz_set1_epi64(DESC_FLAGS_POS,
					PACKED_WRITE_AVAIL_FLAG);
		used_flag_vec = _mm512_maskz_set1_epi64(DESC_FLAGS_POS,
					PACKED_FLAGS_MASK);
#endif
	} else {
#if defined(RTE_ARCH_I686)
		avail_flag_vec = _mm512_set4_epi64(
					PACKED_WRITE_AVAIL_FLAG_WRAP, 0x0,
					PACKED_WRITE_AVAIL_FLAG, 0x0);
		used_flag_vec = _mm512_set4_epi64(0x0, 0x0, 0x0, 0x0);
#else
		avail_flag_vec = _mm512_maskz_set1_epi64(DESC_FLAGS_POS,
					PACKED_WRITE_AVAIL_FLAG_WRAP);
		used_flag_vec = _mm512_setzero_epi32();
#endif
	}

	desc_status = _mm512_mask_cmp_epu16_mask(BATCH_FLAGS_MASK, desc_vec,
				avail_flag_vec, _MM_CMPINT_NE);
	if (desc_status)
		return -1;

	if (dev->features & (1ULL << VIRTIO_F_IOMMU_PLATFORM)) {
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			uint64_t size = (uint64_t)descs[avail_idx + i].len;
			desc_addrs[i] = __vhost_iova_to_vva(dev, vq,
				descs[avail_idx + i].addr, &size,
				VHOST_ACCESS_RW);

			if (!desc_addrs[i])
				return -1;

			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[i], void *,
					0));
		}
	} else {
		/* check buffer fit into one region & translate address */
		struct mem_regions_range *range = dev->regions_range;
		__m512i regions_low_addrs =
			_mm512_loadu_si512((void *)&range->regions_low_addrs);
		__m512i regions_high_addrs =
			_mm512_loadu_si512((void *)&range->regions_high_addrs);
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			uint64_t addr_low = descs[avail_idx + i].addr;
			uint64_t addr_high = addr_low +
						descs[avail_idx + i].len;
			__m512i low_addr_vec = _mm512_set1_epi64(addr_low);
			__m512i high_addr_vec = _mm512_set1_epi64(addr_high);

			cmp_low = _mm512_cmp_epi64_mask(low_addr_vec,
					regions_low_addrs, _MM_CMPINT_NLT);
			cmp_high = _mm512_cmp_epi64_mask(high_addr_vec,
					regions_high_addrs, _MM_CMPINT_LT);
			cmp_result = cmp_low & cmp_high;
			int index = __builtin_ctz(cmp_result);
			if (unlikely((uint32_t)index >= dev->mem->nregions))
				return -1;

			desc_addrs[i] = addr_low +
				dev->mem->regions[index].host_user_addr -
				dev->mem->regions[index].guest_phys_addr;
			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[i], void *,
					0));
		}
	}

	/* check length is enough */
	__m512i pkt_lens = _mm512_set_epi32(
			0, pkts[3]->pkt_len, 0, 0,
			0, pkts[2]->pkt_len, 0, 0,
			0, pkts[1]->pkt_len, 0, 0,
			0, pkts[0]->pkt_len, 0, 0);

	__m512i mbuf_len_offset = _mm512_maskz_set1_epi32(DESC_LENS_POS,
					dev->vhost_hlen);
	__m512i buf_len_vec = _mm512_add_epi32(pkt_lens, mbuf_len_offset);
	uint16_t lens_cmp = _mm512_mask_cmp_epu32_mask(DESC_LENS_POS,
				desc_vec, buf_len_vec, _MM_CMPINT_LT);
	if (lens_cmp)
		return -1;

	vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		rte_memcpy((void *)(uintptr_t)(desc_addrs[i] + buf_offset),
			   rte_pktmbuf_mtod_offset(pkts[i], void *, 0),
			   pkts[i]->pkt_len);
	}

	if (unlikely((dev->features & (1ULL << VHOST_F_LOG_ALL)))) {
		vhost_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			lens[i] = descs[avail_idx + i].len;
			vhost_log_cache_write_iova(dev, vq,
				descs[avail_idx + i].addr, lens[i]);
		}
	}

	vq_inc_last_avail_packed(vq, PACKED_BATCH_SIZE);
	vq_inc_last_used_packed(vq, PACKED_BATCH_SIZE);
	/* save len and flags, skip addr and id */
	__m512i desc_updated = _mm512_mask_add_epi16(desc_vec,
					DESC_LENS_FLAGS_POS, buf_len_vec,
					used_flag_vec);
	_mm512_storeu_si512(desc_addr, desc_updated);

	return 0;
}
