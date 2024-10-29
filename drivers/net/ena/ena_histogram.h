/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2020 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 */

#ifndef _ENA_HISTOGRAM_H_
#define _ENA_HISTOGRAM_H_

#include "ena_ethdev.h"
#include "ena_logs.h"

#ifdef INCLUDE_ENA_HISTOGRAM

/* ena_histogram_info struct size should use a single cache line (64 bytes) */
#define ENA_HISTOGRAM_MAX_NAME 46

struct ena_histogram_info {
	char name[ENA_HISTOGRAM_MAX_NAME];
	uint16_t bin_count;
	uint64_t last_capture;
	uint64_t errors;
};

struct ena_histogram {
	struct ena_histogram_info info;
	uint64_t bins[];
};

/**
 * Histogram percentle calculation internal util
 *
 * @histogram: pointer to histogram variable
 * @samples: total samples count
 * @percentile: requested percentile [0-100]
 */
static inline int16_t percentile(struct ena_histogram *histogram,
				 uint64_t samples,
				 uint8_t percentile)
{
	uint64_t cumulative = 0;
	uint64_t target = 0;

	/* Invalid input */
	if (percentile > 100)
		return -1;

	if (samples <= 0)
		return 0;

	/* Determine the target count for the given percentile */
	target = RTE_MAX((samples * percentile) / 100, 1ULL);

	/* Find the bin that corresponds to the target percentile */
	for (uint16_t bin = 0; bin < histogram->info.bin_count; bin++) {
		cumulative += histogram->bins[bin];
		if (cumulative >= target)
			return bin;
	}

	return -1;
}

/**
 * Histogram struct definition
 *
 * @name: name of histogram variable
 * @bin_count: Numbers of bins - max UINT16_MAX (65536)
 *             For example, histogram with 8 bins will consist of the following bins boundaries:
 *             [0],[1],[2],[3],[4],[5],[6],[7-UINT16_MAX]
 */
#define ENA_HISTOGRAM(name, bin_count)								\
	struct ena_histogram_##name {								\
		struct ena_histogram_info info;							\
		uint64_t bins[bin_count];							\
	} name

/**
 * Initialize histogram
 *
 * @histogram: An uninitialized histogram
 * @histogram_name: Name of the histogram, will be used for histogram dump
 * @histogram_id: Unique ID of the histogram, will be used for histogram dump
 */
#define ENA_HISTOGRAM_INIT(histogram, histogram_name, histogram_id)				\
	do {											\
		typeof(histogram) _histogram = (histogram);					\
		(_histogram)->info.last_capture = 0;						\
		(_histogram)->info.errors = 0;							\
		(_histogram)->info.bin_count = ARRAY_SIZE((_histogram)->bins);			\
		snprintf((_histogram)->info.name, sizeof((_histogram)->info.name), "%s_%u",	\
			 (histogram_name), (histogram_id));					\
												\
		PMD_DRV_LOG(NOTICE, "%s: Bin count = %u, Total size = %" PRIu64 " (bytes)\n",	\
			    (_histogram)->info.name,						\
			    (_histogram)->info.bin_count,					\
			    sizeof(*_histogram));						\
	} while (0)

/**
 * Capture starting point
 *
 * @histogram: pointer to histogram variable
 * @capture: start capture value
 *
 * Notice:
 * 1. Start capture following start capture will increment the error statistic
 * 2. Histogram structure doesn't include any lock to avoid affecting the flow,
 *    make sure the flow is protected
 */
#define ENA_HISTOGRAM_CAPTURE_START(histogram, capture)						\
	do {											\
		typeof(histogram) _histogram = (histogram);					\
		if ((_histogram)->info.last_capture)						\
			(_histogram)->info.errors++;						\
		(_histogram)->info.last_capture = (capture);					\
	} while (0)

/**
 * Capture ending point
 * Calculate the diff between start and end point
 * last bin also consist all bins above
 * In case start capture value is NULL increment error statistic
 *
 * @histogram: pointer to histogram variable
 * @capture: stop capture value
 * @rate: frequency of captured events
 *
 * Notice:
 * 1. Stop capture not following start capture will increment the error statistic
 * 2. histogram structure doesn't include any lock to avoid affecting the flow,
 *    make sure the flow is protected
 * 3. Final histogram bin is divided by the rate and increased by rate,
 *    zero rate doesn't change the histogram
 */
#define ENA_HISTOGRAM_CAPTURE_STOP(histogram, capture, rate)					\
	do {											\
		typeof(histogram) _histogram = (histogram);					\
		typeof(rate) _rate = (rate);							\
		if ((_rate) > 0) {								\
			uint16_t bin_count = (_histogram)->info.bin_count;			\
												\
			if ((_histogram)->info.last_capture) {					\
				uint16_t bin = (((capture) - (_histogram)->info.last_capture)	\
						/ (_rate));					\
												\
				if (bin >= bin_count)						\
					bin = bin_count - 1;					\
												\
				(_histogram)->bins[bin] += (_rate);				\
			} else {								\
				(_histogram)->info.errors++;					\
			}									\
		}										\
		(_histogram)->info.last_capture = 0;						\
	} while (0)

/**
 * Reset histogram statistics
 *
 * @histogram: pointer to histogram variable
 */
#define ENA_HISTOGRAM_RESET(histogram)								\
	do {											\
		typeof(histogram) _histogram = (histogram);					\
		memset((_histogram)->bins, 0, sizeof((_histogram)->bins));			\
		(_histogram)->info.last_capture = 0;						\
		(_histogram)->info.errors = 0;							\
	} while (0)

/**
 * Dump histogram
 * Print all histogram cells above percent parameter
 * Calculate P0/P50/P99/Avg percentile and print error statistics
 *
 * @histogram: pointer to histogram variable
 * @percent: dump histogram above this percent (float)
 */
#define ENA_HISTOGRAM_DUMP(histogram, percent)							\
	do {											\
		typeof(histogram) _histogram = (histogram);					\
		typeof(percent) _percent = (percent);						\
		uint16_t bin_count = (_histogram)->info.bin_count;				\
		uint64_t samples = 0;								\
		uint64_t sum = 0;								\
		float percentage;								\
												\
		for (uint16_t bin = 0; bin < bin_count; bin++) {				\
			if ((_histogram)->bins[bin]) {						\
				samples += (_histogram)->bins[bin];				\
				sum += bin * (_histogram)->bins[bin];				\
			}									\
		}										\
												\
		PMD_DRV_LOG(NOTICE,								\
			    "%s: Samples[%" PRIu64 "], P0[%d], P50[%d], P99[%d], P100[%d], "	\
			    "AVG[%" PRIu64 "], Errors[%" PRIu64 "]\n",				\
			    (_histogram)->info.name,						\
			    samples,								\
			    percentile((struct ena_histogram *)(_histogram), samples, 0),	\
			    percentile((struct ena_histogram *)(_histogram), samples, 50),	\
			    percentile((struct ena_histogram *)(_histogram), samples, 99),	\
			    percentile((struct ena_histogram *)(_histogram), samples, 100),	\
			    (sum / samples),							\
			    (_histogram)->info.errors);						\
												\
		if (samples) {									\
			for (uint16_t bin = 0; bin < bin_count; bin++) {			\
				percentage = 100 * ((float)(_histogram)->bins[bin]) / samples;	\
				if (percentage <= (_percent))					\
					continue;						\
												\
				PMD_DRV_LOG(NOTICE, "%s: bin[%u] = %" PRIu64 ", %.2f%%\n",	\
					    (_histogram)->info.name,				\
					    bin,						\
					    (_histogram)->bins[bin], percentage);		\
			}									\
		}										\
	} while (0)

#else
#define ENA_HISTOGRAM(name, bins_count)
#define ENA_HISTOGRAM_INIT(histogram, histogram_id)
#define ENA_HISTOGRAM_CAPTURE_START(hist_name, value)
#define ENA_HISTOGRAM_CAPTURE_STOP(hist_name, value, rate)
#define ENA_HISTOGRAM_RESET(histogram)
#endif /* INCLUDE_ENA_HISTOGRAM */

#endif /* _ENA_HISTOGRAM_H_ */
