/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include "sxe.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe_ptp.h"

#define SXE_CYCLECOUNTER_MASK   0xffffffffffffffffULL

static void sxe_timecounters_start(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;

	u32 shift = 0;

	memset(&adapter->ptp_ctxt.systime_tc, 0, sizeof(struct rte_timecounter));
	memset(&adapter->ptp_ctxt.rx_tstamp_tc, 0, sizeof(struct rte_timecounter));
	memset(&adapter->ptp_ctxt.tx_tstamp_tc, 0, sizeof(struct rte_timecounter));

	adapter->ptp_ctxt.systime_tc.cc_mask = SXE_CYCLECOUNTER_MASK;
	adapter->ptp_ctxt.systime_tc.cc_shift = shift;
	adapter->ptp_ctxt.systime_tc.nsec_mask = (1ULL << shift) - 1;

	adapter->ptp_ctxt.rx_tstamp_tc.cc_mask = SXE_CYCLECOUNTER_MASK;
	adapter->ptp_ctxt.rx_tstamp_tc.cc_shift = shift;
	adapter->ptp_ctxt.rx_tstamp_tc.nsec_mask = (1ULL << shift) - 1;

	adapter->ptp_ctxt.tx_tstamp_tc.cc_mask = SXE_CYCLECOUNTER_MASK;
	adapter->ptp_ctxt.tx_tstamp_tc.cc_shift = shift;
	adapter->ptp_ctxt.tx_tstamp_tc.nsec_mask = (1ULL << shift) - 1;

	adapter->ptp_ctxt.tx_hwtstamp_nsec = 0;
	adapter->ptp_ctxt.tx_hwtstamp_sec = 0;
}

s32 sxe_timesync_enable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 tses = SXE_TSES_TXES_V2_ALL | SXE_TSES_RXES_V2_ALL;

	struct timespec ts;

	memset(&ts, 0, sizeof(struct timespec));

	clock_gettime(CLOCK_REALTIME, &ts);

	sxe_hw_ptp_init(hw);


	sxe_hw_ptp_timestamp_mode_set(hw, true, 0, tses);

	sxe_hw_ptp_timestamp_enable(hw);

	sxe_hw_ptp_rx_timestamp_clear(hw);

	sxe_hw_ptp_systime_init(hw);

	sxe_timecounters_start(dev);


	sxe_timesync_write_time(dev, &ts);

	return 0;
}

s32 sxe_timesync_disable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	sxe_hw_ptp_timestamp_disable(hw);

	sxe_hw_ptp_timestamp_mode_set(hw, false, 0, 0);

	sxe_hw_ptp_time_inc_stop(hw);

	return 0;
}

s32 sxe_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
				 struct timespec *timestamp,
				 u32 flags __rte_unused)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u64 ns;
	s32 ret = 0;
	bool is_valid;
	u64 rx_tstamp_cycles;

	is_valid = sxe_hw_ptp_is_rx_timestamp_valid(hw);
	if (!is_valid) {
		PMD_LOG_ERR(DRV, "no valid ptp timestamp in rx register");
		ret = -EINVAL;
		goto l_end;
	}

	rx_tstamp_cycles = sxe_hw_ptp_rx_timestamp_get(hw);
	ns = rte_timecounter_update(&adapter->ptp_ctxt.rx_tstamp_tc, rx_tstamp_cycles);
	PMD_LOG_DEBUG(DRV, "got rx_tstamp_cycles = %" SXE_PRIU64 "ns=%" SXE_PRIU64,
			rx_tstamp_cycles, ns);
	*timestamp = rte_ns_to_timespec(ns);

l_end:
	return ret;
}

static u64 sxe_timesync_tx_tstamp_cycles_get(struct sxe_adapter *adapter)
{
	return SXE_TIME_TO_NS(adapter->ptp_ctxt.tx_hwtstamp_nsec,
				adapter->ptp_ctxt.tx_hwtstamp_sec);
}

s32 sxe_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
				 struct timespec *timestamp)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u64 ns;
	s32 ret = 0;
	u64 tx_tstamp_cycles;
	u32 ts_sec;
	u32 ts_ns;
	u32 last_sec;
	u32 last_ns;
	bool tx_tstamp_valid = true;
	u8 i;

	sxe_hw_ptp_tx_timestamp_get(hw, &ts_sec, &ts_ns);
	if (ts_ns  != adapter->ptp_ctxt.tx_hwtstamp_nsec ||
		ts_sec != adapter->ptp_ctxt.tx_hwtstamp_sec) {
		for (i = 0; i < SXE_TXTS_POLL_CHECK; i++)
			sxe_hw_ptp_tx_timestamp_get(hw, &last_sec, &last_ns);

		for (; i < SXE_TXTS_POLL; i++) {
			sxe_hw_ptp_tx_timestamp_get(hw, &ts_sec, &ts_ns);
			if (last_ns != ts_ns || last_sec != ts_sec) {
				tx_tstamp_valid = false;
				break;
			}
		}
	}

	if (!tx_tstamp_valid || (ts_ns == adapter->ptp_ctxt.tx_hwtstamp_nsec &&
			ts_sec == adapter->ptp_ctxt.tx_hwtstamp_sec)) {
		PMD_LOG_DEBUG(DRV, "no valid ptp timestamp in tx register");
		ret = -EINVAL;
		goto l_end;
	} else {
		adapter->ptp_ctxt.tx_hwtstamp_nsec = ts_ns;
		adapter->ptp_ctxt.tx_hwtstamp_sec  = ts_sec;
		tx_tstamp_cycles =
			sxe_timesync_tx_tstamp_cycles_get(adapter);
		ns = rte_timecounter_update(&adapter->ptp_ctxt.tx_tstamp_tc,
						tx_tstamp_cycles);
		PMD_LOG_DEBUG(DRV, "got tx_tstamp_cycles = %"
			SXE_PRIU64 "ns=%" SXE_PRIU64, tx_tstamp_cycles, ns);
		*timestamp = rte_ns_to_timespec(ns);
	}

l_end:
	return ret;
}

s32 sxe_timesync_adjust_time(struct rte_eth_dev *dev, s64 delta)
{
	struct sxe_adapter *adapter = dev->data->dev_private;

	PMD_LOG_DEBUG(DRV, "got delta = %" SXE_PRID64, delta);

	adapter->ptp_ctxt.systime_tc.nsec += delta;
	adapter->ptp_ctxt.rx_tstamp_tc.nsec += delta;
	adapter->ptp_ctxt.tx_tstamp_tc.nsec += delta;

	return 0;
}

s32 sxe_timesync_read_time(struct rte_eth_dev *dev, struct timespec *ts)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u64 ns, systime_cycles;

	systime_cycles = sxe_hw_ptp_systime_get(hw);
	ns = rte_timecounter_update(&adapter->ptp_ctxt.systime_tc, systime_cycles);
	PMD_LOG_DEBUG(DRV, "got systime_cycles = %" SXE_PRIU64 "ns=%" SXE_PRIU64,
			systime_cycles, ns);
	*ts = rte_ns_to_timespec(ns);

	return 0;
}

s32 sxe_timesync_write_time(struct rte_eth_dev *dev,
					const struct timespec *ts)
{
	u64 ns;
	struct sxe_adapter *adapter = dev->data->dev_private;

	ns = rte_timespec_to_ns(ts);
	PMD_LOG_DEBUG(DRV, "set systime ns = %" SXE_PRIU64, ns);
	adapter->ptp_ctxt.systime_tc.nsec = ns;
	adapter->ptp_ctxt.rx_tstamp_tc.nsec = ns;
	adapter->ptp_ctxt.tx_tstamp_tc.nsec = ns;

	return 0;
}
