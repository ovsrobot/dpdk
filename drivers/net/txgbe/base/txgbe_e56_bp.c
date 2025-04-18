#include "txgbe_e56.h"
#include "txgbe_hw.h"
#include "txgbe_osdep.h"
#include "txgbe_phy.h"
#include "txgbe_e56_bp.h"
#include "txgbe.h"
#include "../txgbe_logs.h"

#define CL74_KRTR_TRAINNING_TIMEOUT     2000
#define AN74_TRAINNING_MODE             1

typedef union {
	struct {
		u32 tx0_cursor_factor : 7;
		u32 rsvd0 : 1;
		u32 tx1_cursor_factor : 7;
		u32 rsvd1 : 1;
		u32 tx2_cursor_factor : 7;
		u32 rsvd2 : 1;
		u32 tx3_cursor_factor : 7;
		u32 rsvd3 : 1;
	};
	u32 reg;
} E56G__PMD_TX_FFE_CFG_1;

#define E56G__PMD_TX_FFE_CFG_1_NUM                                          1
#define E56G__PMD_TX_FFE_CFG_1_ADDR                   (E56G__BASEADDR+0x141c)
#define E56G__PMD_TX_FFE_CFG_1_PTR ((volatile E56G__PMD_TX_FFE_CFG_1*)(E56G__PMD_TX_FFE_CFG_1_ADDR))
#define E56G__PMD_TX_FFE_CFG_1_STRIDE                                       4
#define E56G__PMD_TX_FFE_CFG_1_SIZE                                        32
#define E56G__PMD_TX_FFE_CFG_1_ACC_SIZE                                    32
#define E56G__PMD_TX_FFE_CFG_1_READ_MSB                                    30
#define E56G__PMD_TX_FFE_CFG_1_READ_LSB                                     0
#define E56G__PMD_TX_FFE_CFG_1_WRITE_MSB                                   30
#define E56G__PMD_TX_FFE_CFG_1_WRITE_LSB                                    0
#define E56G__PMD_TX_FFE_CFG_1_RESET_VALUE                         0x3f3f3f3f

typedef union {
	struct {
		u32 tx0_precursor1_factor : 6;
		u32 rsvd0 : 2;
		u32 tx1_precursor1_factor : 6;
		u32 rsvd1 : 2;
		u32 tx2_precursor1_factor : 6;
		u32 rsvd2 : 2;
		u32 tx3_precursor1_factor : 6;
		u32 rsvd3 : 2;
	};
	u32 reg;
} E56G__PMD_TX_FFE_CFG_2;

#define E56G__PMD_TX_FFE_CFG_2_NUM                                          1
#define E56G__PMD_TX_FFE_CFG_2_ADDR                   (E56G__BASEADDR+0x1420)
#define E56G__PMD_TX_FFE_CFG_2_PTR ((volatile E56G__PMD_TX_FFE_CFG_2*)(E56G__PMD_TX_FFE_CFG_2_ADDR))
#define E56G__PMD_TX_FFE_CFG_2_STRIDE                                       4
#define E56G__PMD_TX_FFE_CFG_2_SIZE                                        32
#define E56G__PMD_TX_FFE_CFG_2_ACC_SIZE                                    32
#define E56G__PMD_TX_FFE_CFG_2_READ_MSB                                    29
#define E56G__PMD_TX_FFE_CFG_2_READ_LSB                                     0
#define E56G__PMD_TX_FFE_CFG_2_WRITE_MSB                                   29
#define E56G__PMD_TX_FFE_CFG_2_WRITE_LSB                                    0
#define E56G__PMD_TX_FFE_CFG_2_RESET_VALUE                                0x0

typedef union {
	struct {
		u32 tx0_precursor2_factor : 6;
		u32 rsvd0 : 2;
		u32 tx1_precursor2_factor : 6;
		u32 rsvd1 : 2;
		u32 tx2_precursor2_factor : 6;
		u32 rsvd2 : 2;
		u32 tx3_precursor2_factor : 6;
		u32 rsvd3 : 2;
	};
	u32 reg;
} E56G__PMD_TX_FFE_CFG_3;
#define E56G__PMD_TX_FFE_CFG_3_NUM                                          1
#define E56G__PMD_TX_FFE_CFG_3_ADDR                   (E56G__BASEADDR+0x1424)
#define E56G__PMD_TX_FFE_CFG_3_PTR ((volatile E56G__PMD_TX_FFE_CFG_3*)(E56G__PMD_TX_FFE_CFG_3_ADDR))
#define E56G__PMD_TX_FFE_CFG_3_STRIDE                                       4
#define E56G__PMD_TX_FFE_CFG_3_SIZE                                        32
#define E56G__PMD_TX_FFE_CFG_3_ACC_SIZE                                    32
#define E56G__PMD_TX_FFE_CFG_3_READ_MSB                                    29
#define E56G__PMD_TX_FFE_CFG_3_READ_LSB                                     0
#define E56G__PMD_TX_FFE_CFG_3_WRITE_MSB                                   29
#define E56G__PMD_TX_FFE_CFG_3_WRITE_LSB                                    0
#define E56G__PMD_TX_FFE_CFG_3_RESET_VALUE                                0x0

typedef union {
	struct {
		u32 tx0_postcursor_factor : 6;
		u32 rsvd0 : 2;
		u32 tx1_postcursor_factor : 6;
		u32 rsvd1 : 2;
		u32 tx2_postcursor_factor : 6;
		u32 rsvd2 : 2;
		u32 tx3_postcursor_factor : 6;
		u32 rsvd3 : 2;
	};
	u32 reg;
} E56G__PMD_TX_FFE_CFG_4;
#define E56G__PMD_TX_FFE_CFG_4_NUM                                          1
#define E56G__PMD_TX_FFE_CFG_4_ADDR                   (E56G__BASEADDR+0x1428)
#define E56G__PMD_TX_FFE_CFG_4_PTR ((volatile E56G__PMD_TX_FFE_CFG_4*)(E56G__PMD_TX_FFE_CFG_4_ADDR))
#define E56G__PMD_TX_FFE_CFG_4_STRIDE                                       4
#define E56G__PMD_TX_FFE_CFG_4_SIZE                                        32
#define E56G__PMD_TX_FFE_CFG_4_ACC_SIZE                                    32
#define E56G__PMD_TX_FFE_CFG_4_READ_MSB                                    29
#define E56G__PMD_TX_FFE_CFG_4_READ_LSB                                     0
#define E56G__PMD_TX_FFE_CFG_4_WRITE_MSB                                   29
#define E56G__PMD_TX_FFE_CFG_4_WRITE_LSB                                    0
#define E56G__PMD_TX_FFE_CFG_4_RESET_VALUE                                0x0

typedef union {
	struct {
		u32 ana_lcpll_lf_vco_swing_ctrl_i : 4;
		u32 ana_lcpll_lf_lpf_setcode_calib_i : 5;
		u32 rsvd0 : 3;
		u32 ana_lcpll_lf_vco_coarse_bin_i : 5;
		u32 rsvd1 : 3;
		u32 ana_lcpll_lf_vco_fine_therm_i : 8;
		u32 ana_lcpll_lf_clkout_fb_ctrl_i : 2;
		u32 rsvd2 : 2;
	};
	u32 reg;
} E56G__CMS_ANA_OVRDVAL_7;
#define E56G__CMS_ANA_OVRDVAL_7_NUM                                         1
#define E56G__CMS_ANA_OVRDVAL_7_ADDR                   (E56G__BASEADDR+0xccc)
#define E56G__CMS_ANA_OVRDVAL_7_PTR ((volatile E56G__CMS_ANA_OVRDVAL_7*)(E56G__CMS_ANA_OVRDVAL_7_ADDR))
#define E56G__CMS_ANA_OVRDVAL_7_STRIDE                                      4
#define E56G__CMS_ANA_OVRDVAL_7_SIZE                                       32
#define E56G__CMS_ANA_OVRDVAL_7_ACC_SIZE                                   32
#define E56G__CMS_ANA_OVRDVAL_7_READ_MSB                                   29
#define E56G__CMS_ANA_OVRDVAL_7_READ_LSB                                    0
#define E56G__CMS_ANA_OVRDVAL_7_WRITE_MSB                                  29
#define E56G__CMS_ANA_OVRDVAL_7_WRITE_LSB                                   0
#define E56G__CMS_ANA_OVRDVAL_7_RESET_VALUE                               0x0

typedef union {
	struct {
		u32 ovrd_en_ana_lcpll_hf_vco_amp_status_o : 1;
		u32 ovrd_en_ana_lcpll_hf_clkout_fb_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_hf_clkdiv_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_hf_en_odiv_i : 1;
		u32 ovrd_en_ana_lcpll_hf_test_in_i : 1;
		u32 ovrd_en_ana_lcpll_hf_test_out_o : 1;
		u32 ovrd_en_ana_lcpll_lf_en_bias_i : 1;
		u32 ovrd_en_ana_lcpll_lf_en_loop_i : 1;
		u32 ovrd_en_ana_lcpll_lf_en_cp_i : 1;
		u32 ovrd_en_ana_lcpll_lf_icp_base_i : 1;
		u32 ovrd_en_ana_lcpll_lf_icp_fine_i : 1;
		u32 ovrd_en_ana_lcpll_lf_lpf_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_lf_lpf_setcode_calib_i : 1;
		u32 ovrd_en_ana_lcpll_lf_set_lpf_i : 1;
		u32 ovrd_en_ana_lcpll_lf_en_vco_i : 1;
		u32 ovrd_en_ana_lcpll_lf_vco_sel_i : 1;
		u32 ovrd_en_ana_lcpll_lf_vco_swing_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_lf_vco_coarse_bin_i : 1;
		u32 ovrd_en_ana_lcpll_lf_vco_fine_therm_i : 1;
		u32 ovrd_en_ana_lcpll_lf_vco_amp_status_o : 1;
		u32 ovrd_en_ana_lcpll_lf_clkout_fb_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_lf_clkdiv_ctrl_i : 1;
		u32 ovrd_en_ana_lcpll_lf_en_odiv_i : 1;
		u32 ovrd_en_ana_lcpll_lf_test_in_i : 1;
		u32 ovrd_en_ana_lcpll_lf_test_out_o : 1;
		u32 ovrd_en_ana_lcpll_hf_refclk_select_i : 1;
		u32 ovrd_en_ana_lcpll_lf_refclk_select_i : 1;
		u32 ovrd_en_ana_lcpll_hf_clk_ref_sel_i : 1;
		u32 ovrd_en_ana_lcpll_lf_clk_ref_sel_i : 1;
		u32 ovrd_en_ana_test_bias_i : 1;
		u32 ovrd_en_ana_test_slicer_i : 1;
		u32 ovrd_en_ana_test_sampler_i : 1;
	};
	u32 reg;
} E56G__CMS_ANA_OVRDEN_1;
#define E56G__CMS_ANA_OVRDEN_1_NUM                                          1
#define E56G__CMS_ANA_OVRDEN_1_ADDR                    (E56G__BASEADDR+0xca8)
#define E56G__CMS_ANA_OVRDEN_1_PTR ((volatile E56G__CMS_ANA_OVRDEN_1*)(E56G__CMS_ANA_OVRDEN_1_ADDR))
#define E56G__CMS_ANA_OVRDEN_1_STRIDE                                       4
#define E56G__CMS_ANA_OVRDEN_1_SIZE                                        32
#define E56G__CMS_ANA_OVRDEN_1_ACC_SIZE                                    32
#define E56G__CMS_ANA_OVRDEN_1_READ_MSB                                    31
#define E56G__CMS_ANA_OVRDEN_1_READ_LSB                                     0
#define E56G__CMS_ANA_OVRDEN_1_WRITE_MSB                                   31
#define E56G__CMS_ANA_OVRDEN_1_WRITE_LSB                                    0
#define E56G__CMS_ANA_OVRDEN_1_RESET_VALUE                                0x0

typedef union {
	struct {
		u32 ana_lcpll_lf_test_in_i : 32;
	};
	u32 reg;
} E56G__CMS_ANA_OVRDVAL_9;
#define E56G__CMS_ANA_OVRDVAL_9_NUM                                         1
#define E56G__CMS_ANA_OVRDVAL_9_ADDR                   (E56G__BASEADDR+0xcd4)
#define E56G__CMS_ANA_OVRDVAL_9_PTR ((volatile E56G__CMS_ANA_OVRDVAL_9*)(E56G__CMS_ANA_OVRDVAL_9_ADDR))
#define E56G__CMS_ANA_OVRDVAL_9_STRIDE                                      4
#define E56G__CMS_ANA_OVRDVAL_9_SIZE                                       32
#define E56G__CMS_ANA_OVRDVAL_9_ACC_SIZE                                   32
#define E56G__CMS_ANA_OVRDVAL_9_READ_MSB                                   31
#define E56G__CMS_ANA_OVRDVAL_9_READ_LSB                                    0
#define E56G__CMS_ANA_OVRDVAL_9_WRITE_MSB                                  31
#define E56G__CMS_ANA_OVRDVAL_9_WRITE_LSB                                   0
#define E56G__CMS_ANA_OVRDVAL_9_RESET_VALUE                               0x0

#define SFP2_RS0  5
#define SFP2_RS1  4
#define SFP2_TX_DISABLE  1
#define SFP2_TX_FAULT  0
#define SFP2_RX_LOS_BIT  3
#ifdef PHYINIT_TIMEOUT
#undef PHYINIT_TIMEOUT
#define PHYINIT_TIMEOUT   2000
#endif

#define E56PHY_CMS_ANA_OVRDEN_0_ADDR   (E56PHY_CMS_BASE_ADDR+0xA4)
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_REFCLK_BUF_DAISY_EN_I 0,0
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_REFCLK_BUF_PAD_EN_I 1,1
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_REFCLK_BUF_PAD_EN_I_LSB 1
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_VDDINOFF_DCORE_DIG_O 2,2
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_BG_EN_I 11,11
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_BG_EN_I_LSB 11
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_BG_TESTIN_I 12,12
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_BG_TESTIN_I_LSB 12
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_RESCAL_I 13,13
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_RESCAL_I_LSB 13
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_RESCAL_COMP_O 14,14
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_RESCAL_COMP_O_LSB 14
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_RESCAL_CODE_I 15,15
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_RESCAL_CODE_I_LSB 15
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_LDO_CORE_I 16,16
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_LDO_CORE_I_LSB 16
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_TEST_LDO_I 17,17
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_TEST_LDO_I_LSB 17
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_ANA_DEBUG_SEL_I 18,18
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_ANA_DEBUG_SEL_I_LSB 18
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_BIAS_I 19,19
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_BIAS_I_LSB 19
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_LOOP_I 20,20
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_LOOP_I_LSB 20
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_CP_I 21,21
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_EN_CP_I_LSB 21
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_ICP_BASE_I 22,22
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_ICP_BASE_I_LSB 22
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_ICP_FINE_I 23,23
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_ICP_FINE_I_LSB 23
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_CTRL_I 24,24
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_CTRL_I_LSB 24
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I 25,25
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I_LSB 25
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_SET_LPF_I 26,26
#define E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_VCO_SWING_CTRL_I 29,29

#define E56PHY_CMS_ANA_OVRDVAL_2_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I 20,16
#define E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I 12,12
#define E56PHY_CMS_ANA_OVRDVAL_7_ADDR   (E56PHY_CMS_BASE_ADDR+0xCC)
#define E56PHY_CMS_ANA_OVRDVAL_5_ADDR   (E56PHY_CMS_BASE_ADDR+0xC4)
#define E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_LF_TEST_IN_I 23,23
#define E56PHY_CMS_ANA_OVRDVAL_9_ADDR   (E56PHY_CMS_BASE_ADDR+0xD4)
#define E56PHY_CMS_ANA_OVRDVAL_10_ADDR   (E56PHY_CMS_BASE_ADDR+0xD8)
#define E56PHY_CMS_ANA_OVRDVAL_7_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I 8,4
#define E56PHY_CTRL_FSM_CFG_0_CONT_ON_ADC_GAIN_CAL_ERR 5,5

static void
txgbe_e56_set_rxs_ufine_le_max(struct txgbe_hw *hw, u32 speed)
{
	u32 rdata;
	u32 ULTRAFINE_CODE;

	u32 CMVAR_UFINE_MAX = 0;

	if (speed == 10)
		CMVAR_UFINE_MAX = S10G_CMVAR_UFINE_MAX;
	else if (speed == 25)
		CMVAR_UFINE_MAX = S25G_CMVAR_UFINE_MAX;

	EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
	ULTRAFINE_CODE = EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_ultrafine_i);

	while (ULTRAFINE_CODE > CMVAR_UFINE_MAX) {
		ULTRAFINE_CODE = ULTRAFINE_CODE - 1;
		txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_ultrafine_i,
				      ULTRAFINE_CODE);
		txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i,
				      1);
		msleep(20);
	}
}

static int txgbe_e56_rxs_osc_init_for_temp_track_range(struct txgbe_hw *hw,
		u32 speed)
{
	int OFFSET_CENTRE_RANGE_H, OFFSET_CENTRE_RANGE_L, RANGE_FINAL;
	int RX_COARSE_MID_TD, CMVAR_RANGE_H = 0, CMVAR_RANGE_L = 0;
	int T = 40;
	u32 addr, rdata, timer;
	int status = 0;

	/* 1. Read the temperature T just before RXS is enabled. */
	txgbe_e56_get_temp(hw, &T);

	/* 2. Define software variable RX_COARSE_MID_TD */
	if (T < -5)
		RX_COARSE_MID_TD = 10;
	else if (T < 30)
		RX_COARSE_MID_TD = 9;
	else if (T < 65)
		RX_COARSE_MID_TD = 8;
	else if (T < 100)
		RX_COARSE_MID_TD = 7;
	else
		RX_COARSE_MID_TD = 6;

	/* Set CMVAR_RANGE_H/L based on the link speed mode */
	if (speed == 10 || speed == 40) {
		CMVAR_RANGE_H = S10G_CMVAR_RANGE_H;
		CMVAR_RANGE_L = S10G_CMVAR_RANGE_L;
	} else if (speed == 25) {
		CMVAR_RANGE_H = S25G_CMVAR_RANGE_H;
		CMVAR_RANGE_L = S25G_CMVAR_RANGE_L;
	}

	/* TBD select all lane */
	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_5_ANA_BBCDR_OSC_RANGE_SEL_I,
		       CMVAR_RANGE_H);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_RXS_ANA_OVRDEN_0_OVRD_EN_ANA_BBCDR_OSC_RANGE_SEL_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	/* 4. Do SEQ::RX_ENABLE to enable RXS */
	rdata = 0x0000;
	addr = E56PHY_RXS0_OVRDVAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_0_RXS0_RX0_SAMP_CAL_DONE_O, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS0_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_RXS0_OVRDEN_0_OVRD_EN_RXS0_RX0_SAMP_CAL_DONE_O, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0;
	addr = E56PHY_PMD_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);

	set_fields_e56(&rdata, E56PHY_PMD_CFG_0_RX_EN_CFG, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0;
	timer = 0;
	while ((rdata & 0x3f) != 0x9) {
		usec_delay(100);
		rdata = 0;
		addr = E56PHY_INTR_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		if ((rdata & 0x100) == 0x100)
			break;
		rdata = 0;
		addr = E56PHY_CTRL_FSM_RX_STAT_0_ADDR;
		rdata = rd32_ephy(hw, addr);

		if (timer++ > PHYINIT_TIMEOUT) {
			break;
			return -1;
		}
	}

	rdata = 0;
	addr = E56PHY_RXS_ANA_OVRDVAL_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	OFFSET_CENTRE_RANGE_H = (rdata >> 4) & 0xf;
	if (OFFSET_CENTRE_RANGE_H > RX_COARSE_MID_TD)
		OFFSET_CENTRE_RANGE_H = OFFSET_CENTRE_RANGE_H - RX_COARSE_MID_TD;
	else
		OFFSET_CENTRE_RANGE_H = RX_COARSE_MID_TD - OFFSET_CENTRE_RANGE_H;

	rdata = 0;
	addr = E56PHY_PMD_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_0_RX_EN_CFG, 0x0);
	wr32_ephy(hw, addr, rdata);

	timer = 0;
	while (1) {
		usec_delay(100);
		rdata = 0;
		addr = E56PHY_CTRL_FSM_RX_STAT_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		if ((rdata & 0x3f) == 0x21)
			break;
		if (timer++ > PHYINIT_TIMEOUT) {
			break;
			return -1;
		}
	}

	rdata = 0;
	addr = E56PHY_INTR_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	wr32_ephy(hw, addr, 0);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_5_ANA_BBCDR_OSC_RANGE_SEL_I,
		       CMVAR_RANGE_L);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_RXS_ANA_OVRDEN_0_OVRD_EN_ANA_BBCDR_OSC_RANGE_SEL_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS0_OVRDVAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_0_RXS0_RX0_SAMP_CAL_DONE_O, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS0_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDEN_0_OVRD_EN_RXS0_RX0_SAMP_CAL_DONE_O,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0;
	addr = E56PHY_PMD_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);

	set_fields_e56(&rdata, E56PHY_PMD_CFG_0_RX_EN_CFG, 0x1);
	wr32_ephy(hw, addr, rdata);

	/* poll CTRL_FSM_RX_ST */
	timer = 0;
	while ((rdata & 0x3f) != 0x9) {
		usec_delay(100);
		rdata = 0;
		addr = E56PHY_INTR_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		if ((rdata & 0x100) == 0x100)
			break;
		rdata = 0;
		addr = E56PHY_CTRL_FSM_RX_STAT_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		if (timer++ > PHYINIT_TIMEOUT) {
			break;
			return -1;
		}
	}

	rdata = 0;
	addr = E56PHY_RXS_ANA_OVRDVAL_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	OFFSET_CENTRE_RANGE_L = (rdata >> 4) & 0xf;
	if (OFFSET_CENTRE_RANGE_L > RX_COARSE_MID_TD)
		OFFSET_CENTRE_RANGE_L = OFFSET_CENTRE_RANGE_L - RX_COARSE_MID_TD;

	else
		OFFSET_CENTRE_RANGE_L = RX_COARSE_MID_TD - OFFSET_CENTRE_RANGE_L;

	/*13. Perform below calculation in software. */
	if (OFFSET_CENTRE_RANGE_L < OFFSET_CENTRE_RANGE_H)
		RANGE_FINAL = CMVAR_RANGE_L;
	else
		RANGE_FINAL = CMVAR_RANGE_H;

	/* 14. SEQ::RX_DISABLE to disable RXS. Poll ALIAS::PDIG::CTRL_FSM_RX_ST */
	rdata = 0;
	addr = E56PHY_PMD_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_0_RX_EN_CFG, 0x0);
	addr = E56PHY_PMD_CFG_0_ADDR;
	wr32_ephy(hw, addr, rdata);

	timer = 0;
	while (1) {
		usec_delay(100);
		rdata = 0;
		addr = E56PHY_CTRL_FSM_RX_STAT_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		if ((rdata & 0x3f) == 0x21)
			break;
		if (timer++ > PHYINIT_TIMEOUT) {
			break;
			return -1;
		}
	}

	/* 15. Since RX power-up fsm is stopped in RX_SAMP_CAL_ST */
	rdata = 0;
	addr = E56PHY_INTR_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	wr32_ephy(hw, addr, 0);

	/* 16. Program ALIAS::RXS::RANGE_SEL = RANGE_FINAL */
	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_RXS_ANA_OVRDVAL_5_ANA_BBCDR_OSC_RANGE_SEL_I,
		       RANGE_FINAL);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS0_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_RXS0_OVRDEN_0_OVRD_EN_RXS0_RX0_SAMP_CAL_DONE_O,
		       0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0;
	addr = E56PHY_PMD_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_0_RX_EN_CFG, 0x1);
	addr = E56PHY_PMD_CFG_0_ADDR;
	wr32_ephy(hw, addr, rdata);

	return status;
}

static int txgbe_e56_rxs_post_cdr_lock_temp_track_seq(struct txgbe_hw *hw,
		u32 speed)
{
	int status = 0;
	u32 rdata;
	int SECOND_CODE;
	int COARSE_CODE;
	int FINE_CODE;
	int ULTRAFINE_CODE;

	int CMVAR_SEC_LOW_TH ;
	int CMVAR_UFINE_MAX = 0;
	int CMVAR_FINE_MAX ;
	int CMVAR_UFINE_UMAX_WRAP = 0;
	int CMVAR_COARSE_MAX ;
	int CMVAR_UFINE_FMAX_WRAP = 0;
	int CMVAR_FINE_FMAX_WRAP = 0;
	int CMVAR_SEC_HIGH_TH ;
	int CMVAR_UFINE_MIN ;
	int CMVAR_FINE_MIN ;
	int CMVAR_UFINE_UMIN_WRAP ;
	int CMVAR_COARSE_MIN ;
	int CMVAR_UFINE_FMIN_WRAP ;
	int CMVAR_FINE_FMIN_WRAP ;

	if (speed == 10) {
		CMVAR_SEC_LOW_TH = S10G_CMVAR_SEC_LOW_TH;
		CMVAR_UFINE_MAX = S10G_CMVAR_UFINE_MAX;
		CMVAR_FINE_MAX = S10G_CMVAR_FINE_MAX;
		CMVAR_UFINE_UMAX_WRAP = S10G_CMVAR_UFINE_UMAX_WRAP;
		CMVAR_COARSE_MAX = S10G_CMVAR_COARSE_MAX;
		CMVAR_UFINE_FMAX_WRAP = S10G_CMVAR_UFINE_FMAX_WRAP;
		CMVAR_FINE_FMAX_WRAP = S10G_CMVAR_FINE_FMAX_WRAP;
		CMVAR_SEC_HIGH_TH = S10G_CMVAR_SEC_HIGH_TH;
		CMVAR_UFINE_MIN = S10G_CMVAR_UFINE_MIN;
		CMVAR_FINE_MIN = S10G_CMVAR_FINE_MIN;
		CMVAR_UFINE_UMIN_WRAP = S10G_CMVAR_UFINE_UMIN_WRAP;
		CMVAR_COARSE_MIN = S10G_CMVAR_COARSE_MIN;
		CMVAR_UFINE_FMIN_WRAP = S10G_CMVAR_UFINE_FMIN_WRAP;
		CMVAR_FINE_FMIN_WRAP = S10G_CMVAR_FINE_FMIN_WRAP;
	} else if (speed == 25) {
		CMVAR_SEC_LOW_TH = S25G_CMVAR_SEC_LOW_TH;
		CMVAR_UFINE_MAX = S25G_CMVAR_UFINE_MAX;
		CMVAR_FINE_MAX = S25G_CMVAR_FINE_MAX;
		CMVAR_UFINE_UMAX_WRAP = S25G_CMVAR_UFINE_UMAX_WRAP;
		CMVAR_COARSE_MAX = S25G_CMVAR_COARSE_MAX;
		CMVAR_UFINE_FMAX_WRAP = S25G_CMVAR_UFINE_FMAX_WRAP;
		CMVAR_FINE_FMAX_WRAP = S25G_CMVAR_FINE_FMAX_WRAP;
		CMVAR_SEC_HIGH_TH = S25G_CMVAR_SEC_HIGH_TH;
		CMVAR_UFINE_MIN = S25G_CMVAR_UFINE_MIN;
		CMVAR_FINE_MIN = S25G_CMVAR_FINE_MIN;
		CMVAR_UFINE_UMIN_WRAP = S25G_CMVAR_UFINE_UMIN_WRAP;
		CMVAR_COARSE_MIN = S25G_CMVAR_COARSE_MIN;
		CMVAR_UFINE_FMIN_WRAP = S25G_CMVAR_UFINE_FMIN_WRAP;
		CMVAR_FINE_FMIN_WRAP = S25G_CMVAR_FINE_FMIN_WRAP;
	}

	status |= txgbe_e56_rx_rd_second_code(hw, &SECOND_CODE);

	EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
	COARSE_CODE = EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_coarse_i);
	FINE_CODE = EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_fine_i);
	ULTRAFINE_CODE = EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_ultrafine_i);

	if (SECOND_CODE <= CMVAR_SEC_LOW_TH) {
		if (ULTRAFINE_CODE < CMVAR_UFINE_MAX) {
			txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_ultrafine_i,
					      ULTRAFINE_CODE + 1);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		} else if (FINE_CODE < CMVAR_FINE_MAX) {
			EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5,
				  ana_bbcdr_ultrafine_i) = CMVAR_UFINE_UMAX_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_fine_i) = FINE_CODE + 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_fine_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		} else if (COARSE_CODE < CMVAR_COARSE_MAX) {
			EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5,
				  ana_bbcdr_ultrafine_i) = CMVAR_UFINE_FMAX_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_fine_i) = CMVAR_FINE_FMAX_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_coarse_i) = COARSE_CODE + 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_coarse_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_fine_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		}
	} else if (SECOND_CODE >= CMVAR_SEC_HIGH_TH) {
		if (ULTRAFINE_CODE > CMVAR_UFINE_MIN) {
			txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_ultrafine_i,
					      ULTRAFINE_CODE - 1);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		} else if (FINE_CODE > CMVAR_FINE_MIN) {
			EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5,
				  ana_bbcdr_ultrafine_i) = CMVAR_UFINE_UMIN_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_fine_i) = FINE_CODE - 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_fine_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		} else if (COARSE_CODE > CMVAR_COARSE_MIN) {
			EPHY_RREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5,
				  ana_bbcdr_ultrafine_i) = CMVAR_UFINE_FMIN_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_fine_i) = CMVAR_FINE_FMIN_WRAP;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDVAL_5, ana_bbcdr_coarse_i) = COARSE_CODE - 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDVAL_5);
			EPHY_RREG(E56G__RXS0_ANA_OVRDEN_1);
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_coarse_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_fine_i) = 1;
			EPHY_XFLD(E56G__RXS0_ANA_OVRDEN_1, ovrd_en_ana_bbcdr_ultrafine_i) = 1;
			EPHY_WREG(E56G__RXS0_ANA_OVRDEN_1);
		}
	}

	return status;
}

static int txgbe_e56_ctle_bypass_seq(struct txgbe_hw *hw)
{
	int status = 0;
	u32 rdata;

	txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDVAL_0, ana_ctle_bypass_i, 1);
	txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDEN_0, ovrd_en_ana_ctle_bypass_i, 1);

	txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDVAL_3, ana_ctle_cz_cstm_i, 0);
	txgbe_e56_ephy_config(E56G__RXS0_ANA_OVRDEN_0, ovrd_en_ana_ctle_cz_cstm_i, 1);

	EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
	EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_ctle_train_en_i) = 0;
	EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_ctle_train_done_o) = 1;
	EPHY_WREG(E56G__PMD_RXS0_OVRDVAL_1);

	EPHY_RREG(E56G__PMD_RXS0_OVRDEN_1);
	EPHY_XFLD(E56G__PMD_RXS0_OVRDEN_1, ovrd_en_rxs0_rx0_ctle_train_en_i) = 1;
	EPHY_XFLD(E56G__PMD_RXS0_OVRDEN_1, ovrd_en_rxs0_rx0_ctle_train_done_o) = 1;
	EPHY_WREG(E56G__PMD_RXS0_OVRDEN_1);

	return status;
}

static int txgbe_e56_rxs_adc_adapt_seq(struct txgbe_hw *hw, u32 bypass_ctle)
{
	u32 rdata, timer, addr;
	int status = 0, i;

	rdata = 0;
	timer = 0;
	EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);

	while (EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_cdr_rdy_o) != 1) {
		EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
		usec_delay(100);

		if (timer++ > PHYINIT_TIMEOUT) {
			return 1;
		}
	}

	addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_VGA_TRAIN_EN_I, 0x0);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDEN_1_OVRD_EN_RXS0_RX0_VGA_TRAIN_EN_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_CTLE_TRAIN_EN_I, 0x0);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDEN_1_OVRD_EN_RXS0_RX0_CTLE_TRAIN_EN_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDEN_1_OVRD_EN_RXS0_RX0_ADC_INTL_CAL_DONE_O
		       , 0x0);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_INTL_CAL_EN_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
	timer = 0;
	while (((rdata >> E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_INTL_CAL_DONE_O_LSB) & 1)
	       != 1) {
		rdata = rd32_ephy(hw, addr);
		usec_delay(100);

		if (timer++ > PHYINIT_TIMEOUT) {
			break;
		}
	}

	for (i = 0; i < 16; i++) {
		addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_OFST_ADAPT_EN_I, 0x1);
		wr32_ephy(hw, addr, rdata);

		txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
				      ovrd_en_rxs0_rx0_adc_ofst_adapt_done_o, 0);
		rdata = 0;
		timer = 0;
		while (EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1,
				 rxs0_rx0_adc_ofst_adapt_done_o) != 1) {
			EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
			usec_delay(100);
			if (timer++ > PHYINIT_TIMEOUT) {
				break;
			}
		}

		rdata = 0x0000;
		addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_OFST_ADAPT_EN_I, 0x0);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_GAIN_ADAPT_EN_I, 0x1);
		wr32_ephy(hw, addr, rdata);

		txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
				      ovrd_en_rxs0_rx0_adc_ofst_adapt_done_o, 0);
		rdata = 0;
		timer = 0;
		while (EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1,
				 rxs0_rx0_adc_gain_adapt_done_o) != 1) {
			EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
			usec_delay(100);

			if (timer++ > PHYINIT_TIMEOUT) {
				break;
			}
		}

		addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_GAIN_ADAPT_EN_I, 0x0);
		wr32_ephy(hw, addr, rdata);
	}

	addr = E56PHY_RXS0_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS0_OVRDVAL_1_RXS0_RX0_ADC_INTL_ADAPT_EN_I, 0x1);
	wr32_ephy(hw, addr, rdata);
	msleep(10);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
			      ovrd_en_rxs0_rx0_adc_intl_adapt_en_i, 0);

	EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
	EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_vga_train_en_i) = 1;
	if (bypass_ctle == 0)
		EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_ctle_train_en_i) = 1;

	EPHY_WREG(E56G__PMD_RXS0_OVRDVAL_1);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_1,
			      ovrd_en_rxs0_rx0_vga_train_done_o, 0);
	rdata = 0;
	timer = 0;
	while (EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_vga_train_done_o) != 1) {
		EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
		usec_delay(100);

		if (timer++ > PHYINIT_TIMEOUT) {
			break;
		}
	}

	if (bypass_ctle == 0) {
		txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_1,
				      ovrd_en_rxs0_rx0_ctle_train_done_o, 0);
		rdata = 0;
		timer = 0;
		while (EPHY_XFLD(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_ctle_train_done_o) != 1) {
			EPHY_RREG(E56G__PMD_RXS0_OVRDVAL_1);
			usec_delay(100);

			if (timer++ > PHYINIT_TIMEOUT) {
				break;
			}
		}
	}

	EPHY_RREG(E56G__PMD_RXS0_OVRDEN_1);
	EPHY_XFLD(E56G__PMD_RXS0_OVRDEN_1, ovrd_en_rxs0_rx0_vga_train_en_i) = 0;
	if (bypass_ctle == 0)
		EPHY_XFLD(E56G__PMD_RXS0_OVRDEN_1, ovrd_en_rxs0_rx0_ctle_train_en_i) = 0;
	EPHY_WREG(E56G__PMD_RXS0_OVRDEN_1);

	return status;
}

static int txgbe_e56_phy_rxs_calib_adapt_seq(struct txgbe_hw *hw,
		u8 by_link_mode, u32 bypass_ctle)
{
	int status = 0;
	u32 rdata;

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_adc_ofst_adapt_en_i,
			      0);
	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
			      ovrd_en_rxs0_rx0_adc_ofst_adapt_en_i, 1);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_adc_gain_adapt_en_i,
			      0);
	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
			      ovrd_en_rxs0_rx0_adc_gain_adapt_en_i, 1);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_adc_intl_cal_en_i, 0);
	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_1,
			      ovrd_en_rxs0_rx0_adc_intl_cal_en_i, 1);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_adc_intl_cal_done_o,
			      1);
	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_1,
			      ovrd_en_rxs0_rx0_adc_intl_cal_done_o, 1);

	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDVAL_1, rxs0_rx0_adc_intl_adapt_en_i,
			      0);
	txgbe_e56_ephy_config(E56G__PMD_RXS0_OVRDEN_2,
			      ovrd_en_rxs0_rx0_adc_intl_adapt_en_i, 1);

	if (bypass_ctle != 0)
		status |= txgbe_e56_ctle_bypass_seq(hw);

	status |= txgbe_e56_rxs_osc_init_for_temp_track_range(hw, by_link_mode);

	/* Wait an fsm_rx_sts 25G */
	status |= kr_read_poll(rd32_ephy, rdata, ((rdata & 0x3f) == 0x1b), 1000,
			       500000, hw, E56PHY_CTRL_FSM_RX_STAT_0_ADDR);

	return status;
}

static int txgbe_e56_cms_cfg_for_temp_track_range(struct txgbe_hw *hw,
		u8 by_link_mode)
{
	UNREFERENCED_PARAMETER(by_link_mode);
	int status = 0, T = 40;
	u32 addr, rdata;

	status = txgbe_e56_get_temp(hw, &T);
	if (T < 40) {
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_2_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDVAL_2_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_7_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDVAL_7_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);
	} else if (T > 70) {
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_0_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_2_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDVAL_2_ANA_LCPLL_HF_LPF_SETCODE_CALIB_I, 0x3);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I, 0x1);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_7_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata,
			       E56PHY_CMS_ANA_OVRDVAL_7_ANA_LCPLL_LF_LPF_SETCODE_CALIB_I, 0x3);
		wr32_ephy(hw, addr, rdata);
	} else {
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_HF_TEST_IN_I,
			       0x1);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_4_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, 24, 24, 0x1);
		set_fields_e56(&rdata, 31, 29, 0x4);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_5_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, 1, 0, 0x0);
		wr32_ephy(hw, addr, rdata);
		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDEN_1_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_LF_TEST_IN_I,
			       0x1);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_9_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, 24, 24, 0x1);
		set_fields_e56(&rdata, 31, 29, 0x4);
		wr32_ephy(hw, addr, rdata);

		rdata = 0x0000;
		addr = E56PHY_CMS_ANA_OVRDVAL_10_ADDR;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, 1, 0, 0x0);
		wr32_ephy(hw, addr, rdata);
	}
	return status;
}

static int txgbe_e56_tx_ffe_cfg(struct txgbe_hw *hw)
{
	/* Setting the TX EQ main/pre1/pre2/post value */
	wr32_ephy(hw, 0x141c, S25G_TX_FFE_CFG_DAC_MAIN);
	wr32_ephy(hw, 0x1420, S25G_TX_FFE_CFG_DAC_PRE1);
	wr32_ephy(hw, 0x1424, S25G_TX_FFE_CFG_DAC_PRE2);
	wr32_ephy(hw, 0x1428, S25G_TX_FFE_CFG_DAC_POST);

	return 0;
}

static int txgbe_e56_bp_cfg_25g(struct txgbe_hw *hw)
{
	u32 addr, rdata;

	rdata = 0x0000;
	addr = E56PHY_CMS_PIN_OVRDVAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CMS_PIN_OVRDVAL_0_INT_PLL0_TX_SIGNAL_TYPE_I, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CMS_PIN_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CMS_PIN_OVRDEN_0_OVRD_EN_PLL0_TX_SIGNAL_TYPE_I,
		       0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CMS_ANA_OVRDVAL_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CMS_ANA_OVRDVAL_2_ANA_LCPLL_HF_VCO_SWING_CTRL_I,
		       0xf);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CMS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata,
		       E56PHY_CMS_ANA_OVRDEN_0_OVRD_EN_ANA_LCPLL_HF_VCO_SWING_CTRL_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CMS_ANA_OVRDVAL_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 23, 0, 0x260000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr  = E56PHY_CMS_ANA_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CMS_ANA_OVRDEN_1_OVRD_EN_ANA_LCPLL_HF_TEST_IN_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_TXS_CFG_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_TXS_CFG_1_ADAPTATION_WAIT_CNT_X256, 0xf);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_WKUP_CNT_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_WKUP_CNTLDO_WKUP_CNT_X32, 0xff);
	set_fields_e56(&rdata, E56PHY_TXS_WKUP_CNTDCC_WKUP_CNT_X32, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_PIN_OVRDVAL_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 27, 24, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_PIN_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_PIN_OVRDEN_0_OVRD_EN_TX0_EFUSE_BITS_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_ANA_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_ANA_OVRDVAL_1_ANA_TEST_DAC_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_ANA_OVRDEN_0_OVRD_EN_ANA_TEST_DAC_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	txgbe_e56_tx_ffe_cfg(hw);

	rdata = 0x0000;
	addr = E56PHY_RXS_RXS_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_RXS_CFG_0_DSER_DATA_SEL, 0x0);
	set_fields_e56(&rdata, E56PHY_RXS_RXS_CFG_0_TRAIN_CLK_GATE_BYPASS_EN, 0x1fff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr  = E56PHY_RXS_OSC_CAL_N_CDR_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_1_PREDIV1, 0x700);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_1_TARGET_CNT1, 0x2418);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_4_OSC_RANGE_SEL1, 0x1);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_4_VCO_CODE_INIT, 0x7fb);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_4_OSC_CURRENT_BOOST_EN1, 0x0);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_4_BBCDR_CURRENT_BOOST1, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_SDM_WIDTH, 0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_PROP_STEP_PRELOCK,
		       0xf);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_PROP_STEP_POSTLOCK,
		       0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_GAIN_CTRL_POSTLOCK,
		       0xa);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_GAIN_CTRL_PRELOCK,
		       0xf);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BBCDR_RDY_CNT, 0x3);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_6_PI_GAIN_CTRL_PRELOCK, 0x7);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_6_PI_GAIN_CTRL_POSTLOCK, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_INTL_CONFIG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_INTL_CONFIG_0_ADC_INTL2SLICE_DELAY1, 0x3333);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_INTL_CONFIG_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_INTL_CONFIG_2_INTERLEAVER_HBW_DISABLE1, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_0_ADC_DATA_PEAK_LTH, 0x56);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_0_ADC_DATA_PEAK_UTH, 0x6a);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_1_C1_LTH, 0x1f8);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_1_C1_UTH, 0xf0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_2_CM1_LTH, 0x100);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_2_CM1_UTH, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_CM2_LTH, 0x4);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_CM2_UTH, 0x37);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_TXFFE_TRAIN_MOD_TYPE, 0x38);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56G__RXS0_FOM_18__ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56G__RXS0_FOM_18__DFE_COEFFL_HINT__MSB,
		       E56G__RXS0_FOM_18__DFE_COEFFL_HINT__LSB, 0x0);
	set_fields_e56(&rdata, E56G__RXS0_FOM_18__DFE_COEFFH_HINT__MSB,
		       E56G__RXS0_FOM_18__DFE_COEFFH_HINT__LSB, 0x0);
	set_fields_e56(&rdata, E56G__RXS0_FOM_18__DFE_COEFF_HINT_LOAD__MSB,
		       E56G__RXS0_FOM_18__DFE_COEFF_HINT_LOAD__LSB, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_VGA_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_0_VGA_TARGET, 0x34);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_VGA_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA1_CODE_INIT0, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA2_CODE_INIT0, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA1_CODE_INIT123, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA2_CODE_INIT123, 0xa);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_0_CTLE_CODE_INIT0, 0x9);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_0_CTLE_CODE_INIT123, 0x9);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_1_LFEQ_LUT, 0x1ffffea);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P1, 18);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P2, 0);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P3, 0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P1, 1);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P2, 0);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P3, 0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADC_SLICE_DATA_AVG_CNT,
		       0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADC_DATA_AVG_CNT, 0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_FE_OFFSET_DAC_CLK_CNT_X8,
		       0xc);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OFFSET_N_GAIN_CAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_1_SAMP_ADAPT_CFG, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_FFE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_FFE_TRAINING_0_FFE_TAP_EN, 0xf9ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_IDLE_DETECT_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_IDLE_DETECT_1_IDLE_TH_ADC_PEAK_MAX, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_IDLE_DETECT_1_IDLE_TH_ADC_PEAK_MIN, 0x5);
	wr32_ephy(hw, addr, rdata);

	addr = 0x6cc;
	rdata = 0x8020000;
	wr32_ephy(hw, addr, rdata);
	addr = 0x94;
	rdata = 0;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_0_ANA_EN_RTERM_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_RTERM_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 4, 0, 0x0);
	set_fields_e56(&rdata, 14, 13, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_1_OVRD_EN_ANA_BBCDR_VCOFILT_BYP_I,
		       0x1);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_1_OVRD_EN_ANA_TEST_BBCDR_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_15_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 2, 0, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_17_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_17_ANA_VGA2_BOOST_CSTM_I, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_3_OVRD_EN_ANA_ANABS_CONFIG_I, 0x1);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_3_OVRD_EN_ANA_VGA2_BOOST_CSTM_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_14_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 13, 13, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 13, 13, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_EYE_SCAN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_EYE_SCAN_1_EYE_SCAN_REF_TIMER, 0x400);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_RINGO_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 21, 12, 0x366);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_3_CTRL_FSM_TIMEOUT_X64K, 0x80);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_4_TRAIN_DC_ON_PERIOD_X64K, 0x18);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_4_TRAIN_DC_PERIOD_X512K, 0x3e);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_5_USE_RECENT_MARKER_OFFSET, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_CONT_ON_ADC_GAIN_CAL_ERR, 0x1);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_DO_RX_ADC_OFST_CAL, 0x3);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_RX_ERR_ACTION_EN, 0x40);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST0_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST1_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST2_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST3_WAIT_CNT_X4096, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST4_WAIT_CNT_X4096, 0x1);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST5_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST6_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST7_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST8_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST9_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST10_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST11_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST12_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST13_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST14_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST15_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_7_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_7_TRAIN_ST4_EN, 0x4bf);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_7_TRAIN_ST5_EN, 0xc4bf);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_8_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_8_TRAIN_ST7_EN, 0x47ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_12_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_12_TRAIN_ST15_EN, 0x67ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_13_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_13_TRAIN_ST0_DONE_EN, 0x8001);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_13_TRAIN_ST1_DONE_EN, 0x8002);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_14_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_14_TRAIN_ST3_DONE_EN, 0x8008);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_15_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_15_TRAIN_ST4_DONE_EN, 0x8004);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_17_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_17_TRAIN_ST8_DONE_EN, 0x20c0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_18_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_18_TRAIN_ST10_DONE_EN, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_29_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_29_TRAIN_ST15_DC_EN, 0x3f6d);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_33_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_33_TRAIN0_RATE_SEL, 0x8000);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_33_TRAIN1_RATE_SEL, 0x8000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_34_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_34_TRAIN2_RATE_SEL, 0x8000);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_34_TRAIN3_RATE_SEL, 0x8000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_KRT_TFSM_CFG_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_MAX_WAIT_TIMER_X1000K, 0x49);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_MAX_WAIT_TIMER_X8000K, 0x37);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_HOLDOFF_TIMER_X256K, 0x2f);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_FETX_FFE_TRAIN_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_FETX_FFE_TRAIN_CFG_0_KRT_FETX_INIT_FFE_CFG_2,
		       0x2);
	wr32_ephy(hw, addr, rdata);

	return 0;
}

static int txgbe_e56_bp_cfg_10g(struct txgbe_hw *hw)
{
	u32 addr, rdata;

	rdata = 0x0000;
	addr = E56G__CMS_ANA_OVRDVAL_7_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G__CMS_ANA_OVRDVAL_7 *)&rdata)->ana_lcpll_lf_vco_swing_ctrl_i = 0xf;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56G__CMS_ANA_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G__CMS_ANA_OVRDEN_1 *)&rdata)->ovrd_en_ana_lcpll_lf_vco_swing_ctrl_i = 0x1;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56G__CMS_ANA_OVRDVAL_9_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 23, 0, 0x260000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56G__RXS0_ANA_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G__CMS_ANA_OVRDEN_1 *)&rdata)->ovrd_en_ana_lcpll_lf_test_in_i = 0x1;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_TXS_CFG_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_TXS_CFG_1_ADAPTATION_WAIT_CNT_X256, 0xf);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_WKUP_CNT_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_WKUP_CNTLDO_WKUP_CNT_X32, 0xff);
	set_fields_e56(&rdata, E56PHY_TXS_WKUP_CNTDCC_WKUP_CNT_X32, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_PIN_OVRDVAL_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 19, 16, 0x6);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_PIN_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_PIN_OVRDEN_0_OVRD_EN_TX0_EFUSE_BITS_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_ANA_OVRDVAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_ANA_OVRDVAL_1_ANA_TEST_DAC_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_TXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_TXS_ANA_OVRDEN_0_OVRD_EN_ANA_TEST_DAC_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	txgbe_e56_tx_ffe_cfg(hw);

	rdata = 0x0000;
	addr = E56PHY_RXS_RXS_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_RXS_CFG_0_DSER_DATA_SEL, 0x0);
	set_fields_e56(&rdata, E56PHY_RXS_RXS_CFG_0_TRAIN_CLK_GATE_BYPASS_EN, 0x1fff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr  = E56PHY_RXS_OSC_CAL_N_CDR_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G_RXS0_OSC_CAL_N_CDR_0 *)&rdata)->prediv0 = 0xfa0;
	((E56G_RXS0_OSC_CAL_N_CDR_0 *)&rdata)->target_cnt0 = 0x203a;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G_RXS0_OSC_CAL_N_CDR_4 *)&rdata)->osc_range_sel0 = 0x2;
	((E56G_RXS0_OSC_CAL_N_CDR_4 *)&rdata)->vco_code_init = 0x7ff;
	((E56G_RXS0_OSC_CAL_N_CDR_4 *)&rdata)->osc_current_boost_en0 = 0x1;
	((E56G_RXS0_OSC_CAL_N_CDR_4 *)&rdata)->bbcdr_current_boost0 = 0x0;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_SDM_WIDTH, 0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_PROP_STEP_PRELOCK,
		       0xf);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_PROP_STEP_POSTLOCK,
		       0xf);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_GAIN_CTRL_POSTLOCK,
		       0xc);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BB_CDR_GAIN_CTRL_PRELOCK,
		       0xf);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_5_BBCDR_RDY_CNT, 0x3);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OSC_CAL_N_CDR_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_6_PI_GAIN_CTRL_PRELOCK, 0x7);
	set_fields_e56(&rdata, E56PHY_RXS_OSC_CAL_N_CDR_6_PI_GAIN_CTRL_POSTLOCK, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_INTL_CONFIG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G_RXS0_INTL_CONFIG_0 *)&rdata)->adc_intl2slice_delay0 = 0x5555;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_INTL_CONFIG_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	((E56G_RXS0_INTL_CONFIG_2 *)&rdata)->interleaver_hbw_disable0 = 0x1;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_0_ADC_DATA_PEAK_LTH, 0x56);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_0_ADC_DATA_PEAK_UTH, 0x6a);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_1_C1_LTH, 0x1e8);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_1_C1_UTH, 0x78);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_2_CM1_LTH, 0x100);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_2_CM1_UTH, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_TXFFE_TRAINING_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_CM2_LTH, 0x4);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_CM2_UTH, 0x37);
	set_fields_e56(&rdata, E56PHY_RXS_TXFFE_TRAINING_3_TXFFE_TRAIN_MOD_TYPE, 0x38);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_VGA_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_0_VGA_TARGET, 0x34);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_VGA_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA1_CODE_INIT0, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA2_CODE_INIT0, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA1_CODE_INIT123, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_VGA_TRAINING_1_VGA2_CODE_INIT123, 0xa);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_0_CTLE_CODE_INIT0, 0x9);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_0_CTLE_CODE_INIT123, 0x9);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_1_LFEQ_LUT, 0x1ffffea);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P1, 0x18);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P2, 0);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_2_ISI_TH_FRAC_P3, 0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_CTLE_TRAINING_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P1, 1);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P2, 0);
	set_fields_e56(&rdata, E56PHY_RXS_CTLE_TRAINING_3_TAP_WEIGHT_P3, 0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADC_SLICE_DATA_AVG_CNT,
		       0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_ADC_DATA_AVG_CNT, 0x3);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_0_FE_OFFSET_DAC_CLK_CNT_X8,
		       0xc);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_OFFSET_N_GAIN_CAL_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_OFFSET_N_GAIN_CAL_1_SAMP_ADAPT_CFG, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_FFE_TRAINING_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_FFE_TRAINING_0_FFE_TAP_EN, 0xf9ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_IDLE_DETECT_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_IDLE_DETECT_1_IDLE_TH_ADC_PEAK_MAX, 0xa);
	set_fields_e56(&rdata, E56PHY_RXS_IDLE_DETECT_1_IDLE_TH_ADC_PEAK_MIN, 0x5);
	wr32_ephy(hw, addr, rdata);

	addr = 0x6cc;
	rdata = 0x8020000;
	wr32_ephy(hw, addr, rdata);
	addr = 0x94;
	rdata = 0;
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_0_ANA_EN_RTERM_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_0_OVRD_EN_ANA_EN_RTERM_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_6_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 4, 0, 0x6);
	set_fields_e56(&rdata, 14, 13, 0x2);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_1_OVRD_EN_ANA_BBCDR_VCOFILT_BYP_I,
		       0x1);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_1_OVRD_EN_ANA_TEST_BBCDR_I, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_15_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 2, 0, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_17_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDVAL_17_ANA_VGA2_BOOST_CSTM_I, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_3_OVRD_EN_ANA_ANABS_CONFIG_I, 0x1);
	set_fields_e56(&rdata, E56PHY_RXS_ANA_OVRDEN_3_OVRD_EN_ANA_VGA2_BOOST_CSTM_I,
		       0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDVAL_14_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 13, 13, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_ANA_OVRDEN_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 13, 13, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_EYE_SCAN_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_RXS_EYE_SCAN_1_EYE_SCAN_REF_TIMER, 0x400);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_RXS_RINGO_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 21, 12, 0x366);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_3_CTRL_FSM_TIMEOUT_X64K, 0x80);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_4_TRAIN_DC_ON_PERIOD_X64K, 0x18);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_4_TRAIN_DC_PERIOD_X512K, 0x3e);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_PMD_CFG_5_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_PMD_CFG_5_USE_RECENT_MARKER_OFFSET, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);

	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_CONT_ON_ADC_GAIN_CAL_ERR, 0x1);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_DO_RX_ADC_OFST_CAL, 0x3);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_0_RX_ERR_ACTION_EN, 0x40);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_1_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST0_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST1_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST2_WAIT_CNT_X4096, 0xff);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_1_TRAIN_ST3_WAIT_CNT_X4096, 0xff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_2_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST4_WAIT_CNT_X4096, 0x1);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST5_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST6_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_2_TRAIN_ST7_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_3_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST8_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST9_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST10_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_3_TRAIN_ST11_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_4_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST12_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST13_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST14_WAIT_CNT_X4096, 0x4);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_4_TRAIN_ST15_WAIT_CNT_X4096, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_7_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_7_TRAIN_ST4_EN, 0x4bf);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_7_TRAIN_ST5_EN, 0xc4bf);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_8_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_8_TRAIN_ST7_EN, 0x47ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_12_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_12_TRAIN_ST15_EN, 0x67ff);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_13_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_13_TRAIN_ST0_DONE_EN, 0x8001);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_13_TRAIN_ST1_DONE_EN, 0x8002);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_14_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_14_TRAIN_ST3_DONE_EN, 0x8008);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_15_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_15_TRAIN_ST4_DONE_EN, 0x8004);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_17_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_17_TRAIN_ST8_DONE_EN, 0x20c0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_18_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_18_TRAIN_ST10_DONE_EN, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_29_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_29_TRAIN_ST15_DC_EN, 0x3f6d);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_33_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_33_TRAIN0_RATE_SEL, 0x8000);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_33_TRAIN1_RATE_SEL, 0x8000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_CTRL_FSM_CFG_34_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_34_TRAIN2_RATE_SEL, 0x8000);
	set_fields_e56(&rdata, E56PHY_CTRL_FSM_CFG_34_TRAIN3_RATE_SEL, 0x8000);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_KRT_TFSM_CFG_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_MAX_WAIT_TIMER_X1000K, 0x49);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_MAX_WAIT_TIMER_X8000K, 0x37);
	set_fields_e56(&rdata, E56PHY_KRT_TFSM_CFGKRT_TFSM_HOLDOFF_TIMER_X256K, 0x2f);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = E56PHY_FETX_FFE_TRAIN_CFG_0_ADDR;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, E56PHY_FETX_FFE_TRAIN_CFG_0_KRT_FETX_INIT_FFE_CFG_2,
		       0x2);
	wr32_ephy(hw, addr, rdata);

	return 0;
}

static int txgbe_set_phy_link_mode(struct txgbe_hw *hw,
				   u8 by_link_mode)
{
	int status = 0;
	u32 addr, rdata;

	rdata = 0x0000;
	addr = 0x030000;
	rdata = rd32_epcs(hw, addr);
	/* 10G mode */
	if (by_link_mode == 10)
		set_fields_e56(&rdata, 5, 2, 0);
	/* 25G mode */
	else if (by_link_mode == 25)
		set_fields_e56(&rdata, 5, 2, 5);
	wr32_epcs(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0x030007;
	rdata = rd32_epcs(hw, addr);
	/* 10G mode */
	if (by_link_mode == 10)
		set_fields_e56(&rdata, 3, 0, 0);
	/* 25G mode */
	else if (by_link_mode == 25)
		set_fields_e56(&rdata, 3, 0, 7);
	wr32_epcs(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0x010007;
	rdata = rd32_epcs(hw, addr);
	/* 10G mode */
	if (by_link_mode == 10)
		set_fields_e56(&rdata, 6, 0, 0xb);
	/* 25G mode */
	else if (by_link_mode == 25)
		set_fields_e56(&rdata, 6, 0, 0x39);
	wr32_epcs(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xcb0;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 29, 29, 0x1);
	set_fields_e56(&rdata, 1, 1, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xcc4;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 24, 24, 0x0);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xca4;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 1, 1, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xca8;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 30, 30, 0x1);
	set_fields_e56(&rdata, 25, 25, 0x1);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xc10;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 25, 24, 0x1);
	set_fields_e56(&rdata, 17, 16, 0x3);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xc18;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 12, 8, 0x4);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xc48;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 25, 24, 0x1);
	set_fields_e56(&rdata, 17, 16, 0x3);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xc50;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 12, 8, 0x8);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0xc1c;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 18, 8, 0x294);
	set_fields_e56(&rdata, 4, 0, 0x8);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0x142c;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 30, 28, 0x7);
	set_fields_e56(&rdata, 26, 24, 0x5);
	if (by_link_mode == 10)
		set_fields_e56(&rdata, 18, 16, 0x5);
	else if (by_link_mode == 25)
		set_fields_e56(&rdata, 18, 16, 0x3);
	set_fields_e56(&rdata, 14, 12, 0x5);
	set_fields_e56(&rdata, 10, 8, 0x5);
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0x1430;
	rdata = rd32_ephy(hw, addr);
	set_fields_e56(&rdata, 26, 24, 0x5);
	set_fields_e56(&rdata, 10, 8, 0x5);
	if (by_link_mode == 10) {
		set_fields_e56(&rdata, 18, 16, 0x5);
		set_fields_e56(&rdata, 2, 0, 0x5);
	} else if (by_link_mode == 25) {
		set_fields_e56(&rdata, 18, 16, 0x3);
		set_fields_e56(&rdata, 2, 0, 0x3);
	}
	wr32_ephy(hw, addr, rdata);

	rdata = 0x0000;
	addr = 0x1438;
	rdata = rd32_ephy(hw, addr);
	if (by_link_mode == 10)
		set_fields_e56(&rdata, 4, 0, 0x2);
	else if (by_link_mode == 25)
		set_fields_e56(&rdata, 4, 0, 0x9);
	wr32_ephy(hw, addr, rdata);

	status = txgbe_e56_cms_cfg_for_temp_track_range(hw, by_link_mode);

	if (by_link_mode == 10)
		txgbe_e56_bp_cfg_10g(hw);
	else
		txgbe_e56_bp_cfg_25g(hw);

	if (by_link_mode == 10) {
		rdata = 0x0000;
		addr = 0x1400;
		rdata = rd32_ephy(hw, addr);
		set_fields_e56(&rdata, 21, 20, 0x3); /* pll en */
		set_fields_e56(&rdata, 19, 12, 0x1); /* tx/rx en */
		set_fields_e56(&rdata, 8, 8, 0x0); /* pmd mode */
		set_fields_e56(&rdata, 1, 1, 0x1); /* pmd en */
		wr32_ephy(hw, addr, rdata);
	}

	return status;
}

int txgbe_e56_set_link_to_kr(struct txgbe_hw *hw)
{
	int status = 0;
	u32 rdata;

	/* pcs + phy rst */
	rdata = rd32(hw, 0x1000c);
	if (hw->bus.lan_id == 1)
		rdata |= BIT(16);
	else
		rdata |= BIT(19);
	wr32(hw, 0x1000c, rdata);
	msleep(20);

	/* enable pcs intr */
	wr32_epcs(hw, VR_AN_INTR_MSK, 0xf);

	/* clear interrupt */
	wr32_epcs(hw, 0x070000, 0);
	wr32_epcs(hw, 0x078002, 0x0000);
	wr32_epcs(hw, 0x030000, 0x8000);
	rdata = rd32_epcs(hw, 0x070000);
	set_fields_e56(&rdata, 12, 12, 0x1);
	wr32_epcs(hw, 0x070000, rdata);
	wr32_epcs(hw, 0x070010, 0x0001);
	/* 25KR */
	wr32_epcs(hw, 0x070011, 0xC080);

	/* BASE-R FEC */
	wr32_epcs(hw, 0x070012, 0xc000);
	wr32_epcs(hw, 0x070016, 0x0000);
	wr32_epcs(hw, 0x070017, 0x0);
	wr32_epcs(hw, 0x070018, 0x0);

	/* config timer */
	wr32_epcs(hw, 0x078004, 0x003c);
	wr32_epcs(hw, 0x078005, CL74_KRTR_TRAINNING_TIMEOUT);
	wr32_epcs(hw, 0x078006, 25);
	wr32_epcs(hw, 0x078000, 0x0008);

	rdata = rd32_epcs(hw, 0x038000);
	wr32_epcs(hw, 0x038000, rdata | BIT(15));

	status = kr_read_poll(rd32_epcs, rdata,
			      (((rdata >> 15) & 1) == 0), 100,
			      200000, hw,
			      0x038000);
	if (status)
		return status;

	/* wait rx/tx/cm powerdn_st */
	msleep(20);
	/* set phy an status to 0 */
	wr32_ephy(hw, 0x1640, 0x0000);
	rdata = rd32_ephy(hw, 0x1434);
	set_fields_e56(&rdata, 7, 4, 0xe);
	wr32_ephy(hw, 0x1434, rdata);

	status = txgbe_set_phy_link_mode(hw, 10);
	if (status)
		return status;

	status = txgbe_e56_rxs_osc_init_for_temp_track_range(hw, 10);
	if (status)
		return status;

	/* Wait an 10g fsm_rx_sts */
	status = kr_read_poll(rd32_ephy, rdata,
			      ((rdata & 0x3f) == 0xb), 1000,
			      200000, hw,
			      E56PHY_CTRL_FSM_RX_STAT_0_ADDR);

	return status;
}

static int txgbe_e56_cl72_trainning(struct txgbe_hw *hw)
{
	u32 bylinkmode = hw->bp_link_mode;
	int status = 0, pTempData = 0;
	u8 bypassCtle = 0;
	u32 rdata;

	status = txgbe_set_phy_link_mode(hw, bylinkmode);

	/* set phy an status to 1 */
	rdata = rd32_ephy(hw, 0x1434);
	set_fields_e56(&rdata, 7, 4, 0xf);
	wr32_ephy(hw, 0x1434, rdata);

	/* kr training */
	rdata = rd32_ephy(hw, 0x1640);
	set_fields_e56(&rdata, 7, 0, 0x3);
	wr32_ephy(hw, 0x1640, rdata);

	/* enable CMS and its internal PLL and tx enable */
	rdata = rd32_ephy(hw, 0x1400);
	set_fields_e56(&rdata, 21, 20, 0x3);//pll en
	set_fields_e56(&rdata, 19, 12, 0x1);// tx/rx en
	set_fields_e56(&rdata, 8, 8, 0x0);// pmd mode
	set_fields_e56(&rdata, 1, 1, 0x1);// pmd en
	wr32_ephy(hw, 0x1400, rdata);

	status = txgbe_e56_phy_rxs_calib_adapt_seq(hw, bylinkmode, bypassCtle);

	txgbe_e56_set_rxs_ufine_le_max(hw, bylinkmode);

	status = txgbe_e56_get_temp(hw, &pTempData);
	status = txgbe_e56_rxs_post_cdr_lock_temp_track_seq(hw, bylinkmode);

	status = kr_read_poll(rd32_ephy, rdata, (rdata & BIT(1)), 100,
				   200000, hw, 0x163c);

	status = txgbe_e56_rxs_adc_adapt_seq(hw, bypassCtle);

	/* Wait an RLU */
	status = kr_read_poll(rd32_epcs, rdata, (rdata & BIT(2)),
				   100, 500000, hw, 0x30001);

	return status;
}

int handle_e56_bkp_an73_flow(struct txgbe_hw *hw)
{
	int status = 0;

	status = txgbe_e56_cl72_trainning(hw);
	return status;
}

void txgbe_e65_bp_down_event(struct txgbe_hw *hw)
{
	if (!(hw->devarg.auto_neg == 1))
		return;
}
