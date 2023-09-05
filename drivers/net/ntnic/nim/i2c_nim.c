/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nthw_drv.h"
#include "i2c_nim.h"
#include "ntlog.h"
#include "nt_util.h"

#include "nim_sensors.h"
#include "sfp_p_registers.h"
#include "qsfp_registers.h"
#include "sfp_sensors.h"
#include "qsfp_sensors.h"

#include <assert.h>
#include <string.h> /* memcmp, memset */

/*
 * Nim functions
 */
#define QSFP_SUP_LEN_INFO_LIN_ADDR 142 /* 5bytes */
#define QSFP_TRANSMITTER_TYPE_LIN_ADDR 147 /* 1byte */
#define QSFP_CONTROL_STATUS_LIN_ADDR 86
#define QSFP_SOFT_TX_ALL_DISABLE_BITS 0x0F
#define QSFP_SPEC_COMPLIANCE_CODES_ADDR 131 /* 8 bytes */
#define QSFP_EXT_SPEC_COMPLIANCE_CODES_ADDR 192 /* 1 byte */
#define NIM_READ false
#define NIM_WRITE true
#define NIM_PAGE_SEL_REGISTER 127
#define nim_i2c_0xa0 0xA0 /* Basic I2C address */
#define QSFP_VENDOR_NAME_LIN_ADDR 148 /* 16bytes */
#define QSFP_VENDOR_PN_LIN_ADDR 168 /* 16bytes */
#define QSFP_VENDOR_SN_LIN_ADDR 196 /* 16bytes */
#define QSFP_VENDOR_DATE_LIN_ADDR 212 /* 8bytes */
#define QSFP_VENDOR_REV_LIN_ADDR 184 /* 2bytes */
#define QSFP_DMI_OPTION_LIN_ADDR 220

#define QSFP_EXTENDED_IDENTIFIER 129
#define QSFP_POWER_CLASS_BITS_1_4 0xC0
#define QSFP_POWER_CLASS_BITS_5_7 0x03

static bool sfp_is_supported_tri_speed_pn(char *prod_no)
{
	static const char *const pn_trispeed_list[] = {
		"FCMJ-8521-3", "FCLF-8521-3", "FCLF8521P2BTL", "EOLT-C12-02A",
		"AMXP-24RJS",  "ABCU-5710RZ", "ABCU-5740RZ",   "FCLF8522P2BTL",
	};

	/* Determine if copper SFP is supported 3-speed type */
	for (size_t i = 0; i < ARRAY_SIZE(pn_trispeed_list); i++)
		if (strcmp(pn_trispeed_list[i], prod_no) == 0)
			return true;

	return false;
}

static bool page_addressing(nt_nim_identifier_t id)
{
	switch (id) {
	case NT_NIM_SFP_SFP_PLUS:
		return false;
	case NT_NIM_XFP:
		return true;
	case NT_NIM_QSFP:
	case NT_NIM_QSFP_PLUS:
	case NT_NIM_QSFP28:
		return true;
	default:
		NT_LOG(DBG, ETHDEV, "%s: Unknown NIM identifier %d\n", __func__,
		       id);
		return false;
	}
}

nt_nim_identifier_t translate_nimid(const nim_i2c_ctx_t *ctx)
{
	return (nt_nim_identifier_t)ctx->nim_id;
}

static int nim_read_write_i2c_data(nim_i2c_ctx_p ctx, bool do_write,
				uint16_t lin_addr, uint8_t i2c_addr,
				uint8_t reg_addr, uint8_t seq_cnt, uint8_t *p_data)
{
	/* Divide I2C_Addr by 2 because nthw_iic_read/writeData multiplies by 2 */
	const uint8_t i2c_devaddr = i2c_addr / 2U;
	(void)lin_addr; /* Unused */

	if (do_write)
		return nthw_iic_write_data(&ctx->hwiic, i2c_devaddr, reg_addr,
					 seq_cnt, p_data);
	else
		return nthw_iic_read_data(&ctx->hwiic, i2c_devaddr, reg_addr,
					seq_cnt, p_data);
}

/*
 * ------------------------------------------------------------------------------
 * Selects a new page for page addressing. This is only relevant if the NIM
 * supports this. Since page switching can take substantial time the current page
 * select is read and subsequently only changed if necessary.
 * Important:
 * XFP Standard 8077, Ver 4.5, Page 61 states that:
 * If the host attempts to write a table select value which is not supported in
 * a particular module, the table select byte will revert to 01h.
 * This can lead to some surprising result that some pages seems to be duplicated.
 * ------------------------------------------------------------------------------
 */

static int nim_setup_page(nim_i2c_ctx_p ctx, uint8_t page_sel)
{
	uint8_t curr_page_sel;

	/* Read the current page select value */
	if (nim_read_write_i2c_data(ctx, NIM_READ, NIM_PAGE_SEL_REGISTER,
				 nim_i2c_0xa0, NIM_PAGE_SEL_REGISTER,
				 sizeof(curr_page_sel), &curr_page_sel) != 0)
		return -1;

	/* Only write new page select value if necessary */
	if (page_sel != curr_page_sel) {
		if (nim_read_write_i2c_data(ctx, NIM_WRITE, NIM_PAGE_SEL_REGISTER,
					 nim_i2c_0xa0, NIM_PAGE_SEL_REGISTER,
					 sizeof(page_sel), &page_sel) != 0)
			return -1;
	}
	return 0;
}

static int nim_nim_read_write_data_lin(nim_i2c_ctx_p ctx, bool m_page_addressing,
				   uint16_t lin_addr, uint16_t length,
				   uint8_t *p_data, bool do_write)
{
	uint16_t i;
	uint8_t reg_addr; /* The actual register address in I2C device */
	uint8_t i2c_addr;
	int block_size = 128; /* Equal to size of MSA pages */
	int seq_cnt;
	int max_seq_cnt = 1;
	int multi_byte = 1; /* One byte per I2C register is default */
	const int m_port_no = ctx->instance - 2;

	if (lin_addr >= SFP_PHY_LIN_ADDR) {
		/*
		 * This represents an address space at I2C address 0xAC for SFP modules
		 * containing a PHY. (eg 1G Copper SFP). Each register is 16bit and is
		 * accessed MSByte first and this reading latches the LSByte that is
		 * subsequently read from the same address.
		 */
		multi_byte = 2;
		max_seq_cnt = 2;

		/* Test for correct multibyte access */
		if ((length % multi_byte) != 0) {
			NT_LOG(ERR, ETHDEV,
			       "Port %d: %s: Uneven length (%d) for address range [0x%X..0x%X].",
			       m_port_no, __func__, length, SFP_PHY_LIN_ADDR,
			       SFP_PHY_LIN_ADDR + SFP_PHY_LIN_RNG - 1);
			return -1;
		}

		if (lin_addr + (length / 2) >
				SFP_PHY_LIN_ADDR + SFP_PHY_LIN_RNG) {
			NT_LOG(ERR, ETHDEV,
			       "Port %d: %s: Access above address range [0x%X..0x%X].",
			       m_port_no, __func__, SFP_PHY_LIN_ADDR,
			       SFP_PHY_LIN_ADDR + SFP_PHY_LIN_RNG - 1);
			return -1;
		}
	} else if (lin_addr + length > 128) {
		/*
		 * Page addressing could be relevant since the last byte is outside the
		 * basic range so check if it is enabled
		 */
		if (m_page_addressing) {
			/* Crossing into the PHY address range is not allowed */
			if (lin_addr + length > SFP_PHY_LIN_ADDR) {
				NT_LOG(ERR, ETHDEV,
				       "Port %d: %s: Access above paged address range [0..0x%X].",
				       m_port_no, __func__, SFP_PHY_LIN_ADDR);
				return -1;
			}
		} else {
			/* Access outside 0xA2 address range not allowed */
			if (lin_addr + length > 512) {
				NT_LOG(ERR, ETHDEV,
				       "Port %d: %s: Access above address range [0..511].",
				       m_port_no, __func__);
				return -1;
			}
		}
	}
	/* No missing else here - all devices supports access to address [0..127] */

	for (i = 0; i < length;) {
		bool use_page_select = false;

		/*
		 * Find out how much can be read from the current block in case of
		 * single byte access
		 */
		if (multi_byte == 1)
			max_seq_cnt = block_size - (lin_addr % block_size);

		if (m_page_addressing) {
			if (lin_addr >= 128) { /* Only page setup above this address */
				use_page_select = true;

				/* Map to [128..255] of 0xA0 device */
				reg_addr = (uint8_t)(block_size +
						    (lin_addr % block_size));
			} else {
				reg_addr = (uint8_t)lin_addr;
			}
			i2c_addr = nim_i2c_0xa0; /* Base I2C address */
		} else {
			if (lin_addr >= SFP_PHY_LIN_ADDR) {
				/* Map to address [0..31] of 0xAC device */
				reg_addr = (uint8_t)(lin_addr - SFP_PHY_LIN_ADDR);
				i2c_addr = nim_i2c_0xac;
			} else if (lin_addr >= 256) {
				/* Map to address [0..255] of 0xA2 device */
				reg_addr = (uint8_t)(lin_addr - 256);
				i2c_addr = nim_i2c_0xa2;
			} else {
				reg_addr = (uint8_t)lin_addr;
				i2c_addr = nim_i2c_0xa0; /* Base I2C address */
			}
		}

		/* Now actually do the reading/writing */
		seq_cnt = length - i; /* Number of remaining bytes */

		if (seq_cnt > max_seq_cnt)
			seq_cnt = max_seq_cnt;

		/*
		 * Read a number of bytes without explicitly specifying a new address.
		 * This can speed up I2C access since automatic incrementation of the
		 * I2C device internal address counter can be used. It also allows
		 * a HW implementation, that can deal with block access.
		 * Furthermore it also allows for access to data that must be accessed
		 * as 16bit words reading two bytes at each address eg PHYs.
		 */
		if (use_page_select) {
			if (nim_setup_page(ctx,
					   (uint8_t)((lin_addr / 128) - 1)) != 0) {
				NT_LOG(ERR, ETHDEV,
				       "%s: Cannot set up page for linear address %u\n",
				       __func__, lin_addr);
				return -1;
			}
		}
		if (nim_read_write_i2c_data(ctx, do_write, lin_addr, i2c_addr,
					    reg_addr, (uint8_t)seq_cnt,
					    p_data) != 0) {
			NT_LOG(ERR, ETHDEV,
			       "%s: Call to NIM_ReadWriteI2cData failed\n",
			       __func__);
			return -1;
		}

		p_data += seq_cnt;
		i = (uint16_t)(i + seq_cnt);
		lin_addr = (uint16_t)(lin_addr + (seq_cnt / multi_byte));
	}
	return 0;
}

int read_data_lin(nim_i2c_ctx_p ctx, uint16_t lin_addr, uint16_t length,
		void *data)
{
	return nim_nim_read_write_data_lin(ctx, page_addressing(ctx->nim_id),
				       lin_addr, length, data, NIM_READ);
}

static int write_data_lin(nim_i2c_ctx_p ctx, uint16_t lin_addr, uint16_t length,
			void *data)
{
	return nim_nim_read_write_data_lin(ctx, page_addressing(ctx->nim_id),
				       lin_addr, length, data, NIM_WRITE);
}

/* Read and return a single byte */
static uint8_t read_byte(nim_i2c_ctx_p ctx, uint16_t addr)
{
	uint8_t data;

	read_data_lin(ctx, addr, sizeof(data), &data);
	return data;
}

static int nim_read_id(nim_i2c_ctx_t *ctx)
{
	/* We are only reading the first byte so we don't care about pages here. */
	const bool use_page_addressing = false;

	if (nim_nim_read_write_data_lin(ctx, use_page_addressing,
				    NIM_IDENTIFIER_ADDR, sizeof(ctx->nim_id),
				    &ctx->nim_id, NIM_READ) != 0)
		return -1;
	return 0;
}

static int i2c_nim_common_construct(nim_i2c_ctx_p ctx)
{
	ctx->nim_id = 0;
	int res = nim_read_id(ctx);

	if (res) {
		NT_LOG(ERR, PMD, "Can't read NIM id.");
		return res;
	}
	memset(ctx->vendor_name, 0, sizeof(ctx->vendor_name));
	memset(ctx->prod_no, 0, sizeof(ctx->prod_no));
	memset(ctx->serial_no, 0, sizeof(ctx->serial_no));
	memset(ctx->date, 0, sizeof(ctx->date));
	memset(ctx->rev, 0, sizeof(ctx->rev));

	ctx->content_valid = false;
	memset(ctx->len_info, 0, sizeof(ctx->len_info));
	ctx->pwr_level_req = 0;
	ctx->pwr_level_cur = 0;
	ctx->avg_pwr = false;
	ctx->tx_disable = false;
	ctx->lane_idx = -1;
	ctx->lane_count = 1;
	ctx->options = 0;
	return 0;
}

static int nim_read_vendor_info(nim_i2c_ctx_p ctx, uint16_t addr,
				 uint8_t max_len, char *p_data);

#define XSFP_READ_VENDOR_INFO(x)                                             \
	static void x##sfp_read_vendor_info(nim_i2c_ctx_t *ctx)              \
	{                                                                    \
		nim_read_vendor_info(ctx, Q##SFP_VENDOR_NAME_LIN_ADDR,      \
				      sizeof(ctx->vendor_name),               \
				      ctx->vendor_name);                      \
		nim_read_vendor_info(ctx, Q##SFP_VENDOR_PN_LIN_ADDR,        \
				      sizeof(ctx->prod_no), ctx->prod_no);     \
		nim_read_vendor_info(ctx, Q##SFP_VENDOR_SN_LIN_ADDR,        \
				      sizeof(ctx->serial_no), ctx->serial_no); \
		nim_read_vendor_info(ctx, Q##SFP_VENDOR_DATE_LIN_ADDR,      \
				      sizeof(ctx->date), ctx->date);         \
		nim_read_vendor_info(ctx, Q##SFP_VENDOR_REV_LIN_ADDR,       \
				      (uint8_t)(sizeof(ctx->rev) - 2),       \
				      ctx->rev); /*OBS Only two bytes*/      \
	}

XSFP_READ_VENDOR_INFO()
XSFP_READ_VENDOR_INFO(q)

static int sfp_nim_state_build(nim_i2c_ctx_t *ctx, sfp_nim_state_t *state)
{
	int res;

	assert(ctx && state);
	assert(ctx->nim_id != NT_NIM_UNKNOWN && "Nim is not initialized");

	(void)memset(state, 0, sizeof(*state));

	res = nthw_iic_read_data(&ctx->hwiic, ctx->devaddr, SFP_BIT_RATE_ADDR,
			       sizeof(state->br), &state->br);
	return res;
}

static int qsfp_nim_state_build(nim_i2c_ctx_t *ctx, sfp_nim_state_t *state)
{
	int res = 0; /* unused due to no readings from HW */

	assert(ctx && state);
	assert(ctx->nim_id != NT_NIM_UNKNOWN && "Nim is not initialized");

	(void)memset(state, 0, sizeof(*state));

	switch (ctx->nim_id) {
	case 12U:
		state->br = 10U; /* QSFP: 4 x 1G = 4G */
		break;
	case 13U:
		state->br = 103U; /* QSFP+: 4 x 10G = 40G */
		break;
	case 17U:
		state->br = 255U; /* QSFP28: 4 x 25G = 100G */
		break;
	default:
		NT_LOG(INF, PMD,
		       "%s:%d nim_id = %u is not an QSFP/QSFP+/QSFP28 module\n",
		       __func__, __LINE__, ctx->nim_id);
		res = -1;
	}

	return res;
}

int nim_state_build(nim_i2c_ctx_t *ctx, sfp_nim_state_t *state)
{
	if (translate_nimid(ctx) == NT_NIM_SFP_SFP_PLUS)
		return sfp_nim_state_build(ctx, state);
	else
		return qsfp_nim_state_build(ctx, state);
}

const char *nim_id_to_text(uint8_t nim_id)
{
	switch (nim_id) {
	case 0x0:
		return "UNKNOWN";
	case 0x1:
		return "GBIC";
	case 0x2:
		return "FIXED";
	case 0x3:
		return "SFP/SFP+";
	case 0x04:
		return "300 pin XBI";
	case 0x05:
		return "XEN-PAK";
	case 0x06:
		return "XFP";
	case 0x07:
		return "XFF";
	case 0x08:
		return "XFP-E";
	case 0x09:
		return "XPAK";
	case 0x0A:
		return "X2";
	case 0x0B:
		return "DWDM";
	case 0x0C:
		return "QSFP";
	case 0x0D:
		return "QSFP+";
	case 0x11:
		return "QSFP28";
	case 0x12:
		return "CFP4";
	default:
		return "ILLEGAL!";
	}
}

/*
 * Read and check the validity of the NIM basic data.
 * This will also preload the cache
 */
static void check_content_valid(nim_i2c_ctx_p ctx, uint16_t start_addr)
{
	uint32_t sum = 0;
	uint8_t buf[96];

	read_data_lin(ctx, start_addr, sizeof(buf), &buf[0]);

	for (int i = 0; i < 63; i++)
		sum += buf[i];

	if ((sum & 0xFF) != buf[63]) {
		ctx->content_valid = false;
	} else {
		sum = 0;

		for (int i = 64; i < 95; i++)
			sum += buf[i];

		ctx->content_valid = ((sum & 0xFF) == buf[95]);
	}
	if (ctx->content_valid)
		NT_LOG(DBG, NTHW, "NIM content validation passed");
	else
		NT_LOG(WRN, NTHW, "NIM content validation failed");
}

/*
 * Set/reset Soft Rate__select bits (RS0 & RS1)
 */
static void nim_sfp_set_rate_sel_high(nim_i2c_ctx_p ctx, bool rx_rate_high,
				  bool tx_rate_high)
{
	const bool m_page_addressing = page_addressing(ctx->nim_id);
	uint8_t data;

	nim_nim_read_write_data_lin(ctx, m_page_addressing,
				SFP_CONTROL_STATUS_LIN_ADDR, sizeof(data),
				&data, NIM_READ);

	if (rx_rate_high)
		data |= SFP_SOFT_RATE0_BIT;
	else
		data &= (uint8_t)~(SFP_SOFT_RATE0_BIT);

	nim_nim_read_write_data_lin(ctx, m_page_addressing,
				SFP_CONTROL_STATUS_LIN_ADDR, sizeof(data),
				&data, NIM_WRITE);

	/* Read the Extended Status/Control and set/reset Soft RS1 bit */
	nim_nim_read_write_data_lin(ctx, m_page_addressing,
				SFP_EXT_CTRL_STAT0_LIN_ADDR, sizeof(data),
				&data, NIM_READ);

	if (tx_rate_high)
		data |= SFP_SOFT_RATE1_BIT;
	else
		data &= (uint8_t)~(SFP_SOFT_RATE1_BIT);

	nim_nim_read_write_data_lin(ctx, m_page_addressing,
				SFP_EXT_CTRL_STAT0_LIN_ADDR, sizeof(data),
				&data, NIM_WRITE);
}

/*
 * Some NIM modules requires some changes to a rate setting.
 */
static int nim_sfp_set_rate_select(nim_i2c_ctx_p ctx, nt_link_speed_t speed)
{
	if ((speed & (int)ctx->speed_mask) == 0) {
		char buf[128];

		NT_LOG(ERR, ETHDEV, "%s - Speed (%s) not within SpeedMask (%s)",
		       nt_translate_link_speed(speed),
		       nt_translate_link_speed_mask(ctx->speed_mask, buf,
						 sizeof(buf)));
		return -1;
	}

	if (ctx->specific_u.sfp.dual_rate) {
		uint64_t req_speed = nt_get_link_speed(speed);
		uint64_t other_speed =
			nt_get_link_speed((nt_link_speed_t)(ctx->speed_mask ^ (uint32_t)speed));
		bool rate_high = req_speed > other_speed;
		/*
		 * Do this both for 1/10 and 10/25. For Sfp28 it is not known if
		 * this is necessary but it is believed not to do any harm.
		 */
		nim_sfp_set_rate_sel_high(ctx, rate_high, rate_high);
	}
	return 0;
}

/*
 * Disable TX laser.
 */
int nim_sfp_nim_set_tx_laser_disable(nim_i2c_ctx_p ctx, bool disable)
{
	int res;
	uint8_t value;
	const bool pg_addr = page_addressing(ctx->nim_id);

	res = nim_nim_read_write_data_lin(ctx, pg_addr, SFP_CONTROL_STATUS_LIN_ADDR,
				      sizeof(value), &value, NIM_READ);
	if (res != 0)
		return res;

	if (disable)
		value |= SFP_SOFT_TX_DISABLE_BIT;
	else
		value &= (uint8_t)~SFP_SOFT_TX_DISABLE_BIT;

	res = nim_nim_read_write_data_lin(ctx, pg_addr, SFP_CONTROL_STATUS_LIN_ADDR,
				      sizeof(value), &value, NIM_WRITE);

	return res;
}

/*
 * Disable laser for specific lane or all lanes
 */
int nim_qsfp_plus_nim_set_tx_laser_disable(nim_i2c_ctx_p ctx, bool disable,
				       int lane_idx)
{
	uint8_t value;
	uint8_t mask;
	const bool pg_addr = page_addressing(ctx->nim_id);

	if (lane_idx < 0) /* If no lane is specified then all lanes */
		mask = QSFP_SOFT_TX_ALL_DISABLE_BITS;
	else
		mask = (uint8_t)(1U << lane_idx);

	if (nim_nim_read_write_data_lin(ctx, pg_addr, QSFP_CONTROL_STATUS_LIN_ADDR,
				    sizeof(value), &value, NIM_READ) != 0)
		return -1;

	if (disable)
		value |= mask;
	else
		value &= (uint8_t)~mask;

	if (nim_nim_read_write_data_lin(ctx, pg_addr, QSFP_CONTROL_STATUS_LIN_ADDR,
				    sizeof(value), &value, NIM_WRITE) != 0)
		return -1;
	return 0;
}

/*
 * Read vendor information at a certain address. Any trailing whitespace is
 * removed and a missing string termination in the NIM data is handled.
 */
static int nim_read_vendor_info(nim_i2c_ctx_p ctx, uint16_t addr,
				 uint8_t max_len, char *p_data)
{
	const bool pg_addr = page_addressing(ctx->nim_id);
	int i;
	/* Subtract "1" from maxLen that includes a terminating "0" */

	if (nim_nim_read_write_data_lin(ctx, pg_addr, addr, (uint8_t)(max_len - 1),
				    (uint8_t *)p_data, NIM_READ) != 0)
		return -1;

	/* Terminate at first found white space */
	for (i = 0; i < max_len - 1; i++) {
		if (*p_data == ' ' || *p_data == '\n' || *p_data == '\t' ||
				*p_data == '\v' || *p_data == '\f' || *p_data == '\r') {
			*p_data = '\0';
			return 0;
		}

		p_data++;
	}

	/*
	 * Add line termination as the very last character, if it was missing in the
	 * NIM data
	 */
	*p_data = '\0';
	return 0;
}

/*
 * Import length info in various units from NIM module data and convert to meters
 */
static void nim_import_len_info(nim_i2c_ctx_p ctx, uint8_t *p_nim_len_info,
				uint16_t *p_nim_units)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->len_info); i++)
		if (*(p_nim_len_info + i) == 255) {
			ctx->len_info[i] = 65535;
		} else {
			uint32_t len = *(p_nim_len_info + i) * *(p_nim_units + i);

			if (len > 65535)
				ctx->len_info[i] = 65535;
			else
				ctx->len_info[i] = (uint16_t)len;
		}
}

static int qsfpplus_read_basic_data(nim_i2c_ctx_t *ctx)
{
	const bool pg_addr = page_addressing(ctx->nim_id);
	uint8_t options;
	uint8_t value;
	uint8_t nim_len_info[5];
	uint16_t nim_units[5] = { 1000, 2, 1, 1,
				 1
			       }; /* QSFP MSA units in meters */
	const char *yes_no[2] _unused = { "No", "Yes" };

	NT_LOG(DBG, ETHDEV, "Instance %d: NIM id: %s (%d)\n", ctx->instance,
	       nim_id_to_text(ctx->nim_id), ctx->nim_id);

	/* Read DMI options */
	if (nim_nim_read_write_data_lin(ctx, pg_addr, QSFP_DMI_OPTION_LIN_ADDR,
				    sizeof(options), &options, NIM_READ) != 0)
		return -1;
	ctx->avg_pwr = options & QSFP_DMI_AVG_PWR_BIT;
	NT_LOG(DBG, ETHDEV,
	       "Instance %d: NIM options: (DMI: Yes, AvgPwr: %s)\n",
	       ctx->instance, yes_no[ctx->avg_pwr]);

	qsfp_read_vendor_info(ctx);
	NT_LOG(DBG, PMD,
	       "Instance %d: NIM info: (Vendor: %s, PN: %s, SN: %s, Date: %s, Rev: %s)\n",
	       ctx->instance, ctx->vendor_name, ctx->prod_no, ctx->serial_no,
	       ctx->date, ctx->rev);

	if (nim_nim_read_write_data_lin(ctx, pg_addr, QSFP_SUP_LEN_INFO_LIN_ADDR,
				    sizeof(nim_len_info), nim_len_info,
				    NIM_READ) != 0)
		return -1;

	/*
	 * Returns supported length information in meters for various fibers as 5 indivi-
	 * dual values: [SM(9um), EBW(50um), MM(50um), MM(62.5um), Copper]
	 * If no length information is available for a certain entry, the returned value
	 * will be zero. This will be the case for SFP modules - EBW entry.
	 * If the MSBit is set the returned value in the lower 31 bits indicates that the
	 * supported length is greater than this.
	 */

	nim_import_len_info(ctx, nim_len_info, nim_units);

	/* Read required power level */
	if (nim_nim_read_write_data_lin(ctx, pg_addr, QSFP_EXTENDED_IDENTIFIER,
				    sizeof(value), &value, NIM_READ) != 0)
		return -1;

	/*
	 * Get power class according to SFF-8636 Rev 2.7, Table 6-16, Page 43:
	 * If power class >= 5 setHighPower must be called for the module to be fully
	 * functional
	 */
	if ((value & QSFP_POWER_CLASS_BITS_5_7) == 0) {
		/* NIM in power class 1 - 4 */
		ctx->pwr_level_req =
			(uint8_t)(((value & QSFP_POWER_CLASS_BITS_1_4) >> 6) +
				  1);
	} else {
		/* NIM in power class 5 - 7 */
		ctx->pwr_level_req =
			(uint8_t)((value & QSFP_POWER_CLASS_BITS_5_7) + 4);
	}

	return 0;
}

/*
 * If true the user must actively select the desired rate. If false the module
 * however can still support several rates without the user is required to select
 * one of them. Supported rates must then be deduced from the product number.
 * SFF-8636, Rev 2.10a:
 * p40: 6.2.7 Rate Select
 * p85: A.2 Rate Select
 */
static bool qsfp28_is_speed_selection_enabled(nim_i2c_ctx_p ctx)
{
	const uint8_t options_reg_addr = 195;
	const uint8_t enh_options_reg_addr = 221;

	uint8_t rate_select_ena = (read_byte(ctx, options_reg_addr) >> 5) &
				0x01; /* bit: 5 */

	if (rate_select_ena == 0)
		return false;

	uint8_t rate_select_type = (read_byte(ctx, enh_options_reg_addr) >> 2) &
				 0x03; /* bit 3..2 */

	if (rate_select_type != 2) {
		NT_LOG(DBG, NTHW, "NIM has unhandled rate select type (%d)",
		       rate_select_type);
		return false;
	}

	return true; /* When true selectRate() can be used */
}

/*
 * Select a speed that is supported for a multi rate module. The possible speed
 * values must be obtained by setSpeedMask().
 * Currently rate selection is assumed to be between 40Gb (10GBd) and 100G (25Gbd)
 * The value in () are the baud rates for PAM-4 and are valid for extended rate
 * select, version 2.
 */
static int qsfp28_set_link_speed(nim_i2c_ctx_p ctx, nt_link_speed_t speed)
{
	const uint8_t rx_rate_sel_addr = 87;
	const uint8_t tx_rate_sel_addr = 88;

	if (ctx->lane_idx < 0) {
		/*
		 * All lanes together
		 * The condition below indicates that the module supports rate selection
		 */
		if (ctx->speed_mask == (uint32_t)(NT_LINK_SPEED_40G | NT_LINK_SPEED_100G)) {
			uint16_t data;

			if (speed == NT_LINK_SPEED_100G) {
				data = 0xAAAA;
			} else if (speed == NT_LINK_SPEED_40G) {
				data = 0x0000;
			} else {
				NT_LOG(ERR, NTHW, "Unhandled NIM speed (%s).",
				       nt_translate_link_speed(speed));
				return -1;
			}

			/* Set speed for Rx and Tx on all lanes */
			write_data_lin(ctx, rx_rate_sel_addr, sizeof(data), &data);
			write_data_lin(ctx, tx_rate_sel_addr, sizeof(data), &data);
		} else {
			/* For ordinary modules only this speed is supported */
			if (speed != NT_LINK_SPEED_100G) {
				NT_LOG(ERR, NTHW,
				       "NIM cannot select this speed (%s).",
				       nt_translate_link_speed(speed));
				return -1;
			}
		}
	} else {
		/*
		 * Individual lanes
		 * Currently we do not support QSFP28 modules that support rate selection when
		 * running on individual lanes but that might change in the future
		 */
		if (speed != NT_LINK_SPEED_25G) {
			NT_LOG(ERR, NTHW,
			       "NIM cannot select this lane speed (%s).",
			       nt_translate_link_speed(speed));
			return -1;
		}
	}
	return 0;
}

int nim_set_link_speed(nim_i2c_ctx_p ctx, nt_link_speed_t speed)
{
	if (translate_nimid(ctx) == NT_NIM_SFP_SFP_PLUS) {
		return nim_sfp_set_rate_select(ctx, speed);
	} else if (translate_nimid(ctx) == NT_NIM_QSFP28) {
		if (qsfp28_is_speed_selection_enabled(ctx))
			return qsfp28_set_link_speed(ctx, speed);

		return 0; /* NIM picks up the speed automatically */
	}
	NT_LOG(ERR, ETHDEV,
	       "%s nim is not supported for adjustable link speed.",
	       nim_id_to_text(ctx->nim_id));
	return -1;
}

/*
 * Reads basic vendor and DMI information.
 */
static int sfp_read_basic_data(nim_i2c_ctx_p ctx)
{
	const char *yes_no[2] _unused = { "No", "Yes" };

	check_content_valid(ctx, 0);
	NT_LOG(DBG, PMD, "NIM id: %s (%d)", nim_id_to_text(ctx->nim_id),
	       ctx->nim_id);

	/* Read DMI options */
	uint8_t options;

	read_data_lin(ctx, SFP_DMI_OPTION_LIN_ADDR, sizeof(options), &options);
	ctx->avg_pwr = options & SFP_DMI_AVG_PWR_BIT;
	ctx->dmi_supp = options & SFP_DMI_IMPL_BIT;
	ctx->specific_u.sfp.ext_cal = options & SFP_DMI_EXT_CAL_BIT;
	ctx->specific_u.sfp.addr_chg = options & SFP_DMI_ADDR_CHG_BIT;

	if (ctx->dmi_supp) {
		ctx->options |=
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	}

	if (ctx->dmi_supp) {
		NT_LOG(DBG, PMD,
		       "NIM options: (DMI: %s, AvgPwr: %s, ExtCal: %s, AddrChg: %s)",
		       yes_no[ctx->dmi_supp], yes_no[ctx->avg_pwr],
		       yes_no[ctx->specific_u.sfp.ext_cal],
		       yes_no[ctx->specific_u.sfp.addr_chg]);
	} else {
		NT_LOG(DBG, PMD, "NIM options: DMI not supported");
	}
	/* Read enhanced options */
	read_data_lin(ctx, SFP_ENHANCED_OPTIONS_LIN_ADDR, sizeof(options),
		    &options);
	ctx->tx_disable = options & SFP_SOFT_TX_DISABLE_IMPL_BIT;

	if (ctx->tx_disable)
		ctx->options |= (1 << NIM_OPTION_TX_DISABLE);

	sfp_read_vendor_info(ctx);

	uint8_t nim_len_info[5];

	read_data_lin(ctx, SFP_SUP_LEN_INFO_LIN_ADDR, sizeof(nim_len_info),
		    nim_len_info);

	/*
	 * Returns supported length information in meters for various fibers as 5 indivi-
	 * dual values: [SM(9um), EBW(50um), MM(50um), MM(62.5um), Copper]
	 * If no length information is available for a certain entry, the returned value
	 * will be zero. This will be the case for SFP modules - EBW entry.
	 * If the MSBit is set the returned value in the lower 31 bits indicates that the
	 * supported length is greater than this.
	 */

	uint16_t nim_units[5] = { 1000, 100, 10, 10,
				 1
			       }; /* SFP MSA units in meters */
	nim_import_len_info(ctx, &nim_len_info[0], &nim_units[0]);

	if (ctx->len_info[0] != 0 || ctx->len_info[1] != 0) {
		/*
		 * Make sure that for SFP modules the supported length for SM fibers
		 * which is given in both km and 100m units is are equal to the greatest
		 * value.
		 * The following test will also be valid if NIM_LEN_MAX has been set!
		 */
		if (ctx->len_info[1] > ctx->len_info[0])
			ctx->len_info[0] = ctx->len_info[1];

		ctx->len_info[1] = 0; /* EBW is not supported for SFP */
	}

	read_data_lin(ctx, SFP_OPTION0_LIN_ADDR, sizeof(options), &options);

	if (options & SFP_POWER_LEVEL2_REQ_BIT)
		ctx->pwr_level_req = 2;
	else
		ctx->pwr_level_req = 1;

	ctx->pwr_level_cur = 1;

	if (ctx->pwr_level_req == 2) {
		/* Read the current power level status */
		read_data_lin(ctx, SFP_EXT_CTRL_STAT0_LIN_ADDR, sizeof(options),
			    &options);

		if (options & SFP_POWER_LEVEL2_GET_BIT)
			ctx->pwr_level_cur = 2;
		else
			ctx->pwr_level_cur = 1;
	}
	return 0;
}

/*
 * Read the vendor product number and from this determine which QSFP DMI options
 * that are present. This list also covers QSFP28 modules.
 * This function should be used if automatic detection does not work.
 */
static bool qsfpplus_get_qsfp_options_from_pn(nim_i2c_ctx_p ctx)
{
	if (strcmp(ctx->prod_no, "FTL410QE1C") == 0) {
		/* FINISAR FTL410QE1C, QSFP+ */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_TX_BIAS) | (1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "FTL410QE2C") == 0) {
		/* FINISAR FTL410QE2C, QSFP+ */
		ctx->options = (1 << NIM_OPTION_TEMP) |
			       (1 << NIM_OPTION_SUPPLY);
	} else if (strcmp(ctx->prod_no, "FTL4C1QE1C") == 0) {
		/* FINISAR FTL4C1QE1C, QSFP+ */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "AFBR-79E4Z") == 0) {
		/*
		 * AFBR-79E4Z: The digital diagnostic accuracy is not guaranteed so only
		 * the mandatory temperature sensor is made available (although it will
		 * also be inaccurate)
		 */
		/* AVAGO 79E4Z, QSFP+ */
		ctx->options = (1 << NIM_OPTION_TEMP);
	} else if (strcmp(ctx->prod_no, "AFBR-79E4Z-D") == 0) {
		/* AVAGO 79E4Z-D, QSFP+ */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "AFBR-79EQDZ") == 0) {
		/* AVAGO 79EQDZ, QSFP+ */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "AFBR-79EBRZ") == 0) {
		/*
		 * Avago RxOnly BiDi NIM
		 * No sensors available not even the normally mandatory temp sensor and this
		 * is ok since the temp sensor is not mandatory on active optical modules
		 */
		/* SFF-8436_rev4.1, p67 */
		ctx->options = (1 << NIM_OPTION_RX_ONLY);
	} else if (strcmp(ctx->prod_no, "AFBR-79EBPZ-NU1") == 0) {
		/*
		 * Avago RxTx BiDi NIM
		 * No sensors available not even the normally mandatory temp sensor and this
		 * is ok since the temp sensor is not mandatory on active optical modules
		 */
		ctx->options = 0;
	} else if (strcmp(ctx->prod_no, "AFBR-79EBPZ") == 0) {
		/*
		 * Avago RxTx BiDi NIM
		 * No sensors available not even the normally mandatory temp sensor and this
		 * is ok since the temp sensor is not mandatory on active optical modules
		 */
		ctx->options = 0;
	} else if (strcmp(ctx->prod_no, "AFBR-89CDDZ") == 0) {
		/* AVAGO 89CDDZ, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "AFBR-89BDDZ") == 0) {
		/* AVAGO 89BDDZ, QSFP28, BiDi */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "AFBR-89BRDZ") == 0) {
		/*
		 * AVAGO 89BRDZ, QSFP28, BiDi, RxOnly
		 * but sensors have been set as above except for Tx sensors
		 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_RX_ONLY);
		/*
		 * According to mail correspondence AFBR-89BRDZ is a RxOnly version of
		 * AFBR-89BDDZ with lasers default off.
		 * The lasers can be turned on however but should probably not because the
		 * receivers might be degraded, and this is the cause for selling them as RxOnly.
		 */
	} else if (strcmp(ctx->prod_no, "SQF1000L4LNGG01P") == 0) {
		/* Sumitomo SQF1000L4LNGG01P, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "SQF1000L4LNGG01B") == 0) {
		/* Sumitomo SQF1000L4LNGG01B, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "SQF1001L4LNGG01P") == 0) {
		/* Sumitomo SQF1001L4LNGG01P, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "SQF1001L4LNGG01B") == 0) {
		/* Sumitomo SQF1001L4LNGG01B, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "SQF1002L4LNGG01B") == 0) {
		/* Sumitomo SQF1002L4LNGG01B, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "FIM37700/171") == 0) {
		/* Fujitsu FIM37700/171, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "FIM37700/172") == 0) {
		/* Fujitsu FIM37700/172, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "TR-FC85S-NVS") == 0) {
		/* InnoLight TR-FC85S-NVS, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "TR-FC13L-NVS") == 0) {
		/* InnoLight TR-FC13L-NVS, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "FTLC9551REPM") == 0) {
		/* Finisar FTLC9551REPM, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else if (strcmp(ctx->prod_no, "FTLC9558REPM") == 0) {
		/* Finisar FTLC9558REPM, QSFP28 */
		ctx->options =
			(1 << NIM_OPTION_TEMP) | (1 << NIM_OPTION_SUPPLY) |
			(1 << NIM_OPTION_RX_POWER) | (1 << NIM_OPTION_TX_BIAS) |
			(1 << NIM_OPTION_TX_POWER);
	} else {
		/*
		 * DO NOTE: The temperature sensor is not mandatory on active/passive copper
		 * and active optical modules
		 */
		ctx->options = (1 << NIM_OPTION_TEMP);
		return false;
	}

	return true;
}

/*
 * Try to figure out if a sensor is present by reading its value(s) and its limits.
 * This is a highly impirical way that cannot be guaranteed to give the correct
 * result but it was a wish not to be dependent on a PN table based solution.
 */
static void qsfpplus_find_qsfp_sensor_option(nim_i2c_ctx_p ctx,
		uint16_t value_addr,
		uint8_t lane_count,
		uint16_t limit_addr, bool two_compl,
		uint32_t sensor_option)
{
	uint8_t data[8];
	int i, j;
	int value;
	int value_list[4];
	int limit;
	int limit_list[4];
	bool present;

	/* Read current value(s) */
	read_data_lin(ctx, value_addr, (uint16_t)(lane_count * 2), data);

	for (j = 0; j < lane_count; j++) {
		value = 0;

		for (i = 0; i < 2; i++) {
			value = value << 8;
			value += data[2 * j + i];
		}

		if (two_compl && value >= 0x8000)
			value = value - 0x10000;

		value_list[j] = value;
	}

	/* Read limits Warning high/low Alarm high/low 4 values each two bytes */
	read_data_lin(ctx, limit_addr, 8, data);

	for (j = 0; j < 4; j++) {
		limit = 0;

		for (i = 0; i < 2; i++) {
			limit = limit << 8;
			limit += data[2 * j + i];
		}

		if (two_compl && limit >= 0x8000)
			limit = limit - 0x10000;

		limit_list[j] = limit;
	}

	/* Find out if limits contradicts each other */
	int alarm_high = limit_list[0];
	int alarm_low = limit_list[1];
	int warn_high = limit_list[2];
	int warn_low = limit_list[3];

	bool alarm_limits = false; /* Are they present - that is both not zero */
	bool warn_limits = false;
	bool limit_conflict = false;

	if (alarm_high != 0 || alarm_low != 0) {
		alarm_limits = true;

		if (alarm_high <= alarm_low)
			limit_conflict = true;
	}

	if (warn_high != 0 || warn_low != 0) {
		warn_limits = true;

		/* Warning limits must be least restrictive */
		if (warn_high <= warn_low)
			limit_conflict = true;
		else if ((warn_high > alarm_high) || (warn_low < alarm_low))
			limit_conflict = true;
	}

	/* Try to deduce if the sensor is present or not */
	present = false;

	if (limit_conflict) {
		present = false;
	} else if (warn_limits ||
		 alarm_limits) { /* Is one or both present and not contradictory */
		present = true;
	} else {
		/*
		 * All limits are zero - look at the sensor value
		 * If one sensor is non-zero the sensor is set to be present
		 */
		for (j = 0; j < lane_count; j++) {
			if (value_list[j] != 0) {
				present = true;
				break;
			}
		}

		/*
		 * If all limits and values are zero then present will be false here. In this
		 * case it is assumed that the sensor is not present:
		 * Experience indicates that for QSFP+ modules RxPwr will be non-zero even with
		 * no optical input. QSFP28 modules however can easily have RxPwr equal to zero
		 * with no optical input.
		 * For all investigated modules it was found that if RxPwr is implemented then
		 * the limits are also set. This is not always the case with TxBias and TxPwr
		 * but here the measured values will be non-zero when the laser is on what it
		 * will be just after initialization since it has no external hardware disable.
		 */
	}

	if (present)
		ctx->options |= (1U << sensor_option);
}

/*
 * Find active QSFP sensors.
 */
static void qsfpplus_get_qsfp_options_from_data(nim_i2c_ctx_p ctx)
{
	ctx->options = 0;

	qsfpplus_find_qsfp_sensor_option(ctx, QSFP_TEMP_LIN_ADDR, 1,
					 QSFP_TEMP_THRESH_LIN_ADDR, true,
					 NIM_OPTION_TEMP);

	qsfpplus_find_qsfp_sensor_option(ctx, QSFP_VOLT_LIN_ADDR, 1,
					 QSFP_VOLT_THRESH_LIN_ADDR, false,
					 NIM_OPTION_SUPPLY);

	qsfpplus_find_qsfp_sensor_option(ctx, QSFP_RX_PWR_LIN_ADDR, 4,
					 QSFP_RX_PWR_THRESH_LIN_ADDR, false,
					 NIM_OPTION_RX_POWER);

	qsfpplus_find_qsfp_sensor_option(ctx, QSFP_TX_PWR_LIN_ADDR, 4,
					 QSFP_TX_PWR_THRESH_LIN_ADDR, false,
					 NIM_OPTION_TX_POWER);

	qsfpplus_find_qsfp_sensor_option(ctx, QSFP_TX_BIAS_LIN_ADDR, 4,
					 QSFP_BIAS_THRESH_LIN_ADDR, false,
					 NIM_OPTION_TX_BIAS);
}

static void sfp_find_port_params(nim_i2c_ctx_p ctx)
{
	uint8_t data;
	uint16_t bit_rate_nom;
	uint8_t connector;
	uint8_t gig_eth_comp;
	uint8_t dmi_opt;
	uint8_t fiber_chan_tx_tech;
	unsigned int len_sm;
	unsigned int len_mm_50um;
	unsigned int len_mm_62_5um;

	ctx->specific_u.sfp.sfp28 = false;

	/* gigEthComp: */
	static const uint8_t eth_1000_b_t = 1 << 3;
	static const uint8_t eth_1000_b_sx = 1 << 0;
	static const uint8_t eth_1000_b_lx = 1 << 1;

	/* fiberChanTxTech: */
	static const uint8_t cu_passive = 1 << 2;
	static const uint8_t cu_active = 1 << 3;

	/* dmiOpt: */
	static const uint8_t dd_present = 1 << 6;

	/* connector: */
	static const uint8_t cu_pig_tail = 0x21;

	ctx->port_type = NT_PORT_TYPE_SFP_NOT_RECOGNISED;

	read_data_lin(ctx, 12, sizeof(data), &data);
	bit_rate_nom = (uint16_t)(data * 100);

	read_data_lin(ctx, 2, sizeof(connector), &connector);
	read_data_lin(ctx, 6, sizeof(gig_eth_comp), &gig_eth_comp);
	read_data_lin(ctx, 92, sizeof(dmi_opt), &dmi_opt);
	read_data_lin(ctx, 8, sizeof(fiber_chan_tx_tech), &fiber_chan_tx_tech);

	read_data_lin(ctx, 15, sizeof(data), &data);
	len_sm = (unsigned int)data * 100; /* Unit is 100m */

	read_data_lin(ctx, 16, sizeof(data), &data);
	len_mm_50um = (unsigned int)data * 10; /* Unit is 10m */

	read_data_lin(ctx, 17, sizeof(data), &data);
	len_mm_62_5um = (unsigned int)data * 10; /* Unit is 10m */

	/* First find out if it is a SFP or a SFP+ NIM */
	if (bit_rate_nom == 0) {
		/*
		 * A Nominal bit rate of zero indicates that it has not been defined and must
		 * be deduced from transceiver technology
		 */
		ctx->specific_u.sfp.sfpplus = !(gig_eth_comp & eth_1000_b_t);
	} else if (bit_rate_nom == 25500) {
		/* SFF-8024 - 4.4 Extended Specification Compliance References */
		read_data_lin(ctx, 36, sizeof(data), &data);

		if (data == 0x02)
			ctx->port_type = NT_PORT_TYPE_SFP_28_SR;
		else if (data == 0x03)
			ctx->port_type = NT_PORT_TYPE_SFP_28_LR;
		else if (data == 0x0B)
			ctx->port_type = NT_PORT_TYPE_SFP_28_CR_CA_L;
		else if (data == 0x0C)
			ctx->port_type = NT_PORT_TYPE_SFP_28_CR_CA_S;
		else if (data == 0x0D)
			ctx->port_type = NT_PORT_TYPE_SFP_28_CR_CA_N;
		else
			ctx->port_type = NT_PORT_TYPE_SFP_28;

		ctx->specific_u.sfp.sfp28 = true;
		ctx->specific_u.sfp.sfpplus = true;

		/*
		 * Allowlist of 25G transceivers known to also support 10G.
		 * There is no way to inquire about this capability.
		 */
		if ((strcmp(ctx->prod_no, "TR-PZ85S-N00") == 0) ||
				(strcmp(ctx->prod_no, "TR-PZ13L-N00") == 0) ||
				(strcmp(ctx->prod_no, "FTLF8536P4BCV") == 0) ||
				(strcmp(ctx->prod_no, "FTLF1436P4BCV") == 0)) {
			ctx->specific_u.sfp.dual_rate = true;

			/* Change the port type for dual rate modules */
			if (ctx->port_type == NT_PORT_TYPE_SFP_28_SR)
				ctx->port_type = NT_PORT_TYPE_SFP_28_SR_DR;
			else if (ctx->port_type == NT_PORT_TYPE_SFP_28_LR)
				ctx->port_type = NT_PORT_TYPE_SFP_28_LR_DR;
		}

		return;
	}
	ctx->specific_u.sfp.sfpplus = (bit_rate_nom >= 10000);
	/* Then find sub-types of each */
	if (ctx->specific_u.sfp.sfpplus) {
		if (fiber_chan_tx_tech & cu_active) {
			ctx->port_type = NT_PORT_TYPE_SFP_PLUS_ACTIVE_DAC;
		} else if (fiber_chan_tx_tech & cu_passive) {
			if (connector == cu_pig_tail)
				ctx->port_type =
					NT_PORT_TYPE_SFP_PLUS_PASSIVE_DAC;
			else
				ctx->port_type = NT_PORT_TYPE_SFP_PLUS_CU;
		} else {
			ctx->port_type = NT_PORT_TYPE_SFP_PLUS;
		}
		if (gig_eth_comp & (eth_1000_b_sx | eth_1000_b_lx)) {
			ctx->port_type = NT_PORT_TYPE_SFP_PLUS_DUAL_RATE;
			ctx->specific_u.sfp.dual_rate = true;
		}

		read_data_lin(ctx, 65, sizeof(data), &data);
		/* Test hard RATE_SELECT bit */
		ctx->specific_u.sfp.hw_rate_sel = ((data & (1 << 5)) != 0);

		read_data_lin(ctx, 93, sizeof(data), &data);
		/* Test soft RATE_SELECT bit */
		ctx->specific_u.sfp.sw_rate_sel = ((data & (1 << 3)) != 0);
	} else { /* SFP */
		/* 100M */
		if (bit_rate_nom != 0 && bit_rate_nom < 1000) {
			ctx->port_type = NT_PORT_TYPE_SFP_FX;
		/* 1G */
		} else {
			ctx->specific_u.sfp.cu_type = false;
			if (gig_eth_comp & eth_1000_b_sx) {
				ctx->port_type = NT_PORT_TYPE_SFP_SX;
			} else if (gig_eth_comp & eth_1000_b_lx) {
				ctx->port_type = NT_PORT_TYPE_SFP_LX;
			} else if (gig_eth_comp & eth_1000_b_t) {
				ctx->specific_u.sfp.tri_speed =
					sfp_is_supported_tri_speed_pn(ctx->prod_no);

				if (ctx->specific_u.sfp.tri_speed) {
					ctx->port_type =
						NT_PORT_TYPE_SFP_CU_TRI_SPEED;
				} else {
					ctx->port_type = NT_PORT_TYPE_SFP_CU;
				}
				ctx->specific_u.sfp.cu_type = true;
			} else {
				/*
				 * Not all modules report their ethernet compliance correctly so use
				 * length indicators
				 */
				if (len_sm > 0)
					ctx->port_type = NT_PORT_TYPE_SFP_LX;
				else if ((len_mm_50um > 0) || (len_mm_62_5um > 0))
					ctx->port_type = NT_PORT_TYPE_SFP_SX;
			}

			/* Add Diagnostic Data suffix if necessary */
			if (dmi_opt & dd_present) {
				if (ctx->port_type == NT_PORT_TYPE_SFP_SX)
					ctx->port_type = NT_PORT_TYPE_SFP_SX_DD;
				else if (ctx->port_type == NT_PORT_TYPE_SFP_LX)
					ctx->port_type = NT_PORT_TYPE_SFP_LX_DD;
				else if (ctx->port_type == NT_PORT_TYPE_SFP_CU)
					ctx->port_type = NT_PORT_TYPE_SFP_CU_DD;
				else if (ctx->port_type ==
						NT_PORT_TYPE_SFP_CU_TRI_SPEED)
					ctx->port_type =
						NT_PORT_TYPE_SFP_CU_TRI_SPEED_DD;
			}
		}
	}
}


static void sfp_set_speed_mask(nim_i2c_ctx_p ctx)
{
	if (ctx->specific_u.sfp.sfp28) {
		ctx->speed_mask = NT_LINK_SPEED_25G; /* Default for SFP28 */
		if (ctx->specific_u.sfp.dual_rate)
			ctx->speed_mask |= NT_LINK_SPEED_10G;
	} else if (ctx->specific_u.sfp.sfpplus) {
		ctx->speed_mask = NT_LINK_SPEED_10G; /* Default for SFP+ */
		if (ctx->specific_u.sfp.dual_rate)
			ctx->speed_mask |= NT_LINK_SPEED_1G;
		if (ctx->port_type == NT_PORT_TYPE_SFP_PLUS_PASSIVE_DAC)
			ctx->speed_mask |= NT_LINK_SPEED_1G;
		if (ctx->port_type == NT_PORT_TYPE_SFP_PLUS_ACTIVE_DAC)
			ctx->speed_mask |= NT_LINK_SPEED_1G;
	} else { /* SFP */
		if (ctx->port_type == NT_PORT_TYPE_SFP_FX) {
			ctx->speed_mask = NT_LINK_SPEED_100M;
		} else {
			ctx->speed_mask = NT_LINK_SPEED_1G; /* Default for SFP */
			if (ctx->specific_u.sfp.dual_rate ||
					ctx->specific_u.sfp.tri_speed)
				ctx->speed_mask |= NT_LINK_SPEED_100M;
			if (ctx->specific_u.sfp.tri_speed)
				ctx->speed_mask |= NT_LINK_SPEED_10M;
		}
	}
	if (ctx->port_type == NT_PORT_TYPE_SFP_28_CR_CA_L ||
			ctx->port_type == NT_PORT_TYPE_SFP_28_CR_CA_S ||
			ctx->port_type == NT_PORT_TYPE_SFP_28_CR_CA_N) {
		/* Enable multiple speed setting for SFP28 DAC cables */
		ctx->speed_mask = (NT_LINK_SPEED_25G | NT_LINK_SPEED_10G |
				  NT_LINK_SPEED_1G);
	}
}

static void qsfp28_find_port_params(nim_i2c_ctx_p ctx)
{
	uint8_t fiber_chan_speed;

	/* Table 6-17 SFF-8636 */
	read_data_lin(ctx, QSFP_SPEC_COMPLIANCE_CODES_ADDR, 1, &fiber_chan_speed);

	if (fiber_chan_speed & (1 << 7)) {
		/* SFF-8024, Rev 4.7, Table 4-4 */
		uint8_t extended_specification_compliance_code = 0;

		read_data_lin(ctx, QSFP_EXT_SPEC_COMPLIANCE_CODES_ADDR, 1,
			    &extended_specification_compliance_code);

		switch (extended_specification_compliance_code) {
		case 0x02:
			ctx->port_type = NT_PORT_TYPE_QSFP28_SR4;
			break;
		case 0x03:
			ctx->port_type = NT_PORT_TYPE_QSFP28_LR4;
			break;
		case 0x0B:
			ctx->port_type = NT_PORT_TYPE_QSFP28_CR_CA_L;
			break;
		case 0x0C:
			ctx->port_type = NT_PORT_TYPE_QSFP28_CR_CA_S;
			break;
		case 0x0D:
			ctx->port_type = NT_PORT_TYPE_QSFP28_CR_CA_N;
			break;
		case 0x25:
			ctx->port_type = NT_PORT_TYPE_QSFP28_DR;
			break;
		case 0x26:
			ctx->port_type = NT_PORT_TYPE_QSFP28_FR;
			break;
		case 0x27:
			ctx->port_type = NT_PORT_TYPE_QSFP28_LR;
			break;
		default:
			ctx->port_type = NT_PORT_TYPE_QSFP28;
		}
	} else {
		ctx->port_type = NT_PORT_TYPE_QSFP28;
	}
}

/*
 * If true the user must actively select the desired rate. If false the module
 * however can still support several rates without the user is required to select
 * one of them. Supported rates must then be deduced from the product number.
 * SFF-8636, Rev 2.10a:
 * p40: 6.2.7 Rate Select
 * p85: A.2 Rate Select
 */
static bool qsfp28_is_rate_selection_enabled(nim_i2c_ctx_p ctx)
{
	const uint8_t ext_rate_select_compl_reg_addr = 141;
	const uint8_t options_reg_addr = 195;
	const uint8_t enh_options_reg_addr = 221;

	uint8_t rate_select_ena = (read_byte(ctx, options_reg_addr) >> 5) &
				0x01; /* bit: 5 */

	if (rate_select_ena == 0)
		return false;

	uint8_t rate_select_type = (read_byte(ctx, enh_options_reg_addr) >> 2) &
				 0x03; /* bit 3..2 */

	if (rate_select_type != 2) {
		NT_LOG(DBG, PMD, "NIM has unhandled rate select type (%d)",
		       rate_select_type);
		return false;
	}

	uint8_t ext_rate_select_ver = read_byte(ctx, ext_rate_select_compl_reg_addr) &
				   0x03; /* bit 1..0 */

	if (ext_rate_select_ver != 0x02) {
		NT_LOG(DBG, PMD,
		       "NIM has unhandled extended rate select version (%d)",
		       ext_rate_select_ver);
		return false;
	}

	return true; /* When true selectRate() can be used */
}

static void qsfp28_set_speed_mask(nim_i2c_ctx_p ctx)
{
	if (ctx->port_type == NT_PORT_TYPE_QSFP28_FR ||
			ctx->port_type == NT_PORT_TYPE_QSFP28_DR ||
			ctx->port_type == NT_PORT_TYPE_QSFP28_LR) {
		if (ctx->lane_idx < 0)
			ctx->speed_mask = NT_LINK_SPEED_100G;
		else
			ctx->speed_mask =
				0; /* PAM-4 modules can only run on all lanes together */
	} else {
		if (ctx->lane_idx < 0)
			ctx->speed_mask = NT_LINK_SPEED_100G;
		else
			ctx->speed_mask = NT_LINK_SPEED_25G;

		if (qsfp28_is_rate_selection_enabled(ctx)) {
			/*
			 * It is assumed that if the module supports dual rates then the other rate
			 * is 10G per lane or 40G for all lanes.
			 */
			if (ctx->lane_idx < 0)
				ctx->speed_mask |= NT_LINK_SPEED_40G;
			else
				ctx->speed_mask = NT_LINK_SPEED_10G;
		}
	}
}

static void qsfpplus_find_port_params(nim_i2c_ctx_p ctx)
{
	uint8_t device_tech;

	read_data_lin(ctx, QSFP_TRANSMITTER_TYPE_LIN_ADDR, sizeof(device_tech),
		    &device_tech);

	switch (device_tech & 0xF0) {
	case 0xA0: /* Copper cable unequalized */
	case 0xB0: /* Copper cable passive equalized */
		ctx->port_type = NT_PORT_TYPE_QSFP_PASSIVE_DAC;
		break;
	case 0xC0: /* Copper cable, near and far end limiting active equalizers */
	case 0xD0: /* Copper cable, far end limiting active equalizers */
	case 0xE0: /* Copper cable, near end limiting active equalizers */
	case 0xF0: /* Copper cable, linear active equalizers */
		ctx->port_type = NT_PORT_TYPE_QSFP_ACTIVE_DAC;
		break;
	default: /* Optical */
		ctx->port_type = NT_PORT_TYPE_QSFP_PLUS;
		break;
	}
}

static void qsfpplus_set_speed_mask(nim_i2c_ctx_p ctx)
{
	ctx->speed_mask = (ctx->lane_idx < 0) ? NT_LINK_SPEED_40G :
			 (NT_LINK_SPEED_10G);
}

static int sfp_preinit(nim_i2c_ctx_p ctx)
{
	int res = sfp_read_basic_data(ctx);

	if (!res) {
		sfp_find_port_params(ctx);
		sfp_set_speed_mask(ctx);
	}
	return res;
}

static void qsfpplus_construct(nim_i2c_ctx_p ctx, int8_t lane_idx)
{
	assert(lane_idx < 4);
	ctx->specific_u.qsfp.qsfp28 = false;
	ctx->lane_idx = lane_idx;
	ctx->lane_count = 4;
}

static int qsfpplus_preinit(nim_i2c_ctx_p ctx, int8_t lane_idx)
{
	qsfpplus_construct(ctx, lane_idx);
	int res = qsfpplus_read_basic_data(ctx);

	if (!res) {
		qsfpplus_find_port_params(ctx);
		/*
		 * If not on the known modules list try to figure out which sensors that are present
		 */
		if (!qsfpplus_get_qsfp_options_from_pn(ctx)) {
			NT_LOG(DBG, NTHW,
			       "NIM options not known in advance - trying to detect");
			qsfpplus_get_qsfp_options_from_data(ctx);
		}

		/*
		 * Read if TX_DISABLE has been implemented
		 * For passive optical modules this is required while it for copper and active
		 * optical modules is optional. Under all circumstances register 195.4 will
		 * indicate, if TX_DISABLE has been implemented in register 86.0-3
		 */
		uint8_t value;

		read_data_lin(ctx, QSFP_OPTION3_LIN_ADDR, sizeof(value), &value);

		ctx->tx_disable = (value & QSFP_OPTION3_TX_DISABLE_BIT) != 0;

		if (ctx->tx_disable)
			ctx->options |= (1 << NIM_OPTION_TX_DISABLE);

		/*
		 * Previously - considering AFBR-89BRDZ - code tried to establish if a module was
		 * RxOnly by testing the state of the lasers after reset. Lasers were for this
		 * module default disabled.
		 * However that code did not work for GigaLight, GQS-MPO400-SR4C so it was
		 * decided that this option should not be detected automatically but from PN
		 */
		ctx->specific_u.qsfp.rx_only =
			(ctx->options & (1 << NIM_OPTION_RX_ONLY)) != 0;
		qsfpplus_set_speed_mask(ctx);
	}
	return res;
}

static void qsfp28_wait_for_ready_after_reset(nim_i2c_ctx_p ctx)
{
	uint8_t data;
	bool init_complete_flag_present = false;

	/*
	 * Revision compliance
	 * 7: SFF-8636 Rev 2.5, 2.6 and 2.7
	 * 8: SFF-8636 Rev 2.8, 2.9 and 2.10
	 */
	read_data_lin(ctx, 1,
		      sizeof(ctx->specific_u.qsfp.specific_u.qsfp28.rev_compliance),
		      &ctx->specific_u.qsfp.specific_u.qsfp28.rev_compliance);
	NT_LOG(DBG, NTHW, "NIM RevCompliance = %d",
	       ctx->specific_u.qsfp.specific_u.qsfp28.rev_compliance);

	/* Wait if lane_idx == -1 (all lanes are used) or lane_idx == 0 (the first lane) */
	if (ctx->lane_idx > 0)
		return;

	if (ctx->specific_u.qsfp.specific_u.qsfp28.rev_compliance >= 7) {
		/* Check if init complete flag is implemented */
		read_data_lin(ctx, 221, sizeof(data), &data);
		init_complete_flag_present = (data & (1 << 4)) != 0;
	}

	NT_LOG(DBG, NTHW, "NIM InitCompleteFlagPresent = %d",
	       init_complete_flag_present);

	/*
	 * If the init complete flag is not present then wait 500ms that together with 500ms
	 * after reset (in the adapter code) should be enough to read data from upper pages
	 * that otherwise would not be ready. Especially BiDi modules AFBR-89BDDZ have been
	 * prone to this when trying to read sensor options using getQsfpOptionsFromData()
	 * Probably because access to the paged address space is required.
	 */
	if (!init_complete_flag_present) {
		NT_OS_WAIT_USEC(500000);
		return;
	}

	/* Otherwise wait for the init complete flag to be set */
	int count = 0;

	while (true) {
		if (count > 10) { /* 1 s timeout */
			NT_LOG(WRN, NTHW, "Timeout waiting for module ready");
			break;
		}

		read_data_lin(ctx, 6, sizeof(data), &data);

		if (data & 0x01) {
			NT_LOG(DBG, NTHW, "Module ready after %dms",
			       count * 100);
			break;
		}

		NT_OS_WAIT_USEC(100000); /* 100 ms */
		count++;
	}
}

static void qsfp28_get_fec_options(nim_i2c_ctx_p ctx)
{
	const char *const nim_list[] = {
		"AFBR-89BDDZ", /* Avago BiDi */
		"AFBR-89BRDZ", /* Avago BiDi, RxOnly */
		"FTLC4352RKPL", /* Finisar QSFP28-LR */
		"FTLC4352RHPL", /* Finisar QSFP28-DR */
		"FTLC4352RJPL", /* Finisar QSFP28-FR */
		"SFBR-89BDDZ-CS4", /* Foxconn, QSFP28 100G/40G BiDi */
	};

	for (size_t i = 0; i < ARRAY_SIZE(nim_list); i++) {
		if (ctx->prod_no == nim_list[i]) {
			ctx->options |= (1 << NIM_OPTION_MEDIA_SIDE_FEC);
			ctx->specific_u.qsfp.specific_u.qsfp28.media_side_fec_ena =
				true;
			NT_LOG(DBG, NTHW, "Found FEC info via PN list");
			return;
		}
	}

	/*
	 * For modules not in the list find FEC info via registers
	 * Read if the module has controllable FEC
	 * SFF-8636, Rev 2.10a TABLE 6-28 Equalizer, Emphasis, Amplitude and Timing)
	 * (Page 03h, Bytes 224-229)
	 */
	uint8_t data;
	uint16_t addr = 227 + 3 * 128;

	read_data_lin(ctx, addr, sizeof(data), &data);

	/* Check if the module has FEC support that can be controlled */
	ctx->specific_u.qsfp.specific_u.qsfp28.media_side_fec_ctrl =
		(data & (1 << 6)) != 0;
	ctx->specific_u.qsfp.specific_u.qsfp28.host_side_fec_ctrl =
		(data & (1 << 7)) != 0;

	if (ctx->specific_u.qsfp.specific_u.qsfp28.media_side_fec_ctrl)
		ctx->options |= (1 << NIM_OPTION_MEDIA_SIDE_FEC);

	if (ctx->specific_u.qsfp.specific_u.qsfp28.host_side_fec_ctrl)
		ctx->options |= (1 << NIM_OPTION_HOST_SIDE_FEC);
}

static int qsfp28_preinit(nim_i2c_ctx_p ctx, int8_t lane_idx)
{
	int res = qsfpplus_preinit(ctx, lane_idx);

	if (!res) {
		qsfp28_wait_for_ready_after_reset(ctx);
		memset(&ctx->specific_u.qsfp.specific_u.qsfp28, 0,
		       sizeof(ctx->specific_u.qsfp.specific_u.qsfp28));
		ctx->specific_u.qsfp.qsfp28 = true;
		qsfp28_find_port_params(ctx);
		qsfp28_get_fec_options(ctx);
		qsfp28_set_speed_mask(ctx);
	}
	return res;
}

static void sfp_nim_add_all_sensors(uint8_t m_port_no, nim_i2c_ctx_t *ctx,
				  struct nim_sensor_group **nim_sensors_ptr,
				  uint16_t *nim_sensors_cnt)
{
	struct nim_sensor_group *sensor = NULL;
	*nim_sensors_cnt = 0;

	if (ctx == NULL || nim_sensors_ptr == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	/*
	 * If the user has not provided a name for the temperature sensor then apply
	 * one automatically
	 */
	if (strlen(sfp_sensors_level0[0].name) == 0) {
		if (ctx->specific_u.sfp.sfp28) {
			rte_strscpy(sfp_sensors_level0[0].name, "SFP28",
				sizeof(sfp_sensors_level0[0].name));
		} else if (ctx->specific_u.sfp.sfpplus) {
			rte_strscpy(sfp_sensors_level0[0].name, "SFP+",
				sizeof(sfp_sensors_level0[0].name));
		} else {
			rte_strscpy(sfp_sensors_level0[0].name, "SFP",
				sizeof(sfp_sensors_level0[0].name));
		}
	}

	/* allocate temperature sensor */
	nim_sensors_ptr[m_port_no] = allocate_nim_sensor_group(m_port_no,
							       ctx,
							       NT_SENSOR_SOURCE_PORT,
							       &sfp_sensors_level0[0]);
	sensor = nim_sensors_ptr[m_port_no];
	sensor->read = &nim_read_sfp_temp;
	(*nim_sensors_cnt)++;

	/* voltage */
	sensor->next = allocate_nim_sensor_group(m_port_no,
						 ctx,
						 NT_SENSOR_SOURCE_PORT,
						 &sfp_sensors_level1[0]);
	sensor = sensor->next;
	sensor->read = &nim_read_sfp_voltage;
	(*nim_sensors_cnt)++;

	/* bias current */
	sensor->next = allocate_nim_sensor_group(m_port_no,
						 ctx,
						 NT_SENSOR_SOURCE_PORT,
						 &sfp_sensors_level1[1]);
	sensor = sensor->next;
	sensor->read = &nim_read_sfp_bias_current;
	(*nim_sensors_cnt)++;

	/* tx power */
	sensor->next = allocate_nim_sensor_group(m_port_no,
						 ctx,
						 NT_SENSOR_SOURCE_PORT,
						 &sfp_sensors_level1[2]);
	sensor = sensor->next;
	sensor->read = &nim_read_sfp_tx_power;
	(*nim_sensors_cnt)++;

	/* rx power */
	sensor->next = allocate_nim_sensor_group(m_port_no,
						 ctx,
						 NT_SENSOR_SOURCE_PORT,
						 &sfp_sensors_level1[3]);
	sensor = sensor->next;
	sensor->read = &nim_read_sfp_rx_power;
	(*nim_sensors_cnt)++;
}

static void
qsfp_plus_nim_add_all_sensors(uint8_t m_port_no, nim_i2c_ctx_t *ctx,
			   struct nim_sensor_group **nim_sensors_ptr,
			   uint16_t *nim_sensors_cnt)
{
	struct nim_sensor_group *sensor = NULL;

	if (ctx == NULL || nim_sensors_ptr == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	/*
	 * If the user has not provided a name for the temperature sensor then apply
	 * one automatically
	 */
	if (strlen(qsfp_sensor_level0[0].name) == 0) {
		if (ctx->specific_u.qsfp.qsfp28)
			rte_strscpy(qsfp_sensor_level0[0].name, "QSFP28",
				sizeof(qsfp_sensor_level0[0].name));
		else
			rte_strscpy(qsfp_sensor_level0[0].name, "QSFP+",
				sizeof(qsfp_sensor_level0[0].name));
	}

	/* temperature sensor */
	nim_sensors_ptr[m_port_no] = allocate_nim_sensor_group(m_port_no, ctx,
							       NT_SENSOR_SOURCE_PORT,
							       &qsfp_sensor_level0[0]);
	sensor = nim_sensors_ptr[m_port_no];
	sensor->read = &nim_read_qsfp_temp;
	(*nim_sensors_cnt)++;

	/* voltage */
	sensor->next = allocate_nim_sensor_group(m_port_no, ctx,
						 NT_SENSOR_SOURCE_LEVEL1_PORT,
						 &qsfp_sensor_level1[0]);
	sensor = sensor->next;
	sensor->read = &nim_read_qsfp_voltage;
	(*nim_sensors_cnt)++;

	/* bias current sensors */
	for (uint8_t i = 1; i < 5; i++) {
		sensor->next = allocate_nim_sensor_group(m_port_no, ctx,
							 NT_SENSOR_SOURCE_LEVEL1_PORT,
							 &qsfp_sensor_level1[i]);
		sensor = sensor->next;
		sensor->read = &nim_read_qsfp_bias_current;
		(*nim_sensors_cnt)++;
	}

	/* tx power */
	for (uint8_t i = 5; i < 9; i++) {
		sensor->next = allocate_nim_sensor_group(m_port_no, ctx,
							 NT_SENSOR_SOURCE_LEVEL1_PORT,
							 &qsfp_sensor_level1[i]);
		sensor = sensor->next;
		sensor->read = &nim_read_qsfp_tx_power;
		(*nim_sensors_cnt)++;
	}

	/* rx power */
	for (uint8_t i = 9; i < 13; i++) {
		sensor->next = allocate_nim_sensor_group(m_port_no, ctx,
							 NT_SENSOR_SOURCE_LEVEL1_PORT,
							 &qsfp_sensor_level1[i]);
		sensor = sensor->next;
		sensor->read = &nim_read_qsfp_rx_power;
		(*nim_sensors_cnt)++;
	}
}

struct nim_sensor_group *
allocate_nim_sensor_group(uint8_t port, struct nim_i2c_ctx *ctx,
			  enum nt_sensor_source_e ssrc,
			  struct nt_adapter_sensor_description *sd)
{
	struct nim_sensor_group *sg = malloc(sizeof(struct nim_sensor_group));

	if (sg == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: sensor group is NULL", __func__);
		return NULL;
	}
	sg->sensor = allocate_sensor_by_description(port, ssrc, sd);
	sg->ctx = ctx;
	sg->next = NULL;
	return sg;
}

int construct_and_preinit_nim(nim_i2c_ctx_p ctx, void *extra, uint8_t port,
			      struct nim_sensor_group **nim_sensors_ptr,
			      uint16_t *nim_sensors_cnt)
{
	int res = i2c_nim_common_construct(ctx);

	switch (translate_nimid(ctx)) {
	case NT_NIM_SFP_SFP_PLUS:
		sfp_preinit(ctx);
		sfp_nim_add_all_sensors(port, ctx, nim_sensors_ptr,
					nim_sensors_cnt);
		break;
	case NT_NIM_QSFP_PLUS:
		qsfpplus_preinit(ctx, extra ? *(int8_t *)extra : (int8_t)-1);
		qsfp_plus_nim_add_all_sensors(port, ctx, nim_sensors_ptr,
					      nim_sensors_cnt);
		break;
	case NT_NIM_QSFP28:
		qsfp28_preinit(ctx, extra ? *(int8_t *)extra : (int8_t)-1);
		qsfp_plus_nim_add_all_sensors(port, ctx, nim_sensors_ptr,
					      nim_sensors_cnt);
		break;
	default:
		res = 1;
		NT_LOG(ERR, NTHW, "NIM type %s is not supported.\n",
		       nim_id_to_text(ctx->nim_id));
	}

	return res;
}
