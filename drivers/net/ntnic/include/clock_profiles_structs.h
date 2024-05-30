/* */
/* clock_profiles_structs.h */
/* */

/*
 * %NT_SOFTWARE_LICENSE%
 */

#ifndef _NT_CLOCK_PROFILES_STRUCTS_H_
#define _NT_CLOCK_PROFILES_STRUCTS_H_

/* */
/* */
/* */
#include <stdint.h>

/* */
/* */
/* */
#define GET_VAR_NAME(var) #var

#define clk_profile_size_error_msg "Size test failed"

/* */
/* */
/* */
struct clk_profile_data_fmt0_s {
	unsigned char reg_addr;
	unsigned char reg_val;
	unsigned char reg_mask;
};

struct clk_profile_data_fmt1_s {
	uint16_t reg_addr;
	uint8_t reg_val;
};

struct clk_profile_data_fmt2_s {
	unsigned int reg_addr;
	unsigned char reg_val;
};

struct clk_profile_data_fmt3_s {
	unsigned int address;
	unsigned int data;
};

typedef struct clk_profile_data_fmt0_s clk_profile_data_fmt0_t;
typedef struct clk_profile_data_fmt1_s clk_profile_data_fmt1_t;
typedef struct clk_profile_data_fmt2_s clk_profile_data_fmt2_t;
typedef struct clk_profile_data_fmt3_s clk_profile_data_fmt3_t;

enum clk_profile_data_fmt_e {
	clk_profile_data_fmt_0,
	clk_profile_data_fmt_1,
	clk_profile_data_fmt_2,
	clk_profile_data_fmt_3,
};

typedef enum clk_profile_data_fmt_e clk_profile_data_fmt_t;

/* */
/* */
/* */
#endif	/* _NT_CLOCK_PROFILES_STRUCTS_H_ */

/* */
/* EOF */
/* */
