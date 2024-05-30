#ifndef __NTNIC_MOD_REG_H__
#define __NTNIC_MOD_REG_H__

#include <stdint.h>
#include "flow_api.h"
#include "stream_binary_flow_api.h"
#include "nthw_fpga_model.h"
#include "nthw_platform_drv.h"
#include "ntnic_stat.h"
#include "nthw_drv.h"
#include "nt4ga_adapter.h"

/*
 *
 */
struct link_ops_s {
	int (*link_init)(struct adapter_info_s *p_adapter_info, nthw_fpga_t *p_fpga);
};

void register_100g_link_ops(struct link_ops_s *ops);
const struct link_ops_s *get_100g_link_ops(void);

void register_agx_100g_link_ops(struct link_ops_s *ops);
const struct link_ops_s *get_agx_100g_link_ops(void);

void register_25g_link_ops(struct link_ops_s *ops);
const struct link_ops_s *get_25g_link_ops(void);

void register_40g_link_ops(struct link_ops_s *ops);
const struct link_ops_s *get_40g_link_ops(void);

void register_8x10g_link_ops(struct link_ops_s *ops);
const struct link_ops_s *get_8x10g_link_ops(void);

/*
 *
 */
struct avr_sensors_ops {
	struct nt_sensor_group *(*avr_sensor_init)(nthw_spi_v3_t *s_spi, uint8_t m_adapter_no,
		const char *p_name,
		enum nt_sensor_source_e ssrc, enum nt_sensor_type_e type, unsigned int index,
		enum sensor_mon_device avr_dev, uint8_t avr_dev_reg, enum sensor_mon_endian end,
		enum sensor_mon_sign si, int (*conv_func)(uint32_t), uint16_t mask);
};

void register_avr_sensors_ops(struct avr_sensors_ops *ops);
struct avr_sensors_ops *get_avr_sensors_ops(void);

/*
 *
 */
struct board_sensors_ops {
	struct nt_sensor_group *(*fpga_temperature_sensor_init)(uint8_t adapter_no,
		unsigned int sensor_idx,
		nthw_fpga_t *p_fpga);
};

void register_board_sensors_ops(struct board_sensors_ops *ops);
struct board_sensors_ops *get_board_sensors_ops(void);

/*
 *
 */
struct ntavr_ops {
	int (*nt_avr_sensor_mon_ctrl)(nthw_spi_v3_t *s_spi, enum sensor_mon_control ctrl);
	int (*nt_avr_sensor_mon_setup)(struct sensor_mon_setup16 *p_setup, nthw_spi_v3_t *s_spi);
	uint32_t (*sensor_read)(nthw_spis_t *t_spi, uint8_t fpga_idx, uint32_t *p_sensor_result);
};

void register_ntavr_ops(struct ntavr_ops *ops);
struct ntavr_ops *get_ntavr_ops(void);

/*
 *
 */
struct sensor_convertion_fun_ops {
	int (*null_signed)(uint32_t p_sensor_result);
	int (*exar7724_tj)(uint32_t p_sensor_result);
	int (*ds1775_t)(uint32_t p_sensor_result);
	int (*mp2886a_tj)(uint32_t p_sensor_result);
	int (*fan)(uint32_t p_sensor_result);
	int (*null_sign)(uint32_t sensor_result);
	int (*tmp464p_t)(uint32_t p_sensor_result);
	int (*fan_nt400)(uint32_t sensor_result);
	int (*mp8645p_tj)(uint32_t sensor_result);
	int (*mp2978_t)(uint32_t sensor_result);
	int (*max6642_t)(uint32_t p_sensor_result);
	int (*ltm4676_tj)(uint32_t p_sensor_result);
	int (*exar7724_vin)(uint32_t p_sensor_result);
	int (*exar7724_vch)(uint32_t p_sensor_result);
	int (*null_unsigned)(uint32_t p_sensor_result);
};

void register_sensor_convertion_fun_ops(struct sensor_convertion_fun_ops *ops);
struct sensor_convertion_fun_ops *get_sensor_convertion_fun_ops(void);

/*
 *
 */
struct sensor_ops {
	void (*update_sensor_value)(struct nt_adapter_sensor *sensor, int32_t value);
	void (*sensor_deinit)(struct nt_sensor_group *sg);
	struct nt_adapter_sensor *(*allocate_sensor_by_description)(uint8_t adapter_or_port_index,
		enum nt_sensor_source_e ssrc,
		struct nt_adapter_sensor_description *descr);
	void (*dump_sensor)(struct nt_adapter_sensor *sensor);
	struct nt_adapter_sensor *(*allocate_sensor)(uint8_t adapter_or_port_index,
		const char *p_name,
		enum nt_sensor_source_e ssrc,
		enum nt_sensor_type_e type,
		unsigned int index,
		enum nt_sensor_event_alarm_e event_alarm,
		enum sensor_mon_sign si);
	void (*init_sensor_group)(struct nt_sensor_group *sg);
	int32_t (*get_value)(struct nt_sensor_group *sg);
	int32_t (*get_lowest)(struct nt_sensor_group *sg);
	int32_t (*get_highest)(struct nt_sensor_group *sg);
	char *(*get_name)(struct nt_sensor_group *sg);
};

void register_sensor_ops(struct sensor_ops *ops);
struct sensor_ops *get_sensor_ops(void);

/*
 *
 */
struct nim_sensors_ops {
	struct nt_adapter_sensor_description *(*get_sfp_sensors_level0)(void);
	struct nt_adapter_sensor_description *(*get_sfp_sensors_level1)(void);
	struct nt_adapter_sensor_description *(*get_qsfp_sensor_level0)(void);
	struct nt_adapter_sensor_description *(*get_qsfp_sensor_level1)(void);
	struct nt_adapter_sensor *(*allocate_sensor_by_description)(uint8_t adapter_or_port_index,
		enum nt_sensor_source_e src,
		struct nt_adapter_sensor_description *descr);
	void (*update_sensor_value)(struct nt_adapter_sensor *sensor, int32_t value);
};

void register_nim_sensors_ops(struct nim_sensors_ops *ops);
struct nim_sensors_ops *get_nim_sensors_ops(void);

/*
 *
 */
struct port_ops {
	bool (*get_nim_present)(struct adapter_info_s *p, int port);

	/*
	 * port:s link mode
	 */
	void (*set_adm_state)(struct adapter_info_s *p, int port, bool adm_state);
	bool (*get_adm_state)(struct adapter_info_s *p, int port);

	/*
	 * port:s link status
	 */
	void (*set_link_status)(struct adapter_info_s *p, int port, bool status);
	bool (*get_link_status)(struct adapter_info_s *p, int port);

	/*
	 * port: link autoneg
	 */
	void (*set_link_autoneg)(struct adapter_info_s *p, int port, bool autoneg);
	bool (*get_link_autoneg)(struct adapter_info_s *p, int port);

	/*
	 * port: link speed
	 */
	void (*set_link_speed)(struct adapter_info_s *p, int port, nt_link_speed_t speed);
	nt_link_speed_t (*get_link_speed)(struct adapter_info_s *p, int port);

	/*
	 * port: link duplex
	 */
	void (*set_link_duplex)(struct adapter_info_s *p, int port, nt_link_duplex_t duplex);
	nt_link_duplex_t (*get_link_duplex)(struct adapter_info_s *p, int port);

	/*
	 * port: loopback mode
	 */
	void (*set_loopback_mode)(struct adapter_info_s *p, int port, uint32_t mode);
	uint32_t (*get_loopback_mode)(struct adapter_info_s *p, int port);

	uint32_t (*get_link_speed_capabilities)(struct adapter_info_s *p, int port);

	/*
	 * port: nim capabilities
	 */
	nim_i2c_ctx_t (*get_nim_capabilities)(struct adapter_info_s *p, int port);

	/*
	 * port: tx power
	 */
	int (*tx_power)(struct adapter_info_s *p, int port, bool disable);
};

void register_port_ops(const struct port_ops *ops);
const struct port_ops *get_port_ops(void);

/*
 *
 */
struct nt4ga_stat_ops {
	int (*nt4ga_stat_init)(struct adapter_info_s *p_adapter_info);
	int (*nt4ga_stat_setup)(struct adapter_info_s *p_adapter_info);
	int (*nt4ga_stat_stop)(struct adapter_info_s *p_adapter_info);
	int (*nt4ga_stat_dump)(struct adapter_info_s *p_adapter_info, FILE *pfh);
	int (*nt4ga_stat_collect)(struct adapter_info_s *p_adapter_info,
		nt4ga_stat_t *p_nt4ga_stat);
};

void register_nt4ga_stat_ops(const struct nt4ga_stat_ops *ops);
const struct nt4ga_stat_ops *get_nt4ga_stat_ops(void);

/*
 *
 */
struct adapter_ops {
	int (*init)(struct adapter_info_s *p_adapter_info);
	int (*deinit)(struct adapter_info_s *p_adapter_info);

	int (*show_info)(struct adapter_info_s *p_adapter_info, FILE *pfh);
};

void register_adapter_ops(const struct adapter_ops *ops);
const struct adapter_ops *get_adapter_ops(void);

struct clk9530_ops {
	const int *(*get_n_data_9530_si5340_nt200a02_u23_v6)(void);
	const clk_profile_data_fmt2_t *(*get_p_data_9530_si5340_nt200a02_u23_v6)(void);
};

void register_clk9530_ops(struct clk9530_ops *ops);
struct clk9530_ops *get_clk9530_ops(void);

struct clk9544_ops {
	const int *(*get_n_data_9544_si5340_nt200a02_u23_v6)(void);
	const clk_profile_data_fmt2_t *(*get_p_data_9544_si5340_nt200a02_u23_v6)(void);
};

void register_clk9544_ops(struct clk9544_ops *ops);
struct clk9544_ops *get_clk9544_ops(void);

struct clk9563_ops {
	const int *(*get_n_data_9563_si5340_nt200a02_u23_v5)(void);
	const clk_profile_data_fmt2_t *(*get_p_data_9563_si5340_nt200a02_u23_v5)(void);
};

void register_clk9563_ops(struct clk9563_ops *ops);
struct clk9563_ops *get_clk9563_ops(void);

struct clk9572_ops {
	const int *(*get_n_data_9572_si5340_nt200a02_u23_v12)(void);
	const clk_profile_data_fmt2_t *(*get_p_data_9572_si5340_nt200a02_u23_v12)(void);
};

void register_clk9572_ops(struct clk9572_ops *ops);
struct clk9572_ops *get_clk9572_ops(void);

struct rst_nt200a0x_ops {
	int (*nthw_fpga_rst_nt200a0x_init)(struct fpga_info_s *p_fpga_info,
		struct nthw_fpga_rst_nt200a0x *p_rst);
	int (*nthw_fpga_rst_nt200a0x_reset)(nthw_fpga_t *p_fpga,
		const struct nthw_fpga_rst_nt200a0x *p);
};

void register_rst_nt200a0x_ops(struct rst_nt200a0x_ops *ops);
struct rst_nt200a0x_ops *get_rst_nt200a0x_ops(void);

struct rst9530_ops {
	int (*nthw_fpga_rst9530_init)(struct fpga_info_s *p_fpga_info,
		struct nthw_fpga_rst_nt200a0x *const p);
};

void register_rst9530_ops(struct rst9530_ops *ops);
struct rst9530_ops *get_rst9530_ops(void);

struct rst9544_ops {
	int (*nthw_fpga_rst9544_init)(struct fpga_info_s *p_fpga_info,
		struct nthw_fpga_rst_nt200a0x *const p);
};

void register_rst9544_ops(struct rst9544_ops *ops);
struct rst9544_ops *get_rst9544_ops(void);

struct rst9563_ops {
	int (*nthw_fpga_rst9563_init)(struct fpga_info_s *p_fpga_info,
		struct nthw_fpga_rst_nt200a0x *const p);
};

void register_rst9563_ops(struct rst9563_ops *ops);
struct rst9563_ops *get_rst9563_ops(void);

struct rst9572_ops {
	int (*nthw_fpga_rst9572_init)(struct fpga_info_s *p_fpga_info,
		struct nthw_fpga_rst_nt200a0x *const p);
};

void register_rst9572_ops(struct rst9572_ops *ops);
struct rst9572_ops *get_rst9572_ops(void);

struct rst_nt400dxx_ops {
	int (*nthw_fpga_rst_nt400dxx_init)(struct fpga_info_s *p_fpga_info);
	int (*nthw_fpga_rst_nt400dxx_reset)(struct fpga_info_s *p_fpga_info);
};

void register_rst_nt400dxx_ops(struct rst_nt400dxx_ops *ops);
struct rst_nt400dxx_ops *get_rst_nt400dxx_ops(void);

/*
 *
 */
struct profile_inline_ops {
	/*
	 * NT Flow FLM Meter API
	 */
	int (*flow_mtr_supported)(struct flow_eth_dev *dev);

	uint64_t (*flow_mtr_meter_policy_n_max)(void);

	int (*flow_mtr_set_profile)(struct flow_eth_dev *dev, uint32_t profile_id,
		uint64_t bucket_rate_a, uint64_t bucket_size_a,
		uint64_t bucket_rate_b, uint64_t bucket_size_b);

	int (*flow_mtr_set_policy)(struct flow_eth_dev *dev, uint32_t policy_id, int drop);

	int (*flow_mtr_create_meter)(struct flow_eth_dev *dev, uint8_t caller_id, uint32_t mtr_id,
		uint32_t profile_id, uint32_t policy_id, uint64_t stats_mask);

	int (*flow_mtr_probe_meter)(struct flow_eth_dev *dev, uint8_t caller_id, uint32_t mtr_id);

	int (*flow_mtr_destroy_meter)(struct flow_eth_dev *dev, uint8_t caller_id,
		uint32_t mtr_id);

	int (*flm_mtr_adjust_stats)(struct flow_eth_dev *dev, uint8_t caller_id, uint32_t mtr_id,
		uint32_t adjust_value);

	uint32_t (*flow_mtr_meters_supported)(struct flow_eth_dev *dev, uint8_t caller_id);

	void (*flm_setup_queues)(void);
	void (*flm_free_queues)(void);
	uint32_t (*flm_lrn_update)(struct flow_eth_dev *dev, uint32_t *inf_cnt);

	uint32_t (*flm_mtr_update_stats)(struct flow_eth_dev *dev, uint32_t *inf_cnt);
	void (*flm_mtr_read_stats)(struct flow_eth_dev *dev,
		uint8_t caller_id,
		uint32_t id,
		uint64_t *stats_mask,
		uint64_t *green_pkt,
		uint64_t *green_bytes,
		int clear);

	uint32_t (*flm_update)(struct flow_eth_dev *dev);

	/*
	 * Config API
	 */
	int (*flow_set_mtu_inline)(struct flow_eth_dev *dev, uint32_t port, uint16_t mtu);
};

void register_profile_inline_ops(const struct profile_inline_ops *ops);
const struct profile_inline_ops *get_profile_inline_ops(void);

/*
 *
 */
struct flow_filter_ops {
	int (*flow_filter_init)(nthw_fpga_t *p_fpga, struct flow_nic_dev **p_flow_device,
		int adapter_no);
	int (*flow_filter_done)(struct flow_nic_dev *dev);

	/*
	 * Device Management API
	 */
	int (*flow_reset_nic_dev)(uint8_t adapter_no);

	struct flow_eth_dev *(*flow_get_eth_dev)(uint8_t adapter_no,
		uint8_t hw_port_no,
		uint32_t port_id,
		int alloc_rx_queues,
		struct flow_queue_id_s queue_ids[],
		int *rss_target_id,
		enum flow_eth_dev_profile flow_profile,
		uint32_t exception_path);

	int (*flow_eth_dev_add_queue)(struct flow_eth_dev *eth_dev,
		struct flow_queue_id_s *queue_id);

	int (*flow_delete_eth_dev)(struct flow_eth_dev *eth_dev);

	int (*flow_get_tunnel_definition)(struct tunnel_cfg_s *tun, uint32_t flow_stat_id,
		uint8_t vport);

	/*
	 * NT Flow API
	 */
	int (*flow_validate)(struct flow_eth_dev *dev,
		const struct flow_elem item[],
		const struct flow_action action[],
		struct flow_error *error);

	struct flow_handle *(*flow_create)(struct flow_eth_dev *dev,
		const struct flow_attr *attr,
		const struct flow_elem item[],
		const struct flow_action action[],
		struct flow_error *error);

	int (*flow_destroy)(struct flow_eth_dev *dev,
		struct flow_handle *flow,
		struct flow_error *error);

	int (*flow_flush)(struct flow_eth_dev *dev, uint16_t caller_id, struct flow_error *error);

	int (*flow_actions_update)(struct flow_eth_dev *dev,
		struct flow_handle *flow,
		const struct flow_action action[],
		struct flow_error *error);

	int (*flow_query)(struct flow_eth_dev *dev,
		struct flow_handle *flow,
		const struct flow_action *action,
		void **data,
		uint32_t *length,
		struct flow_error *error);

	int (*flow_dev_dump)(struct flow_eth_dev *dev,
		struct flow_handle *flow,
		uint16_t caller_id,
		FILE *file,
		struct flow_error *error);

	/*
	 * NT Flow asynchronous operations API
	 */
	int (*flow_info_get)(struct flow_eth_dev *dev, struct flow_port_info *port_info,
		struct flow_queue_info *queue_info, struct flow_error *error);

	int (*flow_configure)(struct flow_eth_dev *dev, uint8_t caller_id,
		const struct flow_port_attr *port_attr, uint16_t nb_queue,
		const struct flow_queue_attr *queue_attr[],
		struct flow_error *error);

	struct flow_pattern_template *(*flow_pattern_template_create)(struct flow_eth_dev *dev,
		const struct flow_pattern_template_attr *template_attr,
		const struct flow_elem pattern[], struct flow_error *error);

	int (*flow_pattern_template_destroy)(struct flow_eth_dev *dev,
		struct flow_pattern_template *pattern_template,
		struct flow_error *error);

	struct flow_actions_template *(*flow_actions_template_create)(struct flow_eth_dev *dev,
		const struct flow_actions_template_attr *template_attr,
		const struct flow_action actions[], const struct flow_action masks[],
		struct flow_error *error);

	int (*flow_actions_template_destroy)(struct flow_eth_dev *dev,
		struct flow_actions_template *actions_template,
		struct flow_error *error);

	struct flow_template_table *(*flow_template_table_create)(struct flow_eth_dev *dev,
		const struct flow_template_table_attr *table_attr,
		struct flow_pattern_template *pattern_templates[], uint8_t nb_pattern_templates,
		struct flow_actions_template *actions_templates[], uint8_t nb_actions_templates,
		struct flow_error *error);

	int (*flow_template_table_destroy)(struct flow_eth_dev *dev,
		struct flow_template_table *template_table,
		struct flow_error *error);

	struct flow_handle *(*flow_async_create)(struct flow_eth_dev *dev, uint32_t queue_id,
		const struct flow_op_attr *op_attr,
		struct flow_template_table *template_table, const struct flow_elem pattern[],
		uint8_t pattern_template_index, const struct flow_action actions[],
		uint8_t actions_template_index, void *user_data, struct flow_error *error);

	int (*flow_async_destroy)(struct flow_eth_dev *dev, uint32_t queue_id,
		const struct flow_op_attr *op_attr, struct flow_handle *flow,
		void *user_data, struct flow_error *error);

	int (*flow_push)(struct flow_eth_dev *dev, uint32_t queue_id, struct flow_error *error);

	int (*flow_pull)(struct flow_eth_dev *dev, uint32_t queue_id, struct flow_op_result res[],
		uint16_t n_res, struct flow_error *error);

	/*
	 * Other
	 */
	struct flow_eth_dev *(*nic_and_port_to_eth_dev)(uint8_t adapter_no, uint8_t port);
	struct flow_nic_dev *(*get_nic_dev_from_adapter_no)(uint8_t adapter_no);

	int (*flow_nic_set_hasher)(struct flow_nic_dev *ndev, int hsh_idx,
		enum flow_nic_hash_e algorithm);

	int (*flow_get_num_queues)(uint8_t adapter_no, uint8_t port_no);
	int (*flow_get_hw_id)(uint8_t adapter_no, uint8_t port_no, uint8_t queue_no);

	int (*flow_get_flm_stats)(struct flow_nic_dev *ndev, uint64_t *data, uint64_t size);

	int (*hw_mod_hsh_rcp_flush)(struct flow_api_backend_s *be, int start_idx, int count);
};

void register_flow_filter_ops(const struct flow_filter_ops *ops);
const struct flow_filter_ops *get_flow_filter_ops(void);

/*
 *
 */
#ifdef RTE_FLOW_DRIVER_H_
void register_dev_flow_ops(const struct rte_flow_ops *ops);
const struct rte_flow_ops *get_dev_flow_ops(void);
#endif

#endif	/* __NTNIC_MOD_REG_H__ */
