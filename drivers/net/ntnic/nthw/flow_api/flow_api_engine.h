/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _FLOW_API_ENGINE_H_
#define _FLOW_API_ENGINE_H_

#include <stdint.h>
#include "stream_binary_flow_api.h"

struct flow_elem;
/*
 * ****************************************************
 *                Resource management
 * ****************************************************
 */
#define BIT_CONTAINER_8_ALIGN(x) (((x) + 7) / 8)

/*
 * Resource management
 * These are free resources in FPGA
 * Other FPGA memory lists are linked to one of these
 * and will implicitly follow them
 */
enum res_type_e {
	RES_QUEUE,
	RES_CAT_CFN,
	RES_CAT_COT,
	RES_CAT_EXO,
	RES_CAT_LEN,
	RES_KM_FLOW_TYPE,
	RES_KM_CATEGORY,
	RES_HSH_RCP,
	RES_PDB_RCP,
	RES_QSL_RCP,
	RES_QSL_QST,
	RES_SLC_RCP,
	RES_IOA_RCP,
	RES_ROA_RCP,
	RES_FLM_FLOW_TYPE,
	RES_FLM_RCP,
	RES_HST_RCP,
	RES_TPE_RCP,
	RES_TPE_EXT,
	RES_TPE_RPL,
	RES_COUNT,
	RES_INVALID
};

/*
 * ****************************************************
 *           Flow NIC offload management
 * ****************************************************
 */
#define MAX_OUTPUT_DEST (128)
#define NB_QSL_QEN_ADDR 32

#define INVALID_FLOW_STAT_ID 0xffffffff

#define MAX_WORD_NUM 24
#define MAX_BANKS 6

#define MAX_TCAM_START_OFFSETS 4

#define MAX_TAG_INDEX 8

#define MAX_FLM_MTRS_SUPPORTED 4
#define MAX_CPY_WRITERS_SUPPORTED 8

/*
 *          128      128     32     32    32
 * Have  |  QW0  ||  QW4  || SW8 || SW9 | SWX   in FPGA
 *
 * Each word may start at any offset, though
 * they are combined in chronological order, with all enabled to
 * build the extracted match data, thus that is how the match key
 * must be build
 *
 */
enum extractor_e {
	KM_USE_EXTRACTOR_UNDEF,
	KM_USE_EXTRACTOR_QWORD,
	KM_USE_EXTRACTOR_SWORD,
};

struct match_elem_s {
	enum extractor_e extr;
	int masked_for_tcam; /* if potentially selected for TCAM */
	uint32_t e_word[4];
	uint32_t e_mask[4];

	int extr_start_offs_id;
	int8_t rel_offs;
	uint32_t word_len;
};

enum cam_tech_use_e { KM_CAM, KM_TCAM, KM_SYNERGY };

#define MAX_MATCH_FIELDS 16

struct km_flow_def_s {
	struct flow_api_backend_s *be;

	/* For keeping track of identical entries */
	struct km_flow_def_s *reference;
	struct km_flow_def_s *root;

	/* For collect flow elements and sorting */
	struct match_elem_s match[MAX_MATCH_FIELDS];
	struct match_elem_s *match_map[MAX_MATCH_FIELDS];
	int num_ftype_elem;

	/* Finally formatted CAM/TCAM entry */
	enum cam_tech_use_e target;
	uint32_t entry_word[MAX_WORD_NUM];
	uint32_t entry_mask[MAX_WORD_NUM];
	int key_word_size;

	/* TCAM calculated possible bank start offsets */
	int start_offsets[MAX_TCAM_START_OFFSETS];
	int num_start_offsets;

	/* Flow information */

	/*
	 * HW input port ID needed for compare. In port must be identical on flow
	 * types
	 */
	uint32_t port_id;
	uint32_t info; /* used for color (actions) */
	int info_set;
	int flow_type; /* 0 is illegal and used as unset */
	int flushed_to_target; /* if this km entry has been finally programmed into NIC hw */

	/* CAM specific bank management */
	int cam_paired;
	int record_indexes[MAX_BANKS];
	int bank_used;
	uint32_t *cuckoo_moves; /* for CAM statistics only */
	struct cam_distrib_s *cam_dist;
	struct hasher_s *hsh;

	/* TCAM specific bank management */
	struct tcam_distrib_s *tcam_dist;
	int tcam_start_bank;
	int tcam_record;
};

/*
 * KCC-CAM
 */
struct kcc_key_s {
	uint64_t sb_data : 32;
	uint64_t sb_type : 8;
	uint64_t cat_cfn : 8;
	uint64_t port : 16;
};

#define KCC_ID_INVALID 0xffffffff

struct kcc_flow_def_s {
	struct flow_api_backend_s *be;
	union {
		uint64_t key64;
		uint32_t key32[2];
		struct kcc_key_s key;
	};
	uint32_t km_category;
	uint32_t id;

	uint8_t *kcc_unique_ids;

	int flushed_to_target;
	int record_indexes[MAX_BANKS];
	int bank_used;
	uint32_t *cuckoo_moves; /* for CAM statistics only */
	struct kcc_cam_distrib_s *cam_dist;
	struct hasher_s *hsh;
};

/*
 * Tunnel encapsulation header definition
 */
enum { TUN_TYPE_VXLAN = 0, TUN_TYPE_NVGRE = 1 };

#define MAX_TUN_HDR_SIZE 128

struct tunnel_header_s {
	union {
		uint8_t hdr8[MAX_TUN_HDR_SIZE];
		uint32_t hdr32[(MAX_TUN_HDR_SIZE + 3) / 4];
	} d;
	uint32_t user_port_id;
	uint8_t len;

	uint8_t nb_vlans;

	uint8_t ip_version; /* 4: v4, 6: v6 */
	uint16_t ip_csum_precalc;

	uint8_t new_outer;
	uint8_t l2_len;
	uint8_t l3_len;
	uint8_t l4_len;
};

enum port_type_e {
	PORT_NONE, /* not defined or drop */
	PORT_INTERNAL, /* no queues attached */
	PORT_PHY, /* MAC phy output queue */
	PORT_VIRT, /* Memory queues to Host */
};

enum special_partial_match_e {
	SPECIAL_MATCH_NONE,
	SPECIAL_MATCH_LACP,
};

#define PORT_ID_NONE 0xffffffff

struct output_s {
	uint32_t owning_port_id; /* the port who owns this output destination */
	enum port_type_e type;
	int id; /* depending on port type: queue ID or physical port id or not used */
	int active; /* activated */
};

struct nic_flow_def {
	/*
	 * Frame Decoder match info collected
	 */
	int l2_prot;
	int l3_prot;
	int l4_prot;
	int tunnel_prot;
	int tunnel_l3_prot;
	int tunnel_l4_prot;
	int vlans;
	int fragmentation;
	/*
	 * Additional meta data for various functions
	 */
	int in_port_override;
	int l4_dst_port;
	/*
	 * Output destination info collection
	 */
	struct output_s dst_id[MAX_OUTPUT_DEST]; /* define the output to use */
	/* total number of available queues defined for all outputs - i.e. number of dst_id's */
	int dst_num_avail;

	/*
	 * To identify high priority match with mark for special SW processing (non-OVS)
	 */
	enum special_partial_match_e special_match;

	/*
	 * Mark or Action info collection
	 */
	uint32_t mark;
	uint64_t roa_actions;
	uint64_t ioa_actions;

	uint32_t jump_to_group;

	uint32_t mtr_ids[MAX_FLM_MTRS_SUPPORTED];

	int full_offload;
	/*
	 * Action push tunnel
	 */
	struct tunnel_header_s tun_hdr;

	/*
	 * If DPDK RTE tunnel helper API used
	 * this holds the tunnel if used in flow
	 */
	struct tunnel_s *tnl;

	/*
	 * Header Stripper
	 */
	int header_strip_start_dyn;
	int header_strip_start_ofs;
	int header_strip_end_dyn;
	int header_strip_end_ofs;
	int header_strip_removed_outer_ip;

	/*
	 * Modify field
	 */
	struct {
		uint32_t select;
		uint32_t dyn;
		uint32_t ofs;
		uint32_t len;
		uint32_t level;
		union {
			uint8_t value8[16];
			uint16_t value16[8];
			uint32_t value32[4];
		};
	} modify_field[MAX_CPY_WRITERS_SUPPORTED];

	uint32_t modify_field_count;
	uint8_t ttl_sub_enable;
	uint8_t ttl_sub_ipv4;
	uint8_t ttl_sub_outer;

	/*
	 * Key Matcher flow definitions
	 */
	struct km_flow_def_s km;

	/*
	 * Key Matcher Category CAM
	 */
	struct kcc_flow_def_s *kcc;
	int kcc_referenced;

	/*
	 * TX fragmentation IFR/RPP_LR MTU recipe
	 */
	uint8_t flm_mtu_fragmentation_recipe;
};

enum flow_handle_type {
	FLOW_HANDLE_TYPE_FLOW,
	FLOW_HANDLE_TYPE_FLM,
};

struct flow_handle {
	enum flow_handle_type type;

	struct flow_eth_dev *dev;
	struct flow_handle *next;
	struct flow_handle *prev;

	union {
		struct {
			/*
			 * 1st step conversion and validation of flow
			 * verified and converted flow match + actions structure
			 */
			struct nic_flow_def *fd;
			/*
			 * 2nd step NIC HW resource allocation and configuration
			 * NIC resource management structures
			 */
			struct {
				int index; /* allocation index into NIC raw resource table */
				/* number of contiguous allocations needed for this resource */
				int count;
				/*
				 * This resource if not initially created by this flow, but reused
				 * by it
				 */
				int referenced;
			} resource[RES_COUNT];
			int flushed;

			uint32_t flow_stat_id;
			uint32_t color;
			int cao_enabled;
			uint32_t cte;

			uint32_t port_id; /* MAC port ID or override of virtual in_port */
			uint32_t flm_ref_count;
			uint8_t flm_group_index;
			uint8_t flm_ft_index;
		};

		struct {
			uint32_t flm_data[10];
			uint8_t flm_prot;
			uint8_t flm_kid;
			uint8_t flm_prio;

			uint16_t flm_rpl_ext_ptr;
			uint32_t flm_nat_ipv4;
			uint16_t flm_nat_port;
			uint8_t flm_dscp;
			uint32_t flm_teid;
			uint8_t flm_rqi;
			uint8_t flm_qfi;

			uint8_t flm_mtu_fragmentation_recipe;

			struct flow_handle *flm_owner;
		};
	};
};

void km_attach_ndev_resource_management(struct km_flow_def_s *km,
					void **handle);
void km_free_ndev_resource_management(void **handle);

int km_get_cam_population_level(void *cam_dist, uint32_t *cam_elem,
				uint32_t *cuckoo_moves);

int km_add_match_elem(struct km_flow_def_s *km, uint32_t e_word[4],
		      uint32_t e_mask[4], uint32_t word_len,
		      enum frame_offs_e start, int8_t offset);

int km_key_create(struct km_flow_def_s *km, uint32_t port_id);
/*
 * Compares 2 KM key definitions after first collect validate and optimization.
 * km is compared against an existing km1.
 * if identical, km1 flow_type is returned
 */
int km_key_compare(struct km_flow_def_s *km, struct km_flow_def_s *km1);

void km_set_info(struct km_flow_def_s *km, int on);
int km_rcp_set(struct km_flow_def_s *km, int index);

int km_refer_data_match_entry(struct km_flow_def_s *km,
			      struct km_flow_def_s *km1);
int km_write_data_match_entry(struct km_flow_def_s *km, uint32_t color);
int km_clear_data_match_entry(struct km_flow_def_s *km);

void kcc_attach_ndev_resource_management(struct kcc_flow_def_s *kcc,
		void **handle);
void kcc_free_ndev_resource_management(void **handle);
int kcc_alloc_unique_id(struct kcc_flow_def_s *kcc);
void kcc_free_unique_id(struct kcc_flow_def_s *kcc);
int kcc_key_compare(struct kcc_flow_def_s *kcc, struct kcc_flow_def_s *kcc1);
int kcc_add_km_category(struct kcc_flow_def_s *kcc, uint32_t category);

int kcc_key_add_no_sideband(struct kcc_flow_def_s *kcc);
int kcc_key_add_vlan(struct kcc_flow_def_s *kcc, uint16_t tpid, uint16_t vid);
int kcc_key_add_vxlan(struct kcc_flow_def_s *kcc, uint32_t vni);
int kcc_key_add_port(struct kcc_flow_def_s *kcc, uint16_t port);
int kcc_key_add_cat_cfn(struct kcc_flow_def_s *kcc, uint8_t cat_cfn);
uint8_t kcc_key_get_cat_cfn(struct kcc_flow_def_s *kcc);

int kcc_write_data_match_entry(struct kcc_flow_def_s *kcc);
int kcc_key_ref_count_add(struct kcc_flow_def_s *kcc);
int kcc_key_ref_count_dec(struct kcc_flow_def_s *kcc);

/*
 * Group management
 */
int flow_group_handle_create(void **handle, uint32_t group_count);
int flow_group_handle_destroy(void **handle);

int flow_group_translate_get(void *handle, uint8_t owner_id, uint32_t group_in,
			     uint32_t *group_out);
int flow_group_translate_release(void *handle, uint32_t translated_group);

/*
 * Actions management
 */
uint8_t flow_tunnel_alloc_virt_port(void);
uint8_t flow_tunnel_free_virt_port(uint8_t virt_port);
struct tunnel_s *tunnel_parse(const struct flow_elem *elem, int *idx,
			      uint32_t *vni);
int tunnel_release(struct tunnel_s *tnl);
uint8_t get_tunnel_vport(struct tunnel_s *rtnl);
void tunnel_set_flow_stat_id(struct tunnel_s *rtnl, uint32_t flow_stat_id);
int tunnel_get_definition(struct tunnel_cfg_s *tun, uint32_t flow_stat_id,
			  uint8_t vport);

int is_virtual_port(uint8_t virt_port);
int flow_tunnel_create_vxlan_hdr(struct flow_api_backend_s *be,
				 struct nic_flow_def *fd,
				 const struct flow_elem *elem);

/*
 * statistics
 */
uint32_t flow_actions_create_flow_stat_id(uint32_t *stat_map, uint32_t mark);
void flow_actions_delete_flow_stat_id(uint32_t *stat_map,
				      uint32_t flow_stat_id);

#endif /* _FLOW_API_ENGINE_H_ */
