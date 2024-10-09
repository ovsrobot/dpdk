/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#include "test.h"

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdalign.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_errno.h>

#ifndef RTE_EXEC_ENV_WINDOWS
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_random.h>
#include <rte_graph_feature_arc.h>
#include <rte_graph_feature_arc_worker.h>

#define MBUFF_SIZE 512
#define TEST_ARC1_NAME "arc1"
#define TEST_ARC2_NAME "arc2"
#define MAX_INDEXES 10
#define MAX_FEATURES 5

#define SOURCE1 "test_node_arc_source1"
#define INPUT_STATIC "test_node_arc_input_static"
#define OUTPUT_STATIC "test_node_arc_output_static"
#define PKT_FREE_STATIC "test_node_arc_pkt_free_static"
#define ARC1_FEATURE1 "test_node_arc1_feature1"
#define ARC1_FEATURE2 "test_node_arc1_feature2"
#define ARC2_FEATURE1 "test_node_arc2_feature1"
#define ARC2_FEATURE2 "test_node_arc2_feature2"
#define ARC2_FEATURE3 "test_node_arc2_feature3"
#define DUMMY1_STATIC "test_node_arc_dummy1_static"
#define DUMMY2_STATIC "test_node_arc_dummy2_static"

/* (Node index, Node Name, feature user data base */
#define FOREACH_TEST_NODE_ARC {			\
		R(0, SOURCE1, 64)		\
		R(1, INPUT_STATIC, 128)		\
		R(2, OUTPUT_STATIC, 256)	\
		R(3, PKT_FREE_STATIC, 512)	\
		R(4, ARC1_FEATURE1, 1024)	\
		R(5, ARC1_FEATURE2, 2048)	\
		R(6, ARC2_FEATURE1, 4096)	\
		R(7, ARC2_FEATURE2, 8192)	\
		R(8, ARC2_FEATURE3, 16384)	\
		R(9, DUMMY1_STATIC, 32768)	\
		R(10, DUMMY2_STATIC, 65536)	\
	}

/**
 * ARC1: Feature arc on ingress interface
 * ARC2: Feature arc on egress interface
 * XX_static: Static nodes
 * XX_featureX: Feature X on arc
 *
 *            -----> ARC1_FEATURE1
 *           |        |         |
 *           |        |         v
 *           |        |   ARC1_FEATURE2
 *           |        |         |
 *           |        v         v
 *  SOURCE1 ->-----> INPUT_STATIC --> OUTPUT_STATIC -----> PKT_FREE_STATIC
 *                                     |   |  |             ^      ^     ^
 *                                     |   |  |             |      |     |
 *                                     |   |   --> ARC2_FEATURE1   |     |
 *                                     |   |          ^     ^      |     |
 *                                     |   |          |     |      |     |
 *                                     |    ----------c-> ARC2_FEATURE2  |
 *                                     |              |     ^            |
 *                                     |              |     |            |
 *                                      ----------> ARC2_FEATURE3 -------
 */
const char *node_names_feature_arc[] = {
	SOURCE1, INPUT_STATIC, OUTPUT_STATIC, PKT_FREE_STATIC,
	ARC1_FEATURE1, ARC1_FEATURE2, ARC2_FEATURE1, ARC2_FEATURE2, ARC2_FEATURE3,
	DUMMY1_STATIC, DUMMY2_STATIC
};

#define MAX_NODES  RTE_DIM(node_names_feature_arc)

/* Function declarations */
static uint16_t
source1_fn(struct rte_graph *graph, struct rte_node *node,
	   void **objs, uint16_t nb_objs);
static uint16_t
input_fn(struct rte_graph *graph, struct rte_node *node,
	 void **objs, uint16_t nb_objs);
static uint16_t
input_fa_fn(struct rte_graph *graph, struct rte_node *node,
	    void **objs, uint16_t nb_objs);
static uint16_t
output_fn(struct rte_graph *graph, struct rte_node *node,
	  void **objs, uint16_t nb_objs);
static uint16_t
output_fa_fn(struct rte_graph *graph, struct rte_node *node,
	     void **objs, uint16_t nb_objs);
static uint16_t
pkt_free_fn(struct rte_graph *graph, struct rte_node *node,
	    void **objs, uint16_t nb_objs);
static uint16_t
pkt_free_fa_fn(struct rte_graph *graph, struct rte_node *node,
	       void **objs, uint16_t nb_objs);
static uint16_t
dummy1_fn(struct rte_graph *graph, struct rte_node *node,
	  void **objs, uint16_t nb_objs);
static uint16_t
dummy2_fn(struct rte_graph *graph, struct rte_node *node,
	  void **objs, uint16_t nb_objs);
static uint16_t
arc1_feature1_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs);
static uint16_t
arc1_feature1_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs);
static uint16_t
arc1_feature2_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs);
static uint16_t
arc1_feature2_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature1_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature1_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature2_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature2_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature3_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs);
static uint16_t
arc2_feature3_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs);
static int
common_node_init(const struct rte_graph *graph, struct rte_node *node);

typedef struct test_node_priv {
	/* index from 0 - MAX_NODES -1 */
	uint8_t node_index;

	/* feature */
	rte_graph_feature_t feature;

	/* rte_graph node id */
	uint32_t node_id;

	rte_graph_feature_arc_t arc;
} test_node_priv_t;

typedef struct {
	rte_graph_feature_t feature;
	uint16_t egress_interface;
	uint16_t ingress_interface;
} graph_dynfield_t;

static int graph_dynfield_offset = -1;
static rte_graph_feature_arc_t arcs[RTE_GRAPH_FEATURE_ARC_MAX + 128];
static struct rte_mbuf mbuf[MAX_NODES + 1][MBUFF_SIZE];
static void *mbuf_p[MAX_NODES + 1][MBUFF_SIZE];
static rte_graph_t graph_id = RTE_GRAPH_ID_INVALID;

const char *node_patterns_feature_arc[] = {
	"test_node_arc*"
};

static int32_t
compute_unique_user_data(const char *parent, const char *child, uint32_t interface_index)
{
	uint32_t user_data = interface_index;

	RTE_SET_USED(parent);
#define R(idx, node, node_cookie) {				\
		if (!strcmp(child, node)) {			\
			user_data += node_cookie;		\
		}						\
	}

	FOREACH_TEST_NODE_ARC
#undef R

	return user_data;
}

static int
get_edge(struct rte_node_register *parent_node,
	 struct rte_node_register *child_node, rte_edge_t *_edge)
{
	char **next_edges = NULL;
	uint32_t count, i;

	count = rte_node_edge_get(parent_node->id, NULL);

	if (!count)
		return -1;

	next_edges = malloc(count);

	if (!next_edges)
		return -1;

	count = rte_node_edge_get(parent_node->id, next_edges);
	for (i = 0; i < count; i++) {
		if (strstr(child_node->name, next_edges[i])) {
			if (_edge)
				*_edge = (rte_edge_t)i;

			free(next_edges);
			return 0;
		}
	}
	free(next_edges);

	return -1;
}

int
common_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	test_node_priv_t *priv = (test_node_priv_t *)node->ctx;

	RTE_SET_USED(graph);

	priv->node_id = node->id;
	priv->feature = RTE_GRAPH_FEATURE_INVALID;
	priv->arc = RTE_GRAPH_FEATURE_ARC_INITIALIZER;

#define R(idx, _name, user_data) {			\
		if (!strcmp(node->name, _name)) {	\
			priv->node_index = idx;		\
		}					\
	}
	FOREACH_TEST_NODE_ARC
#undef R

	return 0;
}

uint16_t
source1_fn(struct rte_graph *graph, struct rte_node *node,
	   void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register source1 = {
	.name = SOURCE1,
	.process = source1_fn,
	.flags = RTE_NODE_SOURCE_F,
	.nb_edges = 3,
	.init = common_node_init,
	.next_nodes = {INPUT_STATIC, DUMMY1_STATIC, DUMMY2_STATIC},
};
RTE_NODE_REGISTER(source1);

uint16_t
input_fn(struct rte_graph *graph, struct rte_node *node,
		void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

uint16_t
input_fa_fn(struct rte_graph *graph, struct rte_node *node,
		void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register input = {
	.name = INPUT_STATIC,
	.process = input_fn,
	.feat_arc_proc = input_fa_fn,
	.nb_edges = 2,
	.init = common_node_init,
	.next_nodes = {OUTPUT_STATIC, DUMMY1_STATIC},
};
RTE_NODE_REGISTER(input);

uint16_t
output_fn(struct rte_graph *graph, struct rte_node *node,
		void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

uint16_t
output_fa_fn(struct rte_graph *graph, struct rte_node *node,
	     void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register output = {
	.name = OUTPUT_STATIC,
	.process = output_fn,
	.feat_arc_proc = output_fa_fn,
	.nb_edges = 3,
	.init = common_node_init,
	.next_nodes = {DUMMY1_STATIC, PKT_FREE_STATIC, DUMMY2_STATIC},
};
RTE_NODE_REGISTER(output);

uint16_t
pkt_free_fn(struct rte_graph *graph, struct rte_node *node,
		void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

uint16_t
pkt_free_fa_fn(struct rte_graph *graph, struct rte_node *node,
	       void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register pkt_free = {
	.name = PKT_FREE_STATIC,
	.process = pkt_free_fn,
	.feat_arc_proc = pkt_free_fa_fn,
	.nb_edges = 1,
	.init = common_node_init,
	.next_nodes = {DUMMY1_STATIC},
};
RTE_NODE_REGISTER(pkt_free);

uint16_t
dummy1_fn(struct rte_graph *graph, struct rte_node *node,
	  void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register dummy1 = {
	.name = DUMMY1_STATIC,
	.process = dummy1_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(dummy1);

uint16_t
dummy2_fn(struct rte_graph *graph, struct rte_node *node,
	  void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	return 0;
}

static struct rte_node_register dummy2 = {
	.name = DUMMY2_STATIC,
	.process = dummy2_fn,
	.nb_edges = 5,
	.init = common_node_init,
	.next_nodes = { ARC1_FEATURE1, ARC1_FEATURE2, ARC2_FEATURE1,
			ARC2_FEATURE2, ARC2_FEATURE3},
};
RTE_NODE_REGISTER(dummy2);

uint16_t
arc1_feature1_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

uint16_t
arc1_feature1_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

static struct rte_node_register arc1_feature1 = {
	.name = ARC1_FEATURE1,
	.process = arc1_feature1_fn,
	.feat_arc_proc = arc1_feature1_fa_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(arc1_feature1);

uint16_t
arc1_feature2_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

uint16_t
arc1_feature2_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

static struct rte_node_register arc1_feature2 = {
	.name = ARC1_FEATURE2,
	.process = arc1_feature2_fn,
	.feat_arc_proc = arc1_feature2_fa_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(arc1_feature2);

uint16_t
arc2_feature1_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

uint16_t
arc2_feature1_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

static struct rte_node_register arc2_feature1 = {
	.name = ARC2_FEATURE1,
	.process = arc2_feature1_fn,
	.feat_arc_proc = arc2_feature1_fa_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(arc2_feature1);

uint16_t
arc2_feature2_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

uint16_t
arc2_feature2_fa_fn(struct rte_graph *graph, struct rte_node *node,
		    void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

static struct rte_node_register arc2_feature2 = {
	.name = ARC2_FEATURE2,
	.process = arc2_feature2_fn,
	.feat_arc_proc = arc2_feature2_fa_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(arc2_feature2);

uint16_t
arc2_feature3_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

uint16_t
arc2_feature3_fa_fn(struct rte_graph *graph, struct rte_node *node,
		 void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	return 0;
}

static struct rte_node_register arc2_feature3 = {
	.name = ARC2_FEATURE3,
	.process = arc2_feature3_fn,
	.feat_arc_proc = arc2_feature3_fa_fn,
	.nb_edges = 0,
	.init = common_node_init,
};
RTE_NODE_REGISTER(arc2_feature3);

static int
create_graph(void)
{
	struct rte_graph_param gconf = {
		.socket_id = SOCKET_ID_ANY,
		.nb_node_patterns = 1,
		.node_patterns = node_patterns_feature_arc,
	};

	graph_id = rte_graph_create("worker0", &gconf);
	if (graph_id == RTE_GRAPH_ID_INVALID) {
		printf("Graph creation failed with error = %d\n", rte_errno);
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static int
__test_create_feature_arc(rte_graph_feature_arc_t *arcs, int max_arcs)
{
	rte_graph_feature_arc_t arc;
	const char *sample_arc_name = "sample_arc";
	char arc_name[256];
	int n_arcs;

	/* Create max number of feature arcs first */
	for (n_arcs = 0; n_arcs < max_arcs; n_arcs++) {
		snprintf(arc_name, sizeof(arc_name), "%s-%u", sample_arc_name, n_arcs);
		if (rte_graph_feature_arc_create(arc_name, MAX_FEATURES,
						 MAX_INDEXES, &dummy1, &arcs[n_arcs])) {
			printf("Feature arc creation failed for %u\n", n_arcs);
			return TEST_FAILED;
		}
	}
	/* Verify feature arc created more than max_arcs must fail */
	if (!rte_graph_feature_arc_create("negative_test_create_arc", MAX_FEATURES,
					  MAX_INDEXES, &dummy2, &arc)) {
		printf("Feature arc creation success for more than max configured: %u\n", n_arcs);
		return TEST_FAILED;
	}
	/* Make sure lookup passes for all feature arcs */
	for (n_arcs = 0; n_arcs < max_arcs; n_arcs++) {
		snprintf(arc_name, sizeof(arc_name), "%s-%u", sample_arc_name, n_arcs);
		arc = RTE_GRAPH_FEATURE_ARC_INITIALIZER;
		if (!rte_graph_feature_arc_lookup_by_name(arc_name, &arc)) {
			if (arc != arcs[n_arcs]) {
				printf("%s: Feature arc lookup mismatch for arc [%p, exp: %p]\n",
				       arc_name, (void *)arc, (void *)arcs[n_arcs]);
				return TEST_FAILED;
			}
		} else {
			printf("Feature arc lookup %s failed after creation\n", arc_name);
			return TEST_FAILED;
		}
	}
	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_create(void)
{
	int ret = 0, i;

	/*  Create arcs with RTE_GRAPH_FEATURE_ARC_MAX */
	ret = __test_create_feature_arc(arcs, RTE_GRAPH_FEATURE_ARC_MAX);
	if (ret) {
		printf("Feature arc creation test failed for RTE_GRAPH_FEATURE_ARC_MAX arcs\n");
		return TEST_FAILED;
	}
	/* destroy all arcs via cleanup API*/
	ret = rte_graph_feature_arc_cleanup();
	if (ret) {
		printf("Feature arc cleanup failed\n");
		return TEST_FAILED;
	}

#define NUM_FEAT_ARCS 128
	/* create 128 dummy feature arcs */
	ret = rte_graph_feature_arc_init(NUM_FEAT_ARCS);
	if (ret) {
		printf("Feature arc init failed for NUM_FEAT_ARCS");
		return TEST_FAILED;
	}
	ret = __test_create_feature_arc(arcs, NUM_FEAT_ARCS);
	if (ret) {
		printf("Feature arc creation test failed for NUM_FEAT_ARCS\n");
		return TEST_FAILED;
	}
	/* destroy all of them*/
	for (i = 0; i < NUM_FEAT_ARCS; i++) {
		if (rte_graph_feature_arc_destroy(arcs[i])) {
			printf("Feature arc destroy failed for %u\n", i);
			return TEST_FAILED;
		}
	}
	rte_graph_feature_arc_cleanup();

	/* Create two arcs as per test plan */
	/* First arc start/source node is node: SOURCE1 */
	if (rte_graph_feature_arc_create(TEST_ARC1_NAME, MAX_FEATURES,
					 MAX_INDEXES, &source1, &arcs[0])) {
		printf("Feature arc creation failed for %s\n", TEST_ARC1_NAME);
		return TEST_FAILED;
	}

	/* Duplicate name should fail */
	if (!rte_graph_feature_arc_create(TEST_ARC1_NAME, MAX_FEATURES,
					 MAX_INDEXES, &source1, &arcs[1])) {
		printf("Duplicate feature arc %s creation is not caught\n", TEST_ARC1_NAME);
		return TEST_FAILED;
	}
	/* Second arc start/source node is node: OUTPUT_STATIC */
	if (rte_graph_feature_arc_create(TEST_ARC2_NAME, MAX_FEATURES,
					 MAX_INDEXES, &output, &arcs[1])) {
		printf("Feature arc creation failed for %s\n", TEST_ARC1_NAME);
		return TEST_FAILED;
	}
	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_features_add(void)
{
	rte_graph_feature_t temp;

	/* First feature to SOURCE1 start node -> ARC1_FEATURE1 */
	if (rte_graph_feature_add(arcs[0], &arc1_feature1, NULL, NULL)) {
		printf("%s: Feature add failed for adding feature %s\n",
		       TEST_ARC1_NAME, ARC1_FEATURE1);
		return TEST_FAILED;
	}
	/* Second feature to SOURCE1  -> ARC1_FEATURE2 */
	if (rte_graph_feature_add(arcs[0], &arc1_feature2, NULL, NULL)) {
		printf("%s: Feature add failed for adding feature %s\n",
		       TEST_ARC1_NAME, ARC1_FEATURE2);
		return TEST_FAILED;
	}
	/* adding statically connected INPUT_STATIC as a last feature */
	if (rte_graph_feature_add(arcs[0], &input, ARC1_FEATURE2, NULL)) {
		printf("%s: Feature add failed for adding feature %s after %s\n",
		       TEST_ARC1_NAME, INPUT_STATIC, ARC1_FEATURE2);
		return TEST_FAILED;
	}
	/* First feature to OUTPUT_STATIC start node -> ARC2_FEATURE3 */
	if (rte_graph_feature_add(arcs[1], &arc2_feature3, NULL, NULL)) {
		printf("%s: Feature add failed for adding feature %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE3);
		return TEST_FAILED;
	}
	/* Second feature to OUTPUT_STATIC -> ARC2_FEATURE1 and before feature to
	 * ARC2_FEATURE3
	 */
	if (rte_graph_feature_add(arcs[1], &arc2_feature1, NULL, ARC2_FEATURE3)) {
		printf("%s: Feature add failed for adding feature %s after %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE3, ARC2_FEATURE1);
		return TEST_FAILED;
	}
	/* Add PKT_FREE node as last feature, next to arc2_feature3 */
	if (rte_graph_feature_add(arcs[1], &pkt_free, ARC2_FEATURE3, NULL)) {
		printf("%s: Feature add failed for adding feature %s after %s\n",
		       TEST_ARC2_NAME, PKT_FREE_STATIC, ARC2_FEATURE3);
		return TEST_FAILED;
	}
	/* Adding feature ARC2_FEATURE2 between ARC2_FEATURE1 and ARC2_FEATURE3. */
	if (rte_graph_feature_add(arcs[1], &arc2_feature2, ARC2_FEATURE1, ARC2_FEATURE3)) {
		printf("%s: Feature add failed for adding feature %s between [%s - %s]\n",
		       TEST_ARC2_NAME, ARC2_FEATURE2, ARC2_FEATURE1, ARC2_FEATURE3);
		return TEST_FAILED;
	}
	/* Now check feature sequencing is correct for both ARCS */

	/* arc1_featur1 must be first feature to arcs[0] */
	if (!strstr(ARC1_FEATURE1,
		    rte_graph_feature_arc_feature_to_name(arcs[0],
							  rte_graph_feature_cast(0)))) {
		printf("%s: %s is not the first feature instead %s\n",
		       TEST_ARC1_NAME, ARC1_FEATURE1,
		       rte_graph_feature_arc_feature_to_name(arcs[0], rte_graph_feature_cast(0)));
		return TEST_FAILED;
	}

	/* arc1_feature2 must be second feature to arcs[0] */
	if (!strstr(ARC1_FEATURE2,
		    rte_graph_feature_arc_feature_to_name(arcs[0],
							  rte_graph_feature_cast(1)))) {
		printf("%s: %s is not the second feature instead %s\n",
		       TEST_ARC1_NAME, ARC1_FEATURE2,
		       rte_graph_feature_arc_feature_to_name(arcs[0], rte_graph_feature_cast(1)));
		return TEST_FAILED;
	}

	/* Make sure INPUT_STATIC is the last feature in arcs[0] */
	temp = rte_graph_feature_arc_num_features(arcs[0]);
	if (!strstr(INPUT_STATIC,
		    rte_graph_feature_arc_feature_to_name(arcs[0],
							  temp - rte_graph_feature_cast(1)))) {
		printf("%s: %s is not the last feature instead %s\n",
		       TEST_ARC1_NAME, INPUT_STATIC,
		       rte_graph_feature_arc_feature_to_name(arcs[0],
							     temp - rte_graph_feature_cast(1)));
		return TEST_FAILED;
	}

	/* arc2_featur1 must be first feature to arcs[1] */
	if (!strstr(ARC2_FEATURE1,
		    rte_graph_feature_arc_feature_to_name(arcs[1],
							  rte_graph_feature_cast(0)))) {
		printf("%s: %s is not the first feature instead %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE1,
		       rte_graph_feature_arc_feature_to_name(arcs[1], rte_graph_feature_cast(0)));
		return TEST_FAILED;
	}

	/* arc2_feature2 must be second feature to arcs[1] */
	if (!strstr(ARC2_FEATURE2,
		    rte_graph_feature_arc_feature_to_name(arcs[1],
							  rte_graph_feature_cast(1)))) {
		printf("%s: %s is not the second feature instead %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE2,
		       rte_graph_feature_arc_feature_to_name(arcs[1], rte_graph_feature_cast(1)));
		return TEST_FAILED;
	}

	/* arc2_feature3 must be third feature to arcs[1] */
	if (!strstr(ARC2_FEATURE3,
		    rte_graph_feature_arc_feature_to_name(arcs[1],
							  rte_graph_feature_cast(2)))) {
		printf("%s: %s is not the third feature instead %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE3,
		       rte_graph_feature_arc_feature_to_name(arcs[1], rte_graph_feature_cast(2)));
		return TEST_FAILED;
	}

	/* Make sure PKT_FREE is the last feature in arcs[1] */
	temp = rte_graph_feature_arc_num_features(arcs[1]);
	if (!strstr(PKT_FREE_STATIC,
		    rte_graph_feature_arc_feature_to_name(arcs[1],
							  temp - rte_graph_feature_cast(1)))) {
		printf("%s: %s is not the last feature instead %s\n",
		       TEST_ARC2_NAME, PKT_FREE_STATIC,
		       rte_graph_feature_arc_feature_to_name(arcs[1],
							     temp - rte_graph_feature_cast(1)));
		return TEST_FAILED;
	}

	if (get_edge(&arc2_feature1, &pkt_free, NULL)) {
		printf("%s: Edge not found between %s and %s\n",
		       TEST_ARC2_NAME, ARC2_FEATURE1, PKT_FREE_STATIC);
		return TEST_FAILED;
	}

	return create_graph();
}

static int
test_graph_feature_arc_first_feature_enable(void)
{
	uint32_t  n_indexes, n_features, count = 0;
	rte_graph_feature_rt_list_t feature_list, temp = 0;
	struct rte_node_register *parent, *child;
	rte_graph_feature_data_t *fdata = NULL;
	struct rte_graph_feature_arc *arc;
	rte_graph_feature_t feature;
	char *feature_name = NULL;
	int32_t user_data;
	rte_edge_t edge = ~0;

	arc = rte_graph_feature_arc_get(arcs[0]);

	if (rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
		printf("%s: Feature arc should not have any feature enabled by now\n",
		       TEST_ARC1_NAME);
		return TEST_FAILED;
	}

	if (rte_graph_feature_arc_num_enabled_features(arcs[0])) {
		printf("%s: Feature arc should not have any_feature() enabled by now\n",
		       TEST_ARC1_NAME);
		return TEST_FAILED;
	}
	/*
	 * On interface 0, enable feature 0,
	 * On interface 1, enable feature 1 and so on so forth
	 *
	 * later verify first feature on every interface index is unique
	 * and check [rte_edge, user_data] retrieved via fast path APIs
	 */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		n_features = n_indexes % 3 /* 3 features added to arc1 */;
		feature_name = rte_graph_feature_arc_feature_to_name(arcs[0], n_features);
		user_data = compute_unique_user_data(arc->start_node->name, feature_name,
						    n_indexes);
		if (rte_graph_feature_validate(arcs[0], n_indexes, feature_name, 1, true)) {
			printf("%s: Feature validate failed for %s on index %u\n",
			       TEST_ARC1_NAME, feature_name, n_indexes);
			return TEST_FAILED;
		}
		/* negative test case. enable feature on invalid index */
		if (!n_indexes && !rte_graph_feature_enable(arcs[0], MAX_INDEXES, feature_name,
							    (int32_t)user_data)) {
			printf("%s: Feature %s should not be enabled on invalid index\n",
			       TEST_ARC1_NAME, feature_name);
			return TEST_FAILED;
		}
		if (rte_graph_feature_enable(arcs[0], n_indexes, feature_name,
					     (int32_t)user_data)) {
			printf("%s: Feature enable failed for %s on index %u\n",
			       TEST_ARC1_NAME, feature_name, n_indexes);
			return TEST_FAILED;
		}
		/* has any feature should be valid */
		if (!rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
			printf("%s: Feature arc should have any_feature enabled by now\n",
			       TEST_ARC1_NAME);
			return TEST_FAILED;
		}
		if (temp == feature_list) {
			printf("%s: Activer feature list not switched from %u -> %u\n",
			       TEST_ARC1_NAME, temp, feature_list);
			return TEST_FAILED;
		}
		temp = feature_list;
		if ((count + 1) != rte_graph_feature_arc_num_enabled_features(arcs[0])) {
			printf("%s: Number of enabled mismatches [found: %u, exp: %u]\n",
			       TEST_ARC1_NAME,
			       rte_graph_feature_arc_num_enabled_features(arcs[0]),
			       count + 1);
			return TEST_FAILED;
		}
		count++;
	}
	if (!rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
		printf("%s: Feature arc should have any_feature enabled by now\n",
		       TEST_ARC1_NAME);
		return TEST_FAILED;
	}
	/* Negative test case */
	user_data = compute_unique_user_data(arc->start_node->name, ARC2_FEATURE1, 1);
	if (!rte_graph_feature_enable(arcs[0], 1 /* index */, ARC2_FEATURE1, user_data)) {
		printf("%s: Invalid feature %s is enabled on index 1\n",
		       TEST_ARC1_NAME, ARC2_FEATURE1);
		return TEST_FAILED;
	}
	/* Duplicate enable */
	if (!rte_graph_feature_enable(arcs[0], 1 /* index */, ARC1_FEATURE2, user_data)) {
		printf("%s: Duplicate feature %s shouldn't be enabled again on index 1\n",
		       TEST_ARC1_NAME, ARC1_FEATURE2);
		return TEST_FAILED;
	}
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: No first feature enabled on index: %u\n",
			       TEST_ARC1_NAME, n_indexes);
			return TEST_FAILED;
		}
		/* Get first feature data and ensure edge and user_data are correct */
		fdata = rte_graph_feature_data_get(arc, rte_graph_feature_get(arc, feature),
						   n_indexes);
		parent = arc->start_node;
		if (0 == (n_indexes % 3))
			child = &arc1_feature1;
		else if (1 == (n_indexes % 3))
			child = &arc1_feature2;
		else
			child = &input;

		if (get_edge(parent, child, &edge)) {
			printf("%s: Edge not found between %s and %s\n",
			       TEST_ARC1_NAME, parent->name, child->name);
			return TEST_FAILED;
		}
		if (fdata->next_edge != edge) {
			printf("%s: Edge mismatch for first feature on index %u [%u, exp: %u]\n",
			       TEST_ARC1_NAME, n_indexes, fdata->next_edge, edge);
			return TEST_FAILED;
		}
		if (fdata->user_data != compute_unique_user_data(parent->name, child->name,
								n_indexes)) {
			printf("%s: First feature user data mismatch on index %u [%u, exp: %u]\n",
			       TEST_ARC1_NAME, n_indexes, fdata->user_data,
			       compute_unique_user_data(parent->name, child->name, n_indexes));
			return TEST_FAILED;
		}
	}
	return TEST_SUCCESS;
}

static int
verify_feature_sequencing(struct rte_graph_feature_arc *arc)
{
	rte_graph_feature_rt_list_t feature_list;
	struct rte_node_register *parent, *child;
	rte_graph_feature_data_t *fdata = NULL;
	rte_graph_feature_t feature;
	uint32_t  n_indexes;
	rte_edge_t edge = ~0;
	int32_t user_data;

	if (!rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
		printf("%s: feature_list can't be obtained\n",
		       arc->feature_arc_name);
		return TEST_FAILED;
	}
	/* Verify next features on interface 0 and interface 1*/
	for (n_indexes = 0; n_indexes < 2;  n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: No first feature enabled on index: 0\n",
			       arc->feature_arc_name);
			return TEST_FAILED;
		}
		parent = arc->start_node;
		child = rte_graph_feature_arc_feature_to_node(arcs[1], feature);
		/* until fast path API reaches last feature i.e pkt_free */
		while (child != &pkt_free) {
			fdata = rte_graph_feature_data_get(arc,
							   rte_graph_feature_get(arc, feature),
							   n_indexes);

			if (get_edge(parent, child, &edge)) {
				printf("%s: Edge not found between %s and %s\n",
				       arc->feature_arc_name, parent->name, child->name);
				return TEST_FAILED;
			}
			user_data = compute_unique_user_data(parent->name, child->name, n_indexes);
			if (fdata->next_edge != edge) {
				printf("%s: Edge mismatch for %s->%s on index %u [%u, exp: %u]\n",
				       arc->feature_arc_name, parent->name, child->name, n_indexes,
				       fdata->next_edge, edge);
				return TEST_FAILED;
			}
			if (fdata->user_data != user_data) {
				printf("%s: Udata mismatch for %s->%s on index %u [%u, exp: %u]\n",
				       arc->feature_arc_name, parent->name, child->name, n_indexes,
				       fdata->user_data, user_data);
				return TEST_FAILED;
			}

			feature = fdata->next_enabled_feature;

			parent = child;
			child = rte_graph_feature_arc_feature_to_node(arcs[1],
								      fdata->next_enabled_feature);
		}
	}
	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_next_feature_enable(void)
{
	rte_graph_feature_rt_list_t feature_list;
	struct rte_node_register *parent, *child;
	rte_graph_feature_data_t *fdata = NULL;
	struct rte_graph_feature_arc *arc;
	uint32_t  n_indexes, n_features;
	rte_graph_feature_t feature;
	char *feature_name = NULL;
	rte_edge_t edge = ~0;
	int32_t user_data;

	arc = rte_graph_feature_arc_get(arcs[1]);

	if (rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
		printf("%s: Feature arc should not have any feature enabled by now\n",
		       TEST_ARC2_NAME);
		return TEST_FAILED;
	}

	if (rte_graph_feature_arc_num_enabled_features(arcs[1])) {
		printf("%s: Feature arc should not have any_feature() enabled by now\n",
		       TEST_ARC2_NAME);
		return TEST_FAILED;
	}
	/*
	 * On interface 0, enable feature 2, skip feature 1 for later
	 * On interface 1, enable feature 3
	 * On interface 2, enable pkt_free feature
	 * On interface 3, continue as interface 0
	 *
	 * later enable next feature sequence for interface 0 from feature2 -> pkt_free
	 * later enable next feature sequence for interface 1 from feature3 -> pkt_free
	 *
	 * also later enable feature-1 and see first feature changes for all indexes
	 */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		n_features = (n_indexes % 3) + 1; /* feature2 to pkt_free are 3 features */
		feature_name = rte_graph_feature_arc_feature_to_name(arcs[1], n_features);
		user_data = compute_unique_user_data(arc->start_node->name, feature_name,
						     n_indexes);
		if (rte_graph_feature_enable(arcs[1], n_indexes, feature_name,
					     (int32_t)user_data)) {
			printf("%s: Feature enable failed for %s on index %u\n",
			       TEST_ARC2_NAME, feature_name, n_indexes);
			return TEST_FAILED;
		}
		/* has any feature should be valid */
		if (!rte_graph_feature_arc_has_any_feature(arc, &feature_list)) {
			printf("%s: Feature arc should have any_feature enabled by now\n",
			       TEST_ARC2_NAME);
			return TEST_FAILED;
		}
	}
	/* Retrieve latest feature_list */
	rte_graph_feature_arc_has_any_feature(arc, &feature_list);
	/* verify first feature */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: No first feature enabled on index: %u\n",
			       TEST_ARC2_NAME, n_indexes);
			return TEST_FAILED;
		}
		/* Get first feature data and ensure edge and user_data are correct */
		fdata = rte_graph_feature_data_get(arc, rte_graph_feature_get(arc, feature),
						   n_indexes);
		parent = arc->start_node;
		if (0 == (n_indexes % 3))
			child = &arc2_feature2;
		else if (1 == (n_indexes % 3))
			child = &arc2_feature3;
		else
			child = &pkt_free;

		if (get_edge(parent, child, &edge)) {
			printf("%s: Edge not found between %s and %s\n",
			       TEST_ARC2_NAME, parent->name, child->name);
			return TEST_FAILED;
		}
		if (fdata->next_edge != edge) {
			printf("%s: Edge mismatch for first feature on index %u [%u, exp: %u]\n",
			       TEST_ARC2_NAME, n_indexes, fdata->next_edge, edge);
			return TEST_FAILED;
		}
		if (fdata->user_data != compute_unique_user_data(parent->name, child->name,
								n_indexes)) {
			printf("%s: First feature user data mismatch on index %u [%u, exp: %u]\n",
			       TEST_ARC2_NAME, n_indexes, fdata->user_data,
			       compute_unique_user_data(parent->name, child->name, n_indexes));
			return TEST_FAILED;
		}
	}
	/* add next_features now
	 * On interface 0, enable feature-3 and pkt_free
	 * On interface 1, enable pkt_free
	 * Skip interface 2
	 * On interface 3, same as interface 0
	 * On interface 4, same as interface 1
	 */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (0 == (n_indexes % 3)) {
			if (rte_graph_feature_enable(arcs[1], n_indexes, ARC2_FEATURE3,
						     compute_unique_user_data(ARC2_FEATURE2,
									      ARC2_FEATURE3,
									      n_indexes))) {
				printf("%s: Feature enable failed for %s -> (%s) on index %u\n",
				       TEST_ARC2_NAME, ARC2_FEATURE2, ARC2_FEATURE3, n_indexes);
				return TEST_FAILED;
			}
		}
		/* pkt_free on interface-0, 1, 3, 4 and so on */
		if ((0 == (n_indexes % 3)) || (1 == (n_indexes % 3))) {
			if (rte_graph_feature_enable(arcs[1], n_indexes, PKT_FREE_STATIC,
						     compute_unique_user_data(ARC2_FEATURE3,
									      PKT_FREE_STATIC,
									      n_indexes))) {
				printf("%s: Feature enable failed %s -> (%s) on index %u\n",
				       TEST_ARC2_NAME, ARC2_FEATURE3, PKT_FREE_STATIC, n_indexes);
				return TEST_FAILED;
			}
		}
	}

	if (verify_feature_sequencing(arc) == TEST_FAILED)
		return TEST_FAILED;

	/* Enable feature-1 on all interfaces and check first feature changes */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		user_data = compute_unique_user_data(arc->start_node->name, ARC2_FEATURE1,
						     n_indexes);
		if (rte_graph_feature_enable(arcs[1], n_indexes, ARC2_FEATURE1,
					     (int32_t)user_data)) {
			printf("%s: Feature enable failed for %s on index %u\n",
			       TEST_ARC2_NAME, feature_name, n_indexes);
			return TEST_FAILED;
		}
	}
	rte_graph_feature_arc_has_any_feature(arc, &feature_list);
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							    &feature)) {
			printf("%s: None first feature enabled on index: %u\n",
			       TEST_ARC2_NAME, n_indexes);
			return TEST_FAILED;
		}
		if (feature != rte_graph_feature_cast(0)) {
			printf("%s: First feature mismatch on index %u [%u, exp: %u]\n",
			       TEST_ARC2_NAME, n_indexes, feature, rte_graph_feature_cast(0));
			return TEST_FAILED;
		}
	}
	if (verify_feature_sequencing(arc) == TEST_FAILED)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_first_feature_disable(void)
{
	rte_graph_feature_rt_list_t feature_list;
	struct rte_graph_feature_arc *arc;
	rte_graph_feature_t feature;
	uint32_t  n_indexes;

	arc = rte_graph_feature_arc_get(arcs[1]);

	/* Disable feature-1 on all interfaces and check first feature changes */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (rte_graph_feature_disable(arcs[1], n_indexes, ARC2_FEATURE1)) {
			printf("%s: Feature disable failed for %s on index %u\n",
			       TEST_ARC2_NAME, ARC2_FEATURE1, n_indexes);
			return TEST_FAILED;
		}
	}
	rte_graph_feature_arc_has_any_feature(arc, &feature_list);
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: First feature get failed on index: %u\n",
			       TEST_ARC2_NAME, n_indexes);
			return TEST_FAILED;
		}
		if (feature == rte_graph_feature_cast(0)) {
			printf("%s: First feature not disabled on index %u [%u, exp: %u]\n",
			       TEST_ARC2_NAME, n_indexes, feature, rte_graph_feature_cast(1));
			return TEST_FAILED;
		}
		if (!strncmp(ARC2_FEATURE1,
			     rte_graph_feature_arc_feature_to_name(arcs[1], feature),
			     strlen(ARC2_FEATURE1))) {
			printf("%s: First feature mismatch on index %u [%s, exp: %s]\n",
			       TEST_ARC2_NAME, n_indexes,
			       rte_graph_feature_arc_feature_to_name(arcs[1], feature),
			       ARC2_FEATURE2);
			return TEST_FAILED;
		}
	}
	if (verify_feature_sequencing(arc) == TEST_FAILED)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_next_feature_disable(void)
{
	rte_graph_feature_rt_list_t feature_list;
	struct rte_graph_feature_arc *arc;
	rte_graph_feature_t feature;
	uint32_t n_indexes;

	arc = rte_graph_feature_arc_get(arcs[1]);

	/*
	 * On interface 0, disable feature 2, keep feature3 and pkt_free enabled
	 * On interface 1, skip interface 1 where feature3 and pkt_free are enabled
	 * skip interface 2 as only pkt_free is enabled
	 */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!(n_indexes % 3)) {
			if (rte_graph_feature_disable(arcs[1], n_indexes, ARC2_FEATURE2)) {
				printf("%s: Feature disable failed for %s on index %u\n",
				       TEST_ARC2_NAME, ARC2_FEATURE2, n_indexes);
				return TEST_FAILED;
			}
		}

		if (verify_feature_sequencing(arc) == TEST_FAILED)
			return TEST_FAILED;
	}

	/**
	 * Disable feature 3 on all interface 0 and 1 and check first feature
	 * is pkt_free on all indexes
	 */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if ((0 == (n_indexes % 3)) || (1 == (n_indexes % 3))) {
			if (rte_graph_feature_disable(arcs[1], n_indexes, ARC2_FEATURE3)) {
				printf("%s: Feature disable failed for %s on index %u\n",
				       TEST_ARC2_NAME, ARC2_FEATURE3, n_indexes);
				return TEST_FAILED;
			}
		}
	}
	/* Make sure pkt_free is first feature for all indexes */
	rte_graph_feature_arc_has_any_feature(arc, &feature_list);
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (!rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: First feature get failed on index: %u\n",
			       TEST_ARC2_NAME, n_indexes);
			return TEST_FAILED;
		}
		if (strncmp(PKT_FREE_STATIC,
			    rte_graph_feature_arc_feature_to_name(arcs[1], feature),
			    strlen(PKT_FREE_STATIC))) {
			printf("%s: %s is not first feature found on index %u [%s, exp: %s]\n",
			       TEST_ARC2_NAME, PKT_FREE_STATIC, n_indexes,
			       rte_graph_feature_arc_feature_to_name(arcs[1], feature),
			       PKT_FREE_STATIC);
			return TEST_FAILED;
		}
	}

	/* Disable PKT_FREE_STATIC from all indexes with no feature enabled on any interface */
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (rte_graph_feature_disable(arcs[1], n_indexes, PKT_FREE_STATIC)) {
			printf("%s: Feat disable failed for %s on index %u\n",
			       TEST_ARC2_NAME, PKT_FREE_STATIC, n_indexes);
			return TEST_FAILED;
		}
	}
	/* Make sure no feature is enabled now on any interface */
	rte_graph_feature_arc_has_any_feature(arc, &feature_list);
	for (n_indexes = 0; n_indexes < MAX_INDEXES; n_indexes++) {
		if (rte_graph_feature_arc_first_feature_get(arc, feature_list, n_indexes,
							     &feature)) {
			printf("%s: Index: %u should not have first feature enabled\n",
			       TEST_ARC2_NAME, n_indexes);
			return TEST_FAILED;
		}
	}
	return TEST_SUCCESS;
}

static int
test_graph_feature_arc_destroy(void)
{
	rte_graph_feature_arc_t arc;

	if (rte_graph_feature_arc_lookup_by_name(TEST_ARC1_NAME, &arc)) {
		printf("Feature arc lookup failed for %s\n", TEST_ARC1_NAME);
		return TEST_FAILED;
	}

	if (arc != arcs[0]) {
		printf("Feature arc lookup mismatch for %s [%p, exp: %p]\n",
		       TEST_ARC1_NAME, (void *)arc, (void *)arcs[0]);
		return TEST_FAILED;
	}

	if (rte_graph_feature_arc_destroy(arc)) {
		printf("Feature arc destroy failed for %s\n", TEST_ARC1_NAME);
		return TEST_FAILED;
	}

	if (rte_graph_feature_arc_lookup_by_name(TEST_ARC2_NAME, &arc)) {
		printf("Feature arc lookup success after destroy for %s\n", TEST_ARC2_NAME);
		return TEST_FAILED;
	}

	if (arc != arcs[1]) {
		printf("Feature arc lookup mismatch for %s [%p, exp: %p]\n",
		       TEST_ARC2_NAME, (void *)arc, (void *)arcs[1]);
		return TEST_FAILED;
	}
	if (rte_graph_feature_arc_destroy(arc)) {
		printf("Feature arc destroy failed for %s\n", TEST_ARC2_NAME);
		return TEST_FAILED;
	}
	return TEST_SUCCESS;
}

static int
graph_feature_arc_setup(void)
{
	unsigned long i, j;

	static const struct rte_mbuf_dynfield graph_dynfield_desc = {
		.name = "test_graph_dynfield",
		.size = sizeof(graph_dynfield_t),
		.align = alignof(graph_dynfield_t),
	};

	graph_dynfield_offset =
		rte_mbuf_dynfield_register(&graph_dynfield_desc);
	if (graph_dynfield_offset < 0) {
		printf("Cannot register mbuf field\n");
		return TEST_FAILED;
	}
	RTE_SET_USED(graph_dynfield_offset);

	for (i = 0; i <= MAX_NODES; i++) {
		for (j = 0; j < MBUFF_SIZE; j++)
			mbuf_p[i][j] = &mbuf[i][j];
	}

	return TEST_SUCCESS;

}

static void
graph_feature_arc_teardown(void)
{
	if (graph_id != RTE_GRAPH_ID_INVALID)
		rte_graph_destroy(graph_id);

	rte_graph_feature_arc_cleanup();
}

static struct unit_test_suite graph_feature_arc_testsuite = {
	.suite_name = "Graph Feature arc library test suite",
	.setup = graph_feature_arc_setup,
	.teardown = graph_feature_arc_teardown,
	.unit_test_cases = {
		TEST_CASE(test_graph_feature_arc_create),
		TEST_CASE(test_graph_feature_arc_features_add),
		TEST_CASE(test_graph_feature_arc_first_feature_enable),
		TEST_CASE(test_graph_feature_arc_next_feature_enable),
		TEST_CASE(test_graph_feature_arc_first_feature_disable),
		TEST_CASE(test_graph_feature_arc_next_feature_disable),
		TEST_CASE(test_graph_feature_arc_destroy),
		TEST_CASES_END(), /**< NULL terminate unit test array */
	},
};

static int
graph_feature_arc_autotest_fn(void)
{
	return unit_test_suite_runner(&graph_feature_arc_testsuite);
}

REGISTER_FAST_TEST(graph_feature_arc_autotest, true, true, graph_feature_arc_autotest_fn);
#endif /* !RTE_EXEC_ENV_WINDOWS */
