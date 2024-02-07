/* SPDX-License-Identifier: BSD-3-Clause
 * Stub if libbpf is not available
 */

struct bpf_object;
struct bpf_map;

struct tap_rss {
	struct bpf_object *obj;
	struct {
		struct bpf_map *rss_map;
	} maps;
};

static struct tap_rss *tap_rss__open_and_load(void)
{
	errno = ENOTSUP;
	return NULL;
}

static void tap_rss__destroy(struct tap_rss *obj)
{
}

static int tap_rss__attach(struct tap_rss *obj)
{
	return -1;
}

static int bpf_object__btf_fd(struct bpf_object *obj)
{
	return -1;
}

static int bpf_map__update_elem(const struct bpf_map *map, const void *key, size_t key_size,
				const void *value, size_t value_size, int flags)
{
	return -1;
}

static int bpf_map__delete_elem(const struct bpf_map *map,
				const void *key, size_t key_size, int flags)
{
	return -1;
}
