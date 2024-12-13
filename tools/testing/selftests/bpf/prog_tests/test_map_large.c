// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

/* Test that creating a large XSK map and deleting elements works correctly */
static void test_xskmap_large_delete(void)
{
	int map_fd;
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	unsigned int key = 0x80000000 + 1;

	map_fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "xsk_map",
			       sizeof(int), sizeof(int),
			       0x80000000 + 2, &opts);
	if (map_fd == -ENOMEM) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	int err = bpf_map_delete_elem(map_fd, &key);
	ASSERT_OK(err, "map_delete");

	close(map_fd);
}

/* Test that creating a large devmap and deleting elements works correctly */
static void test_devmap_large_delete(void)
{
	int map_fd;
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	unsigned int key = 0x80000000 + 1;

	map_fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP, "dev_map",
			       sizeof(int), sizeof(int),
			       0x80000000 + 2, &opts);
	if (map_fd == -ENOMEM) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	int err = bpf_map_delete_elem(map_fd, &key);
	ASSERT_OK(err, "map_delete");

	close(map_fd);
}

void test_map_large(void)
{
	if (test__start_subtest("xskmap large delete"))
		test_xskmap_large_delete();

	if (test__start_subtest("devmap large delete"))
		test_devmap_large_delete();
}
