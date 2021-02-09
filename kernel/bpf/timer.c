// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/filter.h>
#include <uapi/linux/btf.h>

struct bpf_timer_list {
	struct timer_list timer;
	struct bpf_prog *prog;
	u32 expires; /* in milliseconds */
	struct rcu_head rcu;
};

struct bpf_timer_array {
	struct bpf_map map;
	spinlock_t lock;
	struct bpf_timer_list __rcu *ptrs[];
};

static int timer_map_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries == 0 || attr->max_entries > INT_MAX ||
	    attr->key_size != 4 || attr->value_size != 4)
		return -EINVAL;

	if (attr->map_flags & BPF_F_MMAPABLE)
		return -EINVAL;

	return 0;
}

static struct bpf_map *timer_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_timer_array *array;
	u64 array_size;

	array_size = sizeof(*array);
	array_size += attr->max_entries * sizeof(struct bpf_timer_list *);
	array = bpf_map_area_alloc(array_size, numa_node);
	if (!array)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&array->map, attr);
	spin_lock_init(&array->lock);
	return &array->map;
}

static void timer_map_free(struct bpf_map *map)
{
	struct bpf_timer_array *array = container_of(map, struct bpf_timer_array, map);
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		struct bpf_timer_list *t;

		t = array->ptrs[i];
		if (!t) {
			del_timer_sync(&t->timer);
			kfree_rcu(t, rcu);
		}
	}
	bpf_map_area_free(array);
}

static void *timer_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_timer_array *array = container_of(map, struct bpf_timer_array, map);
	struct bpf_timer_list *t;
	u32 index = *(u32 *)key;
	void *ret = NULL;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	rcu_read_lock();
	t = rcu_dereference(array->ptrs[index]);
	if (t)
		ret = &t->expires;
	rcu_read_unlock();
	return ret;
}

static int timer_map_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 flags)
{
	struct bpf_timer_array *array = container_of(map, struct bpf_timer_array, map);
	u32 expires = *(u32 *)value;
	struct bpf_timer_list *t;
	u32 index = *(u32 *)key;
	unsigned long irq_flags;
	int ret = 0;

	spin_lock_irqsave(&array->lock, irq_flags);
	t = rcu_dereference_protected(array->ptrs[index], true);
	if (t) {
		mod_timer(&t->timer, msecs_to_jiffies(expires));
		t->expires = expires;
	} else {
		ret = -ENOENT;
	}
	spin_unlock_irqrestore(&array->lock, irq_flags);
	return ret;
}

static int timer_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_timer_array *array = container_of(map, struct bpf_timer_array, map);
	struct bpf_timer_list *t;
	u32 index = *(u32 *)key;
	unsigned long irq_flags;

	spin_lock_irqsave(&array->lock, irq_flags);
	t = rcu_dereference_protected(array->ptrs[index], true);
	if (!t) {
		spin_unlock_irqrestore(&array->lock, irq_flags);
		return -ENOENT;
	}

	rcu_replace_pointer(array->ptrs[index], NULL, 1);
	spin_unlock_irqrestore(&array->lock, irq_flags);

	del_timer_sync(&t->timer);
	bpf_prog_put(t->prog);
	kfree_rcu(t, rcu);
	return 0;
}

static int timer_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	struct bpf_timer_array *array = container_of(map, struct bpf_timer_array, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= array->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == array->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

static int timer_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	return -ENOTSUPP;
}

static int timer_map_btf_id;
const struct bpf_map_ops timer_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = timer_map_alloc_check,
	.map_alloc = timer_map_alloc,
	.map_free = timer_map_free,
	.map_mmap = timer_map_mmap,
	.map_lookup_elem = timer_map_lookup_elem,
	.map_update_elem = timer_map_update_elem,
	.map_delete_elem = timer_map_delete_elem,
	.map_get_next_key = timer_map_get_next_key,
	.map_btf_name = "bpf_timer_map",
	.map_btf_id = &timer_map_btf_id,
};

static void bpf_timer_callback(struct timer_list *t)
{
	struct bpf_timer_list *bt = from_timer(bt, t, timer);
	u32 ret;

	rcu_read_lock();
	ret = BPF_PROG_RUN(bt->prog, NULL);
	rcu_read_unlock();
	if (ret)
		mod_timer(&bt->timer, bt->timer.expires + msecs_to_jiffies(ret));
}

int bpf_timer_create(union bpf_attr *attr)
{
	unsigned int flags, timer_flags = 0;
	struct bpf_timer_list *t;
	struct bpf_timer_array *array;
	struct bpf_prog *prog;
	struct bpf_map *map;
	int ret = 0;
	u32 index;

	flags = attr->timer_create.flags;
	if (flags & ~(BTF_TIMER_F_DEFERRABLE | BTF_TIMER_F_PINNED))
		return -EINVAL;

	prog = bpf_prog_get(attr->timer_create.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	if (prog->type != BPF_PROG_TYPE_TIMER) {
		ret = -EINVAL;
		goto out_prog_put;
	}

	map = bpf_map_get(attr->timer_create.map_fd);
	if (IS_ERR(map)) {
		ret = PTR_ERR(map);
		goto out_prog_put;
	}
	if (map->map_type != BPF_MAP_TYPE_TIMER_ARRAY) {
		ret = -EINVAL;
		goto out_map_put;
	}

	array = container_of(map, struct bpf_timer_array, map);
	index = attr->timer_create.index;
	if (index >= array->map.max_entries) {
		ret = -EINVAL;
		goto out_map_put;
	}

	if (rcu_access_pointer(array->ptrs[index])) {
		ret = -EEXIST;
		goto out_map_put;
	}

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		ret = -ENOMEM;
		goto out_map_put;
	}

	if (flags & BTF_TIMER_F_DEFERRABLE)
		timer_flags |= TIMER_DEFERRABLE;
	if (flags & BTF_TIMER_F_PINNED)
		timer_flags |= TIMER_PINNED;
	timer_setup(&t->timer, bpf_timer_callback, timer_flags);
	t->prog = prog;
	RCU_INIT_POINTER(array->ptrs[index], t);

out_map_put:
	bpf_map_put(map);
out_prog_put:
	if (ret)
		bpf_prog_put(prog);
	return ret;
}
