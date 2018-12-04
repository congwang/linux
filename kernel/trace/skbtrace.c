// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Cong Wang <xiyou.wangcong@gmail.com>
 *
 */
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/relay.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/sockios.h>
#include <linux/skbtrace_api.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

#include <trace/events/skb.h>

#include "trace_output.h"


enum {
	SKBTRACE_SETUP = 1,
	SKBTRACE_RUNNING,
	SKBTRACE_STOPPED,
};

static struct dentry *skb_debugfs_root;
static unsigned int skbtrace_seq __read_mostly = 1;

static DEFINE_MUTEX(skb_probe_mutex);
static int skb_probes_ref;

static void skb_trace_add(struct net *net, struct sk_buff *skb)
{
	struct skb_trace *sbt = net->skb_trace;
	struct skb_trace_slot *t;
	unsigned long *sequence;
	unsigned long flags;
	int cpu;

	if (likely(!sbt))
		return;
	if (unlikely(sbt->trace_state != SKBTRACE_RUNNING))
		return;
	cpu = raw_smp_processor_id();
	/*
	 * A word about the locking here - we disable interrupts to reserve
	 * some space in the relay per-cpu buffer, to prevent an irq
	 * from coming in and stepping on our toes.
	 */
	local_irq_save(flags);
	t = relay_reserve(sbt->rchan, sizeof(*t));
	if (t) {
		sequence = per_cpu_ptr(sbt->sequence, cpu);

		t->magic = SKB_TRACE_MAGIC | SKB_TRACE_VERSION;
		t->sequence = ++(*sequence);
		t->time = ktime_to_ns(ktime_get());
		/*
		 * These two are not needed in ftrace as they are in the
		 * generic trace_entry, filled by tracing_generic_entry_update,
		 * but for the trace_event->bin() synthesizer benefit we do it
		 * here too.
		 */
		t->cpu = cpu;
	}

	local_irq_restore(flags);
}

static void skb_trace_add_skb_alloc(void *ignore, struct net *net,
				    struct sk_buff *skb)
{
	skb_trace_add(net, skb);
}

static void skb_register_tracepoints(void)
{
	int ret;
	ret = register_trace_skb_alloc(skb_trace_add_skb_alloc, NULL);
	WARN_ON(ret);
}

static void skb_unregister_tracepoints(void)
{
	unregister_trace_skb_alloc(skb_trace_add_skb_alloc, NULL);

	tracepoint_synchronize_unregister();
}

static int do_skb_trace_startstop(const struct net *net, bool start)
{
	struct skb_trace *sbt = net->skb_trace;
	int ret;

	if (sbt == NULL)
		return -EINVAL;

	ret = -EINVAL;
	if (start) {
		if (sbt->trace_state == SKBTRACE_SETUP ||
		    sbt->trace_state == SKBTRACE_STOPPED) {
			skbtrace_seq++;
			smp_mb();
			sbt->trace_state = SKBTRACE_RUNNING;
			ret = 0;
		}
	} else {
		if (sbt->trace_state == SKBTRACE_RUNNING) {
			sbt->trace_state = SKBTRACE_STOPPED;
			relay_flush(sbt->rchan);
			ret = 0;
		}
	}

	return ret;
}

static int skb_trace_startstop(bool start, char __user *arg)
{
	struct skb_user_trace_setup sbts;
	struct net *target_net;
	int ret;

	ret = copy_from_user(&sbts, arg, sizeof(sbts));
	if (ret)
		return -EFAULT;

	if (sbts.netns_fd == INIT_NET_FD)
		target_net = &init_net;
	else
		target_net = get_net_ns_by_fd(sbts.netns_fd);
	if (IS_ERR(target_net))
		return PTR_ERR(target_net);

	return do_skb_trace_startstop(target_net, start);
}

static void skb_trace_get_probe_ref(void)
{
	mutex_lock(&skb_probe_mutex);
	if (++skb_probes_ref == 1)
		skb_register_tracepoints();
	mutex_unlock(&skb_probe_mutex);
}

static void skb_trace_put_probe_ref(void)
{
	mutex_lock(&skb_probe_mutex);
	if (!--skb_probes_ref)
		skb_unregister_tracepoints();
	mutex_unlock(&skb_probe_mutex);
}

static void skb_trace_free(struct skb_trace *sbt)
{
	relay_close(sbt->rchan);
	debugfs_remove(sbt->dir);
	free_percpu(sbt->sequence);
	free_percpu(sbt->msg_data);
	kfree(sbt);
}

static void skb_trace_cleanup(struct skb_trace *sbt)
{
	skb_trace_free(sbt);
	skb_trace_put_probe_ref();
}

static int do_skb_trace_remove(struct net *net)
{
	struct skb_trace *sbt;

	sbt = xchg(&net->skb_trace, NULL);
	if (!sbt)
		return -EINVAL;

	if (sbt->trace_state != SKBTRACE_RUNNING)
		skb_trace_cleanup(sbt);

	return 0;
}

static int skb_subbuf_start_callback(struct rchan_buf *buf, void *subbuf,
				     void *prev_subbuf, size_t prev_padding)
{
	struct skb_trace *sbt;

	if (!relay_buf_full(buf))
		return 1;

	sbt = buf->chan->private_data;
	return 0;
}

static int skb_remove_buf_file_callback(struct dentry *dentry)
{
	debugfs_remove(dentry);

	return 0;
}

static struct dentry *skb_create_buf_file_callback(const char *filename,
						   struct dentry *parent,
						   umode_t mode,
						   struct rchan_buf *buf,
						   int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static struct rchan_callbacks skb_relay_callbacks = {
	.subbuf_start		= skb_subbuf_start_callback,
	.create_buf_file	= skb_create_buf_file_callback,
	.remove_buf_file	= skb_remove_buf_file_callback,
};

#define SKB_TN_MAX_MSG		128

static int do_skb_trace_setup(struct net *net, struct skb_user_trace_setup *sbts)
{
	struct skb_trace *sbt = NULL;
	struct dentry *dir = NULL;
	int ret;

	if (!sbts->buf_size || !sbts->buf_nr)
		return -EINVAL;

	sbt = kzalloc(sizeof(*sbt), GFP_KERNEL);
	if (!sbt)
		return -ENOMEM;

	ret = -ENOMEM;
	sbt->sequence = alloc_percpu(unsigned long);
	if (!sbt->sequence)
		goto err;

	sbt->msg_data = __alloc_percpu(SKB_TN_MAX_MSG, __alignof__(char));
	if (!sbt->msg_data)
		goto err;

	ret = -ENOENT;

	if (!skb_debugfs_root) {
		skb_debugfs_root = debugfs_create_dir("skbuff", NULL);
		if (!skb_debugfs_root)
			goto err;
	}

	dir = debugfs_lookup(sbts->name, skb_debugfs_root);
	if (!dir)
		sbt->dir = dir = debugfs_create_dir(sbts->name, skb_debugfs_root);
	if (!dir)
		goto err;

	sbt->rchan = relay_open("trace", dir, sbts->buf_size,
				sbts->buf_nr, &skb_relay_callbacks, sbt);
	if (!sbt->rchan)
		goto err;

	sbt->trace_state = SKBTRACE_SETUP;
	ret = -EBUSY;
	if (cmpxchg(&net->skb_trace, NULL, sbt))
		goto err;

	skb_trace_get_probe_ref();

	ret = 0;
err:
	if (dir && !sbt->dir)
		dput(dir);
	if (ret)
		skb_trace_free(sbt);
	return ret;

	return 0;
}

static int skb_trace_setup(char __user *arg)
{
	struct skb_user_trace_setup sbts;
	struct net *target_net;
	int ret;

	ret = copy_from_user(&sbts, arg, sizeof(sbts));
	if (ret)
		return -EFAULT;

	if (sbts.netns_fd == INIT_NET_FD)
		target_net = &init_net;
	else
		target_net = get_net_ns_by_fd(sbts.netns_fd);
	if (IS_ERR(target_net))
		return PTR_ERR(target_net);
	ret = do_skb_trace_setup(target_net, &sbts);
	if (ret)
		return ret;

	if (copy_to_user(arg, &sbts, sizeof(sbts))) {
		do_skb_trace_remove(target_net);
		return -EFAULT;
	}
	return 0;
}

static int skb_trace_remove(char __user *arg)
{
	struct skb_user_trace_setup sbts;
	struct net *target_net;
	int ret;

	ret = copy_from_user(&sbts, arg, sizeof(sbts));
	if (ret)
		return -EFAULT;

	if (sbts.netns_fd == INIT_NET_FD)
		target_net = &init_net;
	else
		target_net = get_net_ns_by_fd(sbts.netns_fd);
	if (IS_ERR(target_net))
		return PTR_ERR(target_net);

	return do_skb_trace_remove(target_net);
}

/**
 * skb_trace_ioctl: - handle the ioctls associated with tracing
 * @cmd:	the ioctl cmd
 * @arg:	the argument data, skb_user_trace_setup
 *
 **/
int skb_trace_ioctl(unsigned cmd, char __user *arg)
{
	bool start = false;
	int ret;

	rtnl_lock();

	switch (cmd) {
	case SIOCSKBTRACESETUP:
		ret = skb_trace_setup(arg);
		break;
	case SIOCSKBTRACESTART:
		start = true;
	case SIOCSKBTRACESTOP:
		ret = skb_trace_startstop(start, arg);
		break;
	case SIOCSKBTRACETEARDOWN:
		ret = skb_trace_remove(arg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	rtnl_unlock();
	return ret;
}
