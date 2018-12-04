/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKBTRACE_H
#define SKBTRACE_H

#include <linux/relay.h>
#include <uapi/linux/skbtrace_api.h>

struct skb_trace {
	int trace_state;
	struct rchan *rchan;
	unsigned long __percpu *sequence;
	unsigned char __percpu *msg_data;
	struct dentry *dir;
};

#ifdef CONFIG_SKB_TRACE
int skb_trace_ioctl(unsigned cmd, char __user *arg);
#else
static inline int skb_trace_ioctl(unsigned cmd, char __user *arg)
{
	return -ENOTSUPP;
}
#endif

#endif
