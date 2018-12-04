/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM skb

#if !defined(_TRACE_SKB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SKB_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/tracepoint.h>


DECLARE_EVENT_CLASS(sk_buff,

	TP_PROTO(struct net *net, struct sk_buff *skb),

	TP_ARGS(net, skb),

	TP_STRUCT__entry(
		__string(	name,			skb->dev->name	)
		__field(	unsigned int,		napi_id		)
		__field(	u16,			queue_mapping	)
		__field(	const void *,		skbaddr		)
		__field(	bool,			vlan_tagged	)
		__field(	u16,			vlan_proto	)
		__field(	u16,			vlan_tci	)
		__field(	u16,			protocol	)
		__field(	u8,			ip_summed	)
		__field(	u32,			hash		)
		__field(	bool,			l4_hash		)
		__field(	unsigned int,		len		)
		__field(	unsigned int,		data_len	)
		__field(	unsigned int,		truesize	)
		__field(	bool,			mac_header_valid)
		__field(	int,			mac_header	)
		__field(	unsigned char,		nr_frags	)
		__field(	u16,			gso_size	)
		__field(	u16,			gso_type	)
	),

	TP_fast_assign(
		__assign_str(name, skb->dev->name);
#ifdef CONFIG_NET_RX_BUSY_POLL
		__entry->napi_id = skb->napi_id;
#else
		__entry->napi_id = 0;
#endif
		__entry->queue_mapping = skb->queue_mapping;
		__entry->skbaddr = skb;
		__entry->vlan_tagged = skb_vlan_tag_present(skb);
		__entry->vlan_proto = ntohs(skb->vlan_proto);
		__entry->vlan_tci = skb_vlan_tag_get(skb);
		__entry->protocol = ntohs(skb->protocol);
		__entry->ip_summed = skb->ip_summed;
		__entry->hash = skb->hash;
		__entry->l4_hash = skb->l4_hash;
		__entry->len = skb->len;
		__entry->data_len = skb->data_len;
		__entry->truesize = skb->truesize;
		__entry->mac_header_valid = skb_mac_header_was_set(skb);
		__entry->mac_header = skb_mac_header(skb) - skb->data;
		__entry->nr_frags = skb_shinfo(skb)->nr_frags;
		__entry->gso_size = skb_shinfo(skb)->gso_size;
		__entry->gso_type = skb_shinfo(skb)->gso_type;
	),

	TP_printk("dev=%s napi_id=%#x queue_mapping=%u skbaddr=%p vlan_tagged=%d vlan_proto=0x%04x vlan_tci=0x%04x protocol=0x%04x ip_summed=%d hash=0x%08x l4_hash=%d len=%u data_len=%u truesize=%u mac_header_valid=%d mac_header=%d nr_frags=%d gso_size=%d gso_type=%#x",
		  __get_str(name), __entry->napi_id, __entry->queue_mapping,
		  __entry->skbaddr, __entry->vlan_tagged, __entry->vlan_proto,
		  __entry->vlan_tci, __entry->protocol, __entry->ip_summed,
		  __entry->hash, __entry->l4_hash, __entry->len,
		  __entry->data_len, __entry->truesize,
		  __entry->mac_header_valid, __entry->mac_header,
		  __entry->nr_frags, __entry->gso_size, __entry->gso_type)
);

DEFINE_EVENT(sk_buff, skb_alloc,

	TP_PROTO(struct net *net, struct sk_buff *skb),

	TP_ARGS(net, skb)
);

/*
 * Tracepoint for free an sk_buff:
 */
TRACE_EVENT(kfree_skb,

	TP_PROTO(struct sk_buff *skb, void *location),

	TP_ARGS(skb, location),

	TP_STRUCT__entry(
		__field(	void *,		skbaddr		)
		__field(	void *,		location	)
		__field(	unsigned short,	protocol	)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->location = location;
		__entry->protocol = ntohs(skb->protocol);
	),

	TP_printk("skbaddr=%p protocol=%u location=%p",
		__entry->skbaddr, __entry->protocol, __entry->location)
);

TRACE_EVENT(consume_skb,

	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb),

	TP_STRUCT__entry(
		__field(	void *,	skbaddr	)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
	),

	TP_printk("skbaddr=%p", __entry->skbaddr)
);

TRACE_EVENT(skb_copy_datagram_iovec,

	TP_PROTO(const struct sk_buff *skb, int len),

	TP_ARGS(skb, len),

	TP_STRUCT__entry(
		__field(	const void *,		skbaddr		)
		__field(	int,			len		)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->len = len;
	),

	TP_printk("skbaddr=%p len=%d", __entry->skbaddr, __entry->len)
);

#endif /* _TRACE_SKB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
