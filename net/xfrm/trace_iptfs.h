// SPDX-License-Identifier: GPL-2.0
/*
 * xfrm_trace_iptfs.h
 *
 * August 12 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM iptfs

#if !defined(_TRACE_IPTFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IPTFS_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tracepoint.h>

struct xfrm_iptfs_data;

DECLARE_EVENT_CLASS(iptfs_ingress_preq_event,
		    TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u8 was_gso),
		    TP_ARGS(skb, xtfs, was_gso),
		    TP_STRUCT__entry(
			__field(struct sk_buff *, skb)
			__field(u32, skb_len)
			__field(u32, data_len)
			__field(u32, proto_seq)
			__field(u8, proto)
			__field(u8, was_gso)),
		    TP_fast_assign(
			__entry->skb = skb;
			__entry->skb_len = skb->len;
			__entry->data_len = skb->data_len;
			__entry->proto = iptfs_payload_proto(skb);
			__entry->proto_seq = iptfs_payload_proto_seq(skb);
			__entry->was_gso = was_gso;
		    ),
		    TP_printk("INGRPREQ: skb=%p len=%u data_len=%u proto=%u proto_seq=%u was_gso=%u",
			      __entry->skb, __entry->skb_len, __entry->data_len,
			      __entry->proto, __entry->proto_seq, __entry->was_gso));

DEFINE_EVENT(iptfs_ingress_preq_event, iptfs_enqueue,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u8 was_gso),
	     TP_ARGS(skb, xtfs, was_gso));

DEFINE_EVENT(iptfs_ingress_preq_event, iptfs_no_queue_space,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u8 was_gso),
	     TP_ARGS(skb, xtfs, was_gso));

DECLARE_EVENT_CLASS(iptfs_ingress_postq_event,
		    TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 mtu, u16 blkoff),
		    TP_ARGS(skb, xtfs, mtu, blkoff),
		    TP_STRUCT__entry(
			__field(struct sk_buff *, skb)
			__field(u32, skb_len)
			__field(u32, data_len)
			__field(u32, mtu)
			__field(u32, proto_seq)
			__field(u16, blkoff)
			__field(u8, proto)),
		    TP_fast_assign(
			__entry->skb = skb;
			__entry->skb_len = skb->len;
			__entry->data_len = skb->data_len;
			__entry->mtu = mtu;
			__entry->blkoff = blkoff;
			__entry->proto = iptfs_payload_proto(skb);
			__entry->proto_seq = iptfs_payload_proto_seq(skb);
		    ),
	    TP_printk("INGRPSTQ: skb=%p len=%u data_len=%u mtu=%u blkoff=%u proto=%u proto_seq=%u",
		      __entry->skb, __entry->skb_len, __entry->data_len, __entry->mtu, __entry->blkoff,
		      __entry->proto, __entry->proto_seq));


DEFINE_EVENT(iptfs_ingress_postq_event, iptfs_first_dequeue,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 mtu, u16 blkoff),
	     TP_ARGS(skb, xtfs, mtu, blkoff));

DEFINE_EVENT(iptfs_ingress_postq_event, iptfs_first_fragmenting,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 mtu, u16 blkoff),
	     TP_ARGS(skb, xtfs, mtu, blkoff));

DEFINE_EVENT(iptfs_ingress_postq_event, iptfs_first_final_fragment,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 mtu, u16 blkoff),
	     TP_ARGS(skb, xtfs, mtu, blkoff));

DEFINE_EVENT(iptfs_ingress_postq_event, iptfs_first_toobig,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 mtu, u16 blkoff),
	     TP_ARGS(skb, xtfs, mtu, blkoff));

#endif /* _TRACE_IPTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_iptfs
#include <trace/define_trace.h>
