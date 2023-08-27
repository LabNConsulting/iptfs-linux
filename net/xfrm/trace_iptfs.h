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
		    TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 pmtu, u8 was_gso),
		    TP_ARGS(skb, xtfs, pmtu, was_gso),
		    TP_STRUCT__entry(
			__field(struct sk_buff *, skb)
			__field(u32, skb_len)
			__field(u32, data_len)
			__field(u32, pmtu)
			__field(u32, queue_size)
			__field(u32, proto_seq)
			__field(u8, proto)
		        __field(u8, was_gso)
			    ),
		    TP_fast_assign(
			    __entry->skb = skb;
			    __entry->skb_len = skb->len;
			    __entry->data_len = skb->data_len;
			    __entry->queue_size = xtfs->cfg.max_queue_size - xtfs->queue_size;
			    __entry->proto = iptfs_payload_proto(skb);
			    __entry->proto_seq = iptfs_payload_proto_seq(skb);
			    __entry->pmtu = pmtu;
			__entry->was_gso = was_gso;
			    ),
		    TP_printk("INGRPREQ: skb=%p len=%u data_len=%u qsize=%u proto=%u proto_seq=%u pmtu=%u was_gso=%u",
			      __entry->skb, __entry->skb_len, __entry->data_len, __entry->queue_size,
			      __entry->proto, __entry->proto_seq, __entry->pmtu, __entry->was_gso));

DEFINE_EVENT(iptfs_ingress_preq_event, iptfs_enqueue,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 pmtu, u8 was_gso),
	     TP_ARGS(skb, xtfs, pmtu, was_gso));

DEFINE_EVENT(iptfs_ingress_preq_event, iptfs_no_queue_space,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 pmtu, u8 was_gso),
	     TP_ARGS(skb, xtfs, pmtu, was_gso));

DEFINE_EVENT(iptfs_ingress_preq_event, iptfs_too_big,
	     TP_PROTO(struct sk_buff *skb, struct xfrm_iptfs_data *xtfs, u32 pmtu, u8 was_gso),
	     TP_ARGS(skb, xtfs, pmtu, was_gso));

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


DECLARE_EVENT_CLASS(iptfs_timer_event,
		    TP_PROTO(struct xfrm_iptfs_data *xtfs, u64 time_val),
		    TP_ARGS(xtfs, time_val),
		    TP_STRUCT__entry(
			__field(u64, time_val)
			__field(u64, set_time)),
		    TP_fast_assign(
			__entry->time_val = time_val;
			__entry->set_time = xtfs->iptfs_settime;
		    ),
		    TP_printk("TIMER: set_time=%llu time_val=%llu", __entry->set_time, __entry->time_val));

DEFINE_EVENT(iptfs_timer_event, iptfs_timer_start,
	     TP_PROTO(struct xfrm_iptfs_data *xtfs, u64 time_val),
	     TP_ARGS(xtfs, time_val));

DEFINE_EVENT(iptfs_timer_event, iptfs_timer_expire,
	     TP_PROTO(struct xfrm_iptfs_data *xtfs, u64 time_val),
	     TP_ARGS(xtfs, time_val));

#endif /* _TRACE_IPTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../net/xfrm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_iptfs
#include <trace/define_trace.h>
