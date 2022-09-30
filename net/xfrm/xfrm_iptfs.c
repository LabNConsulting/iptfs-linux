// SPDX-License-Identifier: GPL-2.0
/*
 * xfrm_iptfs: IPTFS encapsulation support
 *
 * April 21 2022, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2022, LabN Consulting, L.L.C.
 *
 */

#include <linux/kernel.h>
#include <net/icmp.h>
#include <net/inet_ecn.h>
#include <net/iptfs.h>
#include <net/xfrm.h>

#include "xfrm_inout.h"

#define XFRM_IPTFS_MIN_HEADROOM 128

#define NSECS_IN_USEC 1000

#define IPTFS_TYPE_NOCC 0
#define IPTFS_TYPE_CC 1

/* #define IPTFS_ENET_OHEAD (14 + 4 + 8 + 12) */
/* #define GE_PPS(ge, iptfs_ip_mtu) ((1e8 * 10 ^ (ge - 1) / 8) / (iptfs_ip_mtu)) */

#define PR_DEBUG_INFO
#ifdef PR_DEBUG_INFO
#define pr_devinf(...) pr_info(__VA_ARGS__)
#else
#define pr_devinf(...) pr_devel(__VA_ARGS__)
#endif

#define XFRM_INC_SA_STATS(xtfs, stat)

#define IPTFS_HRTIMER_MODE HRTIMER_MODE_REL_SOFT

struct xfrm_iptfs_config {
	bool dont_frag : 1;
	u16 reorder_win_size;
	u32 pkt_size;	    /* outer_packet_size or 0 */
	u32 max_queue_size; /* octets */
	u64 init_delay_us;  /* microseconds */
	u32 drop_time_us;   /* microseconds */
};

struct xfrm_iptfs_data {
	struct xfrm_iptfs_config cfg;
	/*
	 * Ingress User Input
	 */
	struct xfrm_state *x;	    /* owning state */
	struct sk_buff_head queue;  /* output queue */
	u32 queue_size;		    /* octets */
	u64 init_delay_ns;	    /* nanoseconds */
	struct hrtimer iptfs_timer; /* output timer */
	time64_t iptfs_settime;
	/*
	 * Tunnel input reordering.
	 */
	u64 win_nseq;	      /* expected next sequence */
	struct sk_buff **win; /* the reorder window */
	struct spinlock drop_lock;
	struct hrtimer drop_timer;
	u64 drop_time_ns;
	/*
	 * Tunnel input reassembly.
	 */
	struct sk_buff *ra_newskb; /* new pkt being reassembled */
	u64 ra_nseq;		   /* expected next sequence */
	u8 ra_runt[6];		   /* last pkt bytes from last skb */
	u8 ra_runtlen;		   /* count of ra_runt */
};

static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me);
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me);

/* ----------------- */
/* Utility Functions */
/* ----------------- */

static inline uint _proto(struct sk_buff *skb)
{
	return ((struct iphdr *)skb->data)->protocol;
}

static inline uint _seq(struct sk_buff *skb)
{
	uint protocol = _proto(skb);

	if (protocol == IPPROTO_ICMP)
		return ntohs(((struct icmphdr *)((struct iphdr *)skb->data + 1))
				     ->un.echo.sequence);
	else if (protocol == IPPROTO_TCP)
		return ntohl(
			((struct tcphdr *)((struct iphdr *)skb->data + 1))->seq);
	else
		return 0;
}

void xfrm_iptfs_get_rtt_and_delays(struct ip_iptfs_cc_hdr *cch, u32 *rtt,
				   u32 *actual_delay, u32 *xmit_delay)
{
	*rtt = (cch->rtt_and_adelay1[0] << 14) |
	       (cch->rtt_and_adelay1[1] << 6) |
	       (cch->rtt_and_adelay1[2] & 0xFC) >> 2;

	*actual_delay =
		((cch->rtt_and_adelay1[2] & 0x03) << (21 - 2)) |
		(cch->rtt_and_adelay1[3] << (21 - 2 - 8)) |
		(cch->adelay2_and_xdelay[0] << (21 - 2 - 8 - 8)) |
		((cch->adelay2_and_xdelay[1] & 0xE0) >> -(21 - 2 - 8 - 8 - 8));

	*xmit_delay = ((cch->adelay2_and_xdelay[1] & 0x1F) << (21 - 5)) |
		      (cch->adelay2_and_xdelay[2] << 8) |
		      cch->adelay2_and_xdelay[3];
}

/* -------------------------- */
/* State Management Functions */
/* -------------------------- */

int xfrm_iptfs_init_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs;

	xtfs = kzalloc_node(sizeof(*xtfs), GFP_KERNEL, NUMA_NO_NODE);
	x->tfs_data = xtfs;
	if (!xtfs)
		return -ENOMEM;

	xtfs->x = x;
	xtfs->cfg.reorder_win_size = XFRM_IPTFS_DEFAULT_REORDER_WINDOW;
	xtfs->cfg.max_queue_size = XFRM_IPTFS_DEFAULT_MAX_QUEUE_SIZE;
	xtfs->cfg.init_delay_us = XFRM_IPTFS_DEFAULT_INIT_DELAY_USECS;
	xtfs->cfg.drop_time_us = XFRM_IPTFS_DEFAULT_DROP_TIME_USECS;

	__skb_queue_head_init(&xtfs->queue);
	xtfs->init_delay_ns = xtfs->cfg.init_delay_us * NSECS_IN_USEC;
	hrtimer_init(&xtfs->iptfs_timer, CLOCK_MONOTONIC, IPTFS_HRTIMER_MODE);
	xtfs->iptfs_timer.function = iptfs_delay_timer;

	xtfs->drop_time_ns = xtfs->cfg.drop_time_us * NSECS_IN_USEC;
	spin_lock_init(&xtfs->drop_lock);
	hrtimer_init(&xtfs->drop_timer, CLOCK_MONOTONIC, IPTFS_HRTIMER_MODE);
	xtfs->drop_timer.function = iptfs_drop_timer;

	return 0;
}

void xfrm_iptfs_state_destroy(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	if (IS_ERR_OR_NULL(xtfs))
		return;
	hrtimer_cancel(&xtfs->iptfs_timer);
	kfree_sensitive(xtfs);
}

int xfrm_iptfs_user_init(struct net *net, struct xfrm_state *x,
			 struct nlattr **attrs)
{
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	struct xfrm_iptfs_config *xc;

	if (x->props.mode != XFRM_MODE_IPTFS)
		return EINVAL;

	xc = &xtfs->cfg;
	xc->reorder_win_size = net->xfrm.sysctl_iptfs_rewin;
	xc->max_queue_size = net->xfrm.sysctl_iptfs_maxqsize;
	xc->init_delay_us = net->xfrm.sysctl_iptfs_idelay;
	xc->drop_time_us = net->xfrm.sysctl_iptfs_drptime;

	if (attrs[XFRMA_IPTFS_DONT_FRAG])
		xc->dont_frag = true;
	if (attrs[XFRMA_IPTFS_REORD_WIN])
		xc->reorder_win_size =
			nla_get_u16(attrs[XFRMA_IPTFS_REORD_WIN]);
	if (attrs[XFRMA_IPTFS_PKT_SIZE])
		xc->pkt_size = nla_get_u32(attrs[XFRMA_IPTFS_PKT_SIZE]);
	if (attrs[XFRMA_IPTFS_MAX_QSIZE])
		xc->max_queue_size = nla_get_u32(attrs[XFRMA_IPTFS_MAX_QSIZE]);
	if (attrs[XFRMA_IPTFS_DROP_TIME]) {
		xc->drop_time_us = nla_get_u32(attrs[XFRMA_IPTFS_DROP_TIME]);
		xtfs->drop_time_ns = xc->drop_time_us * NSECS_IN_USEC;
	}
	if (attrs[XFRMA_IPTFS_IN_DELAY]) {
		xc->init_delay_us = nla_get_u32(attrs[XFRMA_IPTFS_IN_DELAY]);
		xtfs->init_delay_ns = xc->init_delay_us * NSECS_IN_USEC;
	}
	return 0;
}

int xfrm_iptfs_copy_to_user_state(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_iptfs_config *xc = &x->tfs_data->cfg;
	int ret;

	if (xc->dont_frag) {
		if ((ret = nla_put_flag(skb, XFRMA_IPTFS_DONT_FRAG)))
			return ret;
	}
	ret = nla_put_u16(skb, XFRMA_IPTFS_REORD_WIN, xc->reorder_win_size);
	if (ret)
		return ret;
	if ((ret = nla_put_u32(skb, XFRMA_IPTFS_PKT_SIZE, xc->pkt_size)))
		return ret;
	if ((ret = nla_put_u32(skb, XFRMA_IPTFS_MAX_QSIZE, xc->max_queue_size)))
		return ret;
	if ((ret = nla_put_u32(skb, XFRMA_IPTFS_DROP_TIME, xc->drop_time_us)))
		return ret;
	ret = nla_put_u32(skb, XFRMA_IPTFS_IN_DELAY, xc->init_delay_us);
	return ret;
}

/* ---------------------------------- */
/* IPTFS Receiving (egress) Functions */
/* ---------------------------------- */

struct sk_buff *skb_at_offset(struct sk_buff *skb, uint offset, uint len)
{
	if (offset >= skb->len)
		return NULL;

	if (offset + len > skb->len)
		return NULL;

	if (!skb_is_nonlinear(skb))
		return skb;

	skb_walk_frags (skb, skb) {
		if (offset < skb->len)
			break;
		offset -= skb->len;
	}

	if (!skb)
		WARN_ONCE(1, "sk_buff should have been found");
	else if (skb_shinfo(skb)->frag_list) {
		WARN_ONCE(1, "nested sk_buff frag list");
		skb = NULL;
	}

	return skb;
}

struct sk_buff *skb_clone_data_range(struct sk_buff *skb, uint offset, uint len)
{
	// struct sk_buff *first = skb;

	skb = skb_at_offset(skb, offset, len);
	if (!skb)
		return NULL;
	/* XXX chopps: unfinished */
	return skb;
}

int skb_copy_bits_seq(struct skb_seq_state *st, int offset, void *to, int len)
{
	const u8 *data;
	uint sqlen;

	for (;;) {
		/*
		 * what happens if we advance but then are called again with
		 * original offset? This does NOT work.
		 */
		sqlen = skb_seq_read(offset, &data, st);
		if (sqlen == 0)
			return -ENOMEM;
		if (sqlen >= len) {
			memcpy(to, data, len);
			return 0;
		}
		memcpy(to, data, sqlen);
		to += sqlen;
		offset += sqlen;
		len -= sqlen;
	}
}
EXPORT_SYMBOL(skb_copy_bits_seq);

static struct sk_buff *iptfs_alloc_skb(struct sk_buff *tpl, uint len)
{
	struct sk_buff *skb;
	uint resv = skb_headroom(tpl);

	if (resv < XFRM_IPTFS_MIN_HEADROOM)
		resv = XFRM_IPTFS_MIN_HEADROOM;

	pr_devinf("%s: len %u resv %u\n", __func__, len, resv);
	skb = alloc_skb(len + resv, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, resv);
	skb->csum = 0;
	skb_copy_header(skb, tpl);
	// the skb_copy_header does the following so figure out wth it is :)
	// skb_shinfo(new)->gso_size = skb_shinfo(old)->gso_size;
	// skb_shinfo(new)->gso_segs = skb_shinfo(old)->gso_segs;
	// skb_shinfo(new)->gso_type = skb_shinfo(old)->gso_type;
	if (!skb_sec_path(skb)) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINERROR);
		kfree_skb(skb);
		return NULL;
	}
	return skb;
}

/**
 * iptfs_pskb_extract_seq() - Create and load data into a new sk_buff, `skb`.
 * @skblen: the total data size for `skb`.
 * @resv: the amount of space to reserve for headers.
 * @st: The source for the rest of the data to copy into `skb`.
 * @off: The offset into @st to copy data from.
 * @len: The length of data to copy from @st into `skb`. This must be <=
 *       @skblen.
 *
 * Create a new sk_buff `skb` with @totlen of packet data space plus @resv
 * reserved headroom. If non-zero, copy @rlen bytes of @runt into `skb`. Then
 * using seq functions copy @len bytes from @st into `skb` starting from @off.
 *
 * It is an error for @len to be greater than the amount of data left in @st.
 *
 * Return: The newly allocated sk_buff `skb` or NULL if an error occurs.
 */
static struct sk_buff *iptfs_pskb_extract_seq(uint skblen, uint resv,
					      struct skb_seq_state *st,
					      uint off, int len)
{
	struct sk_buff *skb = iptfs_alloc_skb(st->root_skb, skblen);
	// XXX chopps: what is this _exactly_?
	// skb->ip_summed = 0;
	if (skb_copy_bits_seq(st, off, skb_put(skb, len), len)) {
		kfree_skb(skb);
		return NULL;
	}
	return skb;
}

/* XXX maybe rename iptfs_input_save_spot or something else */
static inline void iptfs_input_save_runt(struct xfrm_iptfs_data *xtfs, u64 seq,
					 u8 *buf, int len)
{
	BUG_ON(xtfs->ra_newskb); /* we won't have a new SKB yet */

	pr_devinf("%s: saving runt len %u, exp seq %llu\n", __func__, len, seq);
	memcpy(xtfs->ra_runt, buf, len);

	xtfs->ra_runtlen = len;
	xtfs->ra_nseq = seq + 1;
}

static uint __iptfs_iplen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	if (iph->version == 0x4)
		return ntohs(iph->tot_len);
	BUG_ON(iph->version != 0x6);
	return ntohs(((struct ipv6hdr *)iph)->payload_len);
}

static uint __iptfs_iphdrlen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	if (iph->version == 0x4)
		return iph->ihl << 2;
	else if (iph->version == 0x6)
		/* XXX check other kernel cases for transport offset */
		return sizeof(struct ipv6hdr);
	return 0;
}

static int iptfs_complete_inner_skb(struct xfrm_state *x, struct sk_buff *skb,
				    uint iphlen)
{
	struct sec_path *sp;
	struct iphdr *iph;
	int err, family;

	if ((family = x->sel.family) == AF_UNSPEC)
		family = x->outer_mode.family;

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, iphlen);

	/*
	 * XXX Need to figure out how to get no head buffer data.
	 * as this doesn't work if the ip header is in a fragment,
	 * that won't happen with our allocated, but what about re-use of
	 * initial input? Do we need to only do reuse if the header is available
	 * in the headroom of the initial skb?
	 */
	iph = ip_hdr(skb);

	pr_devinf("%s: completing inner, iplen %u skb len %u iphlen %u\n",
		  __func__, ntohs(iph->tot_len), skb->len, iphlen);

	if (iph->version == 0x4) {
		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv4_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos,
				       ipip_hdr(skb));
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP_ECN_set_ce(iph);
	} else {
		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv6_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos,
				       ipv6_hdr(skb));
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP6_ECN_set_ce(skb, ipv6_hdr(skb));
	}

	/* XXX family here should be from outer or from inner packet */
	/* XXX this is keeping interface stats and looking up dst
		 * xfrmi interface if that's being used
		 */
	err = xfrm_rcv_cb(skb, family, x->type->proto, 0);
	if (err) {
		xfrm_rcv_cb(skb, family,
			    (x && x->type) ? x->type->proto : XFRM_PROTO_IPTFS,
			    -1);
		return err;
	}

	nf_reset_ct(skb);
	sp = skb_sec_path(skb);
	if (sp)
		sp->olen = 0;
	skb_dst_drop(skb); /* XXX ok to do this on first_skb before done? */

	return 0;
}

static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me)
{
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;

	xtfs = container_of(me, typeof(*xtfs), drop_timer);
	x = xtfs->x;

	XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_DROP_TIMER_FIRES);

	spin_lock(&xtfs->drop_lock);

	if (!xtfs->ra_newskb) {
		pr_devinf("%s: drop timer -- but no reassembly\n", __func__);
	} else {
		pr_devinf("%s: drop timer -- dropping reassemble\n", __func__);
		kfree_skb(xtfs->ra_newskb);
		xtfs->ra_newskb = NULL;
	}

	spin_unlock(&xtfs->drop_lock);

	return HRTIMER_NORESTART;
}

static inline void _iptfs_reassem_done(struct xfrm_iptfs_data *xtfs, bool free)
{
	int ret;
	assert_spin_locked(&xtfs->drop_lock);

	/* We don't care if it works locking takes care of things */
	ret = hrtimer_try_to_cancel(&xtfs->drop_timer);
	pr_devinf("%s: canceled drop timer ret: %d\n", __func__, ret);
	if (free)
		kfree_skb(xtfs->ra_newskb);
	xtfs->ra_newskb = NULL;
}

static inline void iptfs_reassem_abort(struct xfrm_iptfs_data *xtfs)
{
	_iptfs_reassem_done(xtfs, true);
}

static inline void iptfs_reassem_done(struct xfrm_iptfs_data *xtfs)
{
	_iptfs_reassem_done(xtfs, false);
}

static uint iptfs_reassem_cont(struct xfrm_iptfs_data *xtfs, u64 seq,
			       struct skb_seq_state *st, struct sk_buff *skb,
			       uint data, uint blkoff, struct list_head *list)
{
	struct sk_buff *newskb = xtfs->ra_newskb;
	uint remaining = skb->len - data;
	uint copylen, fraglen, ipremain;
	uint rlen, rrem;

	/*
	 * blkoff could be zero if the stream is messed up (or it's an all pad
	 * insertion) be careful to handle that case in each of the below
	 */

	if (xtfs->ra_nseq < seq) {
		/*
		 * We are reassembling but this is an old sequence number.
		 */
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_OLD_SEQ);
		pr_devinf("%s: older seq %llu expecting %llu\n", __func__, seq,
			  xtfs->ra_nseq);
		/* will end parsing */
		return data + remaining;
	}

	/*
	 * Handle all pad case, advance expected sequence number.
	 * RFC XXXX S2.2.3
	 */
	if (xtfs->ra_nseq == seq && blkoff == 0 && (*skb->data & 0xF0) == 0) {
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_ALL_PAD_SKIP);
		pr_devinf("%s: skipping all pad seq %llu \n", __func__, seq);
		xtfs->ra_nseq++;
		/* will end parsing */
		return data + remaining;
	}

	rlen = xtfs->ra_runtlen;
	xtfs->ra_runtlen = 0;
	if (rlen && xtfs->ra_nseq == seq) {
		/* We have run data and expected next sequence we should never
		 * have allocated a skb yet.
		 */
		BUG_ON(xtfs->ra_newskb);
		pr_devinf("%s: have runt data len %u\n", __func__, rlen);
		/*
		 * The start of this inner packet was at the very end of the last
		 * iptfs payload which didn't include enough for the ip header
		 * length field. We must have *at least* that now.
		 */
		rrem = sizeof(xtfs->ra_runt) - rlen;
		if (remaining < rrem || blkoff < rrem) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINBUFFERERROR);
			pr_err_ratelimited(
				"%s: bad recv after runt: blkoff/remain %u/%u < runtrem %u\n",
				__func__, blkoff, remaining, rrem);
			/* will continue on to new data block or end */
			return data + min(blkoff, remaining);
		}
		/* fill in the runt data */
		if (skb_copy_bits_seq(st, data, &xtfs->ra_runt[rlen], rrem)) {
			/* this would be a ridiculous situation, end parsing */
			return data + remaining;
		}
		/* we have enough data to get the ip length value now */
		ipremain = __iptfs_iplen(xtfs->ra_runt);
		newskb = iptfs_alloc_skb(skb, ipremain);
		if (!newskb) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINERROR);
			pr_err_ratelimited("%s: can't get new skb", __func__);
			return data + min(blkoff, remaining);
		}
		xtfs->ra_newskb = newskb;
		/*
		 * Copy the runt data into the buffer, but leave data
		 * pointers the same as normal non-runt entry. The extra `rrem`
		 * recopied bytes are basically cacheline free. Using a single
		 * data pointer logic below avoids a lot of complexity.
		 */
		memcpy(skb_put(newskb, rlen), xtfs->ra_runt,
		       sizeof(xtfs->ra_runt));
	}

	if (!newskb || xtfs->ra_nseq > seq) {
		/*
		* We are not reassembling or this is not the sequence
		* number we are expecting. Skip the partial inner
		* packet fragment at the start of this outer packet.
		*/
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_MISSED_FRAG_START);
		if (!newskb) {
			pr_devinf(
				"%s: block offset: %u (or runt %u) but not reassembling\n",
				__func__, blkoff, rlen);
		} else {
			pr_devinf(
				"%s: missed frag seq, want: %llu got: %llu, skipping over frag %u\n",
				__func__, xtfs->ra_nseq, seq, blkoff);
			/* drop unfinished packet reassembly */
			iptfs_reassem_abort(xtfs);
		}
		if (blkoff >= remaining) {
			pr_devinf("%s: skipping entire fragment payload\n",
				  __func__);
			/* will end parsing */
			return data + remaining;
		}

		/* will continue on to new data block */
		pr_devinf("%s: skipping to next fragment blkoff/remain %u/%u\n",
			  __func__, blkoff, remaining);
		return data + blkoff;
	}

	/* Continue to reassemble the packet */
	ipremain = __iptfs_iplen(newskb->data);
	BUG_ON(newskb->len > ipremain);
	ipremain -= newskb->len;
	if (blkoff < ipremain) {
		/* Corrupt data, we don't have enough to complete the packet */
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_IPLEN_BAD_BLOCKOFF);
		pr_err_ratelimited(
			"%s: bad recv blkoff: blkoff %u < ip remaining %u\n",
			__func__, blkoff, ipremain);
		iptfs_reassem_abort(xtfs);
		/* will end parsing */
		return data + remaining;
	}

	fraglen = min(blkoff, remaining);
	copylen = min(fraglen, ipremain);
	BUG_ON(skb_tailroom(newskb) < copylen);

	pr_devinf(
		"%s: continue to reassem, ipremain %u blkoff %u remain %u fraglen %u copylen %u\n",
		__func__, ipremain, blkoff, remaining, fraglen, copylen);

	/* copy fragment data into newskb */
	if (skb_copy_bits_seq(st, data, skb_put(newskb, copylen), copylen)) {
		pr_err_ratelimited("%s: bad skb\n", __func__);
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINBUFFERERROR);
		iptfs_reassem_abort(xtfs);
		/* will end parsing */
		return data + remaining;
	}

	if (copylen < ipremain) {
		xtfs->ra_nseq++;
		pr_devinf("%s: packet unfinished, inc exp seq to %llu\n",
			  __func__, xtfs->ra_nseq);
	} else {
		/* We are done with packet reassembly! */
		BUG_ON(copylen != ipremain);
		iptfs_reassem_done(xtfs);
		pr_devinf("%s: packet finished, %u left in payload\n", __func__,
			  remaining - copylen);
		if (iptfs_complete_inner_skb(xtfs->x, newskb,
					     __iptfs_iphdrlen(newskb->data))) {
			kfree_skb(newskb);
		} else {
			list_add_tail(&newskb->list, list);
		}
	}

	/* will continue on to new data block or end */
	return data + fraglen;
}

/*
 * We have an IPTFS payload dispense with it and this skb as well.
 */
static int iptfs_input_ordered(struct gro_cells *gro_cells,
			       struct xfrm_state *x, u64 seq,
			       struct sk_buff *skb)
{
	u8 hbytes[sizeof(struct ipv6hdr)];
	struct ip_iptfs_cc_hdr iptcch;
	struct skb_seq_state skbseq;
	struct list_head sublist; /* rename this it's just a list */
	struct sk_buff *first_skb, *defer, *next;
	const unsigned char *old_mac;
	struct xfrm_iptfs_data *xtfs;
	struct ip_iptfs_hdr *ipth;
	struct iphdr *iph;
	struct net *net;
	uint remaining, first_iplen, iplen, iphlen, resv, data, tail;
	uint blkoff, capturelen;
	u8 *tmp;

	xtfs = x->tfs_data;
	net = dev_net(skb->dev);
	first_skb = NULL;
	defer = NULL;

	pr_devinf("%s: processing skb with len %u seq %llu\n", __func__,
		  skb->len, seq);

	/* large enough to hold both types of header */
	ipth = (struct ip_iptfs_hdr *)&iptcch;

	/* when we support DSCP copy option ... */
	// static inline __u8 ipv4_get_dsfield(const struct iphdr *iph)
	// static inline __u8 ipv6_get_dsfield(const struct ipv6hdr *ipv6h)

	// err = skb_unclone(skb, GFP_ATOMIC);

	/* Save the old mac header if set */
	old_mac = skb_mac_header_was_set(skb) ? skb_mac_header(skb) : NULL;

	skb_prepare_seq_read(skb, 0, skb->len, &skbseq);

	/*
	 * Get the IPTFS header and validate it
	 */

	if (skb_copy_bits_seq(&skbseq, 0, ipth, sizeof(*ipth))) {
	badskb:
		pr_err_ratelimited("%s: bad skb\n", __func__);
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
		goto done;
	}
	data = sizeof(*ipth);

	/* set data past the basic header */
	if (ipth->subtype == IPTFS_SUBTYPE_CC) {
		/* copy the rest of the CC header */
		remaining = sizeof(iptcch) - sizeof(*ipth);
		if (skb_copy_bits_seq(&skbseq, data, ipth + 1, remaining))
			goto badskb;
		data += remaining;
	} else if (ipth->subtype != IPTFS_SUBTYPE_BASIC) {
	badhdr:
		pr_err_ratelimited("%s: bad iptfs hdr\n", __func__);
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto done;
	}

	if (ipth->flags != 0)
		goto badhdr;

	INIT_LIST_HEAD(&sublist);

	/*
	 * Handle fragment at start of payload / reassembly.
	 */

	blkoff = ntohs(ipth->block_offset);
	/* check before locking i.e., maybe */
	if (blkoff || xtfs->ra_runtlen || xtfs->ra_newskb) {
		spin_lock(&xtfs->drop_lock);

		/* check again after lock */
		if (blkoff || xtfs->ra_runtlen || xtfs->ra_newskb) {
			data = iptfs_reassem_cont(xtfs, seq, &skbseq, skb, data,
						  blkoff, &sublist);
		}

		spin_unlock(&xtfs->drop_lock);
	}

	/*
	 * New packets.
	 */

	tail = skb->len;
	BUG_ON(xtfs->ra_newskb && data < tail);

	while (data < tail) {
		remaining = tail - data;

		/*
		 * `data` points at the start of the next data block.
		 */

		/* try and copy enough bytes to read length from ipv4/ipv6 */
		iphlen = min(remaining, (uint)6);
		if (skb_copy_bits_seq(&skbseq, data, hbytes, iphlen))
			goto badskb;

		iph = (struct iphdr *)hbytes;
		if (iph->version == 0x4) {
			/* must have at least tot_len field present */
			if (remaining < 4) {
				/* save the bytes we have, advance data and exit */
				iptfs_input_save_runt(xtfs, seq, hbytes,
						      remaining);
				data += remaining;
				break;
			}

			iplen = htons(iph->tot_len);
			iphlen = iph->ihl << 2;
			pr_devinf("%s: ipv4 inner length %u\n", __func__,
				  iplen);
		} else if (iph->version == 0x6) {
			/* must have at least payload_len field present */
			if (remaining < 6) {
				/* save the bytes we have, advance data and exit */
				iptfs_input_save_runt(xtfs, seq, hbytes,
						      remaining);
				data += remaining;
				break;
			}

			iplen = htons(((struct ipv6hdr *)hbytes)->payload_len);
			/* XXX chopps: what about extra headers? ipv6_input
                         * seems to just do this */
			iphlen = sizeof(struct ipv6hdr);
			pr_devinf("%s: ipv6 inner length %u\n", __func__,
				  iplen);
		} else if (iph->version == 0x0) {
			/* pad */
			pr_devinf("%s: padding length %u\n", __func__,
				  remaining);
			data = tail;
			break;
		} else {
			pr_warn("%s: unknown inner datablock type %u\n",
				__func__, iph->version);
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}

		/* /\* XXX chopps: fragmentation support *\/ */
		/* if (iplen > remaining || iphlen > remaining) { */
		/* 	XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR); */
		/* 	goto done; */
		/* } */

		if (unlikely(skbseq.stepped_offset)) {
			/*
			 * We need to reset our sequential run. Reading the
			 * initial ipv* header bytes has moved it to a new
			 * fragment, and the seq read function doesn't support
			 * backing up by fragments (you can backup the offset
			 * otherwise), and we need to start reading from the
			 * beginning of the ipv* header. It would be very easy
			 * for skb_seq_read to just deal with this...
			 */
			skb_abort_seq_read(&skbseq);
			skb_prepare_seq_read(skb, data, tail, &skbseq);
		}

		if (first_skb)
			skb = NULL;
		else {
			first_skb = skb;
			first_iplen = iplen;
			resv = skb_headroom(skb);
			if (resv < XFRM_IPTFS_MIN_HEADROOM)
				resv = XFRM_IPTFS_MIN_HEADROOM;

			if (skb_is_nonlinear(skb)) {
				/* if first skb has frags copy packet data into new skb */
				defer = skb;
				skb = NULL;
			} else if (skb_end_offset(skb) - data >= iplen) {
				/*
				 * Reuse fist skb. Need to move past the initial
				 * iptfs header as well as any initial fragment
				 * for previous inner packet reassembly
				 */
				tmp = skb->data;
				pskb_pull(skb, data);
				/* XXX do these rcsums work with pskb variants? */
				skb_postpull_rcsum(skb, tmp, data);

				/* our range just changed */
				data = 0;
				tail = skb->len;
				remaining = skb->len;

				skb_mac_header_rebuild(skb);

				/* We could have more iplen than remaining, if
				 * the skb we received has extra tailroom that
				 * wasn't used by the receiver, e.g., say the
				 * skb has 4k total space, but a 1500 octet
				 * inner IP packet starts 1000 into the payload
				 * (because it is preceeded by a 1000 octet end
				 * fragment) and the outer packet is 1500
				 * octets, so the payload will be ~500 bytes
				 * (remaining) of total iplen which of 1500. The
				 * last 1000 octets will come in the next skb,
				 * but we can copy that into the tail of this
				 * skb b/c we have tailroom.
				 */
				// This is done below for everyone
				// capturelen = min(iplen, remaining);

				/* all pointers could be changed now reset walk */
				skb_abort_seq_read(&skbseq);
				skb_prepare_seq_read(skb, data, tail, &skbseq);

				pr_devinf("%s: reusing outer skb %p\n",
					  __func__, skb);
			} else {
				/* first skb didn't have enough space */
				defer = skb;
				skb = NULL;
			}
			/* don't trim now since we want are walking the data */
		}

		capturelen = min(iplen, remaining);
		if (!skb) {
			capturelen = min(iplen, remaining);
			skb = iptfs_pskb_extract_seq(iplen, resv, &skbseq, data,
						     capturelen);
			if (!skb) {
				pr_err("%s: failed to alloc new skb\n",
				       __func__);
				XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
				continue;
			}
			pr_devinf("%s: alloc'd new skb %p\n", __func__, skb);

			if (old_mac) {
				/* rebuild the mac header */
				skb_set_mac_header(skb, -first_skb->mac_len);
				memcpy(skb_mac_header(skb), old_mac,
				       first_skb->mac_len);
			}
		}

		pr_devinf("%s: new skb %p ip proto %u icmp/tcp seq %u\n",
			  __func__, skb, _proto(skb), _seq(skb));

		data += capturelen;

		if (skb->len < iplen) {
			BUG_ON(data != tail);
			BUG_ON(xtfs->ra_newskb);

			/*
			 * Start reassembly
			 */
			pr_devinf("%s: payload done, save packet (%u of %u)\n",
				  __func__, skb->len, iplen);

			spin_lock(&xtfs->drop_lock);

			xtfs->ra_newskb = skb;
			xtfs->ra_nseq = seq + 1;
			if (!hrtimer_is_queued(&xtfs->drop_timer)) {
				pr_devinf("%s: starting drop timer\n",
					  __func__);
				/* softirq blocked lest the timer fire and interrupt us */
				BUG_ON(!in_interrupt());
				hrtimer_start(&xtfs->drop_timer,
					      xtfs->drop_time_ns,
					      IPTFS_HRTIMER_MODE);
			}

			spin_unlock(&xtfs->drop_lock);

			break;
		}

		if (iptfs_complete_inner_skb(x, skb, iphlen)) {
			if (skb != first_skb)
				kfree_skb(skb);
			else
				/* XXX or do we drop the rest? */
				defer = skb;
			continue;
		}

		list_add_tail(&skb->list, &sublist);
	}

	if (data != tail) {
		/* error or pdding */
		pr_devinf("%s: error data(%u) != tail(%u)\n", __func__, data,
			  tail);
	}

	if (first_skb && first_iplen && !defer) {
		if (pskb_trim_rcsum(first_skb, first_iplen)) {
			/* error trimming */
			list_del(&first_skb->list);
			defer = first_skb;
		}
	}

	/* Send the packets! */
	list_for_each_entry_safe (skb, next, &sublist, list) {
		skb_list_del_init(skb);
		pr_devinf(
			"%s: sending inner packet len %u skb %p proto %u seq %u\n",
			__func__, (uint)skb->len, skb, _proto(skb), _seq(skb));
		gro_cells_receive(gro_cells, skb);
	}

	/* safe to call even if we were done */
done:
	skb_abort_seq_read(&skbseq);

	if (defer)
		kfree_skb(defer);

	return 0;
}

/*
 * We have an IPTFS payload order it if needed.
 */
int xfrm_iptfs_input(struct gro_cells *gro_cells, struct xfrm_state *x,
		     struct sk_buff *skb)
{
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	u64 seq;

	seq = ntohl(XFRM_SKB_CB(skb)->seq.input.low);
	seq |= (u64)ntohl(XFRM_SKB_CB(skb)->seq.input.hi) << 32;

	/*
	 * XXX We need a lock here somewhere to guarantee ordering
	 */

	if (xtfs->cfg.reorder_win_size == 0)
		return iptfs_input_ordered(gro_cells, x, seq, skb);

	/*
	 * XXX fetch the next N input packets from the reordering window
	 */

	return iptfs_input_ordered(gro_cells, x, seq, skb);
}

/* --------------------------------- */
/* IPTFS Sending (ingress) Functions */
/* --------------------------------- */

/*
 * Check to see if it's OK to queue a packet for sending on tunnel.
 */
static bool iptfs_enqueue(struct xfrm_iptfs_data *xtfs, struct sk_buff *skb)
{
	assert_spin_locked(&xtfs->x->lock);

	/* For now we use a predefined constant value, eventually configuration */
	if (xtfs->queue_size + skb->len > xtfs->cfg.max_queue_size) {
		pr_warn_ratelimited(
			"%s: no space: qsize: %u skb len %u max %u\n", __func__,
			xtfs->queue_size, (uint)skb->len,
			xtfs->cfg.max_queue_size);
		return false;
	}
	__skb_queue_tail(&xtfs->queue, skb);
	xtfs->queue_size += skb->len;
	return true;
}

/*
 * IPv4/IPv6 packet ingress to IPTFS tunnel, arrange to send in IPTFS payload
 * (i.e., aggregating or fragmenting as appropriate).
 */
int xfrm_iptfs_output_collect(struct net *net, struct sock *sk,
			      struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	struct sk_buff *segs, *nskb;
	uint count, qcount;
	bool ok = true;

	/*
	 * We have hooked into dst_entry->output which means we have skipped the
	 * protocol specific netfilter (see xfrm4_output, xfrm6_output).
	 * when our timer runs we will end up calling xfrm_output directly on
	 * the encapsulated traffic.
	 *
	 * For both cases this is the NF_INET_POST_ROUTING hook which allows
	 * changing the skb->dst entry which then may not be xfrm based anymore
	 * in which case a REROUTED flag is set. and dst_output is called.
	 *
	 * For IPv6 we are also skipping fragmentation handling for local
	 * sockets, which may or may not be good depending on our tunnel DF
	 * setting. Normally with fragmentation supported we want to skip this
	 * fragmentation.
	 */

	BUG_ON(xtfs == NULL);

	/* not sure what the sock is used for here */
	/* This will be set if we do a local ping! */
	// WARN_ON(sk != NULL);

	/*
	 * Break apart GSO skbs. If the queue is nearing full then we want the
	 * accounting and queuing to be based on the individual packets not on the
	 * aggregate GSO buffer.
	 */
	if (!skb_is_gso(skb)) {
		segs = skb;
		BUG_ON(skb->next);
	} else {
		netdev_features_t features = netif_skb_features(skb);

		pr_info_once("%s: received GSO skb (only printing once)\n",
			     __func__);
		pr_devinf("%s: splitting up gso skb %p", __func__, skb);

		segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
		if (IS_ERR_OR_NULL(segs)) {
			/* XXX better stat here. */
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
			kfree_skb(skb);
			return PTR_ERR(segs);
		}
		consume_skb(skb);
	}

	count = qcount = 0;

	/* We can be running on multiple cores or from user context */
	spin_lock_bh(&x->lock);

	skb_list_walk_safe (segs, segs, nskb) {
		skb = segs;
		skb_mark_not_on_list(segs);
		count++;

		if (!ok) {
			pr_devinf(
				"%s: no space drop rest: skb: %p len %u data_len %u proto %u seq %u\n",
				__func__, skb, (uint)skb->len, skb->data_len,
				_proto(skb), _seq(skb));
			kfree_skb(skb);
			continue;
		}

		if (!(ok = iptfs_enqueue(xtfs, skb))) {
			kfree_skb(skb);
			continue;
		}
		qcount++;

		// if (skb->protocol == htons(ETH_P_IPV6))
		// mtu = ip6_skb_dst_mtu(skb);
		pr_devinf(
			"%s: skb: %p len %u data_len %u proto %u seq %u dst_mtu() => %d\n",
			__func__, skb, (uint)skb->len, skb->data_len,
			_proto(skb), _seq(skb), (int)dst_mtu(dst));
	}

	if (count)
		pr_devinf("%s: unpacked %u and queued %u from GSO skb\n",
			  __func__, count, qcount);

	if (!ok) {
		/* Sanity check, if queue was full time should be set */
		BUG_ON(xtfs->queue_size &&
		       !hrtimer_is_queued(&xtfs->iptfs_timer));
	}

	/* Start a delay timer if we don't have one yet */
	if (!hrtimer_is_queued(&xtfs->iptfs_timer)) {
		pr_devinf("%s: starting hrtimer\n", __func__);
		/* softirq blocked lest the timer fire and interrupt us */
		BUG_ON(!in_interrupt());
		hrtimer_start(&xtfs->iptfs_timer, xtfs->init_delay_ns,
			      IPTFS_HRTIMER_MODE);
	}

	xtfs->iptfs_settime = ktime_get_raw_fast_ns();
	spin_unlock_bh(&x->lock);
	return 0;
}

static int iptfs_first_skb(struct sk_buff *skb)
{
	struct ip_iptfs_hdr *h;
	size_t hsz = sizeof(*h);
	int mtu = dst_mtu(skb_dst(skb));

	/* (x->outer_mode.encap == IPTFS */
	// if (x->outer_mode.family == AF_INET)
	// else if (x->outer_mode.family == AF_INET6)
	// return -EOPNOTSUPP;

	/* XXX do we want to collect the aggregate IP info from all inners? */
	// xfrm4_extract_header(skb);

	// assert(!xfrm4_tunnel_check_size(skb));
	// get the MTU and check it
	/* we don't have an IP hdr yet */
	/* if iptfs is set to not fragment (always for now */
	// if ((ip_hdr(skb)->frag_off & htons(IP_DF)) || skb->ignore_df)

	/* our first skb -- push the iptfs header */
	h = skb_push(skb, hsz);
	memset(h, 0, hsz);

	/* actually if IPTFS DF is set */
	if (1) {
		/* We've split these up before queuing */
		BUG_ON(skb_is_gso(skb));
		if (skb->len > mtu) {
			/* pop the iptfs header back off */
			skb_pull(skb, hsz);
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu - hsz));
			return -EMSGSIZE;
		}
	}

	/*
	 * network_header current points at the inner IP packet
	 * move it to the iptfs header
	 */
	skb->transport_header = skb->network_header;
	skb->network_header -= hsz;

	IPCB(skb)->flags |= IPSKB_XFRM_TUNNEL_SIZE;
	skb->protocol = htons(ETH_P_IP);

	return 0;
}

static void iptfs_output_queued(struct xfrm_state *x, struct sk_buff_head *list)
{
	/*
	 * When we do timed output things (locking) will be more complex in the
	 * presence of fragmentation. But maybe more efficient since there
	 * shouldn't be any contention due to the pacing timer being regularly
	 * spaced.
	 */

	/*
	 * For now we are just outputting packets as fast as we can, so if we
	 * are fragmenting we will do so until the last inner packet is complete,
	 * Then we just send the last packet padded -- or perhaps check if this
	 * callback's timer has been reset and is sufficiently soon we can
	 * save this final packet to be used by the next timer fire.
	 *
	 * We do not need to lock the put-back packet as we only manipulate this
	 * field in this function.
	 *
	 * The case is exactly the same when not fragmenting, we either send the
	 * last outer packet padded or delay for a soon to fire reset timer.
	 */

	/*
	 * When we do timed packets *and* fragmentation we need to output all packets that contain
	 * the fragments of a single inner packet, consecutively. So we have to
	 * have a lock to keep another CPU from grabbing the next batch of
	 * packets (it's `list`) and trying to output those, while we try to
	 * output our `list`. IOW there can only be one cpu outputting packets
	 * for a given SA at a given time. Thus we need to lock the IPTFS output
	 * on a per SA basis while we process this list.
	 */

	/*
	 * NOTE: for the future, for timed packet sends, if our queue is not
	 * growing longer (i.e., we are keeping up) and a packet we are about to
	 * fragment will not fragment in then next outer packet, we might consider
	 * holding on to it to send whole in the next slot. The question then is
	 * does this introduce a continuous delay in the inner packet stream
	 * with certain packet rates and sizes?
	 */

	/*
	 * Our code path skips xfrm[46]_extract_output b/c we may have multiple
	 * internal packets; however! we can do whatever collection of
	 * flags/mapping values we want here. (see: xfrm[46]_extract_header)
	 *
	 * what gets saved:
	 *
	 * XFRM_MODE_SKB_CB(skb)->protocol = ip_hdr(skb)->protocol;
	 * const struct iphdr *iph = ip_hdr(skb);
	 * XFRM_MODE_SKB_CB(skb)->ihl = sizeof(*iph);
	 * XFRM_MODE_SKB_CB(skb)->id = iph->id;
	 * XFRM_MODE_SKB_CB(skb)->frag_off = iph->frag_off;
	 * XFRM_MODE_SKB_CB(skb)->tos = iph->tos;
	 * XFRM_MODE_SKB_CB(skb)->ttl = iph->ttl;
	 * XFRM_MODE_SKB_CB(skb)->optlen = iph->ihl * 4 - sizeof(*iph);
	 * memset(XFRM_MODE_SKB_CB(skb)->flow_lbl, 0,
	 * sizeof(XFRM_MODE_SKB_CB(skb)->flow_lbl));
	 *
	 * or
	 *
	 * XFRM_MODE_SKB_CB(skb)->protocol = ipv6_hdr(skb)->nexthdr;
	 * XFRM_MODE_SKB_CB(skb)->ihl = sizeof(*iph);
	 * XFRM_MODE_SKB_CB(skb)->id = 0;
	 * XFRM_MODE_SKB_CB(skb)->frag_off = htons(IP_DF);
	 * XFRM_MODE_SKB_CB(skb)->tos = ipv6_get_dsfield(iph);
	 * XFRM_MODE_SKB_CB(skb)->ttl = iph->hop_limit;
	 * XFRM_MODE_SKB_CB(skb)->optlen = 0;
	 * memcpy(XFRM_MODE_SKB_CB(skb)->flow_lbl, iph->flow_lbl,
	 * sizeof(XFRM_MODE_SKB_CB(skb)->flow_lbl));
	 *
	 */

	struct sk_buff *skb, *skb2, **nextp;
	int err;

	/* and send them on their way */

	while ((skb = __skb_dequeue(list))) {
		/* XXX we want this from the tunnel outer encap */
		int remaining = dst_mtu(skb_dst(skb));

		pr_devinf(
			"%s: 1st dequeue skb %p len %u data_len %u proto %u seq %u\n",
			__func__, skb, skb->len, skb->data_len, _proto(skb),
			_seq(skb));
		if (iptfs_first_skb(skb))
			continue;

		remaining -= skb->len;

		nextp = &skb_shinfo(skb)->frag_list;
		while (*nextp)
			nextp = &(skb_shinfo(*nextp))->frag_list;

		/* XXX should peek first to see if we have MTU room to append */
		while ((skb2 = skb_peek(list)) && skb2->len <= remaining) {
			skb2 = __skb_dequeue(list);

			pr_devinf(
				"%s: appendg secondary dequeue skb2 %p len %u data_len %u proto %u seq %u\n",
				__func__, skb2, skb2->len, skb2->data_len,
				_proto(skb2), _seq(skb2));
			// skb_shinfo(skb)->frag_list = skb2;
			*nextp = skb2;
			nextp = &skb2->next;
			BUG_ON(*nextp != NULL);
			skb->data_len += skb2->len;
			skb->len += skb2->len;
			skb->truesize += skb2->truesize;
			/*
                         * if we have fragments on skb2 we need to switch
                         * them to skb's list
                         */
			if (skb_has_frag_list(skb2)) {
				pr_devinf(
					"%s: 2nd skb2 has frag list collapsing\n",
					__func__);
				/*
                                 * I think it might be possible to account for
                                 * a frag list in addition to page fragment if
                                 * it's a valid state to be in. The page
                                 * fragments size should be kept as data_len
                                 * so only the frag_list size is removed, this
                                 * must be done above as well took
                                 */
				BUG_ON(skb_shinfo(skb2)->nr_frags);
				*nextp = skb_shinfo(skb2)->frag_list;
				while (*nextp)
					nextp = &(*nextp)->next;
				skb_frag_list_init(skb2);
				skb2->len -= skb2->data_len;
				skb2->data_len = 0;
			}
			remaining -= skb2->len;
		}

		pr_devinf(
			"%s: output skb %p, total len %u remaining space %u\n",
			__func__, skb, skb->len, remaining);
		err = xfrm_output(NULL, skb);
		if (err < 0) {
			printk("XXX got xfrm_output error: %d", err);
		}
	}
}

static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me)
{
	struct sk_buff_head list;
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;
	time64_t settime;
	size_t osize;

	xtfs = container_of(me, typeof(*xtfs), iptfs_timer);
	x = xtfs->x;

	/*
	 * Process all the queued packets
	 *
         * softirq execution order: timer > tasklet > hrtimer
         *
         * Network rx will have run before us giving one last chance to queue
         * ingress packets for us to process and transmit.
         */

	spin_lock(&x->lock);
	__skb_queue_head_init(&list);
	skb_queue_splice_init(&xtfs->queue, &list);
	osize = xtfs->queue_size;
	xtfs->queue_size = 0;
	settime = xtfs->iptfs_settime;
	spin_unlock(&x->lock);

	/*
	 * After the above unlock, packets can begin queuing again, and the
	 * timer can be set again, from another CPU either in softirq or user
	 * context (not from this one since we are running at softirq level
	 * already).
	 *
	 * XXX verify that a timer callback doesn't need to be re-entrant, i.e.,
	 * that it will never be running concurrently on different CPUs.
	 * If we have to be re-entrant we probably want a lock to avoid
	 * spewing packets out of order.
	 */

	pr_devinf("%s: got %u packets of %u total len\n", __func__,
		  (uint)list.qlen, (uint)osize);
	pr_devinf("%s: time delta %llu\n", __func__,
		  (unsigned long long)(ktime_get_raw_fast_ns() - settime));

	iptfs_output_queued(x, &list);

	return HRTIMER_NORESTART;
}
