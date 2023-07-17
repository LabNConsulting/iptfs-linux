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
#include <linux/icmpv6.h>
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

#undef PR_DEBUG_INFO
#undef PR_DEBUG_STATE
#undef PR_DEBUG_INGRESS
#undef PR_DEBUG_EGRESS

#ifdef PR_DEBUG_INFO
#define _pr_devinf(...) pr_info(__VA_ARGS__)
#else
#define _pr_devinf(...) pr_devel(__VA_ARGS__)
#endif

#define XFRM_INC_SA_STATS(xtfs, stat)
#define XFRM_INC_SA_STATS_N(xtfs, stat, count)

#define IPTFS_HRTIMER_MODE HRTIMER_MODE_REL_SOFT

struct skb_wseq {
	struct sk_buff *skb;
	u64 drop_time;
};

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
	time64_t iptfs_settime;	    /* time timer was set */
	uint payload_mtu;	    /* max payload size */
	/*
	 * Tunnel input reordering.
	 */
	bool w_seq_set;		  /* true after first seq received */
	u64 w_wantseq;		  /* expected next sequence */
	struct skb_wseq *w_saved; /* the saved buf array */
	uint w_savedlen;	  /* the saved len (not size) */
	struct spinlock drop_lock;
	struct hrtimer drop_timer;
	u64 drop_time_ns;
	/*
	 * Tunnel input reassembly.
	 */
	struct sk_buff *ra_newskb; /* new pkt being reassembled */
	u64 ra_wantseq;		   /* expected next sequence */
	u8 ra_runt[6];		   /* last pkt bytes from last skb */
	u8 ra_runtlen;		   /* count of ra_runt */
};

static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me);
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me);

/* ================= */
/* Utility Functions */
/* ================= */

static inline uint _proto(struct sk_buff *skb)
{
	if (((struct iphdr *)skb->data)->version == 4)
		return ((struct iphdr *)skb->data)->protocol;
	return ((struct ipv6hdr *)skb->data)->nexthdr;
}

static inline uint _seq(struct sk_buff *skb)
{
	void *nexthdr;
	uint protocol;

	if (ip_hdr(skb)->version == 4) {
		nexthdr = (void *)(ip_hdr(skb) + 1);
		protocol = ip_hdr(skb)->protocol;
	} else {
		nexthdr = (void *)(ipv6_hdr(skb) + 1);
		protocol = ipv6_hdr(skb)->nexthdr;
	}

	if (protocol == IPPROTO_ICMP)
		return ntohs(((struct icmphdr *)nexthdr)->un.echo.sequence);
	else if (protocol == IPPROTO_ICMPV6)
		return ntohs(((struct icmp6hdr *)nexthdr)->icmp6_sequence);
	else if (protocol == IPPROTO_TCP)
		return ntohl(((struct tcphdr *)nexthdr)->seq);
	else if (protocol == IPPROTO_UDP)
		return ntohs(((struct udphdr *)nexthdr)->source);
	else
		return 0;
}

static inline u64 __esp_seq(struct sk_buff *skb)
{
	u64 seq = ntohl(XFRM_SKB_CB(skb)->seq.input.low);
	return seq;
	// return seq | (u64)ntohl(XFRM_SKB_CB(skb)->seq.input.hi) << 32;
}

#if 0
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
#endif

/* ========================== */
/* State Management Functions */
/* ========================== */

#undef pr_fmt
#define pr_fmt(fmt) "%s: STATE: " fmt, __func__
#undef pr_devinfo
#ifdef PR_DEBUG_STATE
#define pr_devinf(...) _pr_devinf(__VA_ARGS__)
#else
#define pr_devinf(...)
#endif

int xfrm_iptfs_init_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs;

	xtfs = kzalloc_node(sizeof(*xtfs), GFP_KERNEL, NUMA_NO_NODE);
	x->tfs_data = xtfs;
	if (!xtfs)
		return -ENOMEM;

	pr_devinf("init %p\n", xtfs);

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

	pr_devinf("destroy %p\n", xtfs);

	if (IS_ERR_OR_NULL(xtfs))
		return;

	spin_lock(&xtfs->drop_lock);
	hrtimer_cancel(&xtfs->iptfs_timer);
	hrtimer_cancel(&xtfs->drop_timer);
	spin_unlock(&xtfs->drop_lock);
	kfree_sensitive(xtfs->w_saved);
	kfree_sensitive(xtfs);
}

int xfrm_iptfs_user_init(struct net *net, struct xfrm_state *x,
			 struct nlattr **attrs)
{
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	struct xfrm_iptfs_config *xc;

	pr_devinf("user_init %p\n", xtfs);

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
	/* saved array is for saving 1..N seq nums from wantseq */
	if (xc->reorder_win_size)
		xtfs->w_saved = kcalloc(xc->reorder_win_size,
					sizeof(*xtfs->w_saved), GFP_KERNEL);
	if (attrs[XFRMA_IPTFS_PKT_SIZE]) {
		xc->pkt_size = nla_get_u32(attrs[XFRMA_IPTFS_PKT_SIZE]);
		if (!xc->pkt_size)
			xtfs->payload_mtu = 0;
		else if (xc->pkt_size > x->props.header_len)
			xtfs->payload_mtu = xc->pkt_size - x->props.header_len;
		else {
			pr_err("requested iptfs pkt-size %u <= packet header len %u\n",
			       xc->pkt_size, x->props.header_len);
			return EINVAL;
		}
		pr_devinf("IPTFS pkt-size %u => payload_mtu %u\n", xc->pkt_size,
			  xtfs->payload_mtu);
	}
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

	pr_devinf("copy state to user %p\n", x->tfs_data);

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

/* ================================== */
/* IPTFS Receiving (egress) Functions */
/* ================================== */

#undef pr_fmt
#define pr_fmt(fmt) "%s: EGRESS: " fmt, __func__
#undef pr_devinf
#ifdef PR_DEBUG_EGRESS
#define pr_devinf(...) _pr_devinf(__VA_ARGS__)
#else
#define pr_devinf(...)
#endif

#if 0
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
#endif

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

static struct sk_buff *iptfs_alloc_header_skb(void)
{
	struct sk_buff *skb;
	uint resv = XFRM_IPTFS_MIN_HEADROOM;

	pr_devinf("resv %u\n", resv);
	skb = alloc_skb(resv, GFP_ATOMIC);
	if (!skb) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINERROR);
		pr_err_ratelimited("failed to alloc skb\n");
		return NULL;
	}
	skb_reserve(skb, resv);
	// skb->ip_summed = CHECKSUM_NONE;
	return skb;
}

static struct sk_buff *iptfs_alloc_skb(struct sk_buff *tpl, uint len)
{
	struct sk_buff *skb;
	uint resv = skb_headroom(tpl);

	if (resv < XFRM_IPTFS_MIN_HEADROOM)
		resv = XFRM_IPTFS_MIN_HEADROOM;

	skb = alloc_skb(len + resv, GFP_ATOMIC);
	if (!skb) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINERROR);
		pr_err_ratelimited("failed to alloc skb resv %u\n", len + resv);
		return NULL;
	}

	pr_devinf("len %u resv %u skb %p\n", len, resv, skb);

	skb_reserve(skb, resv);
	skb_copy_header(skb, tpl);

	// Let's not copy the checksum!
	skb->csum = 0;
	skb->ip_summed = CHECKSUM_NONE;

	// the skb_copy_header does the following so figure out wth it is :)
	// skb_shinfo(new)->gso_size = skb_shinfo(old)->gso_size;
	// skb_shinfo(new)->gso_segs = skb_shinfo(old)->gso_segs;
	// skb_shinfo(new)->gso_type = skb_shinfo(old)->gso_type;
	BUG_ON(!skb_sec_path(skb));

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
	if (!skb)
		return NULL;
	if (skb_copy_bits_seq(st, off, skb_put(skb, len), len)) {
		XFRM_INC_STATS(dev_net(st->root_skb->dev),
			       LINUX_MIB_XFRMINERROR);
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

	pr_devinf("saving runt len %u, exp seq %llu\n", len, seq);
	memcpy(xtfs->ra_runt, buf, len);

	xtfs->ra_runtlen = len;
	xtfs->ra_wantseq = seq + 1;
}

static uint __iptfs_iplen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	if (iph->version == 0x4)
		return ntohs(iph->tot_len);
	BUG_ON(iph->version != 0x6);
	return ntohs(((struct ipv6hdr *)iph)->payload_len) +
	       sizeof(struct ipv6hdr);
}

static uint __iptfs_iphdrlen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	if (iph->version == 0x4)
		return iph->ihl << 2;
	else if (iph->version == 0x6) {
		/* XXX check other kernel cases for transport offset */
		return sizeof(struct ipv6hdr);
	}
	return 0;
}

static int iptfs_complete_inner_skb(struct xfrm_state *x, struct sk_buff *skb,
				    uint iphlen)
{
	struct sec_path *sp;
	int err, family;

	skb_reset_network_header(skb);
	/* This may be unnecessary as the the inner packet is going to be
	 * delivered back to the resulting L3 input path which will set the
	 * transport header as appropriate
	 */
	skb_set_transport_header(skb, iphlen);

	/*
	 * Our skb will contain the header data copied when this outer packet
	 * which contained the start of this inner packet. This is true
	 * when we allocate a new skb as well as when we reuse the existing skb.
	 */
	if (ip_hdr(skb)->version == 0x4) {
		struct iphdr *iph = ip_hdr(skb);

		pr_devinf("completing inner, iplen %u skb len %u iphlen %u\n",
			  ntohs(iph->tot_len), skb->len, iphlen);

		family = AF_INET;
		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv4_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP_ECN_set_ce(iph);

		skb->protocol = htons(ETH_P_IP);
	} else {
		struct ipv6hdr *iph = ipv6_hdr(skb);

		pr_devinf(
			"completing inner, payload len %u skb len %u iphlen %u\n",
			ntohs(ipv6_hdr(skb)->payload_len), skb->len, iphlen);

		family = AF_INET6;
		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv6_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP6_ECN_set_ce(skb, iph);

		skb->protocol = htons(ETH_P_IPV6);
	}

	/*
	 * This remaining code here is based on the tunnel branch at the
	 * xfrm_input(). Should consider refactoring it.
	 */

	/* track stats for any xfrmi interface being used. */
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

		/* XXX ok to do this on first_skb before done? */
#if 0 // in master..
	if (skb_valid_dst(skb))
		skb_dst_drop(skb);
#else
	skb_dst_drop(skb);
#endif

	return 0;
}

static inline void _iptfs_reassem_done(struct xfrm_iptfs_data *xtfs, bool free)
{
	int ret;
	assert_spin_locked(&xtfs->drop_lock);

	/* We don't care if it works locking takes care of things */
	ret = hrtimer_try_to_cancel(&xtfs->drop_timer);
	pr_devinf("canceled drop timer ret: %d\n", ret);
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
#ifdef PR_DEBUG_INGRESS
	u64 want = xtfs->ra_wantseq;
#endif
	uint runtlen = xtfs->ra_runtlen;
	uint copylen, fraglen, ipremain, rrem;

	pr_devinf(
		"got seq %llu blkoff %u plen %u want %llu skb %p runtlen %u\n",
		seq, blkoff, remaining, want, xtfs->ra_newskb, runtlen);

	/*
	 * Handle packet fragment we aren't expecting
	 */
	if (!runtlen && !xtfs->ra_newskb) {
		pr_devinf("not reassembling, skip fragment\n");
		return data + min(blkoff, remaining);
	}

	/*
	 * Important to remember that input to this function is an ordered
	 * packet stream (unless the user disabled the reorder window). Thus if
	 * we are waiting for, and expecting the next packet so we can continue
	 * assembly. A newer sequence number indicates older ones are not coming
	 * (or if they do should be ignored). Technically we can receive older
	 * ones when the reorder window is disabled; however, the user should
	 * have disabled fragmentation in this case, and regardless we don't
	 * deal with it.
	 *
	 * blkoff could be zero if the stream is messed up (or it's an all pad
	 * insertion) be careful to handle that case in each of the below
	 */

	/*
	 * Too old case: This can happen when the reorder window is disabled so
	 * ordering isn't actually guaranteed.
	 */
	if (seq < xtfs->ra_wantseq) {
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_OLD_SEQ);
		pr_devinf("dropping old seq\n");
		return data + remaining;
	}

	/*
	 * Too new case: We missed what we wanted cleanup.
	 */
	if (seq > xtfs->ra_wantseq) {
		pr_devinf("missed needed seq\n");
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_MISSED_FRAG_START);
	abandon:
		if (xtfs->ra_newskb)
			iptfs_reassem_abort(xtfs);
		else {
			xtfs->ra_runtlen = 0;
			xtfs->ra_wantseq = 0;
		}
		/* skip past fragment, maybe to end */
		return data + min(blkoff, remaining);
	}

	if (blkoff == 0) {
		if ((*skb->data & 0xF0) != 0) {
			pr_devinf("missing expected fragment\n");
			goto abandon;
		}
		/*
		 * Handle all pad case, advance expected sequence number.
		 * (RFC 9347 S2.2.3)
		 */
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_ALL_PAD_SKIP);
		pr_devinf("skipping all pad seq %llu \n", seq);
		xtfs->ra_wantseq++;
		/* will end parsing */
		return data + remaining;
	}

	if (runtlen) {
		BUG_ON(xtfs->ra_newskb);

		/* Regardless of what happens we're done with the runt */
		xtfs->ra_runtlen = 0;

		/*
		 * The start of this inner packet was at the very end of the last
		 * iptfs payload which didn't include enough for the ip header
		 * length field. We must have *at least* that now.
		 */
		rrem = sizeof(xtfs->ra_runt) - runtlen;
		if (remaining < rrem || blkoff < rrem) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINBUFFERERROR);
			pr_err_ratelimited(
				"bad frag after runt: blkoff/remain %u/%u < runtrem %u\n",
				blkoff, remaining, rrem);
			goto abandon;
		}

		/* fill in the runt data */
		if (skb_copy_bits_seq(st, data, &xtfs->ra_runt[runtlen], rrem))
			goto abandon;
		/*
		 * We have enough data to get the ip length value now,
		 * allocate an in progress skb
		 */
		ipremain = __iptfs_iplen(xtfs->ra_runt);
		if (ipremain < sizeof(xtfs->ra_runt)) {
			/* length has to be at least runtsize large */
			XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_BAD_IPLEN);
			pr_devinf("bogus ip length %d\n", ipremain);
			goto abandon;
		}

		newskb = iptfs_alloc_skb(skb, ipremain);
		if (!newskb)
			goto abandon;
		xtfs->ra_newskb = newskb;

		/*
		 * Copy the runt data into the buffer, but leave data
		 * pointers the same as normal non-runt case. The extra `rrem`
		 * recopied bytes are basically cacheline free. Allows using
		 * same logic below to complete.
		 */
		memcpy(skb_put(newskb, runtlen), xtfs->ra_runt,
		       sizeof(xtfs->ra_runt));
	}

	/*
	 * Continue reassembling the packet
	 */
	ipremain = __iptfs_iplen(newskb->data);

	/* we created the newskb knowing the length it can't now be shorter */
	BUG_ON(newskb->len > ipremain);

	ipremain -= newskb->len;
	if (blkoff < ipremain) {
		/* Corrupt data, we don't have enough to complete the packet */
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_IPLEN_BAD_BLOCKOFF);
		pr_err_ratelimited(
			"bad recv blkoff: blkoff %u < ip remaining %u\n",
			blkoff, ipremain);
		goto abandon;
	}

	fraglen = min(blkoff, remaining);
	copylen = min(fraglen, ipremain);
	BUG_ON(skb_tailroom(newskb) < copylen);

	pr_devinf("continue, iprem %u copylen %u\n", ipremain, copylen);

	/* copy fragment data into newskb */
	if (skb_copy_bits_seq(st, data, skb_put(newskb, copylen), copylen)) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINBUFFERERROR);
		pr_err_ratelimited("bad skb\n");
		goto abandon;
	}

	if (copylen < ipremain) {
		xtfs->ra_wantseq++;
		pr_devinf("unfinished, incr expected to %llu\n",
			  xtfs->ra_wantseq);
	} else {
		/* We are done with packet reassembly! */
		BUG_ON(copylen != ipremain);
		iptfs_reassem_done(xtfs);
		pr_devinf("finished, %u left in payload\n",
			  remaining - copylen);
		if (iptfs_complete_inner_skb(xtfs->x, newskb,
					     __iptfs_iphdrlen(newskb->data)))
			kfree_skb(newskb);
		else
			list_add_tail(&newskb->list, list);
	}

	/* will continue on to new data block or end */
	return data + fraglen;
}

/* checkout skb_segment to see if it has much of iptfs_input_ordered in it. */

/*
 * We have an IPTFS payload dispense with it and this skb as well.
 */
static int iptfs_input_ordered(struct gro_cells *gro_cells,
			       struct xfrm_state *x, struct sk_buff *skb)
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
	u64 seq;
	u8 *tmp;

	xtfs = x->tfs_data;
	net = dev_net(skb->dev);
	first_skb = NULL;
	defer = NULL;

	seq = __esp_seq(skb);
	pr_devinf("processing skb with len %u seq %llu\n", skb->len, seq);

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
		pr_err_ratelimited("bad skb\n");
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
		pr_err_ratelimited("bad iptfs hdr\n");
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto done;
	}

	if (ipth->flags != 0)
		goto badhdr;

	INIT_LIST_HEAD(&sublist);

	/*
	 * Handle fragment at start of payload, and/or waiting reassembly.
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
		uint protocol = 0;

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
			protocol = htons(ETH_P_IP);
			pr_devinf("ipv4 inner length %u\n", iplen);
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
			iplen += sizeof(struct ipv6hdr);
			/* XXX chopps: what about extra headers? ipv6_input
                         * seems to just do this */
			iphlen = sizeof(struct ipv6hdr);
			protocol = htons(ETH_P_IPV6);
			pr_devinf("ipv6 inner length %u\n", iplen);
		} else if (iph->version == 0x0) {
			/* pad */
			pr_devinf("padding length %u\n", remaining);
			data = tail;
			break;
		} else {
			pr_warn("unknown inner datablock type %u\n",
				iph->version);
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}

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
			} else if (skb_tailroom(skb) + tail - data >= iplen) {
				/*
				 * Reuse fist skb. Need to move past the initial
				 * iptfs header as well as any initial fragment
				 * for previous inner packet reassembly
				 *
				 * XXX talk about how this is re-using tailroom
				 * for future fragment copyin
				 */
				tmp = skb->data;
				pskb_pull(skb, data);
				/* XXX do these rcsums work with pskb variants? */
				skb_postpull_rcsum(skb, tmp, data);

				/* our range just changed */
				data = 0;
				tail = skb->len;
				remaining = skb->len;

				skb->protocol = protocol;
				skb_mac_header_rebuild(skb);
				if (skb->mac_len)
					eth_hdr(skb)->h_proto = skb->protocol;

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

				pr_devinf("reusing outer skb %p\n", skb);
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
			if (!skb)
				continue;
			pr_devinf("alloc'd new skb %p\n", skb);

			skb->protocol = protocol;
			if (old_mac) {
				/* rebuild the mac header */
				skb_set_mac_header(skb, -first_skb->mac_len);
				memcpy(skb_mac_header(skb), old_mac,
				       first_skb->mac_len);
				eth_hdr(skb)->h_proto = skb->protocol;
			}
		}

		pr_devinf("new skb %p ip proto %u icmp/tcp seq %u\n", skb,
			  _proto(skb), _seq(skb));

		data += capturelen;

		if (skb->len < iplen) {
			BUG_ON(data != tail);
			BUG_ON(xtfs->ra_newskb);

			/*
			 * Start reassembly
			 */
			pr_devinf("payload done, save packet (%u of %u)\n",
				  skb->len, iplen);

			spin_lock(&xtfs->drop_lock);

			xtfs->ra_newskb = skb;
			xtfs->ra_wantseq = seq + 1;
			if (!hrtimer_is_queued(&xtfs->drop_timer)) {
				pr_devinf("starting drop timer, for reassem\n");
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
		pr_devinf("error data(%u) != tail(%u)\n", data, tail);
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
			"sending inner packet len %u skb %p proto %u seq/port %u\n",
			(uint)skb->len, skb, _proto(skb), _seq(skb));
		gro_cells_receive(gro_cells, skb);
	}

	/* safe to call even if we were done */
done:
	skb_abort_seq_read(&skbseq);

	if (defer)
		consume_skb(defer);

	return 0;
}

static void __vec_shift(struct xfrm_iptfs_data *xtfs, u64 shift)
{
	uint savedlen = xtfs->w_savedlen;
#if UINTPTR_MAX != UINT_MAX
	if (shift > UINT_MAX)
		shift = UINT_MAX;
#endif
	if (shift > savedlen)
		shift = savedlen;
	if (shift != savedlen)
		memcpy(xtfs->w_saved, xtfs->w_saved + shift,
		       (savedlen - shift) * sizeof(*xtfs->w_saved));
	memset(xtfs->w_saved + savedlen - shift, 0,
	       shift * sizeof(*xtfs->w_saved));
	xtfs->w_savedlen -= shift;
}

static int __reorder_past(struct xfrm_iptfs_data *xtfs, struct sk_buff *inskb,
			  struct list_head *freelist, uint *fcount)
{
	pr_devinf("drop old got %llu want %llu\n", __esp_seq(inskb),
		  xtfs->w_wantseq);
	XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_OLD_SEQ);
	list_add_tail(&inskb->list, freelist);
	(*fcount)++;
	return 0;
}

static uint __reorder_drop(struct xfrm_iptfs_data *xtfs, struct list_head *list)

{
	struct skb_wseq *s, *se;
	const uint savedlen = xtfs->w_savedlen;
	u64 wantseq = xtfs->w_wantseq;
	time64_t now = ktime_get_raw_fast_ns();
	uint count = 0;
	uint scount = 0;

	BUG_ON(!savedlen);
	if (xtfs->w_saved[0].drop_time > now) {
		pr_devinf("not yet time to drop\n");
		goto set_timer;
	}

	pr_devinf("drop wanted seq %llu savedlen %u\n", wantseq, savedlen);
	wantseq = ++xtfs->w_wantseq;

	/* Keep flushing packets until we reach a drop time greater than now. */
	s = xtfs->w_saved;
	se = s + savedlen;
	do {
		/* Walking past empty slots until we reach a packet */
		for (; s < se && !s->skb; s++)
			if (s->drop_time > now)
				goto outerdone;
		/* Sending packets until we hit another empty slot. */
		for (; s < se && s->skb; scount++, s++)
			list_add_tail(&s->skb->list, list);
	} while (s < se);
outerdone:

	count = s - xtfs->w_saved;
	if (count) {
		xtfs->w_wantseq += count;
		pr_devinf("popped seq %llu to %llu from saved%s (sent %u)\n",
			  wantseq, xtfs->w_wantseq - 1,
			  count == savedlen ? " (all)" : "", scount);

		/* Shift handled slots plus final empty slot into slot 0. */
		__vec_shift(xtfs, count);
	}

	if (xtfs->w_savedlen) {
	set_timer:
		/* Drifting is OK */
		pr_devinf("restarting drop timer, savedlen: %u\n",
			  xtfs->w_savedlen);
		hrtimer_start(&xtfs->drop_timer,
			      xtfs->w_saved[0].drop_time - now,
			      IPTFS_HRTIMER_MODE);
	}
	return scount;
}

static uint __reorder_this(struct xfrm_iptfs_data *xtfs, struct sk_buff *inskb,
			   struct list_head *list)

{
	struct skb_wseq *s, *se;
	const uint savedlen = xtfs->w_savedlen;
	u64 wantseq = xtfs->w_wantseq;
	uint count = 0;

	/* Got what we wanted. */
	pr_devinf("got wanted seq %llu savedlen %u\n", wantseq, savedlen);
	list_add_tail(&inskb->list, list);
	wantseq = ++xtfs->w_wantseq;
	if (!savedlen) {
		pr_devinf("all done, no saved out-of-order pkts\n");
		return 1;
	}

	/*
	 * Flush remaining consecutive packets.
	 */

	/* Keep sending until we hit another missed pkt. */
	for (s = xtfs->w_saved, se = s + savedlen; s < se && s->skb; s++)
		list_add_tail(&s->skb->list, list);
	count = s - xtfs->w_saved;
	if (count) {
		xtfs->w_wantseq += count;
		pr_devinf("popped seq %llu to %llu from saved%s\n", wantseq,
			  xtfs->w_wantseq - 1,
			  count == savedlen ? " (all)" : "");
	}

	/* Shift handled slots plus final empty slot into slot 0. */
	__vec_shift(xtfs, count + 1);

	return count + 1;
}

/*
 * Set the slot's drop time and all the empty slots below it until reaching a
 * filled slot which will already be set.
 */
static void iptfs_set_window_drop_times(struct xfrm_iptfs_data *xtfs, int index)
{
	const uint savedlen = xtfs->w_savedlen;
	struct skb_wseq *s = xtfs->w_saved;
	time64_t drop_time;

	assert_spin_locked(&xtfs->drop_lock);

	if (savedlen > index + 1) {
		/* we are below another, our drop time and the timer are already set */
		BUG_ON(xtfs->w_saved[index + 1].drop_time !=
		       xtfs->w_saved[index].drop_time);
		return;
	}
	/* we are the most future so get a new drop time. */
	drop_time = ktime_get_raw_fast_ns();
	drop_time += xtfs->drop_time_ns;

	/* Walk back through the array setting drop times as we go */
	s[index].drop_time = drop_time;
	while (index-- > 0 && s[index].skb == NULL)
		s[index].drop_time = drop_time;

	/* If we walked all the way back, schedule the drop timer if needed */
	if (index == -1 && !hrtimer_is_queued(&xtfs->drop_timer)) {
		pr_devinf("starting drop timer on first save\n");
		hrtimer_start(&xtfs->drop_timer, xtfs->drop_time_ns,
			      IPTFS_HRTIMER_MODE);
	}
}

static uint __reorder_future_fits(struct xfrm_iptfs_data *xtfs,
				  struct sk_buff *inskb,
				  struct list_head *freelist, uint *fcount)
{
	const uint nslots = xtfs->cfg.reorder_win_size + 1;
	const u64 inseq = __esp_seq(inskb);
	const u64 wantseq = xtfs->w_wantseq;
	const u64 distance = inseq - wantseq;
	const uint savedlen = xtfs->w_savedlen;
	const uint index = distance - 1;

	BUG_ON(distance >= nslots);

	/*
	 * Handle future sequence number received which fits in the window.
	 *
	 * We know we don't have the seq we want so we won't be able to flush
	 * anything.
	 */

	pr_devinf(
		"got future seq %llu want %llu distance %llu savedlen %u nslots %u\n",
		inseq, wantseq, distance, savedlen, nslots);

	/*
	 * slot count is 4, saved size is 3 savedlen is 2
	 *
	 * "window boundary" is based on the fixed window size
	 * distance is also slot number
	 * index is an array index (i.e., - 1 of slot)
	 * : : - implicit NULL after array len
	 *
	 *          +--------- used length (savedlen == 2)
	 *          |   +----- array size (nslots - 1 == 3)
	 *          |   |   + window boundary (nslots == 4)
	 *          V   V | V
	 *                |
	 *  0   1   2   3 |   slot number
	 * ---  0   1   2 |   array index
	 *     [-] [b] : :|   array
	 *
	 * "2" "3" "4" *5*|   seq numbers
	 *
	 * We receive seq number 5
	 * distance == 3 [inseq(5) - w_wantseq(2)]
	 * index == 2 [distance(6) - 1]
	 */

	if (xtfs->w_saved[index].skb) {
		/* a dup of a future */
		pr_devinf("dropping future dup %llu\n", inseq);
		XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_DUP_SEQ);
		list_add_tail(&inskb->list, freelist);
		(*fcount)++;
		return 0;
	}

	xtfs->w_saved[index].skb = inskb;
	xtfs->w_savedlen = max(savedlen, index + 1);
	iptfs_set_window_drop_times(xtfs, index);

	return 0;
}

static uint __reorder_future_shifts(struct xfrm_iptfs_data *xtfs,
				    struct sk_buff *inskb,
				    struct list_head *list,
				    struct list_head *freelist, uint *fcount)
{
	const uint nslots = xtfs->cfg.reorder_win_size + 1;
	const u64 inseq = __esp_seq(inskb);
	uint savedlen = xtfs->w_savedlen;
	u64 wantseq = xtfs->w_wantseq;
	struct sk_buff *slot0 = NULL;
#ifdef PR_DEBUG_EGRESS
	u64 start_drop_seq = xtfs->w_wantseq;
#endif
	u64 last_drop_seq = xtfs->w_wantseq;
	u64 distance, extra_drops, missed, s0seq;
	uint count = 0;
	struct skb_wseq *wnext;
	uint beyond, shifting, slot;

	BUG_ON(inseq <= wantseq);
	distance = inseq - wantseq;
	BUG_ON(distance <= nslots - 1);
	beyond = distance - (nslots - 1);
	missed = 0;

	/*
	 * Handle future sequence number received.
	 *
	 * IMPORTANT: we are at least advancing w_wantseq (i.e., wantseq) by 1
	 * b/c we are beyond the window boundary.
	 *
	 * We know we don't have the wantseq so that counts as a drop.
	 */

	pr_devinf(
		"got future seq %llu want %llu distance %llu savedlen %u nslots %u\n",
		inseq, wantseq, distance, savedlen, nslots);

	/*
	 * ex: slot count is 4, array size is 3 savedlen is 2, slot 0 is the
	 * missing sequence number.
	 *
	 * the final slot at savedlen (index savedlen - 1) is always occupied.
	 *
	 * beyond is "beyond array size" not savedlen.
	 *
	 *          +--------- array length (savedlen == 2)
	 *          |   +----- array size (nslots - 1 == 3)
	 *          |   |   +- window boundary (nslots == 4)
	 *          V   V | V
	 *                |
	 *  0   1   2   3 |   slot number
	 * ---  0   1   2 |   array index
	 *     [b] [c] : :|   array
	 *                |
	 * "2" "3" "4" "5"|*6*  seq numbers
	 *
	 * We receive seq number 6
	 * distance == 4 [inseq(6) - w_wantseq(2)]
	 * newslot == distance
	 * index == 3 [distance(4) - 1]
	 * beyond == 1 [newslot(4) - lastslot((nslots(4) - 1))]
	 * shifting == 1 [min(savedlen(2), beyond(1)]
	 * slot0_skb == [b], and should match w_wantseq
	 *
	 *                +--- window boundary (nslots == 4)
	 *  0   1   2   3 | 4   slot number
	 * ---  0   1   2 | 3   array index
	 *     [b] : : : :|     array
	 * "2" "3" "4" "5" *6*  seq numbers
	 *
	 * We receive seq number 6
	 * distance == 4 [inseq(6) - w_wantseq(2)]
	 * newslot == distance
	 * index == 3 [distance(4) - 1]
	 * beyond == 1 [newslot(4) - lastslot((nslots(4) - 1))]
	 * shifting == 1 [min(savedlen(1), beyond(1)]
	 * slot0_skb == [b] and should match w_wantseq
	 *
	 *                +-- window boundary (nslots == 4)
	 *  0   1   2   3 | 4   5   6   slot number
	 * ---  0   1   2 | 3   4   5   array index
	 *     [-] [c] : :|             array
	 * "2" "3" "4" "5" "6" "7" *8*  seq numbers
	 *
	 * savedlen = 2, beyond = 3
	 * iter 1: slot0 == NULL, missed++, lastdrop = 2 (2+1-1), slot0 = [-]
	 * iter 2: slot0 == NULL, missed++, lastdrop = 3 (2+2-1), slot0 = [c]
	 * 2 < 3, extra = 1 (3-2), missed += extra, lastdrop = 4 (2+2+1-1)
	 *
	 * We receive seq number 8
	 * distance == 6 [inseq(8) - w_wantseq(2)]
	 * newslot == distance
	 * index == 5 [distance(6) - 1]
	 * beyond == 3 [newslot(6) - lastslot((nslots(4) - 1))]
	 * shifting == 2 [min(savedlen(2), beyond(3)]
	 *
	 * XXXX what's this next thing? why isn't it [c]?
	 * slot0_skb == NULL changed from [b] when "savedlen < beyond" is true.
	 */

	/*
	 * Now send any packets that are being shifted out of saved, and account
	 * for missing packets that are exiting the window as we shift it.
	 */

	/* If savedlen > beyond we are shifting some, else all. */
	shifting = min(savedlen, beyond);

	/* slot0 is the buf that just shifted out and into slot0 */
	slot0 = NULL;
	s0seq = wantseq;
	last_drop_seq = s0seq;
	wnext = xtfs->w_saved;
	for (slot = 1; slot <= shifting; slot++, wnext++) {
		/* handle what was in slot0 before we occupy it */
		if (!slot0) {
			pr_devinf("drop slot0 during shift: %llu", s0seq);
			last_drop_seq = s0seq;
			missed++;
		} else {
			pr_devinf("send slot0 during shift: %llu", s0seq);
			list_add_tail(&slot0->list, list);
			count++;
		}
		s0seq++;
		slot0 = wnext->skb;
		wnext->skb = NULL;
	}

	/*
	 * slot0 is now either NULL (in which case it's what we now are waiting
	 * for, or a buf in which case we need to handle it like we received it;
	 * however, we may be advancing past that buffer as well..
	 */

	/*
	 * Handle case where we need to shift more than we had saved, slot0 will
	 * be NULL iff savedlen is 0, otherwise slot0 will always be
	 * non-NULL b/c we shifted the final element, which is always set if
	 * there is any saved, into slot0.
	 */
	if (savedlen < beyond) {
		extra_drops = beyond - savedlen;
		if (savedlen == 0) {
			BUG_ON(slot0);
			pr_devinf("no slot0 skipping %llu more", extra_drops);
			s0seq += extra_drops;
			last_drop_seq = s0seq - 1;
		} else {
			extra_drops--; /* we aren't dropping what's in slot0 */
			BUG_ON(!slot0);
			pr_devinf("send slot0: %llu and skipping %llu more",
				  s0seq, extra_drops);
			list_add_tail(&slot0->list, list);
			/* if extra_drops then we are going past this slot0
			 * so we can safely advance last_drop_seq
			 */
			if (extra_drops)
				last_drop_seq = s0seq + extra_drops;
			s0seq += extra_drops + 1;
			count++;
		}
		missed += extra_drops;
		slot0 = NULL;
		/* slot0 has had an empty slot pushed into it */
	}

	/* Remove the entries */
	__vec_shift(xtfs, beyond);

	/* Advance want seq */
	xtfs->w_wantseq += beyond;

	/*
	 * Process drops here when implementing congestion control
	 */
	XFRM_INC_SA_STATS_N(xtfs, IPTFS_INPUT_MISSED_SEQ, missed);
	if (missed)
		pr_devinf("drop start seq %llu last seq %llu\n", start_drop_seq,
			  last_drop_seq);

	/* We've shifted. plug the packet in at the end. */
	xtfs->w_savedlen = nslots - 1;
	xtfs->w_saved[xtfs->w_savedlen - 1].skb = inskb;
	iptfs_set_window_drop_times(xtfs, xtfs->w_savedlen - 1);

	/* if we don't have a slot0 then we must wait for it */
	if (!slot0)
		return count;

	/* If slot0, seq must match new want seq */
	BUG_ON(xtfs->w_wantseq != __esp_seq(slot0));

	/*
	 * slot0 is valid, treat like we received expected.
	 */
	pr_devinf("have slot0 after shift, process as received:u%llu\n", s0seq);
	count += __reorder_this(xtfs, slot0, list);
	return count;
}

/*
 * Receive a new packet into the reorder window. Return a list of ordered
 * packets from the window.
 */
static uint iptfs_input_reorder(struct xfrm_iptfs_data *xtfs,
				struct sk_buff *inskb, struct list_head *list,
				struct list_head *freelist, uint *fcount)
{
	const uint nslots = xtfs->cfg.reorder_win_size + 1;
	u64 inseq = __esp_seq(inskb);
	u64 wantseq;

	assert_spin_locked(&xtfs->drop_lock);

	if (unlikely(!xtfs->w_seq_set)) {
		pr_devinf("recv reorder: first packet inseq %llu skblen %u\n",
			  inseq, inskb->len);
		xtfs->w_seq_set = true;
		xtfs->w_wantseq = inseq;
	}
	wantseq = xtfs->w_wantseq;

	pr_devinf("recv reorder: inseq %llu want %llu savedlen %u skblen %u\n",
		  inseq, wantseq, xtfs->w_savedlen, inskb->len);

	if (likely(inseq == wantseq))
		return __reorder_this(xtfs, inskb, list);
	else if (inseq < wantseq)
		return __reorder_past(xtfs, inskb, freelist, fcount);
	else if ((inseq - wantseq) < nslots)
		return __reorder_future_fits(xtfs, inskb, freelist, fcount);
	else
		return __reorder_future_shifts(xtfs, inskb, list, freelist,
					       fcount);
}

/*
 * Handle drop timer expiry, this is similar to our input function.
 *
 * The drop timer is set when we start an in progress reassembly, and also when
 * we save a future packet in the window saved array.
 *
 * NOTE packets in the save window are always newer WRT drop times as
 * they get further in the future. i.e. for:
 *
 *    if slots (S0, S1, ... Sn) and `Dn` is the drop time for slot `Sn`,
 *    then D(n-1) <= D(n).
 *
 * So, regardless of why the timer is firing we can always discard any inprogress
 * fragment; either it's the reassembly timer, or slot 0 is going to be
 * dropped as S0 must have the most recent drop time, and slot 0 holds the
 * continuation fragment of the in progress packet.
 */
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me)
{
	struct sk_buff *skb, *next;
	struct list_head freelist, list;
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;
	uint count, fcount;

	xtfs = container_of(me, typeof(*xtfs), drop_timer);
	x = xtfs->x;

	XFRM_INC_SA_STATS(xtfs, IPTFS_INPUT_DROP_TIMER_FIRES);

	spin_lock(&xtfs->drop_lock);

	INIT_LIST_HEAD(&list);
	INIT_LIST_HEAD(&freelist);
	fcount = 0;

	/*
         * Drop any in progress packet
         */

	if (!xtfs->ra_newskb) {
		pr_devinf("no in-progress reassembly\n");
	} else {
		pr_devinf("dropping in-progress reassemble\n");
		kfree_skb(xtfs->ra_newskb);
		xtfs->ra_newskb = NULL;
	}

	/*
         * Now drop as many packets as we should from the reordering window
         * saved array
         */
	count = xtfs->w_savedlen ? __reorder_drop(xtfs, &list) : 0;

	spin_unlock(&xtfs->drop_lock);

	if (count) {
		pr_devinf("receiving ordered list of len %u\n", count);
		list_for_each_entry_safe (skb, next, &list, list) {
			skb_list_del_init(skb);
			(void)iptfs_input_ordered(xfrm_input_gro_cells, x, skb);
		}
	}
	return HRTIMER_NORESTART;
}

/*
 * We have an IPTFS payload order it if needed.
 */
int xfrm_iptfs_input(struct gro_cells *gro_cells, struct xfrm_state *x,
		     struct sk_buff *skb)
{
	struct list_head freelist, list;
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	struct sk_buff *next;
	uint count, fcount;

	/* Fast path for no reorder window. */
	if (xtfs->cfg.reorder_win_size == 0) {
		iptfs_input_ordered(gro_cells, x, skb);
		return 0;
	}

	/*
	 * Fetch list of in-order packets from the reordering window as well as
	 * a list of buffers we need to now free.
	 */
	INIT_LIST_HEAD(&list);
	INIT_LIST_HEAD(&freelist);
	fcount = 0;

	spin_lock(&xtfs->drop_lock);
	count = iptfs_input_reorder(xtfs, skb, &list, &freelist, &fcount);
	spin_unlock(&xtfs->drop_lock);

	if (count) {
		pr_devinf("receiving ordered list of len %u\n", count);
		list_for_each_entry_safe (skb, next, &list, list) {
			skb_list_del_init(skb);
			(void)iptfs_input_ordered(gro_cells, x, skb);
		}
	}

	if (fcount) {
		pr_devinf("freeing list of len %u\n", fcount);
		list_for_each_entry_safe (skb, next, &freelist, list) {
			skb_list_del_init(skb);
			kfree_skb(skb);
			return 0;
		}
	}
	return 0;
}

/* ================================= */
/* IPTFS Sending (ingress) Functions */
/* ================================= */

#undef pr_fmt
#define pr_fmt(fmt) "%s: INGRESS: " fmt, __func__
#undef pr_devinf
#ifdef PR_DEBUG_INGRESS
#define pr_devinf(...) _pr_devinf(__VA_ARGS__)
#else
#define pr_devinf(...)
#endif

/* ------------------------- */
/* Enqueue to send functions */
/* ------------------------- */

/*
 * Check to see if it's OK to queue a packet for sending on tunnel.
 */
static bool iptfs_enqueue(struct xfrm_iptfs_data *xtfs, struct sk_buff *skb)
{
	assert_spin_locked(&xtfs->x->lock);

	/* For now we use a predefined constant value, eventually configuration */
	if (xtfs->queue_size + skb->len > xtfs->cfg.max_queue_size) {
		pr_warn_ratelimited("no space: qsize: %u skb len %u max %u\n",
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
 * This is set in dst->output for an SA.
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
	bool was_gso;

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
	was_gso = skb_is_gso(skb);
	if (!was_gso) {
		segs = skb;
		BUG_ON(skb->next);
	} else {
		netdev_features_t features = netif_skb_features(skb);

		pr_info_once("received GSO skb (only printing once)\n");
		pr_devinf("splitting up GSO skb %p", skb);

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
				"no space drop rest: skb: %p len %u data_len %u proto %u seq %u\n",
				skb, (uint)skb->len, skb->data_len, _proto(skb),
				_seq(skb));
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
			"skb: %p len %u data_len %u proto %u seq %u dst_mtu(skb) %d\n",
			skb, (uint)skb->len, skb->data_len, _proto(skb),
			_seq(skb), (int)dst_mtu(dst));
	}

	if (was_gso)
		pr_devinf("queued %u of %u from gso skb\n", qcount, count);
	else if (count)
		pr_devinf("%s received non-gso skb\n",
			  qcount ? "queued" : "dropped");

	/* Start a delay timer if we don't have one yet */
	if (!hrtimer_is_queued(&xtfs->iptfs_timer)) {
		pr_devinf("starting drop timer for reassembly\n");
		/* softirq blocked lest the timer fire and interrupt us */
		BUG_ON(!in_interrupt());
		hrtimer_start(&xtfs->iptfs_timer, xtfs->init_delay_ns,
			      IPTFS_HRTIMER_MODE);

		xtfs->iptfs_settime = ktime_get_raw_fast_ns();
		pr_devinf("settime <- %llu\n", xtfs->iptfs_settime);
	}

	spin_unlock_bh(&x->lock);
	return 0;
}

/* -------------------------- */
/* Dequeue and send functions */
/* -------------------------- */

static int iptfs_xfrm_output(struct sk_buff *skb, uint remaining)
{
	int err;

	pr_devinf("output skb %p, total len %u remaining space %u\n", skb,
		  skb->len, remaining);
	err = xfrm_output(NULL, skb);
	if (err < 0)
		pr_warn_ratelimited("xfrm_output error: %d", err);
	return err;
}

static void iptfs_output_prepare_skb(struct sk_buff *skb, uint blkoff)
{
	struct ip_iptfs_hdr *h;
	size_t hsz = sizeof(*h);

	/* now reset values to be pointing at the rest of the packets */
	h = skb_push(skb, hsz);
	memset(h, 0, hsz);
	if (blkoff)
		h->block_offset = htons(blkoff);

	/*
	 * network_header current points at the inner IP packet
	 * move it to the iptfs header
	 */
	skb->transport_header = skb->network_header;
	skb->network_header -= hsz;

	IPCB(skb)->flags |= IPSKB_XFRM_TUNNEL_SIZE;

	/* xfrm[46]_prepare_output sets skb->protocol here, but the resulting
	 * called ip[6]_output functions also set this value as appropriate so
	 * seems unnecessary
	 *
	 * skb->protocol = htons(ETH_P_IP) or htons(ETH_P_IPV6);
	 */
}

static int iptfs_first_skb(struct sk_buff **skbp, bool df, uint mtu,
			   uint blkoff)
{
	struct sk_buff *skb = *skbp;
	struct sk_buff *nskb;
	int err;

	/*
	 * Classic ESP skips the don't fragment ICMP error if DF is clear on
	 * the inner packet or ignore_df is set. Otherwise it will send an ICMP
	 * or local error if the inner packet won't fit it's MTU.
	 *
	 * With IPTFS we do not care about the inner packet DF bit. If the
	 * tunnel is configured to "don't fragment" we error back if things
	 * don't fit in our max packet size. Otherwise we iptfs-fragment as
	 * normal.
	 */

	/* The opportunity for HW offload has ended */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		BUG_ON(blkoff);
		err = skb_checksum_help(skb);
		if (err)
			return err;
	}

	/* We've split these up before queuing */
	BUG_ON(skb_is_gso(skb));

	/* mtu accounted for all the overhead including the basic header size */
	if (skb->len > mtu) {
		if (df) {
			/* pop the iptfs header back off */
			pr_devinf(
				"skb: DF too big len %u mtu %d proto %u seq %u\n",
				(uint)skb->len, mtu, _proto(skb), _seq(skb));
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMOUTERROR);

			if (skb->sk)
				xfrm_local_error(skb, mtu);
			else
				icmp_send(skb, ICMP_DEST_UNREACH,
					  ICMP_FRAG_NEEDED, htonl(mtu));
			return -EMSGSIZE;
		}

		pr_devinf(
			"skb: iptfs-df-not-set len %u mtu %d blkoff %u proto %u seq %u\n",
			(uint)skb->len, mtu, blkoff, _proto(skb), _seq(skb));

		/* A user packet has come in on from an interface with larger
		 * MTU than the IPTFS tunnel pktsize -- we need to fragment.
		 *
		 * orig ====> orig       clone      clone
		 * skb         skb        1          2
		 *+--+ head   +--+ head  +--+ head  +--+ head
		 *|  |	      |  |	 |  |	    |  |
		 *+--+ data   +--+ data  |  |       |  |        ---
		 *|x |	      |x |	 |  |       |  |         |
		 *|x |	      |x |	 |  |       |  |        mtu
		 *|x |        |x |	 |  |       |  |         |
		 *|x | ====>  +--+ tail  +--+ data  |  |        ---
		 *|x |        |  |	 |x |       |  |         |
		 *|x |	      |  |	 |x |       |  |        mtu
		 *|x |	      |  |	 |x |       |  |         |
		 *|x |	      |  |	 +--+ tail  +--+ data   ---
		 *|x |	      |  |	 |  |	    |x |         | fraglen
		 *+--+ tail   |  |       |  |	    +--+ tail   ---
		 *|  |	      |  |	 |  |	    |  |
		 *+--+ end    +--+ end   +--+ end    +--+ end
		 *
		 * We need a linear buffer for the above. Do some performance
		 * testing, if this is a problem try really complex page sharing
		 * thing if we have to. This is not a common code path, though.
		 */
		if (skb_is_nonlinear(skb)) {
			pr_info_once("LINEARIZE: skb len %u\n", skb->len);
			err = __skb_linearize(skb);
			if (err) {
				XFRM_INC_STATS(dev_net(skb->dev),
					       LINUX_MIB_XFRMOUTERROR);
				pr_err_ratelimited("skb_linearize failed\n");
				return err;
			}
		}

		/* loop creating skb clones of the data until we have enough iptfs packets */
		while (skb->len > mtu) {
			nskb = skb_clone(skb, GFP_ATOMIC);
			if (!nskb) {
				XFRM_INC_STATS(dev_net(skb->dev),
					       LINUX_MIB_XFRMOUTERROR);
				pr_err_ratelimited("failed to clone skb\n");
				return -ENOMEM;
			}

			/* this skb set to mtu len, next pull down mtu len */
			__skb_set_length(skb, mtu);
			__skb_pull(nskb, mtu);

			/* output the full iptfs packet in skb */
			iptfs_output_prepare_skb(skb, blkoff);
			iptfs_xfrm_output(skb, 0);

			/* nskb->len is the remaining amount until next packet */
			blkoff = nskb->len;

			*skbp = skb = nskb;
		}
	}

	iptfs_output_prepare_skb(skb, blkoff);

	return 0;
}

static struct sk_buff **iptfs_rehome_fraglist(struct sk_buff **nextp,
					      struct sk_buff *child)
{
	uint fllen = 0;

	BUG_ON(!skb_has_frag_list(child));
	pr_devinf("2nd skb2 has frag list collapsing\n");
	/*
	 * I think it might be possible to account for
	 * a frag list in addition to page fragment if
	 * it's a valid state to be in. The page
	 * fragments size should be kept as data_len
	 * so only the frag_list size is removed, this
	 * must be done above as well took
	 */
	BUG_ON(skb_shinfo(child)->nr_frags);
	*nextp = skb_shinfo(child)->frag_list;
	while (*nextp) {
		fllen += (*nextp)->len;
		nextp = &(*nextp)->next;
	}
	skb_frag_list_init(child);
	BUG_ON(fllen > child->data_len);
	child->len -= fllen;
	child->data_len -= fllen;

	return nextp;
}

/*
 * Return if we should fragment skb using `remaining` octets.
 * For now we just say yes; however, we can do smarter things here. For example,
 * see that out output queue is not growing over time then we could wait to send
 * this skb in it's own packet avoiding fragmentation.
 *
 * TODO: add a short history of queue sizes when we unload the queue and use
 * this to determine if we should fragment.
 *
 * We also do not try and fragment non-linerar skbs or create tiny fragments
 * heads less than enough to container IP/IPv6 packet length field.
 */
static bool iptfs_should_fragment(struct sk_buff *skb, uint mtu, uint remaining)
{
	if (skb_is_nonlinear(skb))
		return false;
	return remaining >= 6; // true;
}

static void iptfs_output_queued(struct xfrm_state *x, struct sk_buff_head *list)
{
	struct xfrm_iptfs_data *xtfs = x->tfs_data;
	uint payload_mtu = xtfs->payload_mtu;
	bool df = xtfs->cfg.dont_frag;
	struct sk_buff *skb, *skb2, *nskb, **nextp;
	uint blkoff;

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

	/* blkoff is the offset to the start of the next packet if a fragment
	 * is at the start
	 */
	blkoff = 0;

	/* and send them on their way */

	while ((skb = __skb_dequeue(list))) {
		uint mtu = dst_mtu(skb_dst(skb));
		int remaining;

		if (payload_mtu && payload_mtu < mtu)
			mtu = payload_mtu;
		remaining = mtu;

		pr_devinf(
			"1st dequeue skb %p len %u data_len %u proto %u seq %u blkoff %u\n",
			skb, skb->len, skb->data_len, _proto(skb), _seq(skb),
			blkoff);

		if (iptfs_first_skb(&skb, df, mtu, blkoff)) {
			kfree_skb(skb);
			continue;
		}

		/*
		 * The MTU has the basic IPTFS header len inc, and we added that
		 * header to the first skb, so subtract from the skb length
		 */
		remaining -= (skb->len - sizeof(struct ip_iptfs_hdr));

		/*
		 * we are starting over now, no fragmentation yet.
		 */
		blkoff = 0;

		nextp = &skb_shinfo(skb)->frag_list;
		while (*nextp) {
			if (skb_has_frag_list(*nextp))
				nextp = iptfs_rehome_fraglist(&(*nextp)->next,
							      *nextp);
			else
				nextp = &(*nextp)->next;
		}

		/* See if we have enough space to simply append */
		while ((skb2 = skb_peek(list)) && skb2->len <= remaining) {
			__skb_unlink(skb2, list);

			/* The opportunity for HW offload has ended */
			if (skb2->ip_summed == CHECKSUM_PARTIAL) {
				if (skb_checksum_help(skb2)) {
					XFRM_INC_STATS(
						dev_net(skb_dst(skb2)->dev),
						LINUX_MIB_XFRMOUTERROR);
					kfree_skb(skb2);
					continue;
				}
			}

			pr_devinf(
				"append secondary dequeue skb2 %p len %u data_len %u proto %u seq %u\n",
				skb2, skb2->len, skb2->data_len, _proto(skb2),
				_seq(skb2));

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
			if (skb_has_frag_list(skb2))
				nextp = iptfs_rehome_fraglist(nextp, skb2);

			remaining -= skb2->len;
		}

		/*
		 * Check to see if we had a packet that didn't fit that we could
		 * fragment into the current iptfs skb.
		 */
		if (!df && skb2 && !skb_has_frag_list(skb2) &&
		    iptfs_should_fragment(skb2, mtu, remaining)) {
			struct sk_buff *head_skb;

			/* XXX remove this when we start sharing page frags */
			BUG_ON(skb_is_nonlinear(skb2));

			/* The opportunity for HW offload has ended */
			if (skb2->ip_summed == CHECKSUM_PARTIAL) {
				if (skb_checksum_help(skb2)) {
					BUG_ON(skb2 != __skb_dequeue(list));
					XFRM_INC_STATS(
						dev_net(skb_dst(skb2)->dev),
						LINUX_MIB_XFRMOUTERROR);
					kfree_skb(skb2);
					goto sendit;
				}
			}

			head_skb = iptfs_alloc_header_skb();
			if (!head_skb)
				goto sendit;

			nskb = skb_clone(skb2, GFP_ATOMIC);
			if (!nskb) {
				consume_skb(head_skb);
				XFRM_INC_STATS(dev_net(skb->dev),
					       LINUX_MIB_XFRMOUTERROR);
				pr_err_ratelimited("failed to clone skb\n");
				goto sendit;
			}

			/* Dequeue now that there's no chance of error */
			__skb_unlink(skb2, list);

			/* copy a couple selected items from skb2 into new head skb */
			head_skb->tstamp = skb2->tstamp;
			head_skb->dev = skb2->dev;
			memcpy(head_skb->cb, skb2->cb, sizeof(skb2->cb));
			skb_dst_copy(head_skb, skb2);
			__skb_ext_copy(head_skb, skb2);
			__nf_copy(head_skb, skb2, false);

			pr_devinf(
				"appending skb as fragment: skb2->len %u skb2->data_len %u\n",
				skb2->len, skb2->data_len);

			/* Set skb2 to remaining avail len, pull down remainning
			 * from the clone nskb.
			 */
			__skb_set_length(skb2, remaining);
			__skb_pull(nskb, remaining);

			/* put leftovers into blank head skb */
			skb_shinfo(head_skb)->frag_list = nskb;
			head_skb->len += nskb->len;
			head_skb->data_len += nskb->len;
			head_skb->truesize += nskb->truesize;
			blkoff = head_skb->len;

			pr_devinf(
				"append fragment len %u data_len %u proto %u seq %u\n"
				"new head and leftover on queue with remaining len %u data_len %u\n",
				skb2->len, skb2->data_len, _proto(skb2),
				_seq(skb2), head_skb->len, head_skb->data_len);

			/* link skb2 into current packet */
			*nextp = skb2;
			nextp = &skb2->next;
			BUG_ON(*nextp != NULL);
			skb->data_len += skb2->len;
			skb->len += skb2->len;
			skb->truesize += skb2->truesize;

			if (skb_has_frag_list(skb2))
				nextp = iptfs_rehome_fraglist(nextp, skb2);

			remaining -= skb2->len;
			BUG_ON(remaining != 0);

			/* put the new head skb back on the top of the queue */
			__skb_queue_head(list, head_skb);
		}
	sendit:
		iptfs_xfrm_output(skb, remaining);
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

	pr_devinf("got %u packets of %u total len\n", (uint)list.qlen,
		  (uint)osize);
	pr_devinf("time delta %llu\n",
		  (unsigned long long)(ktime_get_raw_fast_ns() - settime));

	iptfs_output_queued(x, &list);

	return HRTIMER_NORESTART;
}
