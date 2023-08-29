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
#include <net/ip6_route.h>
#include <net/inet_ecn.h>
#include <net/iptfs.h>
#include <net/xfrm.h>

#include <crypto/aead.h>

#include "xfrm_inout.h"
#include "trace_iptfs.h"

#define XFRM_IPTFS_MIN_HEADROOM 128

#define NSECS_IN_USEC 1000

#define IPTFS_TYPE_NOCC 0
#define IPTFS_TYPE_CC 1

/* #define IPTFS_ENET_OHEAD (14 + 4 + 8 + 12) */
/* #define GE_PPS(ge, iptfs_ip_mtu) ((1e8 * 10 ^ (ge - 1) / 8) / (iptfs_ip_mtu)) */

#undef PR_DEBUG_INFO
#define PR_DEBUG_STATE
#define PR_DEBUG_INGRESS
#define PR_DEBUG_EGRESS

#ifdef PR_DEBUG_INFO
#define _pr_devinf(...) pr_info(__VA_ARGS__)
#else
#define _pr_tracek(fmt, ...) trace_printk(fmt, ##__VA_ARGS__)
#define _pr_devinf(fmt, ...) _pr_tracek(pr_fmt(fmt), ##__VA_ARGS__)
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

static u32 __iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu);
static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me);
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me);

/* For leaking */
static struct kmem_cache *iptfs_leak_cache __ro_after_init;

/* ================= */
/* Utility Functions */
/* ================= */

static inline uint iptfs_payload_proto(struct sk_buff *skb)
{
	if (((struct iphdr *)skb->data)->version == 4)
		return ((struct iphdr *)skb->data)->protocol;
	return ((struct ipv6hdr *)skb->data)->nexthdr;
}

static inline uint iptfs_payload_proto_seq(struct sk_buff *skb)
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

#define _proto(skb) iptfs_payload_proto(skb)
#define _seq(skb) iptfs_payload_proto_seq(skb)

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

/* ================================== */
/* IPTFS Trace Event Definitions      */
/* ================================== */

#define CREATE_TRACE_POINTS
#include "trace_iptfs.h"

/* ================================== */
/* IPTFS Receiving (egress) Functions */
/* ================================== */

#undef pr_fmt
#ifdef PR_DEBUG_INFO
#define pr_fmt(fmt) "%s: EGRESS: " fmt, __func__
#else
#define pr_fmt(fmt) "EGRESS: " fmt
#endif
#undef pr_devinf
#ifdef PR_DEBUG_EGRESS
#define pr_devinf(...) _pr_devinf(__VA_ARGS__)
#else
#define pr_devinf(...)
#endif

/**
 * skb_copy_bits_seq - copy bits from a skb_seq_state to kernel buffer
 * @st: source skb_seq_state
 * @offset: offset in source
 * @to: destination buffer
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @offset bytes into the the source @st to the destination
 * buffer @to.
 *
 * TODO: this is generically named with the belief that this function belongs
 * along with theu other skb_..._seq functions.
 */
static int skb_copy_bits_seq(struct skb_seq_state *st, int offset, void *to, int len)
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

static struct sk_buff *iptfs_alloc_skb(struct sk_buff *tpl, uint len)
{
	struct sk_buff *skb;
	uint resv = skb_headroom(tpl);

	if (resv < XFRM_IPTFS_MIN_HEADROOM)
		resv = XFRM_IPTFS_MIN_HEADROOM;

	skb = alloc_skb(len + resv, GFP_ATOMIC);
	if (!skb) {
		XFRM_INC_STATS(dev_net(tpl->dev), LINUX_MIB_XFRMINERROR);
		pr_err_ratelimited("failed to alloc skb resv %u\n", len + resv);
		return NULL;
	}

	pr_devinf("len %u resv %u skb %p\n", len, resv, skb);

	skb_reserve(skb, resv);
	skb_copy_header(skb, tpl);

	/* Let's not copy the checksum */
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
 * iptfs_pskb_extract_seq() - Create and load data into a new sk_buff.
 * @skblen: the total data size for `skb`.
 * @resv: the amount of space to reserve for headers.
 * @st: The source for the rest of the data to copy into `skb`.
 * @off: The offset into @st to copy data from.
 * @len: The length of data to copy from @st into `skb`. This must be <=
 *       @skblen.
 *
 * Create a new sk_buff `skb` with @skblen of packet data space plus @resv
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

/**
 * iptfs_input_save_runt() - save data in xtfs runt space
 *
 * Save the small (`len`) start of a fragmented packet in `buf` in the xtfs data
 * runt space.
 */
static inline void iptfs_input_save_runt(struct xfrm_iptfs_data *xtfs, u64 seq,
					 u8 *buf, int len)
{
	BUG_ON(xtfs->ra_newskb); /* we won't have a new SKB yet */

	pr_devinf("saving runt len %u, exp seq %llu\n", len, seq);
	memcpy(xtfs->ra_runt, buf, len);

	xtfs->ra_runtlen = len;
	xtfs->ra_wantseq = seq + 1;
}

/**
 * __iptfs_iplen() - return the v4/v6 length using packet data.
 *
 * Grab the IPv4 or IPv6 length value in the start of the inner packet header
 * pointed to by `data`. Assumes data len is enough for the length field only.
 */
static uint __iptfs_iplen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	if (iph->version == 0x4)
		return ntohs(iph->tot_len);
	BUG_ON(iph->version != 0x6);
	return ntohs(((struct ipv6hdr *)iph)->payload_len) +
	       sizeof(struct ipv6hdr);
}

/**
 * iptfs_complete_inner_skb() - finish preparing the inner packet for gro recv.
 *
 * Finish the standard xfrm processing on the inner packet prior to sending back
 * through gro_cells_receive. We do this separately b/c we are building a list
 * of packets in the hopes that one day a list will be taken by
 * xfrm_input.
 */
static void iptfs_complete_inner_skb(struct xfrm_state *x, struct sk_buff *skb)
{
	skb_reset_network_header(skb);

	/* The packet is going back through gro_cells_receive no need to
	 * set this.
	 */
	skb_reset_transport_header(skb);

	/*
	 * Our skb will contain the header data copied when this outer packet
	 * which contained the start of this inner packet. This is true
	 * when we allocate a new skb as well as when we reuse the existing skb.
	 */
	if (ip_hdr(skb)->version == 0x4) {
		struct iphdr *iph = ip_hdr(skb);

		pr_devinf("completing inner, iplen %u skb len %u\n",
			  ntohs(iph->tot_len), skb->len);

		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv4_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP_ECN_set_ce(iph);

		skb->protocol = htons(ETH_P_IP);
	} else {
		struct ipv6hdr *iph = ipv6_hdr(skb);

		pr_devinf("completing inner, payload len %u skb len %u\n",
			  ntohs(ipv6_hdr(skb)->payload_len), skb->len);

		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv6_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP6_ECN_set_ce(skb, iph);

		skb->protocol = htons(ETH_P_IPV6);
	}
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
#ifdef PR_DEBUG_EGRESS
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
	 * assembly, a newer sequence number indicates older ones are not coming
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
			"bad recv blkoff: blkoff %u < ip remaining %u seq %llu\n",
			blkoff, ipremain, seq);
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

	/* TODO: update or clear cksum for the reconstructed packet in skb? */

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
		iptfs_complete_inner_skb(xtfs->x, newskb);
		list_add_tail(&newskb->list, list);
	}

	/* will continue on to new data block or end */
	return data + fraglen;
}

/* checkout skb_segment to see if it has much of iptfs_input_ordered in it. */

/*
 * We have an IPTFS payload dispense with it and this skb as well.
 */
static int iptfs_input_ordered(struct xfrm_state *x, struct sk_buff *skb)
{
	// void *leak;
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

	xtfs = x->mode_data;
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
			/* XXX double check that we are handling payload len
			 * correctly in IPv6 it does *NOT* contain the base
			 * header length
			 */

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
				 * TODO: talk about how this is re-using tailroom
				 * for future fragment copyin
				 */
				tmp = skb->data;
				pskb_pull(skb, data);

				/* TODO: do these rcsums work with pskb variants? */
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
			skb = iptfs_pskb_extract_seq(iplen, resv, &skbseq, data,
						     capturelen);
			if (!skb) {
				data += capturelen;
				continue;
			}
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

		iptfs_complete_inner_skb(x, skb);
		list_add_tail(&skb->list, &sublist);
	}

	if (data != tail) {
		/* this should not happen from the above code */
		pr_err_ratelimited("error data(%u) != tail(%u)\n", data, tail);
	}

	if (first_skb && first_iplen && !defer && first_skb != xtfs->ra_newskb) {
		/* first_skb is queued b/c !defer and not partial */
		if (pskb_trim_rcsum(first_skb, first_iplen)) {
			/* error trimming */
			pr_warn_once("pskb_trim_rcsum failed\n");
			list_del(&first_skb->list);
			defer = first_skb;
		}
	}

	/* Send the packets! */
	list_for_each_entry_safe (skb, next, &sublist, list) {
		BUG_ON(skb == defer);
		skb_list_del_init(skb);
		pr_devinf(
			"resume sending inner packet len %u skb %p proto %u seq/port %u\n",
			(uint)skb->len, skb, _proto(skb), _seq(skb));

		// leak = kmem_cache_alloc(iptfs_leak_cache, GFP_ATOMIC);
		if (xfrm_input(skb, 0, 0, -3))
			kfree_skb(skb);
		// (void)leak;
	}

	/* safe to call even if we were done */
done:
	skb = skbseq.root_skb;
	skb_abort_seq_read(&skbseq);

	if (defer) {
		pr_devinf("calling consume_skb: skb=%p\n", defer);
		consume_skb(defer);
	} else if (!first_skb) {
		/* skb is the original passed in skb, but we didn't get far
		 * enough to process it as the first_skb, if we had it would
		 * either be save in ra_newskb, trimmed and sent on as an skb or
		 * placed in defer to be freed.
		 */
		BUG_ON(!skb);
		pr_devinf("freeing skb: skb=%p\n", skb);
		kfree_skb(skb);
	}

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
			(void)iptfs_input_ordered(x, skb);
		}
	}
	return HRTIMER_NORESTART;
}

/*
 * We have an IPTFS payload order it if needed.
 */
static int iptfs_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct list_head freelist, list;
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct sk_buff *next;
	uint count, fcount;

	/* Fast path for no reorder window. */
	if (xtfs->cfg.reorder_win_size == 0) {
		iptfs_input_ordered(x, skb);
		goto done;
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
			(void)iptfs_input_ordered(x, skb);
		}
	}

	if (fcount) {
		pr_devinf("freeing list of len %u\n", fcount);
		list_for_each_entry_safe (skb, next, &freelist, list) {
			skb_list_del_init(skb);
			kfree_skb(skb);
		}
	}
done:
	/* We always have dealt with the input SKB, either we are re-using it,
	 * or we have freed it. Return EINPROGRESS so that xfrm_input stops
	 * processing it.
	 */
	return -EINPROGRESS;
}

/* ================================= */
/* IPTFS Sending (ingress) Functions */
/* ================================= */

#undef pr_fmt
#ifdef PR_DEBUG_INFO
#define pr_fmt(fmt) "%s: INGRESS: " fmt, __func__
#else
#define pr_fmt(fmt) "INGRESS: " fmt
#endif
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

static int iptfs_get_cur_pmtu(struct xfrm_state *x, struct xfrm_iptfs_data *xtfs,
			     struct sk_buff *skb)
{
	struct xfrm_dst *xdst = (struct xfrm_dst *)skb_dst(skb);
	uint payload_mtu = xtfs->payload_mtu;
	uint pmtu = __iptfs_get_inner_mtu(x, xdst->child_mtu_cached);

	if (payload_mtu && payload_mtu < pmtu)
		pmtu = payload_mtu;

	return pmtu;
}

static int iptfs_is_too_big(struct sock *sk, struct sk_buff *skb, uint pmtu)
{
	struct flowi6 fl6;

	if (skb->len <= pmtu)
		return 0;

	/*
	 * We only send ICMP too big if the user has configured us as
	 * dont-fragment. We need to adjust something in the
	 * stack as we are never getting here (good) even when
	 * our no DF config is set (bad).
	 */
	XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMOUTERROR);

	if (!sk)
		sk = skb->sk;
	if (sk) {
		/* TODO: can these be different? */
		sk = skb->sk ? skb->sk : sk;

		if (ip_hdr(skb)->version == 4)
			xfrm_local_error(skb, pmtu);
		else {
			WARN_ON_ONCE(ip_hdr(skb)->version != 6);

			memset(&fl6, 0, sizeof(fl6));
			ipv6_local_error(skb->sk, EMSGSIZE, &fl6, pmtu);
		}
	} else if (ip_hdr(skb)->version == 4)
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(pmtu));
	else {
		WARN_ON_ONCE(ip_hdr(skb)->version != 6);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, pmtu);
	}
	return 1;
}

/*
 * IPv4/IPv6 packet ingress to IPTFS tunnel, arrange to send in IPTFS payload
 * (i.e., aggregating or fragmenting as appropriate).
 * This is set in dst->output for an SA.
 */
static int iptfs_output_collect(struct net *net, struct sock *sk,
				struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct sk_buff *segs, *nskb;
	uint count, qcount;
	uint pmtu = 0;
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

	if (xtfs->cfg.dont_frag)
		pmtu = iptfs_get_cur_pmtu(x, xtfs, skb);

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
			/* TODO: better stat here. */
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
			kfree_skb(skb);
			return PTR_ERR(segs);
		}
		consume_skb(skb);
		skb = NULL;
	}

	count = qcount = 0;

	/* We can be running on multiple cores and from the network softirq or
	 * from user context depending on where the packet is coming from.
	 */
	spin_lock_bh(&x->lock);

	skb_list_walk_safe (segs, segs, nskb) {
		skb = segs;
		skb_mark_not_on_list(segs);
		count++;

		/* Once we drop due to no queue space we continue to drop the
		 * rest of the packets from that GRO.
		 */
		if (!ok) {
		nospace:
			trace_iptfs_no_queue_space(skb, xtfs, pmtu, was_gso);
			kfree_skb_reason(skb, SKB_DROP_REASON_FULL_RING);
			continue;
		}

		/* If the user indicated no iptfs fragmenting check before
		 * enqueuing.
		 */
		if (xtfs->cfg.dont_frag && iptfs_is_too_big(sk, skb, pmtu)) {
			trace_iptfs_too_big(skb, xtfs, pmtu, was_gso);
			kfree_skb_reason(skb, SKB_DROP_REASON_PKT_TOO_BIG);
			continue;
		}

		/*
		 * Enqueue to send in tunnel
		 */

		if (!(ok = iptfs_enqueue(xtfs, skb)))
			goto nospace;

		trace_iptfs_enqueue(skb, xtfs, pmtu, was_gso);
		qcount++;

	}

	if (was_gso)
		pr_devinf("queued %u of %u from gso skb\n", qcount, count);
	else if (count)
		pr_devinf("%s received non-gso skb\n",
			  qcount ? "queued" : "dropped");

	/* Start a delay timer if we don't have one yet */
	if (!hrtimer_is_queued(&xtfs->iptfs_timer)) {
		/* softirq blocked lest the timer fire and interrupt us */
		BUG_ON(!in_interrupt());
		hrtimer_start(&xtfs->iptfs_timer, xtfs->init_delay_ns,
			      IPTFS_HRTIMER_MODE);

		xtfs->iptfs_settime = ktime_get_raw_fast_ns();
		trace_iptfs_timer_start(xtfs, xtfs->init_delay_ns);
	}

	spin_unlock_bh(&x->lock);
	return 0;
}

/* -------------------------- */
/* Dequeue and send functions */
/* -------------------------- */

#if 0
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
	return skb;
}
#endif

static struct sk_buff *iptfs_copy_some_skb(struct sk_buff *src, uint copy_len)
{
	struct sk_buff *skb;
	struct sec_path *sp;
	uint resv = XFRM_IPTFS_MIN_HEADROOM;
	uint i;

	skb = alloc_skb(copy_len + resv, GFP_ATOMIC);
	if (!skb) {
		XFRM_INC_STATS(dev_net(src->dev), LINUX_MIB_XFRMINERROR);
		pr_err_ratelimited("failed to alloc skb resv %u\n",
				   copy_len + resv);
		return NULL;
	}

	pr_devinf("len %u resv %u skb %p\n", copy_len, resv, skb);

	skb_reserve(skb, resv);
	skb_copy_header(skb, src);

	/* inc refcnt on copied xfrm_state in secpath */
	sp = skb_sec_path(skb);
	if (sp)
		for (i = 0; i < sp->len; i++)
			xfrm_state_hold(sp->xvec[i]);

	skb->csum = 0;
	skb->ip_summed = CHECKSUM_NONE;

	/* Now copy `copy_len` data from src */
	memcpy(skb_put(skb, copy_len), src->data, copy_len);

	return skb;
}

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

static int iptfs_first_skb(struct sk_buff **skbp, struct xfrm_iptfs_data *xtfs,
			   uint mtu)
{
	struct sk_buff *skb = *skbp;
	struct sk_buff *nskb, *head_skb;
	uint blkoff;
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
		err = skb_checksum_help(skb);
		if (err)
			return err;
	}

	/* We've split these up before queuing */
	BUG_ON(skb_is_gso(skb));

	trace_iptfs_first_dequeue(skb, xtfs, mtu, 0);

	/* See if it fits -- mtu accounted for all the overhead including the
	 * basic IPTFS header.
	 */
	if (skb->len <= mtu) {
		iptfs_output_prepare_skb(skb, 0);
		return 0;
	}

	BUG_ON(xtfs->cfg.dont_frag);

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
		pr_info_ratelimited(
			"LINEARIZE skb->len=%u skb->data_len=%u skb->nr_frags=%u skb->frag_list=%p\n",
			skb->len, skb->data_len, skb_shinfo(skb)->nr_frags,
			skb_shinfo(skb)->frag_list);
		err = __skb_linearize(skb);
		if (err) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMOUTERROR);
			pr_err_ratelimited("skb_linearize failed\n");
			return err;
		}
	}

	/* loop creating skb copies of the data until we have enough iptfs packets */
	nskb = NULL;
	head_skb = NULL;
	blkoff = 0;
	while (skb->len > mtu) {
		nskb = iptfs_copy_some_skb(skb, mtu);
		if (!nskb) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMOUTERROR);
			pr_err_ratelimited("failed to clone skb\n");
			return -ENOMEM;
		}
		__skb_pull(skb, mtu);

		trace_iptfs_first_fragmenting(nskb, xtfs, mtu, blkoff);

		iptfs_output_prepare_skb(nskb, blkoff);
		iptfs_xfrm_output(nskb, 0);

		/* skb->len is the remaining amount until next inner packet */
		blkoff = skb->len;
	}

	trace_iptfs_first_final_fragment(skb, xtfs, mtu, blkoff);

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

static void iptfs_output_queued(struct xfrm_state *x, struct sk_buff_head *list)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	uint payload_mtu = xtfs->payload_mtu;
	struct sk_buff *skb, *skb2, **nextp;

	/* For now we are just outputting packets as fast as we can, so if we
	 * are fragmenting we will do so until the last inner packet has been
	 * consumed.
	 *
	 * When we are fragmenting we need to output all outer packets that
	 * contain the fragments of a single inner packet, consecutively (ESP
	 * seq-wise). So we need a lock to keep another CPU from sending the
	 * next batch of packets (it's `list`) and trying to output those, while
	 * we output our `list` resuling with interleaved non-spec-client inner
	 * packet streams. Thus we need to lock the IPTFS output on a per SA
	 * basis while we process this list.
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

	/* and send them on their way */

	while ((skb = __skb_dequeue(list))) {
		struct xfrm_dst *xdst = (struct xfrm_dst *)skb_dst(skb);
		uint mtu = __iptfs_get_inner_mtu(x, xdst->child_mtu_cached);
		int remaining;

		/* protocol comes to us cleared sometimes */
		skb->protocol = x->outer_mode.family == AF_INET ?
					htons(ETH_P_IP) :
					htons(ETH_P_IPV6);

		if (payload_mtu && payload_mtu < mtu)
			mtu = payload_mtu;

		if (skb->len > mtu && xtfs->cfg.dont_frag) {
			/* We handle this cas before enqueueing so we are only
			 * here b/c MTU changed after we enqueued before we
			 * dequeued, just drop these.
			 */
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMOUTERROR);

			trace_iptfs_first_toobig(skb, xtfs, mtu, 0);
			kfree_skb_reason(skb, SKB_DROP_REASON_PKT_TOO_BIG);
			continue;
		}

		remaining = mtu;

		if (iptfs_first_skb(&skb, xtfs, mtu)) {
			kfree_skb(skb);
			continue;
		}

		/*
		 * The MTU has the basic IPTFS header len inc, and we added that
		 * header to the first skb, so subtract from the skb length
		 */
		remaining -= (skb->len - sizeof(struct ip_iptfs_hdr));

		/* Rehome fragment lists so we don't have fragments lists of
		 * fragment lists.
		 */
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

			/* XXX free up XFRM extras? Not sure why this wouldn't
			 * happen as the list get's walked and freed but maybe
			 * this is out leak?
			 */
			// skb_ext_putskb_shinfo(skb)->frag_list = skb2;
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
		 * Consider fragmenting this skb2 that didn't fit. For demand
		 * driven variable sized IPTFS pkts, though this isn't buying
		 * a whole lot, especially if we are doing a copy which waiting
		 * to send in a new pkt would not.
		 */

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
	 * TODO: verify that a timer callback doesn't need to be re-entrant, i.e.,
	 * that it will never be running concurrently on different CPUs.
	 * If we have to be re-entrant we probably want a lock to avoid
	 * spewing packets out of order.
	 */

	pr_devinf("got %u packets of %u total len\n", (uint)list.qlen,
		  (uint)osize);
	trace_iptfs_timer_expire(xtfs,
		  (unsigned long long)(ktime_get_raw_fast_ns() - settime));

	iptfs_output_queued(x, &list);

	return HRTIMER_NORESTART;
}

/**
 * iptfs_encap_add_4 - add outer encaps
 *
 * This was originally taken from xfrm4_tunnel_encap_add. The reason for the
 * copy is that IP-TFS/AGGFRAG can have different functionality for how to set
 * the TOS/DSCP bits. Sets the protocol to a different value and doesn't do
 * anything with inner headers as they aren't pointing into a normal IP
 * singleton inner packet.
 */
static int iptfs_encap_add_4(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct iphdr *top_iph;
	int flags;

	skb_reset_inner_network_header(skb);
	skb_reset_inner_transport_header(skb);

	skb_set_network_header(skb, -(x->props.header_len - x->props.enc_hdr_len));
	skb->mac_header = skb->network_header + offsetof(struct iphdr, protocol);
	skb->transport_header = skb->network_header + sizeof(*top_iph);

	top_iph = ip_hdr(skb);
	top_iph->ihl = 5;
	top_iph->version = 4;
	top_iph->protocol = IPPROTO_AGGFRAG;

	/* DS disclosing depends on XFRM_SA_XFLAG_DONT_ENCAP_DSCP */
	if (x->props.extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)
		top_iph->tos = 0;
	else
		/* TODO: we need to actually acquire this value we are using */
		top_iph->tos = XFRM_MODE_SKB_CB(skb)->tos;

	top_iph->tos = INET_ECN_encapsulate(top_iph->tos,
					    XFRM_MODE_SKB_CB(skb)->tos);
	flags = x->props.flags;
	if (flags & XFRM_STATE_NOECN)
		IP_ECN_clear(top_iph);

	top_iph->frag_off = htons(IP_DF);
	top_iph->ttl = ip4_dst_hoplimit(xfrm_dst_child(dst));
	top_iph->saddr = x->props.saddr.a4;
	top_iph->daddr = x->id.daddr.a4;
	ip_select_ident(dev_net(dst->dev), skb, NULL);

	return 0;
}

/**
 * iptfs_encap_add_6 - add outer encaps
 *
 * This was originally taken from xfrm6_tunnel_encap_add. The reason for the
 * copy is that IP-TFS/AGGFRAG can have different functionality for how to set
 * the flow label and TOS/DSCP bits. It also sets the protocol to a different
 * value and doesn't do anything with inner headers as they aren't pointing into
 * a normal IP singleton inner packet.
 */
static int iptfs_encap_add_6(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct ipv6hdr *top_iph;
	int dsfield;

	skb_reset_inner_network_header(skb);
	skb_reset_inner_transport_header(skb);

	skb_set_network_header(skb,
			       -x->props.header_len + x->props.enc_hdr_len);
	skb->mac_header = skb->network_header +
			  offsetof(struct ipv6hdr, nexthdr);
	skb->transport_header = skb->network_header + sizeof(*top_iph);

	top_iph = ipv6_hdr(skb);
	top_iph->version = 6;
	memset(top_iph->flow_lbl, 0, sizeof(top_iph->flow_lbl));
	top_iph->nexthdr = IPPROTO_AGGFRAG;
	if (x->props.extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)
		dsfield = 0;
	else
		dsfield = XFRM_MODE_SKB_CB(skb)->tos;
	dsfield = INET_ECN_encapsulate(dsfield, XFRM_MODE_SKB_CB(skb)->tos);
	if (x->props.flags & XFRM_STATE_NOECN)
		dsfield &= ~INET_ECN_MASK;
	ipv6_change_dsfield(top_iph, 0, dsfield);
	top_iph->hop_limit = ip6_dst_hoplimit(xfrm_dst_child(dst));
	top_iph->saddr = *(struct in6_addr *)&x->props.saddr;
	top_iph->daddr = *(struct in6_addr *)&x->id.daddr;

	return 0;
}

static int iptfs_prepare_output(struct xfrm_state *x, struct sk_buff *skb)
{
	if (x->outer_mode.family == AF_INET)
		return iptfs_encap_add_4(x, skb);
	if (x->outer_mode.family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		return iptfs_encap_add_6(x, skb);
#else
		WARN_ON_ONCE(1);
		return -EAFNOSUPPORT;
#endif
	}
	WARN_ON_ONCE(1);
	return -EOPNOTSUPP;
}

/* ========================== */
/* State Management Functions */
/* ========================== */

#undef pr_fmt
#ifdef PR_DEBUG_INFO
#define pr_fmt(fmt) "%s: STATE: " fmt, __func__
#else
#define pr_fmt(fmt) "STATE: " fmt
#endif
#undef pr_devinf
#ifdef PR_DEBUG_STATE
#define pr_devinf(...) _pr_devinf(__VA_ARGS__)
#else
#define pr_devinf(...)
#endif

/**
 * __iptfs_get_inner_mtu() - return inner MTU with no fragmentation.
 */
static u32 __iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu)
{
	// struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct crypto_aead *aead;
	u32 blksize;

	aead = x->data;
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	return ((outer_mtu - x->props.header_len - crypto_aead_authsize(aead)) &
		~(blksize - 1)) -
	       2;
}

/**
 * iptfs_get_mtu() - return the inner MTU for an IPTFS xfrm.
 * @x:   XFRM state.
 * @outer_mtu: Outer MTU for the encapsulated packet.
 *
 * Return: Correct MTU taking in to account the encap overhead.
 */
static u32 iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;

	/* If not dont-frag we have no MTU */
	if (!xtfs->cfg.dont_frag)
		return x->outer_mode.family == AF_INET ? IP_MAX_MTU :
							 IP6_MAX_MTU;
	return __iptfs_get_inner_mtu(x, outer_mtu);
}

static int iptfs_user_init(struct net *net, struct xfrm_state *x,
			 struct nlattr **attrs)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
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

static int iptfs_copy_to_user(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct xfrm_iptfs_config *xc = &xtfs->cfg;
	int ret;

	pr_devinf("copy state %p to user\n", xtfs);

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

static int iptfs_create_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs;

	xtfs = kzalloc_node(sizeof(*xtfs), GFP_KERNEL, NUMA_NO_NODE);
	x->mode_data = xtfs;
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

	/*
	 * Modify type (esp) adjustment values
	 */
	if (x->props.family == AF_INET)
		x->props.header_len += sizeof(struct iphdr) + sizeof(struct ip_iptfs_hdr);
	else if (x->props.family == AF_INET6)
		x->props.header_len += sizeof(struct ipv6hdr) + sizeof(struct ip_iptfs_hdr);
        x->props.enc_hdr_len = sizeof(struct ip_iptfs_hdr);

	return 0;
}

static void iptfs_delete_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;

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

const static struct xfrm_mode_cbs iptfs_mode_cbs = {
	.owner = THIS_MODULE,
	.create_state = iptfs_create_state,
	.delete_state = iptfs_delete_state,
	.user_init = iptfs_user_init,
	.copy_to_user = iptfs_copy_to_user,
	.get_inner_mtu = iptfs_get_inner_mtu,
	.input = iptfs_input,
	.output = iptfs_output_collect,
	.prepare_output = iptfs_prepare_output,
};

static int __init xfrm_iptfs_init(void)
{
	int err;

	pr_info("xfrm_iptfs: IPsec IP-TFS tunnel mode module\n");

	err = xfrm_register_mode_cbs(XFRM_MODE_IPTFS, &iptfs_mode_cbs);
	if (err < 0)
		pr_info("%s: can't register IP-TFS\n", __func__);

	/*
	 * Create a cache we will leak out of.
	 */
	iptfs_leak_cache =
		kmem_cache_create("iptfs_leak_cache", 100, 0,
				  SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	return err;
}

static void __exit xfrm_iptfs_fini(void)
{
	xfrm_unregister_mode_cbs(XFRM_MODE_IPTFS);
}

module_init(xfrm_iptfs_init);
module_exit(xfrm_iptfs_fini);
MODULE_LICENSE("GPL");
