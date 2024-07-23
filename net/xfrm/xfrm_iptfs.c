// SPDX-License-Identifier: GPL-2.0
/* xfrm_iptfs: IPTFS encapsulation support
 *
 * April 21 2022, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2022, LabN Consulting, L.L.C.
 *
 */

#include <linux/kernel.h>
#include <linux/icmpv6.h>
#include <linux/skbuff_ref.h>
#include <net/gro.h>
#include <net/icmp.h>
#include <net/ip6_route.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>

#include <crypto/aead.h>

#include "xfrm_inout.h"

/* IPTFS encap (header) values. */
#define IPTFS_SUBTYPE_BASIC 0
#define IPTFS_SUBTYPE_CC 1

/**
 * IP-TFS default SA values (tunnel egress/dir-in)
 *
 * IPTFS_DEFAULT_DROP_TIME_USECS
 *        The default IPTFS drop time in microseconds. The drop time is the amount
 *        of time before a missing out-of-order IPTFS tunnel packet is considered
 *        lost. See also the reorder window.
 *
 *        Default 1s (1000000).
 */
#define IPTFS_DEFAULT_DROP_TIME_USECS	(1000000000ull) /* 1s */

/**
 * IP-TFS default SA values (tunnel ingress/dir-out)
 *
 * IPTFS_DEFAULT_INIT_DELAY_USECS
 *        The default IPTFS initial output delay in microseconds. The initial
 *        output delay is the amount of time prior to servicing the output queue
 *        after queueing the first packet on said queue. This applies anytime
 *        the output queue was previously empty.
 *
 *        Default 0.

 * IPTFS_DEFAULT_MAX_QUEUE_SIZE
 *        The default IPTFS max output queue size in octets. The output queue is
 *        where received packets destined for output over an IPTFS tunnel are
 *        stored prior to being output in aggregated/fragmented form over the
 *        IPTFS tunnel.
 *
 *        Default 1M.
 */
#define IPTFS_DEFAULT_INIT_DELAY_USECS	(0ull) /* no initial delay */
#define IPTFS_DEFAULT_MAX_QUEUE_SIZE	(1024 * 10240) /* 1MB */

/* 1) skb->head should be cache aligned.
 * 2) when resv is for L2 headers (i.e., ethernet) we want the cacheline to
 * start -16 from data.
 * 3) when resv is for L3+L2 headers IOW skb->data points at the IPTFS payload
 * we want data to be cache line aligned so all the pushed headers will be in
 * another cacheline.
 */
#define XFRM_IPTFS_MIN_L3HEADROOM 128
#define XFRM_IPTFS_MIN_L2HEADROOM (64 + 16)
#define IPTFS_FRAG_COPY_MAX 256 /* max for copying to create iptfs frags */
#define NSECS_IN_USEC 1000

#define IPTFS_HRTIMER_MODE HRTIMER_MODE_REL_SOFT

struct xfrm_iptfs_config {
	bool dont_frag : 1;
	u32 pkt_size;	    /* outer_packet_size or 0 */
	u32 max_queue_size; /* octets */
};

struct xfrm_iptfs_data {
	struct xfrm_iptfs_config cfg;

	/* Ingress User Input */
	struct xfrm_state *x;	   /* owning state */
	struct sk_buff_head queue; /* output queue */

	u32 queue_size;		    /* octets */
	u32 ecn_queue_size;	    /* octets above which ECN mark */
	u64 init_delay_ns;	    /* nanoseconds */
	struct hrtimer iptfs_timer; /* output timer */
	u32 payload_mtu;	    /* max payload size */

	/* Tunnel egress */
	spinlock_t drop_lock;
	struct hrtimer drop_timer;
	u64 drop_time_ns;

	/* Tunnel egress reassembly */
	struct sk_buff *ra_newskb; /* new pkt being reassembled */
	u64 ra_wantseq;		   /* expected next sequence */
	u8 ra_runt[6];		   /* last pkt bytes from last skb */
	u8 ra_runtlen;		   /* count of ra_runt */
};

static u32 __iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu);
static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me);
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me);

/* ================= */
/* Utility Functions */
/* ================= */

static u64 __esp_seq(struct sk_buff *skb)
{
	u64 seq = ntohl(XFRM_SKB_CB(skb)->seq.input.low);

	return seq | (u64)ntohl(XFRM_SKB_CB(skb)->seq.input.hi) << 32;
}

/* ================= */
/* SK_BUFF Functions */
/* ================= */

/**
 * iptfs_alloc_skb() - Allocate a new `skb` using a meta-data template.
 * @tpl: the template to copy the new `skb`s meta-data from.
 * @len: the linear length of the head data, zero is fine.
 * @l3resv: true if reserve needs to support pushing L3 headers
 *
 * A new `skb` is allocated and it's meta-data is initialized from `tpl`, the
 * head data is sized to `len` + reserved space set according to the @l3resv
 * boolean. When @l3resv is false, resv is XFRM_IPTFS_MIN_L2HEADROOM which
 * arranges for `skb->data - 16` (etherhdr space) to be the start of a cacheline.
 * Otherwise, @l3resv is true and resv is either the size of headroom from `tpl` or
 * XFRM_IPTFS_MIN_L3HEADROOM whichever is greater, which tries to align
 * skb->data to a cacheline as all headers will be pushed on the previous
 * cacheline bytes.
 *
 * When copying meta-data from the @tpl, the sk_buff->headers are not copied.
 *
 * Zero length skbs are allocated when we only need a head skb to hold new
 * packet headers (basically the mac header) that sit on top of existing shared
 * packet data.
 *
 * Return: the new skb or NULL.
 */
static struct sk_buff *iptfs_alloc_skb(struct sk_buff *tpl, u32 len,
				       bool l3resv)
{
	struct sk_buff *skb;
	u32 resv;

	if (!l3resv) {
		resv = XFRM_IPTFS_MIN_L2HEADROOM;
	} else {
		resv = skb_headroom(tpl);
		if (resv < XFRM_IPTFS_MIN_L3HEADROOM)
			resv = XFRM_IPTFS_MIN_L3HEADROOM;
	}

	skb = alloc_skb(len + resv, GFP_ATOMIC);
	if (!skb) {
		XFRM_INC_STATS(dev_net(tpl->dev), LINUX_MIB_XFRMINERROR);
		return NULL;
	}

	skb_reserve(skb, resv);

	/* Code from __copy_skb_header() -- we do not want any of the
	 * tpl->headers copied over, so we aren't using `skb_copy_header()`.
	 */
	skb->tstamp = tpl->tstamp;
	skb->dev = tpl->dev;
	memcpy(skb->cb, tpl->cb, sizeof(skb->cb));
	skb_dst_copy(skb, tpl);
	__skb_ext_copy(skb, tpl);
	__nf_copy(skb, tpl, false);

	return skb;
}

/**
 * skb_head_to_frag() - initialize a skb_frag_t based on skb head data
 * @skb: skb with the head data
 * @frag: frag to initialize
 */
static void skb_head_to_frag(const struct sk_buff *skb, skb_frag_t *frag)
{
	struct page *page = virt_to_head_page(skb->data);
	unsigned char *addr = (unsigned char *)page_address(page);

	BUG_ON(!skb->head_frag);
	skb_frag_fill_page_desc(frag, page, skb->data - addr, skb_headlen(skb));
}

/**
 * skb_copy_bits_seq - copy bits from a skb_seq_state to kernel buffer
 * @st: source skb_seq_state
 * @offset: offset in source
 * @to: destination buffer
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @offset bytes into the source @st to the destination
 * buffer @to. `offset` should increase (or be unchanged) with each subsequent
 * call to this function. If offset needs to decrease from the previous use `st`
 * should be reset first.
 *
 * Return: 0 on success or a negative error code on failure
 */
static int skb_copy_bits_seq(struct skb_seq_state *st, int offset, void *to,
			     int len)
{
	const u8 *data;
	u32 sqlen;

	for (;;) {
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

/* ================================== */
/* IPTFS Receiving (egress) Functions */
/* ================================== */

/**
 * iptfs_pskb_extract_seq() - Create and load data into a new sk_buff.
 * @skblen: the total data size for `skb`.
 * @st: The source for the rest of the data to copy into `skb`.
 * @off: The offset into @st to copy data from.
 * @len: The length of data to copy from @st into `skb`. This must be <=
 *       @skblen.
 *
 * Create a new sk_buff `skb` with @skblen of packet data space. If non-zero,
 * copy @rlen bytes of @runt into `skb`. Then using seq functions copy @len
 * bytes from @st into `skb` starting from @off.
 *
 * It is an error for @len to be greater than the amount of data left in @st.
 *
 * Return: The newly allocated sk_buff `skb` or NULL if an error occurs.
 */
static struct sk_buff *
iptfs_pskb_extract_seq(u32 skblen, struct skb_seq_state *st, u32 off, int len)
{
	struct sk_buff *skb = iptfs_alloc_skb(st->root_skb, skblen, false);

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
 * iptfs_input_save_runt() - save data in xtfs runt space.
 * @xtfs: xtfs state
 * @seq: the current sequence
 * @buf: packet data
 * @len: length of packet data
 *
 * Save the small (`len`) start of a fragmented packet in `buf` in the xtfs data
 * runt space.
 */
static void iptfs_input_save_runt(struct xfrm_iptfs_data *xtfs, u64 seq,
				  u8 *buf, int len)
{
	BUG_ON(xtfs->ra_newskb); /* we won't have a new SKB yet */

	memcpy(xtfs->ra_runt, buf, len);

	xtfs->ra_runtlen = len;
	xtfs->ra_wantseq = seq + 1;
}

/**
 * __iptfs_iphlen() - return the v4/v6 header length using packet data.
 * @data: pointer at octet with version nibble
 *
 * The version data is expected to be valid (i.e., either 4 or 6).
 *
 * Return: the IP header size based on the IP version.
 */
static u32 __iptfs_iphlen(u8 *data)
{
	struct iphdr *iph = (struct iphdr *)data;

	if (iph->version == 0x4)
		return sizeof(*iph);
	BUG_ON(iph->version != 0x6);
	return sizeof(struct ipv6hdr);
}

/**
 * __iptfs_iplen() - return the v4/v6 length using packet data.
 * @data: pointer to ip (v4/v6) packet header
 *
 * Grab the IPv4 or IPv6 length value in the start of the inner packet header
 * pointed to by `data`. Assumes data len is enough for the length field only.
 *
 * The version data is expected to be valid (i.e., either 4 or 6).
 *
 * Return: the length value.
 */
static u32 __iptfs_iplen(u8 *data)
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
 * @x: xfrm state
 * @skb: the inner packet
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

	/* Packet already has checksum value set. */
	skb->ip_summed = CHECKSUM_NONE;

	/* Our skb will contain the header data copied when this outer packet
	 * which contained the start of this inner packet. This is true
	 * when we allocate a new skb as well as when we reuse the existing skb.
	 */
	if (ip_hdr(skb)->version == 0x4) {
		struct iphdr *iph = ip_hdr(skb);

		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv4_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP_ECN_set_ce(iph);

		skb->protocol = htons(ETH_P_IP);
	} else {
		struct ipv6hdr *iph = ipv6_hdr(skb);

		if (x->props.flags & XFRM_STATE_DECAP_DSCP)
			ipv6_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, iph);
		if (!(x->props.flags & XFRM_STATE_NOECN))
			if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
				IP6_ECN_set_ce(skb, iph);

		skb->protocol = htons(ETH_P_IPV6);
	}
}

static void __iptfs_reassem_done(struct xfrm_iptfs_data *xtfs, bool free)
{
	assert_spin_locked(&xtfs->drop_lock);

	/* We don't care if it works locking takes care of things */
	hrtimer_try_to_cancel(&xtfs->drop_timer);
	if (free)
		kfree_skb(xtfs->ra_newskb);
	xtfs->ra_newskb = NULL;
}

/**
 * iptfs_reassem_abort() - In-progress packet is aborted free the state.
 * @xtfs: xtfs state
 */
static void iptfs_reassem_abort(struct xfrm_iptfs_data *xtfs)
{
	__iptfs_reassem_done(xtfs, true);
}

/**
 * iptfs_reassem_done() - In-progress packet is complete, clear the state.
 * @xtfs: xtfs state
 */
static void iptfs_reassem_done(struct xfrm_iptfs_data *xtfs)
{
	__iptfs_reassem_done(xtfs, false);
}

/**
 * iptfs_reassem_cont() - Continue the reassembly of an inner packets.
 * @xtfs: xtfs state
 * @seq: sequence of current packet
 * @st: seq read stat for current packet
 * @skb: current packet
 * @data: offset into sequential packet data
 * @blkoff: packet blkoff value
 * @list: list of skbs to enqueue completed packet on
 *
 * Process an IPTFS payload that has a non-zero `blkoff` or when we are
 * expecting the continuation b/c we have a runt or in-progress packet.
 *
 * Return: the new data offset to continue processing from.
 */
static u32 iptfs_reassem_cont(struct xfrm_iptfs_data *xtfs, u64 seq,
			      struct skb_seq_state *st, struct sk_buff *skb,
			      u32 data, u32 blkoff, struct list_head *list)
{
	struct sk_buff *newskb = xtfs->ra_newskb;
	u32 remaining = skb->len - data;
	u32 runtlen = xtfs->ra_runtlen;
	u32 copylen, fraglen, ipremain, iphlen, iphremain, rrem;

	/* Handle packet fragment we aren't expecting */
	if (!runtlen && !xtfs->ra_newskb)
		return data + min(blkoff, remaining);

	/* Important to remember that input to this function is an ordered
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

	/* Too old case: This can happen when the reorder window is disabled so
	 * ordering isn't actually guaranteed.
	 */
	if (seq < xtfs->ra_wantseq)
		return data + remaining;

	/* Too new case: We missed what we wanted cleanup. */
	if (seq > xtfs->ra_wantseq) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINIPTFSERROR);
		goto abandon;
	}

	if (blkoff == 0) {
		if ((*skb->data & 0xF0) != 0) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINIPTFSERROR);
			goto abandon;
		}
		/* Handle all pad case, advance expected sequence number.
		 * (RFC 9347 S2.2.3)
		 */
		xtfs->ra_wantseq++;
		/* will end parsing */
		return data + remaining;
	}

	if (runtlen) {
		BUG_ON(xtfs->ra_newskb);

		/* Regardless of what happens we're done with the runt */
		xtfs->ra_runtlen = 0;

		/* The start of this inner packet was at the very end of the last
		 * iptfs payload which didn't include enough for the ip header
		 * length field. We must have *at least* that now.
		 */
		rrem = sizeof(xtfs->ra_runt) - runtlen;
		if (remaining < rrem || blkoff < rrem) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINIPTFSERROR);
			goto abandon;
		}

		/* fill in the runt data */
		if (skb_copy_bits_seq(st, data, &xtfs->ra_runt[runtlen],
				      rrem)) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINBUFFERERROR);
			goto abandon;
		}

		/* We have enough data to get the ip length value now,
		 * allocate an in progress skb
		 */
		ipremain = __iptfs_iplen(xtfs->ra_runt);
		if (ipremain < sizeof(xtfs->ra_runt)) {
			/* length has to be at least runtsize large */
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINIPTFSERROR);
			goto abandon;
		}

		/* For the runt case we don't attempt sharing currently. NOTE:
		 * Currently, this IPTFS implementation will not create runts.
		 */

		newskb = iptfs_alloc_skb(skb, ipremain, false);
		if (!newskb) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINERROR);
			goto abandon;
		}
		xtfs->ra_newskb = newskb;

		/* Copy the runt data into the buffer, but leave data
		 * pointers the same as normal non-runt case. The extra `rrem`
		 * recopied bytes are basically cacheline free. Allows using
		 * same logic below to complete.
		 */
		memcpy(skb_put(newskb, runtlen), xtfs->ra_runt,
		       sizeof(xtfs->ra_runt));
	}

	/* Continue reassembling the packet */
	ipremain = __iptfs_iplen(newskb->data);
	iphlen = __iptfs_iphlen(newskb->data);

	/* Sanity check, we created the newskb knowing the IP length so the IP
	 * length can't now be shorter.
	 */
	BUG_ON(newskb->len > ipremain);

	ipremain -= newskb->len;
	if (blkoff < ipremain) {
		/* Corrupt data, we don't have enough to complete the packet */
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINIPTFSERROR);
		goto abandon;
	}

	/* We want the IP header in linear space */
	if (newskb->len < iphlen) {
		iphremain = iphlen - newskb->len;
		if (blkoff < iphremain) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINIPTFSERROR);
			goto abandon;
		}
		fraglen = min(blkoff, remaining);
		copylen = min(fraglen, iphremain);
		BUG_ON(skb_tailroom(newskb) < copylen);
		if (skb_copy_bits_seq(st, data, skb_put(newskb, copylen),
				      copylen)) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINBUFFERERROR);
			goto abandon;
		}
		/* this is a silly condition that might occur anyway */
		if (copylen < iphremain) {
			xtfs->ra_wantseq++;
			return data + fraglen;
		}
		/* update data and things derived from it */
		data += copylen;
		blkoff -= copylen;
		remaining -= copylen;
		ipremain -= copylen;
	}

	fraglen = min(blkoff, remaining);
	copylen = min(fraglen, ipremain);

	/* We verified this was true in the main receive routine */
	BUG_ON(skb_tailroom(newskb) < copylen);

	/* copy fragment data into newskb */
	if (skb_copy_bits_seq(st, data, skb_put(newskb, copylen), copylen)) {
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMINBUFFERERROR);
		goto abandon;
	}

	if (copylen < ipremain) {
		xtfs->ra_wantseq++;
	} else {
		/* We are done with packet reassembly! */
		BUG_ON(copylen != ipremain);
		iptfs_reassem_done(xtfs);
		iptfs_complete_inner_skb(xtfs->x, newskb);
		list_add_tail(&newskb->list, list);
	}

	/* will continue on to new data block or end */
	return data + fraglen;

abandon:
	if (xtfs->ra_newskb) {
		iptfs_reassem_abort(xtfs);
	} else {
		xtfs->ra_runtlen = 0;
		xtfs->ra_wantseq = 0;
	}
	/* skip past fragment, maybe to end */
	return data + min(blkoff, remaining);
}

/**
 * iptfs_input() - handle receipt of iptfs payload
 * @x: xfrm state
 * @skb: the packet
 *
 * Process the IPTFS payload in `skb` and consume it afterwards.
 *
 * Returns 0.
 */
static int iptfs_input(struct xfrm_state *x, struct sk_buff *skb)
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
	u32 remaining, first_iplen, iplen, iphlen, data, tail;
	u32 blkoff, capturelen;
	u64 seq;

	xtfs = x->mode_data;
	net = dev_net(skb->dev);
	first_skb = NULL;
	defer = NULL;

	seq = __esp_seq(skb);

	/* Large enough to hold both types of header */
	ipth = (struct ip_iptfs_hdr *)&iptcch;

	/* Save the old mac header if set */
	old_mac = skb_mac_header_was_set(skb) ? skb_mac_header(skb) : NULL;

	skb_prepare_seq_read(skb, 0, skb->len, &skbseq);

	/* Get the IPTFS header and validate it */

	if (skb_copy_bits_seq(&skbseq, 0, ipth, sizeof(*ipth))) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
		goto done;
	}
	data = sizeof(*ipth);

	/* Set data past the basic header */
	if (ipth->subtype == IPTFS_SUBTYPE_CC) {
		/* Copy the rest of the CC header */
		remaining = sizeof(iptcch) - sizeof(*ipth);
		if (skb_copy_bits_seq(&skbseq, data, ipth + 1, remaining)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}
		data += remaining;
	} else if (ipth->subtype != IPTFS_SUBTYPE_BASIC) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto done;
	}

	if (ipth->flags != 0) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto done;
	}

	INIT_LIST_HEAD(&sublist);

	/* Handle fragment at start of payload, and/or waiting reassembly. */

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

	/* New packets */

	tail = skb->len;
	BUG_ON(xtfs->ra_newskb && data < tail);

	while (data < tail) {
		__be16 protocol = 0;

		/* Gather information on the next data block.
		 * `data` points to the start of the data block.
		 */
		remaining = tail - data;

		/* try and copy enough bytes to read length from ipv4/ipv6 */
		iphlen = min_t(u32, remaining, 6);
		if (skb_copy_bits_seq(&skbseq, data, hbytes, iphlen)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}

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

			iplen = be16_to_cpu(iph->tot_len);
			iphlen = iph->ihl << 2;
			protocol = cpu_to_be16(ETH_P_IP);
			XFRM_MODE_SKB_CB(skbseq.root_skb)->tos = iph->tos;
		} else if (iph->version == 0x6) {
			/* must have at least payload_len field present */
			if (remaining < 6) {
				/* save the bytes we have, advance data and exit */
				iptfs_input_save_runt(xtfs, seq, hbytes,
						      remaining);
				data += remaining;
				break;
			}

			iplen = be16_to_cpu(
				((struct ipv6hdr *)hbytes)->payload_len);
			iplen += sizeof(struct ipv6hdr);
			iphlen = sizeof(struct ipv6hdr);
			protocol = cpu_to_be16(ETH_P_IPV6);
			XFRM_MODE_SKB_CB(skbseq.root_skb)->tos =
				ipv6_get_dsfield((struct ipv6hdr *)iph);
		} else if (iph->version == 0x0) {
			/* pad */
			data = tail;
			break;
		} else {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}

		if (unlikely(skbseq.stepped_offset)) {
			/* We need to reset our seq read, it can't backup at
			 * this point.
			 */
			struct sk_buff *save = skbseq.root_skb;

			skb_abort_seq_read(&skbseq);
			skb_prepare_seq_read(save, data, tail, &skbseq);
		}

		if (first_skb) {
			skb = NULL;
		} else {
			first_skb = skb;
			first_iplen = iplen;

			/* We are going to skip over `data` bytes to reach the
			 * start of the IP header of `iphlen` len for `iplen`
			 * inner packet.
			 */

			if (skb_has_frag_list(skb)) {
				defer = skb;
				skb = NULL;
			} else if (data + iphlen <= skb_headlen(skb) &&
				   /* make sure our header is 32-bit aligned? */
				   /* ((uintptr_t)(skb->data + data) & 0x3) == 0 && */
				   skb_tailroom(skb) + tail - data >= iplen) {
				/* Reuse the received skb.
				 *
				 * We have enough headlen to pull past any
				 * initial fragment data, leaving at least the
				 * IP header in the linear buffer space.
				 *
				 * For linear buffer space we only require that
				 * linear buffer space is large enough to
				 * eventually hold the entire reassembled
				 * packet (by including tailroom in the check).
				 *
				 * For non-linear tailroom is 0 and so we only
				 * re-use if the entire packet is present
				 * already.
				 *
				 * NOTE: there are many more options for
				 * sharing, KISS for now. Also, this can produce
				 * skb's with the IP header unaligned to 32
				 * bits. If that ends up being a problem then a
				 * check should be added to the conditional
				 * above that the header lies on a 32-bit
				 * boundary as well.
				 */
				skb_pull(skb, data);

				/* our range just changed */
				data = 0;
				tail = skb->len;
				remaining = skb->len;

				skb->protocol = protocol;
				skb_mac_header_rebuild(skb);
				if (skb->mac_len)
					eth_hdr(skb)->h_proto = skb->protocol;

				/* all pointers could be changed now reset walk */
				skb_abort_seq_read(&skbseq);
				skb_prepare_seq_read(skb, data, tail, &skbseq);
			} else {
				/* We couldn't reuse the input skb so allocate a
				 * new one.
				 */
				defer = skb;
				skb = NULL;
			}

			/* Don't trim `first_skb` until the end as we are
			 * walking that data now.
			 */
		}

		capturelen = min(iplen, remaining);
		if (!skb) {
			skb = iptfs_pskb_extract_seq(iplen, &skbseq, data,
						     capturelen);
			if (!skb) {
				/* skip to next packet or done */
				data += capturelen;
				continue;
			}
			BUG_ON(skb->len != capturelen);

			skb->protocol = protocol;
			if (old_mac) {
				/* rebuild the mac header */
				skb_set_mac_header(skb, -first_skb->mac_len);
				memcpy(skb_mac_header(skb), old_mac,
				       first_skb->mac_len);
				eth_hdr(skb)->h_proto = skb->protocol;
			}
		}

		data += capturelen;

		if (skb->len < iplen) {
			BUG_ON(data != tail);
			BUG_ON(xtfs->ra_newskb);

			/* Start reassembly */
			spin_lock(&xtfs->drop_lock);

			xtfs->ra_newskb = skb;
			xtfs->ra_wantseq = seq + 1;
			if (!hrtimer_is_queued(&xtfs->drop_timer)) {
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

	if (data != tail)
		/* this should not happen from the above code */
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINIPTFSERROR);

	if (first_skb && first_iplen && !defer && first_skb != xtfs->ra_newskb) {
		/* first_skb is queued b/c !defer and not partial */
		if (pskb_trim(first_skb, first_iplen)) {
			/* error trimming */
			list_del(&first_skb->list);
			defer = first_skb;
		}
		first_skb->ip_summed = CHECKSUM_NONE;
	}

	/* Send the packets! */
	list_for_each_entry_safe(skb, next, &sublist, list) {
		BUG_ON(skb == defer);
		skb_list_del_init(skb);
		if (xfrm_input(skb, 0, 0, -3))
			kfree_skb(skb);
	}

done:
	skb = skbseq.root_skb;
	skb_abort_seq_read(&skbseq);

	if (defer) {
		consume_skb(defer);
	} else if (!first_skb) {
		/* skb is the original passed in skb, but we didn't get far
		 * enough to process it as the first_skb, if we had it would
		 * either be save in ra_newskb, trimmed and sent on as an skb or
		 * placed in defer to be freed.
		 */
		BUG_ON(!skb);
		kfree_skb(skb);
	}

	/* We always have dealt with the input SKB, either we are re-using it,
	 * or we have freed it. Return EINPROGRESS so that xfrm_input stops
	 * processing it.
	 */
	return -EINPROGRESS;
}

/**
 * iptfs_drop_timer() - Handle drop timer expiry.
 * @me: the timer
 *
 * This is similar to our input function.
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
 *
 * Returns HRTIMER_NORESTART.
 */
static enum hrtimer_restart iptfs_drop_timer(struct hrtimer *me)
{
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;

	xtfs = container_of(me, typeof(*xtfs), drop_timer);
	x = xtfs->x;

	/* Drop any in progress packet */
	spin_lock(&xtfs->drop_lock);
	if (xtfs->ra_newskb) {
		kfree_skb(xtfs->ra_newskb);
		xtfs->ra_newskb = NULL;
	}
	spin_unlock(&xtfs->drop_lock);

	return HRTIMER_NORESTART;
}

/* ================================= */
/* IPTFS Sending (ingress) Functions */
/* ================================= */

/* ------------------------- */
/* Enqueue to send functions */
/* ------------------------- */

/**
 * iptfs_enqueue() - enqueue packet if ok to send.
 * @xtfs: xtfs state
 * @skb: the packet
 *
 * Return: true if packet enqueued.
 */
static bool iptfs_enqueue(struct xfrm_iptfs_data *xtfs, struct sk_buff *skb)
{
	u64 newsz = xtfs->queue_size + skb->len;
	struct iphdr *iph;

	assert_spin_locked(&xtfs->x->lock);

	if (newsz > xtfs->cfg.max_queue_size)
		return false;

	/* Set ECN CE if we are above our ECN queue threshold */
	if (newsz > xtfs->ecn_queue_size) {
		iph = ip_hdr(skb);
		if (iph->version == 4)
			IP_ECN_set_ce(iph);
		else if (iph->version == 6)
			IP6_ECN_set_ce(skb, ipv6_hdr(skb));
	}

	__skb_queue_tail(&xtfs->queue, skb);
	xtfs->queue_size += skb->len;
	return true;
}

static int iptfs_get_cur_pmtu(struct xfrm_state *x,
			      struct xfrm_iptfs_data *xtfs, struct sk_buff *skb)
{
	struct xfrm_dst *xdst = (struct xfrm_dst *)skb_dst(skb);
	u32 payload_mtu = xtfs->payload_mtu;
	u32 pmtu = __iptfs_get_inner_mtu(x, xdst->child_mtu_cached);

	if (payload_mtu && payload_mtu < pmtu)
		pmtu = payload_mtu;

	return pmtu;
}

static int iptfs_is_too_big(struct sock *sk, struct sk_buff *skb, u32 pmtu)
{
	if (skb->len <= pmtu)
		return 0;

	/* We only send ICMP too big if the user has configured us as
	 * dont-fragment.
	 */
	if (skb->dev)
		XFRM_INC_STATS(dev_net(skb->dev), LINUX_MIB_XFRMOUTERROR);

	if (sk) {
		xfrm_local_error(skb, pmtu);
	} else if (ip_hdr(skb)->version == 4) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(pmtu));
	} else {
		WARN_ON_ONCE(ip_hdr(skb)->version != 6);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, pmtu);
	}
	return 1;
}

/* IPv4/IPv6 packet ingress to IPTFS tunnel, arrange to send in IPTFS payload
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
	u32 pmtu = 0;
	bool ok = true;
	bool was_gso;

	/* We have hooked into dst_entry->output which means we have skipped the
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

	BUG_ON(!xtfs);

	if (xtfs->cfg.dont_frag)
		pmtu = iptfs_get_cur_pmtu(x, xtfs, skb);

	/* Break apart GSO skbs. If the queue is nearing full then we want the
	 * accounting and queuing to be based on the individual packets not on the
	 * aggregate GSO buffer.
	 */
	was_gso = skb_is_gso(skb);
	if (!was_gso) {
		segs = skb;
	} else {
		segs = skb_gso_segment(skb, 0);
		if (IS_ERR_OR_NULL(segs)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			if (IS_ERR(segs))
				return PTR_ERR(segs);
			return -EINVAL;
		}
		consume_skb(skb);
		skb = NULL;
	}

	/* We can be running on multiple cores and from the network softirq or
	 * from user context depending on where the packet is coming from.
	 */
	spin_lock_bh(&x->lock);

	skb_list_walk_safe(segs, skb, nskb) {
		skb_mark_not_on_list(skb);

		/* Once we drop due to no queue space we continue to drop the
		 * rest of the packets from that GRO.
		 */
		if (!ok) {
nospace:
			if (skb->dev)
				XFRM_INC_STATS(dev_net(skb->dev),
					       LINUX_MIB_XFRMOUTNOQSPACE);
			kfree_skb_reason(skb, SKB_DROP_REASON_FULL_RING);
			continue;
		}

		/* If the user indicated no iptfs fragmenting check before
		 * enqueue.
		 */
		if (xtfs->cfg.dont_frag && iptfs_is_too_big(sk, skb, pmtu)) {
			kfree_skb_reason(skb, SKB_DROP_REASON_PKT_TOO_BIG);
			continue;
		}

		/* Enqueue to send in tunnel */
		ok = iptfs_enqueue(xtfs, skb);
		if (!ok)
			goto nospace;
	}

	/* Start a delay timer if we don't have one yet */
	if (!hrtimer_is_queued(&xtfs->iptfs_timer))
		hrtimer_start(&xtfs->iptfs_timer, xtfs->init_delay_ns,
			      IPTFS_HRTIMER_MODE);

	spin_unlock_bh(&x->lock);
	return 0;
}

/* -------------------------- */
/* Dequeue and send functions */
/* -------------------------- */

static void iptfs_output_prepare_skb(struct sk_buff *skb, u32 blkoff)
{
	struct ip_iptfs_hdr *h;
	size_t hsz = sizeof(*h);

	/* now reset values to be pointing at the rest of the packets */
	h = skb_push(skb, hsz);
	memset(h, 0, hsz);
	if (blkoff)
		h->block_offset = htons(blkoff);

	/* network_header current points at the inner IP packet
	 * move it to the iptfs header
	 */
	skb->transport_header = skb->network_header;
	skb->network_header -= hsz;

	IPCB(skb)->flags |= IPSKB_XFRM_TUNNEL_SIZE;
}

/**
 * iptfs_copy_create_frag() - create an inner fragment skb.
 * @st: The source packet data.
 * @offset: offset in @st of the new fragment data.
 * @copy_len: the amount of data to copy from @st.
 *
 * Create a new skb holding a single IPTFS inner packet fragment. @copy_len must
 * not be greater than the max fragment size.
 *
 * Return: the new fragment skb or an ERR_PTR().
 */
static struct sk_buff *iptfs_copy_create_frag(struct skb_seq_state *st,
					      u32 offset, u32 copy_len)
{
	struct sk_buff *src = st->root_skb;
	struct sk_buff *skb;
	int err;

	skb = iptfs_alloc_skb(src, copy_len, true);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/* Now copy `copy_len` data from src */
	err = skb_copy_bits_seq(st, offset, skb_put(skb, copy_len), copy_len);
	if (err) {
		XFRM_INC_STATS(dev_net(src->dev), LINUX_MIB_XFRMOUTERROR);
		kfree_skb(skb);
		return ERR_PTR(err);
	}

	return skb;
}

/**
 * iptfs_copy_create_frags() - create and send N-1 fragments of a larger skb.
 * @skbp: the source packet skb (IN), skb holding the last fragment in
 *        the fragment stream (OUT).
 * @xtfs: IPTFS SA state.
 * @mtu: the max IPTFS fragment size.
 *
 * This function is responsible for fragmenting a larger inner packet into a
 * sequence of IPTFS payload packets. The last fragment is returned rather than
 * being sent so that the caller can append more inner packets (aggregation) if
 * there is room.
 *
 * Return: 0 on success or a negative error code on failure
 */
static int iptfs_copy_create_frags(struct sk_buff **skbp,
				   struct xfrm_iptfs_data *xtfs, u32 mtu)
{
	struct skb_seq_state skbseq;
	struct list_head sublist;
	struct sk_buff *skb = *skbp;
	struct sk_buff *nskb = *skbp;
	u32 copy_len, offset;
	u32 to_copy = skb->len - mtu;
	int err = 0;

	INIT_LIST_HEAD(&sublist);

	BUG_ON(skb->len <= mtu);
	skb_prepare_seq_read(skb, 0, skb->len, &skbseq);

	/* A trimmed `skb` will be sent as the first fragment, later. */
	offset = mtu;
	to_copy = skb->len - offset;
	while (to_copy) {
		/* Send all but last fragment to allow agg. append */
		list_add_tail(&nskb->list, &sublist);

		/* FUTURE: if the packet has an odd/non-aligning length we could
		 * send less data in the penultimate fragment so that the last
		 * fragment then ends on an aligned boundary.
		 */
		copy_len = min(to_copy, mtu);
		nskb = iptfs_copy_create_frag(&skbseq, offset, copy_len);
		if (IS_ERR(nskb)) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMOUTERROR);
			skb_abort_seq_read(&skbseq);
			err = PTR_ERR(nskb);
			nskb = NULL;
			break;
		}
		iptfs_output_prepare_skb(nskb, to_copy);
		offset += copy_len;
		to_copy -= copy_len;
	}
	skb_abort_seq_read(&skbseq);

	/* return last fragment that will be unsent (or NULL) */
	*skbp = nskb;

	/* trim the original skb to MTU */
	if (!err)
		err = pskb_trim(skb, mtu);

	if (err) {
		/* Free all frags. Don't bother sending a partial packet we will
		 * never complete.
		 */
		kfree_skb(nskb);
		list_for_each_entry_safe(skb, nskb, &sublist, list) {
			skb_list_del_init(skb);
			kfree_skb(skb);
		}
		return err;
	}

	/* prepare the initial fragment with an iptfs header */
	iptfs_output_prepare_skb(skb, 0);

	/* Send all but last fragment, if we fail to send a fragment then free
	 * the rest -- no point in sending a packet that can't be reassembled.
	 */
	list_for_each_entry_safe(skb, nskb, &sublist, list) {
		skb_list_del_init(skb);
		if (!err)
			err = xfrm_output(NULL, skb);
		else
			kfree_skb(skb);
	}
	if (err)
		kfree_skb(*skbp);
	return err;
}

/**
 * iptfs_first_should_copy() - determine if we should copy packet data.
 * @first_skb: the first skb in the packet
 * @mtu: the MTU.
 *
 * Determine if we should create subsequent skbs to hold the remaining data from
 * a large inner packet by copying the packet data, or cloning the original skb
 * and adjusting the offsets.
 *
 * Return: true if we should copy the data out of the skb.
 */
static bool iptfs_first_should_copy(struct sk_buff *first_skb, u32 mtu)
{
	u32 frag_copy_max;

	/* If we have less than frag_copy_max for remaining packet we copy
	 * those tail bytes as it is more efficient.
	 */
	frag_copy_max = min(mtu, IPTFS_FRAG_COPY_MAX);
	if ((int)first_skb->len - (int)mtu < (int)frag_copy_max)
		return true;

	/* If we have non-linear skb just use copy */
	if (skb_is_nonlinear(first_skb))
		return true;

	/* So we have a simple linear skb, easy to clone and share */
	return false;
}

/**
 * iptfs_first_skb() - handle the first dequeued inner packet for output
 * @skbp: the source packet skb (IN), skb holding the last fragment in
 *        the fragment stream (OUT).
 * @xtfs: IPTFS SA state.
 * @mtu: the max IPTFS fragment size.
 *
 * This function is responsible for fragmenting a larger inner packet into a
 * sequence of IPTFS payload packets. If it needs to fragment into subsequent
 * skb's, it will either do so by copying or cloning.
 *
 * The last fragment is returned rather than being sent so that the caller can
 * append more inner packets (aggregation) if there is room.
 *
 * Return: 0 on success or a negative error code on failure
 */
static int iptfs_first_skb(struct sk_buff **skbp, struct xfrm_iptfs_data *xtfs,
			   u32 mtu)
{
	struct sk_buff *skb = *skbp;
	int err;

	/* Classic ESP skips the don't fragment ICMP error if DF is clear on
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

	/* Simple case -- it fits. `mtu` accounted for all the overhead
	 * including the basic IPTFS header.
	 */
	if (skb->len <= mtu) {
		iptfs_output_prepare_skb(skb, 0);
		return 0;
	}

	if (iptfs_first_should_copy(skb, mtu))
		return iptfs_copy_create_frags(skbp, xtfs, mtu);

	/* For now we always copy */
	return iptfs_copy_create_frags(skbp, xtfs, mtu);
}

static struct sk_buff **iptfs_rehome_fraglist(struct sk_buff **nextp,
					      struct sk_buff *child)
{
	u32 fllen = 0;

	/* It might be possible to account for a frag list in addition to page
	 * fragment if it's a valid state to be in. The page fragments size
	 * should be kept as data_len so only the frag_list size is removed,
	 * this must be done above as well.
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

static void iptfs_consume_frags(struct sk_buff *to, struct sk_buff *from)
{
	struct skb_shared_info *fromi = skb_shinfo(from);
	struct skb_shared_info *toi = skb_shinfo(to);
	unsigned int new_truesize;

	/* If we have data in a head page, grab it */
	if (!skb_headlen(from)) {
		new_truesize = SKB_TRUESIZE(skb_end_offset(from));
	} else {
		skb_head_to_frag(from, &toi->frags[toi->nr_frags]);
		skb_frag_ref(to, toi->nr_frags++);
		new_truesize = SKB_DATA_ALIGN(sizeof(struct sk_buff));
	}

	/* Move any other page fragments rather than copy */
	memcpy(&toi->frags[toi->nr_frags], fromi->frags,
	       sizeof(fromi->frags[0]) * fromi->nr_frags);
	toi->nr_frags += fromi->nr_frags;
	fromi->nr_frags = 0;
	from->data_len = 0;
	from->len = 0;
	to->truesize += from->truesize - new_truesize;
	from->truesize = new_truesize;

	/* We are done with this SKB */
	consume_skb(from);
}

static void iptfs_output_queued(struct xfrm_state *x, struct sk_buff_head *list)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct sk_buff *skb, *skb2, **nextp;
	struct skb_shared_info *shi, *shi2;

	/* If we are fragmenting due to a large inner packet we will output all
	 * the outer IPTFS packets required to contain the fragments of the
	 * single large inner packet. These outer packets need to be sent
	 * consecutively (ESP seq-wise). Since this output function is always
	 * running from a timer we do not need a lock to provide this guarantee.
	 * We will output our packets consecutively before the timer is allowed
	 * to run again on some other CPU.
	 */

	while ((skb = __skb_dequeue(list))) {
		u32 mtu = iptfs_get_cur_pmtu(x, xtfs, skb);
		bool share_ok = true;
		int remaining;

		/* protocol comes to us cleared sometimes */
		skb->protocol = x->outer_mode.family == AF_INET ?
					htons(ETH_P_IP) :
					htons(ETH_P_IPV6);

		if (skb->len > mtu && xtfs->cfg.dont_frag) {
			/* We handle this case before enqueueing so we are only
			 * here b/c MTU changed after we enqueued before we
			 * dequeued, just drop these.
			 */
			if (skb->dev)
				XFRM_INC_STATS(dev_net(skb->dev),
					       LINUX_MIB_XFRMOUTERROR);

			kfree_skb_reason(skb, SKB_DROP_REASON_PKT_TOO_BIG);
			continue;
		}

		/* Convert first inner packet into an outer IPTFS packet,
		 * dealing with any fragmentation into multiple outer packets
		 * if necessary.
		 */
		if (iptfs_first_skb(&skb, xtfs, mtu))
			continue;

		/* If fragmentation was required the returned skb is the last
		 * IPTFS fragment in the chain, and it's IPTFS header blkoff has
		 * been set just past the end of the fragment data.
		 *
		 * In either case the space remaining to send more inner packet
		 * data is `mtu` - (skb->len - sizeof iptfs header). This is b/c
		 * the `mtu` value has the basic IPTFS header len accounted for,
		 * and we added that header to the skb so it is a part of
		 * skb->len, thus we subtract it from the skb length.
		 */
		remaining = mtu - (skb->len - sizeof(struct ip_iptfs_hdr));

		/* Re-home (un-nest) nested fragment lists. We need to do this
		 * b/c we will simply be appending any following aggregated
		 * inner packets using the frag list.
		 */
		shi = skb_shinfo(skb);
		nextp = &shi->frag_list;
		while (*nextp) {
			if (skb_has_frag_list(*nextp))
				nextp = iptfs_rehome_fraglist(&(*nextp)->next,
							      *nextp);
			else
				nextp = &(*nextp)->next;
		}

		if (shi->frag_list || skb_cloned(skb) || skb_shared(skb))
			share_ok = false;

		/* See if we have enough space to simply append.
		 *
		 * NOTE: Maybe do not append if we will be mis-aligned,
		 * SW-based endpoints will probably have to copy in this
		 * case.
		 */
		while ((skb2 = skb_peek(list))) {
			if (skb2->len > remaining)
				break;

			__skb_unlink(skb2, list);

			/* If we don't have a cksum in the packet we need to add
			 * one before encapsulation.
			 */
			if (skb2->ip_summed == CHECKSUM_PARTIAL) {
				if (skb_checksum_help(skb2)) {
					XFRM_INC_STATS(dev_net(skb_dst(skb2)->dev),
						       LINUX_MIB_XFRMOUTERROR);
					kfree_skb(skb2);
					continue;
				}
			}

			/* skb->pp_recycle is passed to __skb_flag_unref for all
			 * frag pages so we can only share pages with skb's who
			 * match ourselves.
			 */
			shi2 = skb_shinfo(skb2);
			if (share_ok &&
			    (shi2->frag_list ||
			     (!skb2->head_frag && skb_headlen(skb)) ||
			     skb->pp_recycle != skb2->pp_recycle ||
			     skb_zcopy(skb2) ||
			     (shi->nr_frags + shi2->nr_frags + 1 > MAX_SKB_FRAGS)))
				share_ok = false;

			/* Do accounting */
			skb->data_len += skb2->len;
			skb->len += skb2->len;
			remaining -= skb2->len;

			if (share_ok) {
				iptfs_consume_frags(skb, skb2);
			} else {
				/* Append to the frag_list */
				*nextp = skb2;
				nextp = &skb2->next;
				BUG_ON(*nextp);
				if (skb_has_frag_list(skb2))
					nextp = iptfs_rehome_fraglist(nextp,
								      skb2);
				skb->truesize += skb2->truesize;
			}
		}

		xfrm_output(NULL, skb);
	}
}

static enum hrtimer_restart iptfs_delay_timer(struct hrtimer *me)
{
	struct sk_buff_head list;
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;

	xtfs = container_of(me, typeof(*xtfs), iptfs_timer);
	x = xtfs->x;

	/* Process all the queued packets
	 *
	 * softirq execution order: timer > tasklet > hrtimer
	 *
	 * Network rx will have run before us giving one last chance to queue
	 * ingress packets for us to process and transmit.
	 */

	spin_lock(&x->lock);
	__skb_queue_head_init(&list);
	skb_queue_splice_init(&xtfs->queue, &list);
	xtfs->queue_size = 0;
	spin_unlock(&x->lock);

	/* After the above unlock, packets can begin queuing again, and the
	 * timer can be set again, from another CPU either in softirq or user
	 * context (not from this one since we are running at softirq level
	 * already).
	 */

	iptfs_output_queued(x, &list);

	return HRTIMER_NORESTART;
}

/**
 * iptfs_encap_add_ipv4() - add outer encaps
 * @x: xfrm state
 * @skb: the packet
 *
 * This was originally taken from xfrm4_tunnel_encap_add. The reason for the
 * copy is that IP-TFS/AGGFRAG can have different functionality for how to set
 * the TOS/DSCP bits. Sets the protocol to a different value and doesn't do
 * anything with inner headers as they aren't pointing into a normal IP
 * singleton inner packet.
 *
 * Return: 0 on success or a negative error code on failure
 */
static int iptfs_encap_add_ipv4(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct iphdr *top_iph;

	skb_reset_inner_network_header(skb);
	skb_reset_inner_transport_header(skb);

	skb_set_network_header(skb,
			       -(x->props.header_len - x->props.enc_hdr_len));
	skb->mac_header =
		skb->network_header + offsetof(struct iphdr, protocol);
	skb->transport_header = skb->network_header + sizeof(*top_iph);

	top_iph = ip_hdr(skb);
	top_iph->ihl = 5;
	top_iph->version = 4;
	top_iph->protocol = IPPROTO_AGGFRAG;

	/* As we have 0, fractional, 1 or N inner packets there's no obviously
	 * correct DSCP mapping to inherit. ECN should be cleared per RFC9347
	 * 3.1.
	 */
	top_iph->tos = 0;

	top_iph->frag_off = htons(IP_DF);
	top_iph->ttl = ip4_dst_hoplimit(xfrm_dst_child(dst));
	top_iph->saddr = x->props.saddr.a4;
	top_iph->daddr = x->id.daddr.a4;
	ip_select_ident(dev_net(dst->dev), skb, NULL);

	return 0;
}

/**
 * iptfs_encap_add_ipv6() - add outer encaps
 * @x: xfrm state
 * @skb: the packet
 *
 * This was originally taken from xfrm6_tunnel_encap_add. The reason for the
 * copy is that IP-TFS/AGGFRAG can have different functionality for how to set
 * the flow label and TOS/DSCP bits. It also sets the protocol to a different
 * value and doesn't do anything with inner headers as they aren't pointing into
 * a normal IP singleton inner packet.
 *
 * Return: 0 on success or a negative error code on failure
 */
static int iptfs_encap_add_ipv6(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct ipv6hdr *top_iph;
	int dsfield;

	skb_reset_inner_network_header(skb);
	skb_reset_inner_transport_header(skb);

	skb_set_network_header(skb,
			       -x->props.header_len + x->props.enc_hdr_len);
	skb->mac_header =
		skb->network_header + offsetof(struct ipv6hdr, nexthdr);
	skb->transport_header = skb->network_header + sizeof(*top_iph);

	top_iph = ipv6_hdr(skb);
	top_iph->version = 6;
	top_iph->priority = 0;
	memset(top_iph->flow_lbl, 0, sizeof(top_iph->flow_lbl));
	top_iph->nexthdr = IPPROTO_AGGFRAG;

	/* As we have 0, fractional, 1 or N inner packets there's no obviously
	 * correct DSCP mapping to inherit. ECN should be cleared per RFC9347
	 * 3.1.
	 */
	dsfield = 0;
	ipv6_change_dsfield(top_iph, 0, dsfield);

	top_iph->hop_limit = ip6_dst_hoplimit(xfrm_dst_child(dst));
	top_iph->saddr = *(struct in6_addr *)&x->props.saddr;
	top_iph->daddr = *(struct in6_addr *)&x->id.daddr;

	return 0;
}

/**
 * iptfs_prepare_output() -  prepare the skb for output
 * @x: xfrm state
 * @skb: the packet
 *
 * Return: Error value, if 0 then skb values should be as follows:
 *    - transport_header should point at ESP header
 *    - network_header should point at Outer IP header
 *    - mac_header should point at protocol/nexthdr of the outer IP
 */
static int iptfs_prepare_output(struct xfrm_state *x, struct sk_buff *skb)
{
	if (x->outer_mode.family == AF_INET)
		return iptfs_encap_add_ipv4(x, skb);
	if (x->outer_mode.family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		return iptfs_encap_add_ipv6(x, skb);
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

/**
 * __iptfs_get_inner_mtu() - return inner MTU with no fragmentation.
 * @x: xfrm state.
 * @outer_mtu: the outer mtu
 *
 * Return: Correct MTU taking in to account the encap overhead.
 */
static u32 __iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu)
{
	struct crypto_aead *aead;
	u32 blksize;

	aead = x->data;
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	return ((outer_mtu - x->props.header_len - crypto_aead_authsize(aead)) &
		~(blksize - 1)) - 2;
}

/**
 * iptfs_get_inner_mtu() - return the inner MTU for an IPTFS xfrm.
 * @x: xfrm state.
 * @outer_mtu: Outer MTU for the encapsulated packet.
 *
 * Return: Correct MTU taking in to account the encap overhead.
 */
static u32 iptfs_get_inner_mtu(struct xfrm_state *x, int outer_mtu)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;

	/* If not dont-frag we have no MTU */
	if (!xtfs->cfg.dont_frag)
		return x->outer_mode.family == AF_INET ? IP_MAX_MTU : IP6_MAX_MTU;
	return __iptfs_get_inner_mtu(x, outer_mtu);
}

/**
 * iptfs_user_init() - initialize the SA with IPTFS options from netlink.
 * @net: the net data
 * @x: xfrm state
 * @attrs: netlink attributes
 * @extack: extack return data
 *
 * Return: 0 on success or a negative error code on failure
 */
static int iptfs_user_init(struct net *net, struct xfrm_state *x,
			   struct nlattr **attrs,
			   struct netlink_ext_ack *extack)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct xfrm_iptfs_config *xc;

	xc = &xtfs->cfg;
	xc->max_queue_size = IPTFS_DEFAULT_MAX_QUEUE_SIZE;
	xtfs->drop_time_ns = IPTFS_DEFAULT_DROP_TIME_USECS * NSECS_IN_USEC;
	xtfs->init_delay_ns = IPTFS_DEFAULT_INIT_DELAY_USECS * NSECS_IN_USEC;

	if (attrs[XFRMA_IPTFS_DONT_FRAG])
		xc->dont_frag = true;
	if (attrs[XFRMA_IPTFS_PKT_SIZE]) {
		xc->pkt_size = nla_get_u32(attrs[XFRMA_IPTFS_PKT_SIZE]);
		if (!xc->pkt_size) {
			xtfs->payload_mtu = 0;
		} else if (xc->pkt_size > x->props.header_len) {
			xtfs->payload_mtu = xc->pkt_size - x->props.header_len;
		} else {
			NL_SET_ERR_MSG(extack,
				       "Packet size must be 0 or greater than IPTFS/ESP header length");
			return -EINVAL;
		}
	}
	if (attrs[XFRMA_IPTFS_MAX_QSIZE])
		xc->max_queue_size = nla_get_u32(attrs[XFRMA_IPTFS_MAX_QSIZE]);
	if (attrs[XFRMA_IPTFS_DROP_TIME])
		xtfs->drop_time_ns =
			(u64)nla_get_u32(attrs[XFRMA_IPTFS_DROP_TIME]) *
			NSECS_IN_USEC;
	if (attrs[XFRMA_IPTFS_INIT_DELAY])
		xtfs->init_delay_ns =
			(u64)nla_get_u32(attrs[XFRMA_IPTFS_INIT_DELAY]) *
			NSECS_IN_USEC;

	xtfs->ecn_queue_size = (u64)xc->max_queue_size * 95;
	(void)do_div(xtfs->ecn_queue_size, 100);

	return 0;
}

static unsigned int iptfs_sa_len(const struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct xfrm_iptfs_config *xc = &xtfs->cfg;
	unsigned int l = 0;

	if (x->dir == XFRM_SA_DIR_IN) {
		l += nla_total_size(sizeof(u32)); /* drop time usec */
	} else {
		if (xc->dont_frag)
			l += nla_total_size(0);	  /* dont-frag flag */
		l += nla_total_size(sizeof(u32)); /* init delay usec */
		l += nla_total_size(sizeof(xc->max_queue_size));
		l += nla_total_size(sizeof(xc->pkt_size));
	}

	return l;
}

static int iptfs_copy_to_user(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;
	struct xfrm_iptfs_config *xc = &xtfs->cfg;
	int ret = 0;
	u64 q;

	if (x->dir == XFRM_SA_DIR_IN) {
		q = xtfs->drop_time_ns;
		(void)do_div(q, NSECS_IN_USEC);
		ret = nla_put_u32(skb, XFRMA_IPTFS_DROP_TIME, q);
	} else {
		if (xc->dont_frag) {
			ret = nla_put_flag(skb, XFRMA_IPTFS_DONT_FRAG);
			if (ret)
				return ret;
		}

		q = xtfs->init_delay_ns;
		(void)do_div(q, NSECS_IN_USEC);
		ret = nla_put_u32(skb, XFRMA_IPTFS_INIT_DELAY, q);
		if (ret)
			return ret;

		ret = nla_put_u32(skb, XFRMA_IPTFS_MAX_QSIZE,
				  xc->max_queue_size);
		if (ret)
			return ret;

		ret = nla_put_u32(skb, XFRMA_IPTFS_PKT_SIZE, xc->pkt_size);
	}

	return ret;
}

static int __iptfs_init_state(struct xfrm_state *x,
			      struct xfrm_iptfs_data *xtfs)
{
	__skb_queue_head_init(&xtfs->queue);
	hrtimer_init(&xtfs->iptfs_timer, CLOCK_MONOTONIC, IPTFS_HRTIMER_MODE);
	xtfs->iptfs_timer.function = iptfs_delay_timer;

	spin_lock_init(&xtfs->drop_lock);
	hrtimer_init(&xtfs->drop_timer, CLOCK_MONOTONIC, IPTFS_HRTIMER_MODE);
	xtfs->drop_timer.function = iptfs_drop_timer;

	/* Modify type (esp) adjustment values */

	if (x->props.family == AF_INET)
		x->props.header_len += sizeof(struct iphdr) + sizeof(struct ip_iptfs_hdr);
	else if (x->props.family == AF_INET6)
		x->props.header_len += sizeof(struct ipv6hdr) + sizeof(struct ip_iptfs_hdr);
	x->props.enc_hdr_len = sizeof(struct ip_iptfs_hdr);

	/* Always have a module reference if x->mode_data is set */
	if (!try_module_get(x->mode_cbs->owner))
		return -EINVAL;

	x->mode_data = xtfs;
	xtfs->x = x;

	return 0;
}

static int iptfs_clone(struct xfrm_state *x, struct xfrm_state *orig)
{
	struct xfrm_iptfs_data *xtfs;
	int err;

	xtfs = kmemdup(orig->mode_data, sizeof(*xtfs), GFP_KERNEL);
	if (!xtfs)
		return -ENOMEM;

	xtfs->ra_newskb = NULL;

	err = __iptfs_init_state(x, xtfs);
	if (err) {
		kfree_sensitive(xtfs->w_saved);
		kfree_sensitive(xtfs);
		return err;
	}

	return 0;
}

static int iptfs_create_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs;
	int err;

	xtfs = kzalloc(sizeof(*xtfs), GFP_KERNEL);
	if (!xtfs)
		return -ENOMEM;

	err = __iptfs_init_state(x, xtfs);
	if (err) {
		kfree_sensitive(xtfs);
		return err;
	}

	return 0;
}

static void iptfs_delete_state(struct xfrm_state *x)
{
	struct xfrm_iptfs_data *xtfs = x->mode_data;

	if (!xtfs)
		return;

	spin_lock_bh(&xtfs->drop_lock);
	hrtimer_cancel(&xtfs->iptfs_timer);
	hrtimer_cancel(&xtfs->drop_timer);
	spin_unlock_bh(&xtfs->drop_lock);

	if (xtfs->ra_newskb)
		kfree_skb(xtfs->ra_newskb);

	kfree_sensitive(xtfs);

	module_put(x->mode_cbs->owner);
}

static const struct xfrm_mode_cbs iptfs_mode_cbs = {
	.owner = THIS_MODULE,
	.create_state = iptfs_create_state,
	.delete_state = iptfs_delete_state,
	.user_init = iptfs_user_init,
	.copy_to_user = iptfs_copy_to_user,
	.sa_len = iptfs_sa_len,
	.clone = iptfs_clone,
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

	return err;
}

static void __exit xfrm_iptfs_fini(void)
{
	xfrm_unregister_mode_cbs(XFRM_MODE_IPTFS);
}

module_init(xfrm_iptfs_init);
module_exit(xfrm_iptfs_fini);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IP-TFS support for xfrm ipsec tunnels");
