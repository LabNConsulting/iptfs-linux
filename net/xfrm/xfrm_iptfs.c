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
#define NSECS_IN_USECS 1000
#define NSECS_IN_MSECS (NSECS_IN_USECS * 1000)

#define XFRM_IPTFS_DELAY_NSECS (200 * NSECS_IN_MSECS)

/* maximum depth of queue for aggregating */
#define XFRM_IPTFS_MAX_QUEUE_SIZE (1500 * 129)

#undef PR_DEBUG_INFO
#ifdef PR_DEBUG_INFO
#define pr_devinf(...) pr_info(__VA_ARGS__)
#else
#define pr_devinf(...) pr_devel(__VA_ARGS__)
#endif

struct xfrm_iptfs_data {
	struct xfrm_state *x; /* owning state */
	struct sk_buff_head delay_queue;
	size_t delay_queue_size;
	struct hrtimer iptfs_timer;
	spinlock_t iptfs_lock;
	time64_t iptfs_settime;
};

static enum hrtimer_restart xfrm_iptfs_delay_timer(struct hrtimer *me);

/* ----------------- */
/* Utility Functions */
/* ----------------- */

uint icmpseq(struct sk_buff *skb)
{
	return ntohs(((struct icmphdr *)((struct iphdr *)skb->data + 1))
			     ->un.echo.sequence);
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
	__skb_queue_head_init(&xtfs->delay_queue);
	spin_lock_init(&xtfs->iptfs_lock);
	hrtimer_init(&xtfs->iptfs_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_SOFT);
	xtfs->iptfs_timer.function = xfrm_iptfs_delay_timer;

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
		 * original offset?
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

struct sk_buff *pskb_extract_seq(struct skb_seq_state *st, uint off, int len,
				 uint resv, gfp_t gfp)
{
	struct sk_buff *skb;

	skb = alloc_skb(len + resv, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, resv);

	skb->csum = 0;
	skb_copy_header(skb, st->root_skb);
	// the skb_copy_header does the following so figure out wth it is :)
	// skb_shinfo(new)->gso_size = skb_shinfo(old)->gso_size;
	// skb_shinfo(new)->gso_segs = skb_shinfo(old)->gso_segs;
	// skb_shinfo(new)->gso_type = skb_shinfo(old)->gso_type;

	// XXX chopps: what is this _exactly_?
	// skb->ip_summed = 0;

	skb_put(skb, len);
	if (skb_copy_bits_seq(st, off, skb->data, len)) {
		kfree_skb(skb);
		return NULL;
	}
	return skb;
}
EXPORT_SYMBOL(pskb_extract_seq);

/*
 * We have an IPTFS payload dispense with it and this skb as well.
 */
int xfrm_iptfs_input(struct gro_cells *gro_cells, struct xfrm_state *x,
		     struct sk_buff *skb)
{
	struct sk_buff *first_skb = NULL;
	struct sk_buff *defer = NULL;
	struct net *net = dev_net(skb->dev);
	int family = x->sel.family;
	struct ip_iptfs_cc_hdr iptcch;
	struct skb_seq_state skbseq;
	struct list_head sublist;
	struct ip_iptfs_hdr *ipth = (struct ip_iptfs_hdr *)&iptcch;
	const unsigned char *old_mac;
	struct iphdr *iph;
	uint data, tail;
	struct sk_buff *next;
	struct sec_path *sp, *nsp;
	uint remaining, first_iplen, iplen, iphlen, resv;
	int err;

	/* when we support DSCP copy option ... */
	// static inline __u8 ipv4_get_dsfield(const struct iphdr *iph)
	// static inline __u8 ipv6_get_dsfield(const struct ipv6hdr *ipv6h)

	// err = skb_unclone(skb, GFP_ATOMIC);

	if (x->sel.family == AF_UNSPEC)
		family = x->outer_mode.family;

	/* advance past the IPTFS header */

	// skb_pull(skb, sizeof(*ipth));

	data = 0;
	tail = skb->len;
	remaining = tail - data;
	skb_prepare_seq_read(skb, data, tail, &skbseq);

	/* Save the old mac header if set */
	old_mac = skb_mac_header_was_set(skb) ? skb_mac_header(skb) : NULL;

	/*
	 * Get the IPTFS header and validate it
	 */
	if (remaining < sizeof(*ipth)) {
	badhdr:
		pr_err("%s: BADHDR error\n", __func__);
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto done;
	}
	if (skb_copy_bits_seq(&skbseq, data, ipth, sizeof(*ipth)))
		goto badhdr;
	data += sizeof(*ipth);
	if (ipth->flags != 0 || ipth->block_offset != 0)
		goto badhdr;
	if (ipth->subtype == IPTFS_SUBTYPE_CC) {
		remaining = sizeof(iptcch) - sizeof(*ipth);
		if (skb_copy_bits_seq(&skbseq, data, ipth + 1, remaining))
			goto badhdr;
		data += remaining;
	} else if (ipth->subtype != IPTFS_SUBTYPE_BASIC)
		goto badhdr;

	INIT_LIST_HEAD(&sublist);
	while (data < tail) {
		u8 hbytes[sizeof(struct ipv6hdr)];

		remaining = tail - data;

		iphlen = min(remaining, (uint)6);
		if (skb_copy_bits_seq(&skbseq, data, hbytes, iphlen))
			goto badhdr;

		iph = (struct iphdr *)hbytes;

		if (iph->version == 0x4) {
			/* must have at least tot_len field present */
			/* XXX chopps: fragmentation support */
			if (iphlen < 4)
				goto badhdr;

			iplen = htons(iph->tot_len);
			iphlen = iph->ihl << 2;
			pr_devinf("%s: ipv4 inner length %u\n", __func__,
				  iplen);
		} else if (iph->version == 0x6) {
			/* must have at least payload_len field present */
			/* XXX chopps: fragmentation support */
			if (iphlen < 6)
				goto badhdr;

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

		/* XXX chopps: fragmentation support */
		if (iplen > remaining || iphlen > remaining) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto done;
		}

		if (first_skb)
			skb = NULL;
		else {
			first_skb = skb;
			first_iplen = iplen;
			resv = skb_headroom(skb);
			if (resv < XFRM_IPTFS_MIN_HEADROOM)
				resv = XFRM_IPTFS_MIN_HEADROOM;

			if (!skb_is_nonlinear(skb)) {
				/* since reusing skb move past the IPTFS header */
				pskb_pull(skb, data);

				skb_mac_header_rebuild(skb);

				/* our range just changed */
				data = 0;
				tail = skb->len;
				remaining = tail - data;

				/* all pointers could be changed now reset walk */
				skb_abort_seq_read(&skbseq);
				skb_prepare_seq_read(skb, data, tail, &skbseq);

				pr_devinf("%s: reusing outer skb %p\n",
					  __func__, skb);
			} else {
				/* if first skb has frags also extract into new skb */
				defer = skb;
				skb = NULL;
			}
			/* don't trim now since we want are walking the data */
		}
		if (!skb) {
#if 0
			skb = pskb_extract(first_skb, data, iplen, GFP_ATOMIC);
#else
			/*
			 * XXX might not be save to re-use data offset here if
			 * getting the initial hbytes advanced the seq read to
			 * next block of data
			 */
			skb = pskb_extract_seq(&skbseq, data, iplen, resv,
					       GFP_ATOMIC);
#endif
			if (!skb) {
				pr_err("%s: failed to alloc new skb\n",
				       __func__);
				XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
				continue;
			}
			pr_devinf("%s: alloc'd new skb %p\n", __func__, skb);
			sp = skb_sec_path(first_skb);
			BUG_ON(!sp);
			nsp = skb_sec_path(skb);
			if (!nsp) {
				XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
				kfree_skb(skb);
				continue;
			}

			if (old_mac) {
				/* rebuild the mac header */
				skb_set_mac_header(skb, -first_skb->mac_len);
				memcpy(skb_mac_header(skb), old_mac,
				       first_skb->mac_len);
			}
		}
		pr_devinf("%s: skb %p icmpseq %u\n", __func__, skb,
			  icmpseq(skb));

		skb_reset_network_header(skb);
		skb_set_transport_header(skb, iphlen);

		/* point iph at the actual header rather than hbytes */
		/* XXX this doesn't work if the header is in a fragment */
		iph = ip_hdr(skb);

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

		/* XXX rebuild mac header? */
		data += iplen;

		/* XXX family here should be from outer or from inner packet */
		/* XXX this is keeping interface stats and looking up dst
		 * xfrmi interface if that's being used
		 */
		err = xfrm_rcv_cb(skb, family, x->type->proto, 0);
		if (err) {
			xfrm_rcv_cb(skb, family,
				    (x && x->type) ? x->type->proto :
						     XFRM_PROTO_IPTFS,
				    -1);
			if (skb != first_skb)
				kfree_skb(skb);
			else
				/* XXX or do we drop the rest? */
				defer = skb;
			continue;
		}

		nf_reset_ct(skb);
		sp = skb_sec_path(skb);
		if (sp)
			sp->olen = 0;
		skb_dst_drop(
			skb); /* XXX ok to do this on first_skb before done? */

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
		pr_devinf("%s: sending inner packet len %u skb %p icmpseq %u\n",
			  __func__, (uint)skb->len, skb, icmpseq(skb));
		gro_cells_receive(gro_cells, skb);
	}

	/* safe to call even if we were done */
done:
	skb_abort_seq_read(&skbseq);

	if (defer)
		kfree_skb(defer);

	return 0;
}

/* --------------------------------- */
/* IPTFS Sending (ingress) Functions */
/* --------------------------------- */

/*
 * Check to see if it's OK to queue a packet for sending on tunnel, lock must be
 * held.
 */
static bool __xfrm_itpfs_enqueue(struct xfrm_iptfs_data *xtfs,
				 struct sk_buff *skb)
{
	/* For now we use a predefined constant value, eventually configuration */
	if (xtfs->delay_queue_size + skb->len > XFRM_IPTFS_MAX_QUEUE_SIZE) {
		pr_warn_ratelimited(
			"%s: no space: qsize: %u skb len %u max %u\n", __func__,
			(uint)xtfs->delay_queue_size, (uint)skb->len,
			(uint)XFRM_IPTFS_MAX_QUEUE_SIZE);
		kfree_skb(skb);
		return false;
	}
	__skb_queue_tail(&xtfs->delay_queue, skb);
	xtfs->delay_queue_size += skb->len;
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

	BUG_ON(xtfs == NULL);

	/* not sure what the sock is used for here */
	/* This will be set if we do a local ping! */
	// WARN_ON(sk != NULL);

	/* can be running on multiple cores */
	spin_lock(&x->lock);

	if (!__xfrm_itpfs_enqueue(xtfs, skb))
		goto done;

	// if (skb->protocol == htons(ETH_P_IPV6))
	// mtu = ip6_skb_dst_mtu(skb);
	pr_devinf("%s: skb: %p len %u icmpseq %u dst_mtu() => %d\n", __func__,
		  skb, (uint)skb->len, icmpseq(skb), (int)dst_mtu(dst));

	/* Start a delay timer if we don't have one yet */
	if (!hrtimer_is_queued(&xtfs->iptfs_timer)) {
		pr_devinf("%s: starting hrtimer\n", __func__);
		hrtimer_start(&xtfs->iptfs_timer, XFRM_IPTFS_DELAY_NSECS,
			      HRTIMER_MODE_REL_SOFT);
		xtfs->iptfs_settime = ktime_get_raw_fast_ns();
	}

done:
	spin_unlock(&x->lock);
	return 0;
}

static int xfrm_iptfs_first_skb(struct sk_buff *skb)
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

	if (1) { /* actually if IPTFS DF is set */
		/* XXX verify skb->network_header points at skb->data? */
		if ((!skb_is_gso(skb) && skb->len > mtu) ||
		    (skb_is_gso(skb) &&
		     !skb_gso_validate_network_len(skb, ip_skb_dst_mtu(skb->sk,
								       skb)))) {
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

static void __xfrm_iptfs_output_queued(struct xfrm_state *x,
				       struct sk_buff_head *list)
{
	struct sk_buff *skb, *skb2, **nextp;
	int err;

	/* and send them on their way */
	while ((skb = __skb_dequeue(list))) {
		/* XXX we want this from the tunnel outer encap */
		int remaining = dst_mtu(skb_dst(skb));

		pr_devinf("%s: 1st dequeue skb %p len %u icmpseq: %u\n",
			  __func__, skb, skb->len, icmpseq(skb));
		if (xfrm_iptfs_first_skb(skb))
			continue;

		remaining -= skb->len;

		nextp = &skb_shinfo(skb)->frag_list;
		while (*nextp)
			nextp = &(skb_shinfo(*nextp))->frag_list;

		/* XXX should peek first to see if we have MTU room to append */
		while ((skb2 = skb_peek(list)) && skb2->len <= remaining) {
			skb2 = __skb_dequeue(list);

			pr_devinf(
				"%s: appendg secondary dequeue skb2 %p len %u data_len %u icmpseq %u\n",
				__func__, skb2, skb2->len, skb2->data_len,
				icmpseq(skb2));
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

static enum hrtimer_restart xfrm_iptfs_delay_timer(struct hrtimer *me)
{
	struct sk_buff_head list;
	struct xfrm_iptfs_data *xtfs;
	struct xfrm_state *x;
	time64_t settime;
	size_t osize;

	xtfs = container_of(me, typeof(*xtfs), iptfs_timer);
	x = xtfs->x;

	/*
         * softirq execution order: timer > tasklet > hrtimer
         *
         * Network rx will have run before us giving one last chance to queue
         * ingress packets for us to process and transmit.
         */
	spin_lock(&x->lock);
	__skb_queue_head_init(&list);
	skb_queue_splice_init(&xtfs->delay_queue, &list);
	osize = xtfs->delay_queue_size;
	xtfs->delay_queue_size = 0;
	settime = xtfs->iptfs_settime;
	spin_unlock(&x->lock);

	pr_devinf("%s: got %u packets of %u total len\n", __func__,
		  (uint)list.qlen, (uint)osize);
	pr_devinf("%s: time delta %llu\n", __func__,
		  (unsigned long long)(ktime_get_raw_fast_ns() - settime));

	spin_lock(&xtfs->iptfs_lock);
	__xfrm_iptfs_output_queued(x, &list);
	spin_unlock(&xtfs->iptfs_lock);

	return HRTIMER_NORESTART;
}
