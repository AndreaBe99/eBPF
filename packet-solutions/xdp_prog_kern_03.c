/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <errno.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define PROG(F) SEC("xdp/"__stringify(F)) int bpf_func_##F

#define ENABLE_STATS

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};

#define PROG_NUM_MAX 32
struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = PROG_NUM_MAX,
};

#define PCPU_SCRATCH_BUFSIZE 128
struct bpf_map_def SEC("maps") pcpu_scratch = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = PCPU_SCRATCH_BUFSIZE,
	.max_entries = 1,
};

struct srv6_prog_info {

	/* the program type is used for binding the IPv6 DA with a specific
	 * program to be executed. Such value is used for loading in the
	 * correct section the correspondent eBPF program.
	 * */
	int prog_type;
};

struct bpf_map_def SEC("maps") ingress_match_table = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct in6_addr),
	.value_size = sizeof(struct bpf_prog_info),
	.max_entries = 64,
};

/* table for the monitoring program */
struct bpf_map_def SEC("maps") map_color = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

#define COLOR_MAX 2
struct counter_info {
	__u64 counter[COLOR_MAX];
};

//struct bpf_map_def SEC("maps") counter_table = {
//	.type = BPF_MAP_TYPE_PERCPU_HASH,
//	.key_size = sizeof(struct in6_addr),
//	.value_size = sizeof(struct counter_info),
//	.max_entries = 64,
//};

struct bpf_map_def SEC("maps") counter_table = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct counter_info),
	.max_entries = 64,
};

/* define tail_call progs at the beginning */

#define PARSE_IPv4 		11
#define PARSE_IPv6 		12

#define PROG_ENCAP_IPv6_IPv6	13
#define PROG_CUSTOM_2		14
#define PROG_ENCAP_SRH		15
#define PROG_ENCAP_SRH_AND_MON	16

/* 17-20 reserved for srh encap 1,2,4,8 */

#define PROG_REDIRECT		31

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static __always_inline
int xdp_return_action(struct xdp_md *ctx, int action)
{
#ifdef ENABLE_STATS
	return xdp_stats_record_action(ctx, action);
#else
	return action;
#endif
}

static __always_inline void *get_scratch(void)
{
	__u32 off = 0;
	return  bpf_map_lookup_elem(&pcpu_scratch, &off);
}

SEC("xdp_blackhole")
int xdp_blackhole_func(struct xdp_md *ctx)
{
	/* by default we drop the traffic (with the ABORT code) */
	int action = XDP_ABORTED;

	return xdp_return_action(ctx, action);
}

/* Solution to packet03/assignment-1 */
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply, old_csum;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common icmphdr_old;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);


	/* Patch the packet and update the checksum.*/
	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	/* Another, less generic, but a bit more efficient way to update the
	 * checksum is listed below.  As only one 16-bit word changed, the sum
	 * can be patched using this formula: sum' = ~(~sum + ~m0 + m1), where
	 * sum' is a new sum, sum is an old sum, m0 and m1 are the old and new
	 * 16-bit words, correspondingly. In the formula above the + operation
	 * is defined as the following function:
	 *
	 *     static __always_inline __u16 csum16_add(__u16 csum, __u16 addend)
	 *     {
	 *         csum += addend;
	 *         return csum + (csum < addend);
	 *     }
	 *
	 * So an alternative code to update the checksum might look like this:
	 *
	 *     __u16 m0 = * (__u16 *) icmphdr;
	 *     icmphdr->type = echo_reply;
	 *     __u16 m1 = * (__u16 *) icmphdr;
	 *     icmphdr->checksum = ~(csum16_add(csum16_add(~icmphdr->checksum, ~m0), m1));
	 */

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

PROG(PROG_REDIRECT)(struct xdp_md *ctx)
{
	int action;

	action = bpf_redirect_map(&tx_port, 0, 0);

	return xdp_return_action(ctx, action);
}

#define PROG_TAIL_CALL(NAME, F, NEXT)	 				\
	PROG(F)(struct xdp_md *ctx)					\
	{								\
		int action = XDP_ABORTED;				\
									\
		bpf_tail_call(ctx, &jmp_table, NEXT);			\
									\
		return xdp_return_action(ctx, action);			\
	}


/* just for making the code readable */
#define PROG_8

PROG_TAIL_CALL(PROG_8, 8, 7);
PROG_TAIL_CALL(PROG_8, 7, 6);
PROG_TAIL_CALL(PROG_8, 6, 5);
PROG_TAIL_CALL(PROG_8, 5, 4);
PROG_TAIL_CALL(PROG_8, 4, 3);
PROG_TAIL_CALL(PROG_8, 3, 2);
PROG_TAIL_CALL(PROG_8, 2, 1);
PROG_TAIL_CALL(PROG_8, 1, PROG_REDIRECT);

PROG(PARSE_IPv4)(struct xdp_md *ctx)
{
	int action = XDP_DROP;

	return xdp_return_action(ctx, action);
}

#if 0
PROG(PARSE_IPv6)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6hdr;
	struct hdr_cursor *nh;
	int action = XDP_DROP;
	int len;

	nh = get_scratch();
	if (!nh)
		goto out;

	len = data_end - data;
	if (len < 0)
		goto out;
	if (len > 1500)
		/* we search search the ipv6 header in the first 1500 bytes.
		 * This check is for making the verifier happy, otherwhise
		 * it will complain about an invalid packet/mem access.
		 */
		len = 1500;

	if (nh->nhoff < 0 || nh->nhoff > len)
		goto out;

	nh->pos = data + nh->nhoff;
	parse_ip6hdr(nh, data_end, &ip6hdr);
	if (!ip6hdr || ip6hdr + 1 > data_end)
		goto out;

	/* fake processing */
	if (ip6hdr->hop_limit <= 8)
		goto out;

	ip6hdr->hop_limit = 17;

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}
#endif

#define NHOFF_MAX 1500
#if 0
PROG(PARSE_IPv6)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6hdr;
	struct hdr_cursor *nh;
	int action = XDP_DROP;
	int ret;

	nh = get_scratch();
	if (!nh)
		goto out;

	/* check on the nhoff is mandatory here to make happy the verifier */
	if (nh->nhoff < 0 || nh->nhoff > NHOFF_MAX)
		goto out;

	nh->pos = data + nh->nhoff;
	ret = parse_ip6hdr(nh, data_end, &ip6hdr);
	if (ret < 0)
		goto out;

	/* even if the parse_ip6hdr(...) checks for the packet boundaries, we
	 * need to perform the check once again to make happy the verifier.
	 */
	if (!ip6hdr || ip6hdr + 1 > data_end)
		goto out;

	/* fake processing */
	if (ip6hdr->hop_limit < 8)
		ip6hdr->hop_limit = 17;

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}
#endif

#if 0
PROG(PROG_CUSTOM_1)(struct xdp_md *ctx)
{
	int action;

	action = bpf_redirect_map(&tx_port, 0, 0);

	return xdp_return_action(ctx, action);
}
#endif

struct ipv6_cb {
	/* order really matters */
	struct hdr_cursor nh;
};

#define check_header_off(__nh, __off) \
	((__nh)->__off >= 0 && (__nh)->__off <= NHOFF_MAX)

PROG(PROG_ENCAP_IPv6_IPv6)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6hdr, ip6hdr_copy;
	struct ethhdr *eth, eth_copy;
	__u32 eth_len, ipv6_len;
	int action = XDP_PASS;
	struct hdr_cursor *nh;
	struct ipv6_cb *cb;
	__u16 payload_len;
	void *ptr;

	cb = get_scratch();
	if (!cb)
		goto out;
	nh = &cb->nh;
	if (!nh)
		goto out;

	/* check for the mac offset  */
	if (!check_header_off(nh, mhoff))
		goto out;
	if (!check_header_off(nh, nhoff))
		goto out;

	/* layer 2 */
	eth_len = nh->nhoff - nh->mhoff;
	if (eth_len < 0 || eth_len > NHOFF_MAX)
		goto out;

	ptr = data + nh->mhoff;
	if (ptr + eth_len  > data_end)
		goto out;

	eth = (struct ethhdr *)ptr;
	/* to make the verifier happy  */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: _memcpy does not allow to use variable size here, only
	 * constant value. It means that we have to analyze the packet more to
	 * find out how many vlan tags are pushed and returns with a value that
	 * is const.
	 */
	__builtin_memcpy(&eth_copy, eth, sizeof(*eth));

	/* layer 3 */
	ipv6_len = sizeof(*ip6hdr);
	ptr = data + eth_len;
	if (ptr + ipv6_len > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	/* to make the verifier happy */
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(&ip6hdr_copy, ip6hdr, sizeof(*ip6hdr));
	/* ipv6 in ipv6 encap just for testing:
	 *  - adjust the next header of the outer packet;
	 *  - ajust the payload len of the outer packet.
	 */
	ip6hdr_copy.nexthdr = 41;
	payload_len = bpf_ntohs(ip6hdr_copy.payload_len) + ipv6_len;
	ip6hdr_copy.payload_len = bpf_htons(payload_len);

	/* add the space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - ipv6_len))
			goto out;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 *
	 * NOTE: nhoff and mhoff are not valid anymore because they refer to
	 * the previous head of the packet which has been moved on.
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	ptr = eth;
	if (ptr + eth_len > data_end)
		goto out;
	/* to make the compiler happy */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(eth, &eth_copy, sizeof(*eth));

	ptr = ptr + eth_len;
	if (ptr + sizeof(*ip6hdr) > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(ip6hdr, &ip6hdr_copy, sizeof(*ip6hdr));

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}

#define eval_nsegs(__srhlen) (((__srhlen) - 8) >> 4)

static
int __always_inline dummy_init_srh(void *ptr, struct in6_addr *sid, __u16 len,
				   __u8 proto)
{
	struct ipv6_sr_hdr *srh = ptr;

	/* XXX: fixed length: len bytes -> 1 sid */
	srh->hdrlen = (len >> 3) - 1;
	srh->type = 4;
	srh->segments_left = eval_nsegs(len) - 1;
	srh->first_segment = eval_nsegs(len) - 1;
	srh->nexthdr = proto;

	return 0;
}

#define SRH_LENGTH 24
PROG(PROG_ENCAP_SRH)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6hdr, ip6hdr_copy;
	struct ethhdr *eth, eth_copy;
	struct ipv6_sr_hdr *srh;
	__u32 eth_len, ipv6_len;
	int action = XDP_PASS;
	struct hdr_cursor *nh;
	struct ipv6_cb *cb;
	__u16 payload_len;
	void *ptr;

	cb = get_scratch();
	if (!cb)
		goto out;
	nh = &cb->nh;
	if (!nh)
		goto out;

	/* check for the mac offset  */
	if (!check_header_off(nh, mhoff))
		goto out;
	if (!check_header_off(nh, nhoff))
		goto out;

	/* layer 2 */
	eth_len = nh->nhoff - nh->mhoff;
	if (eth_len < 0 || eth_len > NHOFF_MAX)
		goto out;

	ptr = data + nh->mhoff;
	if (ptr + eth_len > data_end)
		goto out;

	eth = (struct ethhdr *)ptr;
	/* to make the verifier happy  */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: _memcpy does not allow to use variable size here, only
	 * constant value. It means that we have to analyze the packet more to
	 * find out how many vlan tags are pushed and returns with a value that
	 * is const.
	 */
	__builtin_memcpy(&eth_copy, eth, sizeof(*eth));

	/* layer 3 */
	ipv6_len = sizeof(*ip6hdr);
	ptr = data + eth_len;
	if (ptr + ipv6_len > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	/* to make the verifier happy */
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(&ip6hdr_copy, ip6hdr, sizeof(*ip6hdr));
	/* ipv6 in ipv6 encap just for testing:
	 *  - adjust the next header of the outer packet;
	 *  - ajust the payload len of the outer packet.
	 */
	ip6hdr_copy.nexthdr = 43;

	payload_len = bpf_ntohs(ip6hdr_copy.payload_len);
	payload_len += ipv6_len + SRH_LENGTH;
	ip6hdr_copy.payload_len = bpf_htons(payload_len);

	/* add the space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (ipv6_len + SRH_LENGTH)))
			goto out;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 *
	 * NOTE: nhoff and mhoff are not valid anymore because they refer to
	 * the previous head of the packet which has been moved on.
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	ptr = eth;
	if (ptr + eth_len > data_end)
		goto out;
	/* to make the compiler happy */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(eth, &eth_copy, sizeof(*eth));

	ptr = ptr + eth_len;
	if (ptr + sizeof(*ip6hdr) > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(ip6hdr, &ip6hdr_copy, sizeof(*ip6hdr));

	/* srh layer */
	ptr = ptr + ipv6_len;
	if (ptr + SRH_LENGTH > data_end)
		goto out;

	srh = (struct ipv6_sr_hdr *)ptr;
	if (srh + 1 > data_end)
		goto out;

	/* set the nexthader */
	dummy_init_srh(srh, &ip6hdr->daddr, SRH_LENGTH, 41);
	__builtin_memcpy(&srh->segments[0], &ip6hdr->daddr,
			 sizeof(ip6hdr->daddr));

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}
#undef SRH_LENGTH

static __always_inline int dummy_srh_encap(struct xdp_md *ctx, __u8 nsegs)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	const __u32 srhlen = 8 + (nsegs << 4);
	struct ipv6hdr *ip6hdr, ip6hdr_copy;
	struct ethhdr *eth, eth_copy;
	struct ipv6_sr_hdr *srh;
	__u32 eth_len, ipv6_len;
	struct hdr_cursor *nh;
	struct ipv6_cb *cb;
	__u16 payload_len;
	void *ptr;
	int i;

	cb = get_scratch();
	if (!cb)
		goto out;
	nh = &cb->nh;
	if (!nh)
		goto out;

	/* check for the mac offset  */
	if (!check_header_off(nh, mhoff))
		goto out;
	if (!check_header_off(nh, nhoff))
		goto out;

	/* layer 2 */
	eth_len = nh->nhoff - nh->mhoff;
	if (eth_len < 0 || eth_len > NHOFF_MAX)
		goto out;

	ptr = data + nh->mhoff;
	if (ptr + eth_len > data_end)
		goto out;

	eth = (struct ethhdr *)ptr;
	/* to make the verifier happy  */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: _memcpy does not allow to use variable size here, only
	 * constant value. It means that we have to analyze the packet more to
	 * find out how many vlan tags are pushed and returns with a value that
	 * is const.
	 */
	__builtin_memcpy(&eth_copy, eth, sizeof(*eth));

	/* layer 3 */
	ipv6_len = sizeof(*ip6hdr);
	ptr = data + eth_len;
	if (ptr + ipv6_len > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	/* to make the verifier happy */
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(&ip6hdr_copy, ip6hdr, sizeof(*ip6hdr));
	/* ipv6 in ipv6 encap just for testing:
	 *  - adjust the next header of the outer packet;
	 *  - ajust the payload len of the outer packet.
	 */
	ip6hdr_copy.nexthdr = 43;

	payload_len = bpf_ntohs(ip6hdr_copy.payload_len);
	payload_len += ipv6_len + srhlen;
	ip6hdr_copy.payload_len = bpf_htons(payload_len);

	/* add the space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (ipv6_len + srhlen)))
		goto out;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 *
	 * NOTE: nhoff and mhoff are not valid anymore because they refer to
	 * the previous head of the packet which has been moved on.
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	ptr = eth;
	if (ptr + eth_len > data_end)
		goto out;
	/* to make the compiler happy */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(eth, &eth_copy, sizeof(*eth));

	ptr = ptr + eth_len;
	if (ptr + sizeof(*ip6hdr) > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(ip6hdr, &ip6hdr_copy, sizeof(*ip6hdr));

	/* srh layer */
	ptr = ptr + ipv6_len;
	if (ptr + srhlen > data_end)
		goto out;

	srh = (struct ipv6_sr_hdr *)ptr;
	if (srh + 1 > data_end)
		goto out;

	/* set the nexthader */
	dummy_init_srh(srh, &ip6hdr->daddr, srhlen, 41);

	#pragma unroll
	for(i = 0; i < 8 && i < nsegs; ++i) {
		__builtin_memcpy(&srh->segments[i], &ip6hdr->daddr,
				 sizeof(ip6hdr->daddr));
	}

	return 0;

out:
	return -ENOBUFS;
}

#define PROG_ENCAP_SRH_TEST(NAME, NSEGS)	 		\
	PROG(NAME)(struct xdp_md *ctx)				\
	{ 							\
		int action = XDP_ABORTED;			\
		int ret;					\
								\
		ret = dummy_srh_encap(ctx, NSEGS);		\
		if (ret < 0)					\
			goto out;				\
								\
		action = bpf_redirect_map(&tx_port, 0, 0);	\
								\
	out:							\
		return xdp_return_action(ctx, action);		\
	}							\

PROG_ENCAP_SRH_TEST(17, 1);
PROG_ENCAP_SRH_TEST(18, 2);
PROG_ENCAP_SRH_TEST(19, 4);
PROG_ENCAP_SRH_TEST(20, 8);

#if 0
PROG(PROG_ENCAP_SRH_2)(struct xdp_md *ctx)
{
	int action = XDP_ABORTED;
	int ret;

	ret = dummy_srh_encap(ctx, 2);
	if (ret < 0)
		goto out;

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}
#endif

static __always_inline int update_mon_counter(struct in6_addr *addr)
{
	struct counter_info *cinfo;
	const __u32 index = 0;
	__u32 color;
	__u32 *cc;

	cc = bpf_map_lookup_elem(&map_color, &index);
	if (!cc)
		return -ENOENT;

	cinfo = bpf_map_lookup_elem(&counter_table, &index);
	if (!cinfo)
		return -ENOENT;

	/* check the validity of the active color */
	color = *cc;
	if (color >= COLOR_MAX)
		return -EDOM;

	++cinfo->counter[color];

	return 0;
}

#define SRH_LENGTH 24
PROG(PROG_ENCAP_SRH_AND_MON)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6hdr, ip6hdr_copy;
	struct ethhdr *eth, eth_copy;
	struct ipv6_sr_hdr *srh;
	__u32 eth_len, ipv6_len;
	struct in6_addr *daddr;
	int action = XDP_PASS;
	struct hdr_cursor *nh;
	struct ipv6_cb *cb;
	__u16 payload_len;
	void *ptr;

	cb = get_scratch();
	if (!cb)
		goto out;
	nh = &cb->nh;
	if (!nh)
		goto out;

	/* check for the mac offset  */
	if (!check_header_off(nh, mhoff))
		goto out;
	if (!check_header_off(nh, nhoff))
		goto out;

	/* layer 2 */
	eth_len = nh->nhoff - nh->mhoff;
	if (eth_len < 0 || eth_len > NHOFF_MAX)
		goto out;

	ptr = data + nh->mhoff;
	if (ptr + eth_len > data_end)
		goto out;

	eth = (struct ethhdr *)ptr;
	/* to make the verifier happy  */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: _memcpy does not allow to use variable size here, only
	 * constant value. It means that we have to analyze the packet more to
	 * find out how many vlan tags are pushed and returns with a value that
	 * is const.
	 */
	__builtin_memcpy(&eth_copy, eth, sizeof(*eth));

	/* layer 3 */
	ipv6_len = sizeof(*ip6hdr);
	ptr = data + eth_len;
	if (ptr + ipv6_len > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	/* to make the verifier happy */
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(&ip6hdr_copy, ip6hdr, sizeof(*ip6hdr));
	/* ipv6 in ipv6 encap just for testing:
	 *  - adjust the next header of the outer packet;
	 *  - ajust the payload len of the outer packet.
	 */
	ip6hdr_copy.nexthdr = 43;

	payload_len = bpf_ntohs(ip6hdr_copy.payload_len);
	payload_len += ipv6_len + SRH_LENGTH;
	ip6hdr_copy.payload_len = bpf_htons(payload_len);

	/* add the space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (ipv6_len + SRH_LENGTH)))
			goto out;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 *
	 * NOTE: nhoff and mhoff are not valid anymore because they refer to
	 * the previous head of the packet which has been moved on.
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	ptr = eth;
	if (ptr + eth_len > data_end)
		goto out;
	/* to make the compiler happy */
	if (eth + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(eth, &eth_copy, sizeof(*eth));

	ptr = ptr + eth_len;
	if (ptr + sizeof(*ip6hdr) > data_end)
		goto out;

	ip6hdr = (struct ipv6hdr *)ptr;
	if (ip6hdr + 1 > data_end)
		goto out;

	/* XXX: see above */
	__builtin_memcpy(ip6hdr, &ip6hdr_copy, sizeof(*ip6hdr));

	/* srh layer */
	ptr = ptr + ipv6_len;
	if (ptr + SRH_LENGTH > data_end)
		goto out;

	srh = (struct ipv6_sr_hdr *)ptr;
	if (srh + 1 > data_end)
		goto out;

	daddr = &ip6hdr->daddr;
	
	/* set the nextheader */
	dummy_init_srh(srh, daddr, SRH_LENGTH, 41);
	__builtin_memcpy(&srh->segments[0], daddr, sizeof(*daddr));

	/* XXX: this should be another PROG but we are out of time... */
	update_mon_counter(daddr);

	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_return_action(ctx, action);
}
#undef SRH_LENGTH

PROG(PROG_CUSTOM_2)(struct xdp_md *ctx)
{
	int action = XDP_ABORTED;

	return xdp_return_action(ctx, action);
}

#define NHOFF_MAX 1500
PROG(PARSE_IPv6)(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct srv6_prog_info *prog_info;
	struct ipv6hdr *ip6hdr;
	struct in6_addr *daddr;
	struct hdr_cursor *nh;
	int action = XDP_PASS;
	int prog_type;
	int ret;

	nh = get_scratch();
	if (!nh)
		goto out;

	/* NOTE: nh->pos is considered invalid. Please use the nh->nhoff for
	 * passing the new header offset in a new tail call.
	 */

	/* check on the nhoff is mandatory here to make happy the verifier */
	if (nh->nhoff < 0 || nh->nhoff > NHOFF_MAX)
		goto out;

	nh->pos = data + nh->nhoff;
	ret = parse_ip6hdr(nh, data_end, &ip6hdr);
	if (ret < 0)
		goto out;

	/* even if the parse_ip6hdr(...) checks for the packet boundaries, we
	 * need to perform the check once again to make happy the verifier.
	 */
	if (!ip6hdr || ip6hdr + 1 > data_end)
		goto out;

	daddr = &ip6hdr->daddr;
	if (!daddr)
		goto out;

	/* retrieve the prog's info if there is a match in the table */
	prog_info = bpf_map_lookup_elem(&ingress_match_table, daddr);
	if (!prog_info)
		goto out;

	prog_type = prog_info->prog_type;
	if (prog_type < 0 || prog_type >= PROG_NUM_MAX)
		goto out;

	/* at this point we call the registered program for the DA.
	 *
	 * NOTE: we do not move the nhoff towards. The nhoff value will be
	 * sticked to the network header.
	 */
	bpf_tail_call(ctx, &jmp_table, prog_type);

	/* fall through here */

out:
	return xdp_return_action(ctx, action);
}

SEC("xdp_dispatcher")
int xdp_dispatcher_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = NULL;
	int action = XDP_PASS;
	struct hdr_cursor *nh;
	int eth_type;
	void *head;

	/* These keep track of the next header type and iterator pointer */
	nh = get_scratch();
	if (!nh)
		goto out;

	/* offset of the mac header from the beginning of the packet (data) */
	nh->pos = head = data;
	nh->mhoff = 0;

	eth_type = parse_ethhdr(nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	if (!eth)
		goto out;

	/* update the nhoff which is used in the tail called progs: in this way
	 * we avoid to parse the packet again and again.
	 */
	nh->nhoff = nh->pos - head;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		bpf_tail_call(ctx, &jmp_table, PARSE_IPv4);
		/* fall through if the prog is not set or in case of error */
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		bpf_tail_call(ctx, &jmp_table, PARSE_IPv6);

		/* fall through if the prog is not set or in case of error */
		action = XDP_DROP;
	}

out:
	return xdp_return_action(ctx, action);
}

SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	int action;

	action = bpf_redirect_map(&tx_port, 0, 0);

	return xdp_return_action(ctx, action);
}

#if 0
#define __PASSTHROUGH_REDIRECT
/* Solution to packet03/assignment-3 */
SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
#ifndef __PASSTHROUGH_REDIRECT
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	unsigned char *dst;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Do we know where to redirect this packet? */
	dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	if (!dst)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
#endif
	action = bpf_redirect_map(&tx_port, 0, 0);

#ifndef __PASSTHROUGH_REDIRECT
out:
	return xdp_stats_record_action(ctx, action);
#else
	return action;
#endif
}
#endif

#define AF_INET 2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

/* Solution to packet03/assignment-4 */
SEC("xdp_router")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
