
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

#define HIKE_DEBUG 1

#include "hike_vm.h"

/* aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa */

/* Some helper functions used for toy tests... */

struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH		2
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

/* oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo */

__section("xdp_abracadabra")
int __xdp_hike_vm_entrypoint(struct xdp_md *ctx)
{
	const __u32 chain_id = 0x4a;
	int rc;

	bpf_printk(">>> Chain Boostrap, chain_ID=0x%x", chain_id);

	rc = hike_chain_boostrap(ctx, chain_id);

	bpf_printk(">>> Chain Boostrap, chain ID=0x%x returned=%d",
		   chain_id, rc);

	return XDP_ABORTED;
}

__section("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/* uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu */

/* xdp_md *ctx and hike_chain_regmem *regmem are automatically injiected */
HIKE_PROG(foo)
{
	__u64 *R0 = _I_RREG(0);

	bpf_printk("HIKe Prog: foo REG_0=0x%llx", *R0);

	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(foo, 8);

HIKE_PROG(bar)
{
	__u64 R0 = _I_REG(0);
	__u64 R1 = _I_REG(1);
	__u64 R2 = _I_REG(2);

	bpf_printk("HIKe Prog: bar REG_0=0x%llx, REG_1=0x%llx, REG_2=0x%llx",
		   R0, R1, R2);

	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(bar, 9);

HIKE_PROG(parse_ethernet)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	__be16 h_proto;

	nh.pos = data;

	h_proto = parse_ethhdr(&nh, data_end, &eth);
	_I_REG(0) = 0xffff & bpf_ntohs(h_proto);

	return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG(parse_ethernet, 10);

#define HIKE_EBPF_PROG_ALLOW_ANY	11
#define HIKE_EBPF_PROG_DROP_ANY		12

HIKE_PROG(allow_any)
{
	bpf_printk("HIKe Prog: allow_any REG_1=0x%llx, REG_2=0x%llx",
		   _I_REG(1), _I_REG(2));

	return XDP_PASS;
}
EXPORT_HIKE_PROG(allow_any, HIKE_EBPF_PROG_ALLOW_ANY);

HIKE_PROG(drop_any)
{
	bpf_printk("HIKe Prog: drop_any REG_1=0x%llx, REG_2=0x%llx",
		   _I_REG(1), _I_REG(2));

	return XDP_DROP;
}
EXPORT_HIKE_PROG(drop_any, HIKE_EBPF_PROG_DROP_ANY);


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Example of HIKe Program for the HIKe VM */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */


#define HIKE_CHAIN_MYCHAIN1_ID 		0x49
#define HIKE_CHAIN_MYCHAIN2_ID		0x4a
#define HIKE_CHAIN_MYCHAIN3_ID		0x4b
#define HIKE_CHAIN_MYCHAIN4_ID		0x4c

/* 0x4d */
#define HIKE_CHAIN_MYCHAIN5_ID		77

__section("__sec_chain_mychain1")
int __chain_mychain1(void)
{
#define __ETH_PROTO_TYPE_ABS_OFF	12
#define __IPV6_HOP_LIM_ABS_OFF		21
	__u16 eth_type;
	__u8 hop_lim;

	hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
	if (eth_type == 0x800)
		goto drop;

	if (eth_type == 0x86dd) {
		/* change the TTL of the IPv4 packet */
		hike_packet_read_u8(&hop_lim, __IPV6_HOP_LIM_ABS_OFF);
		if (hop_lim != 64)
			goto allow;

		/* rewrite the hop_limit */
		hike_packet_write_u8(__IPV6_HOP_LIM_ABS_OFF, 17);
	}

	/* by default allow any protocol */
allow:
	hike_elem_call_2(HIKE_EBPF_PROG_ALLOW_ANY, eth_type);
	goto out;
drop:
	hike_elem_call_2(HIKE_EBPF_PROG_DROP_ANY, eth_type);
out:
	return 0;
#undef __ETH_PROTO_TYPE_ABS_OFF
#undef __IPV6_HOP_LIM_ABS_OFF
}

__section("__sec_chain_mychain2")
int __chain_mychain2(void)
{
#define __ETH_PROTO_TYPE_ABS_OFF	12
#define __IPV6_HOP_LIM_ABS_OFF		21
	__u16 eth_type;
	__u8 allow = 1;			/* allow any by default */
	__u8 hop_lim;

	hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
	if (eth_type == 0x800) {
		/* block IPv4 */
		allow = 0;
		goto out;
	}

	if (eth_type == 0x86dd) {
		/* change the TTL of the IPv4 packet */
		hike_packet_read_u8(&hop_lim, __IPV6_HOP_LIM_ABS_OFF);
		if (hop_lim != 64)
			goto out;

		/* rewrite the hop_limit */
		hike_packet_write_u8(__IPV6_HOP_LIM_ABS_OFF, 17);
	}

out:
	hike_elem_call_3(HIKE_CHAIN_MYCHAIN5_ID, allow, eth_type);

	return 0;
#undef __ETH_PROTO_TYPE_ABS_OFF
#undef __IPV6_HOP_LIM_ABS_OFF
}

__section("__sec_chain_mychain3")
int __chain_mychain3(void)
{
	__u16 eth_type; /* passed in register r3 */
	__u32 prog_id;
	__u8 allow;	/* passed in register r2 */

	/* explicit access to registers for retrieving passed arguments */
	__asm__ ("%[d0] = r2 \t\n"
		 "%[d1] = r3 \t\n"
		 : [d0] "=r" (allow), [d1] "=r" (eth_type)
		 :
		 : "r2","r3");

	prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY : HIKE_EBPF_PROG_DROP_ANY;
	hike_elem_call_2(prog_id, eth_type);

	return 0;
}

HIKE_CHAIN(HIKE_CHAIN_MYCHAIN5_ID, __u8 allow, __u16 eth_type)
{
	__u32 prog_id;

	prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY : HIKE_EBPF_PROG_DROP_ANY;
	hike_elem_call_2(prog_id, eth_type);

	return 0;
}

HIKE_CHAIN(abc)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
