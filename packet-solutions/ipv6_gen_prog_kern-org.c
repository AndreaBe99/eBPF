
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errno.h>

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
	const __u32 chain_id = 0x49;
	int rc;

	bpf_printk(">>> Chain Boostrap, chain_id=%x", chain_id);

	rc = hike_chain_boostrap(ctx, chain_id);

	bpf_printk(">>> Chain Boostrap, chain id=%x returned=%d",
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

/* --- DO NOT TOUCH ABOVE --- */

#define HIKE_EBPF_PROG_DROP_ANY		12
#define HIKE_EBPF_PROG_ALLOW_ANY	11

HIKE_PROG(allow_any)
{
	bpf_printk("HIKe Prog: allow_any REG_2=0x%llx", _I_REG(2));

	return XDP_PASS;
}
EXPORT_HIKE_PROG(allow_any, HIKE_EBPF_PROG_ALLOW_ANY);

HIKE_PROG(drop_any)
{
	bpf_printk("HIKe Prog: drop_any REG_2=0x%llx", _I_REG(2));

	return XDP_DROP;
}
EXPORT_HIKE_PROG(drop_any, HIKE_EBPF_PROG_DROP_ANY);


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Example of HIKe Program for the HIKe VM */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define __PACKET_BASE_ADDR ((size_t)(HIKE_MEM_PACKET_ADDR_DATA))

#define __READ_PACKET(__type, __offset)					\
	((volatile __type)*(__type *)((__PACKET_BASE_ADDR) + (__offset)))

#define __WRITE_PACKET(__type, __offset)				\
	*(volatile __type *)((__PACKET_BASE_ADDR) + (__offset))

__section("__sec_chain_mychain1")
int __chain_mychain1(void)
{
	__u16 eth_type;

	eth_type = bpf_ntohs(__READ_PACKET(__be16, 12));
	if (eth_type == 0x86dd) {
		hike_elem_call_2(HIKE_EBPF_PROG_DROP_ANY, eth_type);
		goto out;
	}

	if (eth_type == 0x800)
		/* change the TTL of the IPv4 packet */
		__WRITE_PACKET(__u8, 22) = 64;

	hike_elem_call_2(HIKE_EBPF_PROG_ALLOW_ANY, eth_type);
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
