
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
//#include <linux/ipv6.h>
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


#include "path_tracing.c"
/* oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo */

__section("xdp_abracadabra")
int __xdp_hike_vm_entrypoint(struct xdp_md *ctx)
{
	const __u32 chain_id = 0x4c;
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


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Example of HIKe Chains for the HIKe VM */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
//#include "eclat_output.c"

#define HIKE_CHAIN_80_ID 80
#define HIKE_CHAIN_81_ID 81

#define HIKE_EBPF_PROG_DROP_ANY 12
#include "eCLAT_Code/Code/Lib/Import/hike_program/drop.c"

#define HIKE_EBPF_PROG_ALLOW_ANY 11
#include "eCLAT_Code/Code/Lib/Import/hike_program/allow.c"

#define __ETH_PROTO_TYPE_ABS_OFF 12

#define __IPV4_TOTAL_LEN_ABS_OFF 16

#define __IPV6_HOP_LIM_ABS_OFF 21

HIKE_CHAIN_1(HIKE_CHAIN_80_ID){
    __u8 hop_lim;
    __u8 allow = 1;
    __u16 ip4_len;
    __u16 eth_type = hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
    if (eth_type == 0x800){
        ip4_len = hike_packet_read_u16(&ip4_len, __IPV4_TOTAL_LEN_ABS_OFF);
        if (ip4_len >= 128){
            hike_elem_call_3(HIKE_CHAIN_81_ID, allow, eth_type);
            return 0;
        }
        allow = 0;
        hike_elem_call_3(HIKE_CHAIN_81_ID, allow, eth_type);
        return 0;
    }
    if (eth_type == 0x86dd){
        hop_lim = hike_packet_read_u8(&hop_lim, __IPV6_HOP_LIM_ABS_OFF);
        if (hop_lim != 64){
            hike_elem_call_3(HIKE_CHAIN_81_ID, allow, eth_type);
            return 0;
        }
        hike_packet_write_u8(__IPV6_HOP_LIM_ABS_OFF, 17);
    }
    hike_elem_call_3(HIKE_CHAIN_81_ID, allow, eth_type);
    return 0;
}

HIKE_CHAIN_3(HIKE_CHAIN_81_ID, __u8, allow, __u16, eth_type){
    __u32 prog_id;
    if (allow == 1){
        prog_id = HIKE_EBPF_PROG_ALLOW_ANY;
    }
    else{
        prog_id = HIKE_EBPF_PROG_DROP_ANY;
    }
    hike_elem_call_2(prog_id, eth_type);

    return 0;
}


char _license[] SEC("license") = "GPL";
