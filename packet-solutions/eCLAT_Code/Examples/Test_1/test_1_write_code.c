/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Example of HIKe Program for the HIKe VM */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define HIKE_CHAIN_MYCHAIN1_ID 0x49
#define HIKE_CHAIN_MYCHAIN2_ID 0x4a
#define HIKE_CHAIN_MYCHAIN3_ID 0x4b
#define HIKE_CHAIN_MYCHAIN4_ID 0x4c

/* 0x4d */
#define HIKE_CHAIN_MYCHAIN5_ID 77

__section("__sec_chain_mychain1") 
int __chain_mychain1(void){
#define __ETH_PROTO_TYPE_ABS_OFF 12
#define __IPV6_HOP_LIM_ABS_OFF 21
    __u16 eth_type;
    __u8 hop_lim;

    hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
    if (eth_type == 0x800)
        goto drop;

    if (eth_type == 0x86dd){
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
int __chain_mychain2(void) {
#define __ETH_PROTO_TYPE_ABS_OFF 12
#define __IPV6_HOP_LIM_ABS_OFF 21
    __u16 eth_type;
    __u8 allow = 1; /* allow any by default */
    __u8 hop_lim;

    hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
    if (eth_type == 0x800){
        /* block IPv4 */
        allow = 0;
        goto out;
    }

    if (eth_type == 0x86dd){
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
int __chain_mychain3(void){
    __u16 eth_type; /* passed in register r3 */
    __u32 prog_id;
    __u8 allow; /* passed in register r2 */

    /* explicit access to registers for retrieving passed arguments */
    __asm__("%[d0] = r2 \t\n"
            "%[d1] = r3 \t\n"
            : [d0] "=r"(allow), [d1] "=r"(eth_type)
            :
            : "r2", "r3");

    prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY : HIKE_EBPF_PROG_DROP_ANY;
    hike_elem_call_2(prog_id, eth_type);

    return 0;
}

HIKE_CHAIN(HIKE_CHAIN_MYCHAIN5_ID, __u8 allow, __u16 eth_type){
    __u32 prog_id;

    prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY : HIKE_EBPF_PROG_DROP_ANY;
    hike_elem_call_2(prog_id, eth_type);

    return 0;
}