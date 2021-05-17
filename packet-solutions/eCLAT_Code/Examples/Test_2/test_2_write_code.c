
HIKE_CHAIN_1(HIKE_CHAIN_MYCHAIN4_ID)
{
#define __ETH_PROTO_TYPE_ABS_OFF 12
#define __IPV4_TOTAL_LEN_ABS_OFF 16
#define __IPV6_HOP_LIM_ABS_OFF 21
    __u16 eth_type;
    __u8 allow = 1; /* allow any by default */
    __u16 ip4_len;
    __u8 hop_lim;

    hike_packet_read_u16(&eth_type, __ETH_PROTO_TYPE_ABS_OFF);
    if (eth_type == 0x800)
    {
        hike_packet_read_u16(&ip4_len, __IPV4_TOTAL_LEN_ABS_OFF);
        if (ip4_len >= 128)
            goto out;

        /* drop any IPv4 packet if IPv4 Total Len  < 128 */
        allow = 0;
        goto out;
    }

    if (eth_type == 0x86dd)
    {
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
#undef __IPV4_TOTAL_LEN_ABS_OFF
#undef __IPV6_HOP_LIM_ABS_OFF
}

HIKE_CHAIN_3(HIKE_CHAIN_MYCHAIN5_ID, __u8, allow, __u16, eth_type)
{
    __u32 prog_id;

    prog_id = allow ? HIKE_EBPF_PROG_ALLOW_ANY : HIKE_EBPF_PROG_DROP_ANY;
    hike_elem_call_2(prog_id, eth_type);

    return 0;
}