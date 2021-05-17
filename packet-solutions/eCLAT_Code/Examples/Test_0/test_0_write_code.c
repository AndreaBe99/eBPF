/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Example of HIKe Program for the HIKe VM */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

#define __PACKET_BASE_ADDR ((size_t)(HIKE_MEM_PACKET_ADDR_DATA))

#define __READ_PACKET(__type, __offset) \
    ((volatile __type) * (__type *)((__PACKET_BASE_ADDR) + (__offset)))

#define __WRITE_PACKET(__type, __offset) \
    *(volatile __type *)((__PACKET_BASE_ADDR) + (__offset))

__section("__sec_chain_mychain1") int __chain_mychain1(void)
{
    __u16 eth_type;

    eth_type = bpf_ntohs(__READ_PACKET(__be16, 12));
    if (eth_type == 0x86dd)
    {
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