#include <bpf_endian.h>
#include <stdio.h>
#include <time.h>
#include "ip6hbh.h"
#include "parsing_helpers.h"


SEC("get_time_8_bit_sec")
int get_time_8_bit(){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	int n;
	sscanf(asctime(timeinfo), "%d", &n);
	return n;

}

SEC("get_iflabel_id_sec")
int get_iflabel_id(struct hdr_cursor *nh, __u16 ingress_ifindex){
	return ingress_ifindex;
}

SEC("strcat_sec")
char * strcat(char *dest, const char *src){
    size_t i,j;
    for (i = 0; dest[i] != '\0'; i++)
        ;
    for (j = 0; src[j] != '\0'; j++)
        dest[i+j] = src[j];
    dest[i+j] = '\0';
    return dest;
}

SEC("get_ingress_ifindex_sec")
int get_ingress_ifindex(struct hdr_cursor *nh){
	struct ipv6hdr *ip6h = nh->pos;
	__u8 ingress_ifindex_1 = ip6h->daddr.in6_u.u6_addr8[14] & 0x0f;
	__u8 ingress_ifindex_2 = ip6h->daddr.in6_u.u6_addr8[15];
	
	char ingress_1[4], ingress_2[8];
	sprintf(ingress_1, "%d", ingress_ifindex_1);
	sprintf(ingress_2, "%d", ingress_ifindex_2);

	char *str = strcat(ingress_1, ingress_2);
	int i;
	sscanf(str, "%d", &i);
	return i;
}

SEC("move_pkt_mem_sec")
void move_pkt_mem(struct hdr_cursor *nh){
	struct ipv6hdr *ip6h = nh->pos;
	ip6h->cmd_14 = ip6h->cmd_13;
	ip6h->cmd_13 = ip6h->cmd_12;
	ip6h->cmd_12 = ip6h->cmd_11;
	ip6h->cmd_11 = ip6h->cmd_10;
	ip6h->cmd_10 = ip6h->cmd_9;
	ip6h->cmd_9 = ip6h->cmd_8;
	ip6h->cmd_8 = ip6h->cmd_7;
	ip6h->cmd_7 = ip6h->cmd_6;
	ip6h->cmd_6 = ip6h->cmd_5;
	ip6h->cmd_5 = ip6h->cmd_4;
	ip6h->cmd_4 = ip6h->cmd_3;
	ip6h->cmd_3 = ip6h->cmd_2;
	ip6h->cmd_2 = ip6h->cmd_1;
	ip6h->cmd_1 = 0;
}

SEC("path_tracing_sec")
int path_tracing(struct xdp_md *ctx)
{   
    int action = XDP_PASS;
    int eth_type;
    //int ip_type;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6hdr;
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		//ip_type = parse_iphdr(&nh, data_end, &iphdr);
        action = XDP_ABORTED;
        goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		//ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
        parse_ip6hdr(&nh, data_end, &ipv6hdr);
        // 	If packet has PT option:
        //  Compute the CMD information for this node
          
        if (ipv6hdr->opt_type == 32){
            __u32 end_of_stack = ipv6hdr->cmd_14;
            end_of_stack = end_of_stack & 0x00ffffff;

            /* if is empty
            if(HbH-PT.Stack[39:41] == 0) */
            if (end_of_stack == 0){
                // HbH-PT.Stack[3:41] = HbH-PT.Stack[0:38] 
                // Shift Hbh-PT CMD Stack 3B to the right
                //pkt_mem_move(672, 361, 24)
                move_pkt_mem(&nh);
                __u8 time = get_time_8_bit();	// 8 bit
                // get_iflabel_id(get_ingress_ifindex()) ???
                // __u16 ex_id = get_iflabel_id(nh, get_ingress_ifindex())     // 12 bit
                __u16 ex_id = get_ingress_ifindex(&nh);    					// 12 bit

                // __u8 in_load = interface_load(get_ingress_ifindex())   // 4  bit
                __u8 in_load = 0;                                        // 4  bit

                // Push the CMD at the beginning of the Stack (i.e., HBH-PT.Stack[0:2])
                char time_str[8], ex_id_str[12], in_load_str[4];
                sprintf(time_str, "%d", time);
                sprintf(ex_id_str, "%d", ex_id & 0x0fff);
                sprintf(in_load_str, "%d", in_load & 0x000f);
                char *str = strcat(time_str, strcat(ex_id_str, in_load_str));
                __u32 i;
                sscanf(str, "%d", &i);
                ipv6hdr->cmd_1 = i;
            } else {
                action = XDP_ABORTED;
                goto out;
            }
        } 
	}
    out:
	return action;
}