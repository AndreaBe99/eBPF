/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <arpa/inet.h>
#include <linux/ipv6.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

#ifndef BUF_SIZE
#define BUF_SIZE 64
#endif

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },

	{{"dest-mac", required_argument, NULL, 'R' },
	 "Destination MAC address of <redirect-dev>", "<mac>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int write_iface_params(int map_fd, unsigned char *src, unsigned char *dest)
{
	if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf(" - Forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;
}

static int
parse_prog_key(struct in6_addr *addr, int *prog_type, char const *str)
{
	char buf[BUF_SIZE];
	char *token;
	int len;
	int ret;

	len = strlen(str);
	if (len >= BUF_SIZE)
		goto err;

	memcpy(buf, str, len);
	buf[BUF_SIZE] = 0;

	token = strtok(buf, "@");
	if (!token)
		goto err;

	ret = inet_pton(AF_INET6, token, &addr->s6_addr[0]);
	if (ret != 1)
		goto err;

	token = strtok(NULL, "@");
	if (!token)
		goto err;

	*prog_type = atoi(token);

	return 0;

err:
	fprintf(stderr, "ERR: cannot parse the prog_key %s\n", str);

	return -EINVAL;
}

static int parse_mon_flow(struct in6_addr *addr, char const *str)
{
	return inet_pton(AF_INET6, str, &addr->s6_addr[0]);
}

static
int write_srv6_prog_key_reg(int map_fd, struct in6_addr *addr, int prog_type)
{
	char buf[BUF_SIZE];

	if (bpf_map_update_elem(map_fd, addr, &prog_type, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	if (!inet_ntop(AF_INET6, &addr->s6_addr[0], buf, BUF_SIZE))
		return -EINVAL;

	printf(" - eBPF/XDP program type %d associated with %s\n",
	       prog_type, buf);

	return 0;
}

/* FIXME: duplicated */
static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		n = sscanf(buff, "%u-%u", &start, &end);
		if (n == 0) {
			printf("Failed to retrieve # possible CPUs!\n");
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}

static int write_mon_flow(int map_fd, struct in6_addr *addr)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	/* XXX: this structure is replicated, see xdp_prog_kern_03.c */
	#define COLOR_MAX 2
	struct counter_info {
		__u64 counter[COLOR_MAX];
	};
	char buf[BUF_SIZE];
	struct counter_info cinfo[nr_cpus];

	memset((void *)cinfo, 0, sizeof(cinfo[0]) * nr_cpus);

	if (bpf_map_update_elem(map_fd, &addr->s6_addr[0], &cinfo[0], 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	if (!inet_ntop(AF_INET6, &addr->s6_addr[0], buf, BUF_SIZE))
		return -EINVAL;

	printf(" - Add monitored flow %s\n", buf);

	return 0;

}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int i;
	int len;
	int map_fd, map_fd2, map_fd3;
	bool redirect_map;
	char pin_dir[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];
	int prog_type;
	struct in6_addr ipv6_daddr, mon_ipv6_addr;
	int ret;

	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);

	if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.src_mac, src) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.src_mac);
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.dest_mac, dest) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.dest_mac);
		return EXIT_FAIL_OPTION;
	}

	/* Open the tx_port map corresponding to the cfg.ifname interface */
	map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s\n", pin_dir);

	if (redirect_map) {
		/* setup a virtual port for the static redirect */
		i = 0;
		bpf_map_update_elem(map_fd, &i, &cfg.redirect_ifindex, 0);
		printf(" - Redirect from ifindex=%d to ifindex=%d\n",
		       cfg.ifindex, cfg.redirect_ifindex);

		/* Open the redirect_params map */
		map_fd = open_bpf_map_file(pin_dir, "redirect_params", NULL);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* Setup the mapping containing MAC addresses */
		if (write_iface_params(map_fd, src, dest) < 0) {
			fprintf(stderr, "can't write iface params\n");
			return 1;
		}
	} else {
		/* setup 1-1 mapping for the dynamic router */
		for (i = 1; i < 256; ++i)
			bpf_map_update_elem(map_fd, &i, &i, 0);
	}

	if (cfg.prog_key_load) {
		map_fd2 = open_bpf_map_file(pin_dir, "ingress_match_table",
					    NULL);
		if (map_fd2 < 0)
			return EXIT_FAIL_BPF;

		ret = parse_prog_key(&ipv6_daddr, &prog_type, cfg.prog_key);
		if (ret < 0)
			return EXIT_FAIL_BPF;

		ret = write_srv6_prog_key_reg(map_fd2, &ipv6_daddr, prog_type);
		if (ret < 0)
			return EXIT_FAIL_BPF;

		/* FIXME: close the map_fd2 */


//		/* XXX */
//		map_fd3 = open_bpf_map_file(pin_dir, "counter_table", NULL);
//		if (map_fd3 < 0)
//			return EXIT_FAIL_BPF;
//
//		ret = parse_mon_flow(&mon_ipv6_addr, cfg.prog_key);
//		if (ret < 0)
//			return EXIT_FAIL_BPF;
//
//		ret = write_mon_flow(map_fd3, &mon_ipv6_addr);
//		if (ret < 0)
//			return EXIT_FAIL_BPF;
	}

	
	return EXIT_OK;
}
