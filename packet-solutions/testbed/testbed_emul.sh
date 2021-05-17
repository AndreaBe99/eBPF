#!/bin/bash

#                     +------------------+      +------------------+
#                     |        TG        |      |       SUT        |
#                     |                  |      |                  |
#                     |         enp6s0f0 +------+ enp6s0f0         |
#                     |                  |      |                  |
#                     |                  |      |                  |
#                     |         enp6s0f1 +------+ enp6s0f1         |
#                     |                  |      |                  |
#                     +------------------+      +------------------+


TMUX=ebpf
IPP=ip

XDP_LOADER="../xdp_loader"
XDP_PROG_USER="../xdp_prog_user"

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

# Clean up previous network namespaces
$IPP -all netns delete

$IPP netns add tg
$IPP netns add sut
$IPP netns add lgs

$IPP netns exec tg $IPP link add enp6s0f0 type veth peer name enp6s0f0 netns sut
$IPP netns exec tg $IPP link add enp6s0f1 type veth peer name enp6s0f1 netns sut

# select the eBPF/XDP kernel program to be run in the SUT
XDP_PROG_KERN="$1"
if [ -z ${XDP_PROG_KERN} ]; then
	echo "Invalid argument: missing eBPF/XDP kernel program"
	exit 1
fi

###################
#### Node: TG #####
###################
echo -e "\nNode: TG"
#$IPP netns exec tg sysctl -w net.ipv4.ip_forward=1
#$IPP netns exec tg sysctl -w net.ipv6.conf.all.forwarding=1

$IPP netns exec tg $IPP link set dev lo up

$IPP netns exec tg $IPP link set dev enp6s0f0 address 00:00:00:00:01:00
$IPP netns exec tg $IPP link set dev enp6s0f1 address 00:00:00:00:01:01

$IPP netns exec tg $IPP link set dev enp6s0f0 up
$IPP netns exec tg $IPP link set dev enp6s0f1 up

$IPP netns exec tg $IPP addr add 12:1::1/64 dev enp6s0f0
$IPP netns exec tg $IPP addr add 10.12.1.1/24 dev enp6s0f0

$IPP netns exec tg $IPP addr add 12:2::1/64 dev enp6s0f1
$IPP netns exec tg $IPP addr add 10.12.2.1/24 dev enp6s0f1

$IPP netns exec tg $IPP -6 neigh add 12:1::2 lladdr 00:00:00:00:02:00 dev enp6s0f0

$IPP netns exec tg $IPP -6 route add fc00::1 via 12:1::2 dev enp6s0f0

read -r -d '' tg_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	# Load the xdp_redirect_map on the ingress interface
	# ${XDP_LOADER} -d enp6s0f0 -F --progsec xdp_pass

	# Load the dummy xdp_pass prog on the ingress interface
	# NOTE: both the veth endpoints need to be set with a xdp/eBPF program
	# otherwise packets are discarded.
	${XDP_LOADER} -d enp6s0f1 -F --progsec xdp_pass
	
	/bin/bash
EOF

####################
#### Node: SUT #####
####################
echo -e "\nNode: SUT"
$IPP netns exec sut sysctl -w net.ipv4.ip_forward=1
$IPP netns exec sut sysctl -w net.ipv6.conf.all.forwarding=1

$IPP netns exec sut $IPP link set dev lo up

$IPP netns exec sut $IPP link set dev enp6s0f0 address 00:00:00:00:02:00
$IPP netns exec sut $IPP link set dev enp6s0f1 address 00:00:00:00:02:01

$IPP netns exec sut $IPP link set dev enp6s0f0 up
$IPP netns exec sut $IPP link set dev enp6s0f1 up

$IPP netns exec sut $IPP addr add 12:1::2/64 dev enp6s0f0
$IPP netns exec sut $IPP addr add 10.12.1.2/24 dev enp6s0f0

$IPP netns exec sut $IPP addr add 12:2::2/64 dev enp6s0f1
$IPP netns exec sut $IPP addr add 10.12.2.2/24 dev enp6s0f1

read -r -d '' sut_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).

	mount -t bpf bpf /sys/fs/bpf/
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	# Load the dummy xdp_pass prog on the egress interface
	${XDP_LOADER} -d enp6s0f1 -F --progsec xdp_pass

	# NOTE: maps are ovewritten here
	# Load the xdp_redirect_map on the ingress interface
	${XDP_LOADER} -d enp6s0f0 -F -j --progsec ${XDP_PROG_KERN}
	${XDP_PROG_USER} -M --dev enp6s0f0 \
		--redirect-dev enp6s0f1 -k 12:1::2@20
	${XDP_PROG_USER} -M --dev enp6s0f0 \
		--redirect-dev enp6s0f1 -k fc00::1@14

	/bin/bash
EOF

## Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n TG $IPP netns exec tg bash -c "${tg_env}"
tmux new-window -t $TMUX -n SUT $IPP netns exec sut bash -c "${sut_env}"

tmux select-window -t :0
tmux set-option -g mouse on
tmux attach -t $TMUX
