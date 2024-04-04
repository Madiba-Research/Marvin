#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u32 invocations = 0;
__u32 assertion_error = 0;
__u32 retval_value = 0;

SEC("cgroup/connect4")
int get_retval(struct bpf_sock_addr *ctx)
{
    unsigned int uid = bpf_get_current_uid_gid();
    if (ctx->user_ip4 != 0x2db4a8c0 && (ctx->user_port == 0xbb01 || ctx->user_port == 0x5000) && uid > 0x2805)
    {
        bpf_printk("Forced-Connection-Data=(%x:%x),uid=%d", ctx->user_ip4,ctx->user_port, uid);
        ctx->user_ip4 = 0x2db4a8c0;
        ctx->user_port = 0x901f;
    }
    else
    {
        bpf_printk("Connection-Data=(%x:%x),uid=%d", ctx->user_ip4,ctx->user_port, uid);
    }
    return 1;
}


/*

SEC("cgroupsock/inet/create")
int inet_socket_create(struct bpf_sock* ctx) {
    uint64_t gid_uid = bpf_get_current_uid_gid();
    bpf_printk("data=(%x:%x),pid=%d", ctx->user_ip4,ctx->user_port, pid);
    return 0;
}
*/
char __license[] __attribute__((section("license"), used)) = "GPL";

/*
// sudo bpftool prog load d.o /sys/fs/bpf/bpf_connect type cgroup/connect4
//sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect
sudo bpftool prog load d.o /sys/fs/bpf/bpf_connect type cgroup/connect4;sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect
//sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect
//sudo rm /sys/fs/bpf/bpf_connect
sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect; sudo rm /sys/fs/bpf/bpf_connect
*/

// sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect; sudo rm /sys/fs/bpf/bpf_connect; clang -O2 -g  -Wall -target bpf -c d.c -o d.o ; sudo bpftool prog load d.o /sys/fs/bpf/bpf_connect type cgroup/connect4;sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect
// sudo bpftool cgroup detach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4; sudo rm /sys/fs/bpf/bpf_connect4; clang -O2 -g  -Wall -target bpf -I /usr/include/aarch64-linux-gnu -c d.c -o d.o ; sudo bpftool prog load d.o /sys/fs/bpf/bpf_connect4 type cgroup/connect4;sudo bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4


//sudo tc filter del dev wlan0 egress ; clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o ; sudo tc filter add dev wlan0 egress bpf da obj bpf.o
