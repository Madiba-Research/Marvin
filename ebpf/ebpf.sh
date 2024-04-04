echo 1 > /sys/kernel/tracing/tracing_on
/data/ebpf/run-command "/usr/sbin/bpftool prog load /root/d.o /sys/fs/bpf/bpf_connect4 type cgroup/connect4"
/data/ebpf/run-command "/usr/sbin/bpftool cgroup attach /sys/fs/cgroup/ connect4 pinned /sys/fs/bpf/bpf_connect4"
/data/ebpf/run-command "/usr/sbin/bpftool prog load /root/e.o /sys/fs/bpf/bpf_connect6 type cgroup/connect6"
/data/ebpf/run-command "/usr/sbin/bpftool cgroup attach /sys/fs/cgroup/ connect6 pinned /sys/fs/bpf/bpf_connect6"
