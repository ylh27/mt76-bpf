#include "vmlinux.h"          // keep this first

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct message {
  __u32 pid;
  __u32 tgid;
  __u64 timestamp_ns;
};

// BPF_MAP_TYPE_PERF_EVENT_ARRAY seems to be best given the high packet send
// rate (and therefore high volume of notifs sent)
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// verifier needs us to provide license
char LICENSE[] SEC("license") = "GPL";

//SEC("fexit/__x64_sys_execve")
//SEC("fexit/tcp_sendmsg")
//SEC("fexit/dev_hard_start_xmit")
SEC("kprobe/ieee80211_tx")
int BPF_PROG(fexit_test) {
  struct message msg = {};

  msg.pid = bpf_get_current_pid_tgid() & 0x0000FFFF;
  msg.tgid = bpf_get_current_pid_tgid() >> 32;
  msg.timestamp_ns = bpf_ktime_get_ns();

  // add data to perf buffer so userspace program can grab it
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));

  return 0;
}
