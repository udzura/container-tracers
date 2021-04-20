#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const volatile bool targ_failed = false;

#define TASK_COMM_LEN 16
struct event {
  pid_t pid;
  u64 flags;
  int ret;
  char comm[TASK_COMM_LEN];
};

struct args_t {
  u64 flags;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct args_t);
} start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint__syscalls__sys_enter_unshare(struct trace_event_raw_sys_enter* ctx)
{
  u32 pid = bpf_get_current_pid_tgid();
  struct args_t args = {};
  args.flags = (u64)ctx->args[0];
  bpf_map_update_elem(&start, &pid, &args, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_unshare")
int tracepoint__syscalls__sys_exit_unshare(struct trace_event_raw_sys_exit* ctx)
{
  struct event event = {0};
  struct args_t *ap;
  int ret;
  u32 pid = bpf_get_current_pid_tgid();

  ap = bpf_map_lookup_elem(&start, &pid);
  if (!ap)
    return 0;

  ret = ctx->ret;
  if (!targ_failed && ret < 0)
    goto cleanup;

  event.pid = pid;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  event.flags = ap->flags;
  event.ret = ret;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                        &event, sizeof(event));

 cleanup:
  bpf_map_delete_elem(&start, &pid);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
