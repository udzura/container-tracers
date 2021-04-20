#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct key_t {
  u32 tid;
  u64 syscall_nr;
};
struct leaf_t{
  u64 count;
  u64 elapsed_ns;
  u64 enter_ns;
};

const volatile u64 targ_cgid = 0;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 30000);
  __type(key, struct key_t);
  __type(value, struct leaf_t);
} dist SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter* ctx)
{
  if (targ_cgid != 0 && targ_cgid != bpf_get_current_cgroup_id())
    goto cleanup;

  struct key_t key = {0};
  struct leaf_t initial = {0}, val, *val_;
  key.tid = bpf_get_current_pid_tgid();
  key.syscall_nr = ctx->id;

  val_ = bpf_map_lookup_elem(&dist, &key);
  if (!val_) {
    bpf_map_update_elem(&dist, &key, &initial, 0);
    val_ = bpf_map_lookup_elem(&dist, &key);
    if (!val_)
      goto cleanup;
  }

  val = *val_;
  val.count += 1;
  val.enter_ns = bpf_ktime_get_ns();
  bpf_map_update_elem(&dist, &key, &val, 2);

cleanup:
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit* ctx)
{
  struct key_t key = {0};
  struct leaf_t val, *val_;
  key.tid = bpf_get_current_pid_tgid();
  key.syscall_nr = ctx->id;

  val_ = bpf_map_lookup_elem(&dist, &key);
  if (val_) {
    val = *val_;
    u64 delta = bpf_ktime_get_ns() - val.enter_ns;
    val.enter_ns = 0;
    val.elapsed_ns += delta;

    bpf_map_update_elem(&dist, &key, &val, 2);
  }
  return 0;
}
