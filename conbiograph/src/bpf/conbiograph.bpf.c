#include "vmlinux.h"
#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern __u32 LINUX_KERNEL_VERSION __kconfig;

const volatile u64 targ_cgid = 0;

struct value_t {
  u64 count;
  u64 processed_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4);
  __type(key, u32);
  __type(value, struct value_t);
} dist SEC(".maps");

static int trace_rq_issue(struct request *rq)
{
  u32 key = 1;
  struct value_t *vp, init = {0};

  vp = bpf_map_lookup_elem(&dist, &key);
  if (!vp) {
    bpf_map_update_elem(&dist, &key, &init, 0);
    vp = bpf_map_lookup_elem(&dist, &key);
    if (!vp)
      return 0;
  }
  __sync_fetch_and_add(&vp->count, 1);
  __sync_fetch_and_add(&vp->processed_bytes, rq->__data_len);
  return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
  if(targ_cgid != 0 && targ_cgid != bpf_get_current_cgroup_id())
    return 0;

  /**
   * commit a54895fa (v5.11-rc1) changed tracepoint argument list
   * from TP_PROTO(struct request_queue *q, struct request *rq)
   * to TP_PROTO(struct request *rq)
   * ref: https://github.com/iovisor/bcc/blob/master/libbpf-tools/bitesize.bpf.c
   */
  if (LINUX_KERNEL_VERSION > KERNEL_VERSION(5, 10, 0))
    return trace_rq_issue((void *)ctx[0]);
  else
    return trace_rq_issue((void *)ctx[1]);
}

char LICENSE[] SEC("license") = "GPL";
