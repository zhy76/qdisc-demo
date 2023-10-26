#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

SEC("kprobe/pfifo_enqueue")
int kprobe__pfifo_enqueue(struct pt_regs *ctx)
{
    __bpf_printk("enqueue");
    // Get the sch pointer from the second argument of pfifo_enqueue function.
    struct Qdisc *sch = (struct Qdisc *)PT_REGS_PARM2(ctx);
    u32 handle;
    u32 parent;
    u32 limit;
    __u32 qlen;
    
    if(bpf_probe_read(&handle, sizeof(handle), &sch->handle)<0) {
        return 0;
    }

    if(bpf_probe_read(&parent, sizeof(parent), &sch->parent)<0) {
        return 0;
    }

    if (bpf_probe_read(&limit, sizeof(limit), &(sch->limit))<0) {
        return 0;
    }
    if (bpf_probe_read(&qlen, sizeof(qlen), &(sch->q.qlen))<0) {
        return 0;
    }
    __bpf_printk("kprobe/pfifo_enqueue: parent=0x%X qdisc handle=0x%X\n", parent, handle);
    __bpf_printk("kprobe/pfifo_enqueue: qdisc limit=%u qlen=%u\n", limit, qlen);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";