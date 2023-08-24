// qdisc_full.c
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

// struct trace_event_raw_qdisc_enqueue {
//     unsigned long unused;

//     struct Qdisc * qdisc;
//     const struct netdev_queue * txq;
//     int packets;
//     void * skbaddr;
//     int ifindex;
//     u32 handle;
//     u32 parent;
//     unsigned long txq_state;
// };

// SEC("tracepoint/qdisc/qdisc_enqueue")
// int qdisc_enqueue(struct trace_event_raw_qdisc_enqueue *ctx) {
//     struct trace_event_raw_qdisc_enqueue args = {};
//     if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
//         return 0;
//     }
//     int common_pid;
//     void * skbaddr;
//     int ifindex;
//     u32 handle;
//     u32 parent;
//     u32 limit;
//     __u32 qlen;

//     // if(bpf_probe_read(&common_pid, sizeof(common_pid), &args.common_pid)<0) {
//     //     return 0;
//     // }

//     if(bpf_probe_read(&skbaddr, sizeof(skbaddr), &args.skbaddr)<0) {
//         return 0;
//     }

//     if(bpf_probe_read(&ifindex, sizeof(ifindex), &args.ifindex)<0) {
//         return 0;
//     }
    
//     if(bpf_probe_read(&handle, sizeof(handle), &args.qdisc->handle)<0) {
//         return 0;
//     }

//     if(bpf_probe_read(&parent, sizeof(parent), &args.qdisc->parent)<0) {
//         return 0;
//     }

//     if (bpf_probe_read(&limit, sizeof(limit), &args.qdisc->limit)<0) {
//         return 0;
//     }
//     if (bpf_probe_read(&qlen, sizeof(qlen), &args.qdisc->q.qlen)<0) {
//         return 0;
//     }
//     __bpf_printk("enqueue ifindex=%d qdisc handle=0x%X\n", ifindex, handle);
//     __bpf_printk("enqueue parent=0x%X skbaddr=%px\n", parent, skbaddr);
//     __bpf_printk("enqueue: qdisc limit=%u qlen=%u\n", limit, qlen);

//     return 0;
// }

// SEC("tracepoint/qdisc/qdisc_dequeue")
// int qdisc_dequeue(struct trace_event_raw_qdisc_enqueue *ctx) {
//     struct trace_event_raw_qdisc_enqueue args = {};
//     if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
//         return 0;
//     }
//     int common_pid;
//     void * skbaddr;
//     int ifindex;
//     u32 handle;
//     u32 parent;
//     u32 limit;
//     __u32 qlen;

//     // if(bpf_probe_read(&common_pid, sizeof(common_pid), &args.common_pid)<0) {
//     //     return 0;
//     // }

//     if(bpf_probe_read(&skbaddr, sizeof(skbaddr), &args.skbaddr)<0) {
//         return 0;
//     }

//     if(bpf_probe_read(&ifindex, sizeof(ifindex), &args.ifindex)<0) {
//         return 0;
//     }
    
//     if(bpf_probe_read(&handle, sizeof(handle), &args.qdisc->handle)<0) {
//         return 0;
//     }

//     if(bpf_probe_read(&parent, sizeof(parent), &args.qdisc->parent)<0) {
//         return 0;
//     }

//     if (bpf_probe_read(&limit, sizeof(limit), &args.qdisc->limit)<0) {
//         return 0;
//     }
//     if (bpf_probe_read(&qlen, sizeof(qlen), &args.qdisc->q.qlen)<0) {
//         return 0;
//     }
//     __bpf_printk("dequeue ifindex=%d qdisc handle=0x%X\n", ifindex, handle);
//     __bpf_printk("dequeue parent=0x%X skbaddr=%px\n", parent, skbaddr);
//     __bpf_printk("dequeue: qdisc limit=%u qlen=%u\n", limit, qlen);

//     return 0;
// }

// SEC("kprobe/pfifo_enqueue")
// int kprobe__pfifo_enqueue(struct pt_regs *ctx)
// {
//     __bpf_printk("enqueue");
//     // Get the sch pointer from the second argument of pfifo_enqueue function.
//     struct Qdisc *sch = (struct Qdisc *)PT_REGS_PARM2(ctx);
//     void * skbaddr;
//     int ifindex;
//     u32 handle;
//     u32 parent;
//     u32 limit;
//     __u32 qlen;

//     // if(bpf_probe_read(&skbaddr, sizeof(skbaddr), sch.skbaddr)<0) {
//     //     return 0;
//     // }

//     // if(bpf_probe_read(&ifindex, sizeof(ifindex), &args.ifindex)<0) {
//     //     return 0;
//     // }
    
//     // if(bpf_probe_read(&handle, sizeof(handle), &args.qdisc->handle)<0) {
//     //     return 0;
//     // }

//     // if(bpf_probe_read(&parent, sizeof(parent), &args.qdisc->parent)<0) {
//     //     return 0;
//     // }

//     if (bpf_probe_read(&limit, sizeof(limit), &(sch->limit))<0) {
//         return 0;
//     }
//     if (bpf_probe_read(&qlen, sizeof(qlen), &(sch->q.qlen))<0) {
//         return 0;
//     }
//     // __bpf_printk("dequeue ifindex=%d qdisc handle=0x%X\n", ifindex, handle);
//     // __bpf_printk("dequeue parent=0x%X skbaddr=%px\n", parent, skbaddr);
//     __bpf_printk("kprobe enqueue: qdisc limit=%u qlen=%u\n", limit, qlen);
//     return 0;
// }

SEC("kprobe/sch_direct_xmit")
int kprobe__sch_direct_xmit(struct pt_regs *ctx)
{
    __bpf_printk("dequeue");
    // Get the sch pointer from the second argument of pfifo_enqueue function.
    struct Qdisc *sch = (struct Qdisc *)PT_REGS_PARM2(ctx);
    void * skbaddr;
    int ifindex;
    u32 handle;
    u32 parent;
    u32 limit;
    __u32 qlen;

    // if(bpf_probe_read(&skbaddr, sizeof(skbaddr), sch.skbaddr)<0) {
    //     return 0;
    // }

    // if(bpf_probe_read(&ifindex, sizeof(ifindex), &args.ifindex)<0) {
    //     return 0;
    // }
    
    // if(bpf_probe_read(&handle, sizeof(handle), &args.qdisc->handle)<0) {
    //     return 0;
    // }

    // if(bpf_probe_read(&parent, sizeof(parent), &args.qdisc->parent)<0) {
    //     return 0;
    // }

    if (bpf_probe_read(&limit, sizeof(limit), &(sch->limit))<0) {
        return 0;
    }
    if (bpf_probe_read(&qlen, sizeof(qlen), &(sch->q.qlen))<0) {
        return 0;
    }
    // __bpf_printk("dequeue ifindex=%d qdisc handle=0x%X\n", ifindex, handle);
    // __bpf_printk("dequeue parent=0x%X skbaddr=%px\n", parent, skbaddr);
    __bpf_printk("kprobe dequeue: qdisc limit=%u qlen=%u\n", limit, qlen);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";