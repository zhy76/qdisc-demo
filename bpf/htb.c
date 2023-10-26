#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

struct htb_sched {
	struct Qdisc_class_hash clhash;
	int			defcls;		/* class where unclassified flows go to */
	int			rate2quantum;	/* quant = rate / rate2quantum */

	/* filters for qdisc itself */
	// struct tcf_proto __rcu	*filter_list;
	struct tcf_block	*block;

#define HTB_WARN_TOOMANYEVENTS	0x1
	unsigned int		warned;	/* only one warning */
	int			direct_qlen;
	struct work_struct	work;

	/* non shaped skbs; let them go directly thru */
	struct qdisc_skb_head	direct_queue;
	u32			direct_pkts;
	u32			overlimits;

	struct qdisc_watchdog	watchdog;

	s64			now;	/* cached dequeue time */

	/* time of nearest event per level (row) */
	// s64			near_ev_cache[TC_HTB_MAXDEPTH];

	// int			row_mask[TC_HTB_MAXDEPTH];

	// struct htb_level	hlevel[TC_HTB_MAXDEPTH];

	struct Qdisc		**direct_qdiscs;
	unsigned int            num_direct_qdiscs;

	bool			offload;
};

static inline void *qdisc_priv(struct Qdisc *q)
{
	return &q->privdata;
}

SEC("kprobe/htb_enqueue")
int kprobe__htb_enqueue(struct pt_regs *ctx)
{
    __bpf_printk("enqueue");
    // Get the sch pointer from the second argument of pfifo_enqueue function.
    struct Qdisc *sch = (struct Qdisc *)PT_REGS_PARM2(ctx);
    struct htb_sched *q = qdisc_priv(sch);
    int direct_qlen;
    
    // if(bpf_probe_read(&handle, sizeof(handle), &sch->handle)<0) {
    //     return 0;
    // }

    // if(bpf_probe_read(&parent, sizeof(parent), &sch->parent)<0) {
    //     return 0;
    // }

    // if (bpf_probe_read(&limit, sizeof(limit), &(sch->limit))<0) {
    //     return 0;
    // }
    // if (bpf_probe_read(&qlen, sizeof(qlen), &(sch->q.qlen))<0) {
    //     return 0;
    // }
    if (bpf_probe_read(&direct_qlen, sizeof(direct_qlen), &(q->direct_qlen))<0) {
        return 0;
    }
    __bpf_printk("kprobe/htb_enqueue: qdisc direct_qlen=%d\n", direct_qlen);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
