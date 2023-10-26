#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define __rcu		__attribute__((noderef, address_space(4)))
/* HTB section */
#define TC_HTB_NUMPRIO		8
#define TC_HTB_MAXDEPTH		8
#define TC_HTB_PROTOVER		3 /* the same as HTB and TC's major */
struct htb_prio {
	union {
		struct rb_root	row;
		struct rb_root	feed;
	};
	struct rb_node	*ptr;
	/* When class changes from state 1->2 and disconnects from
	 * parent's feed then we lost ptr value and start from the
	 * first child again. Here we store classid of the
	 * last valid ptr (used when ptr is NULL).
	 */
	u32		last_ptr_id;
};

struct htb_level {
	struct rb_root	wait_pq;
	struct htb_prio hprio[TC_HTB_NUMPRIO];
};

struct htb_sched {
	struct Qdisc_class_hash clhash;
	int			defcls;		/* class where unclassified flows go to */
	int			rate2quantum;	/* quant = rate / rate2quantum */

	/* filters for qdisc itself */
	struct tcf_proto __rcu *filter_list;
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
	s64			near_ev_cache[TC_HTB_MAXDEPTH];

	int			row_mask[TC_HTB_MAXDEPTH];

	struct htb_level	hlevel[TC_HTB_MAXDEPTH];

	struct Qdisc		**direct_qdiscs;
	unsigned int            num_direct_qdiscs;

	bool			offload;
};

static inline void *qdisc_priv(struct Qdisc *q)
{
	return &q->privdata;
}

SEC("tracepoint/qdisc/qdisc_enqueue")
int qdisc_enqueue(struct trace_event_raw_qdisc_enqueue *ctx) {
    struct trace_event_raw_qdisc_enqueue args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
	char id[16];
    int common_pid;
    void * skbaddr;
    // const char *dev_name = args.qdisc->dev_queue->dev->name;
    u32 handle;
    u32 parent;
    u32 limit;
    __u32 qlen;

	struct htb_sched *q = qdisc_priv(args.qdisc);
    int direct_qlen;

	if (bpf_probe_read(&direct_qlen, sizeof(direct_qlen), &(q->direct_qlen))<0) {
        return 0;
    }

	// bpf_probe_read(&(id), sizeof(args.qdisc->ops->id), &args.qdisc->ops->id);

    if(bpf_probe_read(&skbaddr, sizeof(skbaddr), &args.skbaddr)<0) {
        return 0;
    }

    if(bpf_probe_read(&handle, sizeof(handle), &args.qdisc->handle)<0) {
        return 0;
    }

    if(bpf_probe_read(&parent, sizeof(parent), &args.qdisc->parent)<0) {
        return 0;
    }

    if (bpf_probe_read(&qlen, sizeof(qlen), &q->direct_queue.qlen)<0) {
        return 0;
    }

    __bpf_printk("enqueue id=%s qdisc handle=0x%X\n", id, handle);
    __bpf_printk("enqueue parent=0x%X skbaddr=%px\n", parent, skbaddr);
    __bpf_printk("enqueue: qdisc qlen=%u, direct_qlen=%d\n", qlen, direct_qlen);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
