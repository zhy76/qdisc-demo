#include "common.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // change to current pid_max
    __uint(max_entries, 1 << 10);
    // key is tgid
    __type(key, u32);
    //value is see_app's value
    __type(value, char[36]); 
    //pinning
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tgid_see_app SEC(".maps");

static __always_inline int equal_to_true(const char *cs, const char *ct, int size)
{
    int len = 0;
    unsigned char c1, c2;
    for (len=0; len < (size & 0xff); len++) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
     }
     return 0;
}