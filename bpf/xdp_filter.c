//go:build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

struct event {
    __u32 src_ip;
};

//  Déclaration Map eBPF : Le Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Taille du buffer (256 KB)
} events SEC(".maps");

//  (Hook) XDP
SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    // (Boundary check)
    if ((void *)(eth + 1) > data_end) {
	return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
	return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end) {
	return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_ICMP) {

	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);

	if (e) {
	    e->src_ip = ip->saddr;

	    bpf_ringbuf_submit(e, 0);
	}
	return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
