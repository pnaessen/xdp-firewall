//go:build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#define MAX_IPS 10000

// Déclaration Map eBPF Agrégation par CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);
    __type(value, __u64);
} icmp_stats SEC(".maps");

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

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
        __u32 src_ip = ip->saddr;
        __u64 *counter;

        counter = bpf_map_lookup_elem(&icmp_stats, &src_ip);
        if (counter) {
            // no need (__sync_fetch_and_add)
            // une map PERCPU.
            *counter += 1;
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&icmp_stats, &src_ip, &init_val, BPF_ANY);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
