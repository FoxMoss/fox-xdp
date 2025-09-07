
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdatomic.h>

#define OVER(x, d) (x + 1 > (typeof(x))d)

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

static bool is_tcp(struct ethhdr *eth, void *data_end) {
  if ((void *)(eth + 1) > data_end)
    return false;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return false;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  if ((void *)(ip + 1) > data_end)
    return false;

  if (ip->protocol != IPPROTO_TCP)
    return false;

  return true;
}

struct {
  __uint(priority, 10);
  __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;

  if (!is_tcp(eth, data_end))
    return XDP_PASS;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  int ip_hdr_len = ip->ihl * 4;
  if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

  if ((void *)ip + ip_hdr_len > data_end)
    return XDP_PASS;

  struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  const int tcp_header_bytes = 32;

  if ((void *)tcp + tcp_header_bytes > data_end)
    return XDP_PASS;

  if (ip->daddr != -1484932659 && ip->saddr != -1484932659)
    return XDP_PASS;

  bpf_printk("Source IP: %pI4", &ip->saddr);
  bpf_printk("Destination IP: %pI4", &ip->daddr);

  int index = ctx->rx_queue_index;

  if (bpf_map_lookup_elem(&xsks_map, &index))
    return bpf_redirect_map(&xsks_map, index, 0);

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
