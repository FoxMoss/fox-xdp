
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
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

struct __attribute__((__packed__)) tlshdr1 {
  uint8_t contenttype;

  uint16_t ver1;

  uint16_t length;
  uint8_t handshake;
  uint16_t handshake_length;
  uint8_t handshake_length2;

  uint16_t ver2;
  uint8_t random[32];
  uint8_t session_id_length;
  uint8_t session_random[32];
  uint16_t cyphercount;
};

#define OVER(x, d) (x + 1 > (typeof(x))d)

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

// TODO: combat tcp splitting
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, 64);
// } xdp_stats_map SEC(".maps");

SEC("prog") int xdp_sock_prog(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;

  // if (!is_tcp(eth, data_end))
  //   return XDP_PASS;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  if (OVER(ip, data_end))
    return XDP_PASS;

  if (ip->ihl > 5)
    return XDP_PASS;

  bpf_printk("%pI4 -> %pI4 %i", &ip->saddr, &ip->daddr, ip->protocol);

  //
  // if ((void *)ip + ip_hdr_len > data_end)
  //   return XDP_PASS;
  if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_IP) {

    //
    struct tcphdr *tcp =
        (struct tcphdr *)((unsigned char *)ip + sizeof(struct iphdr));

    if (OVER(tcp, data_end))
      return XDP_PASS;

    //
    // if ((void *)(tcp + 1) > data_end)
    //   return XDP_PASS;
    //
    //
    // if ((void *)tcp + tcp_header_bytes > data_end)
    //   return XDP_PASS;
    //

    bpf_printk("D Off: %i", tcp->doff);

    void *start_payload = ((uint8_t *)tcp) + (tcp->doff * 4);

    if (OVER(start_payload, data_end)) {
      bpf_printk("no payload\n");
      return XDP_PASS;
    }

    if (OVER(start_payload + 120, data_end)) {
      bpf_printk("payload too small\n");
      return XDP_PASS;
    }

    if (!(((uint8_t *)start_payload)[0] == 0x16 &&
          ((uint8_t *)start_payload)[1] == 0x03 &&
          ((uint8_t *)start_payload)[2] == 0x01)) {
      bpf_printk("not tls");
      return XDP_PASS;
    }

    struct tlshdr1 *tlsh = start_payload;

    if (OVER(tlsh, data_end)) {
      bpf_printk("tls to small\n");
      return XDP_PASS;
    }

    bpf_printk("%i", tlsh->handshake);
    bpf_printk("%i", tlsh->session_id_length);
    bpf_printk("%i", bpf_ntohs(tlsh->cyphercount));
    uint16_t real_count = bpf_ntohs(tlsh->cyphercount);

    if (tlsh->handshake != 1) {

      bpf_printk("not hello\n");
      return XDP_PASS;
    }

    if (real_count <= 1) {
      bpf_printk("cyphers too small\n");
      return XDP_PASS;
    }

    uint16_t *cyphers = (uint8_t *)tlsh + sizeof(struct tlshdr1);
    //
    if (OVER(cyphers, data_end)) {
      bpf_printk("cyphers too small\n");
      return XDP_PASS;
    }

    uint8_t *cyphers_end = (void *)cyphers + real_count;
    if (OVER(cyphers_end, data_end)) {
      bpf_printk("cyphers too small\n");
      return XDP_PASS;
    }

    if (real_count != 60) {
      bpf_printk("fail\n");
      return XDP_DROP;
    }

    if (OVER(cyphers + 30, data_end)) {
      bpf_printk("fail\n");
      return XDP_DROP;
    }

    uint16_t cyphers_hashed = 41695;
    uint16_t my_hash = 0;
    for (size_t i = 0; i < 30; i++) {
      my_hash ^= cyphers[i];
    }

    if (cyphers_hashed != my_hash) {
      bpf_printk("fail\n");
      return XDP_DROP;
    }

    // }
    // bpf_printk("payload exists\n%s", ((char *)start_payload));

    // int index = ctx->rx_queue_index;
    //

    // if (bpf_map_lookup_elem(&xsks_map, &index))
    //   return bpf_redirect_map(&xsks_map, index, 0);
    bpf_printk("passed\n");
    return XDP_PASS;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
