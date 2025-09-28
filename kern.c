
#include "shared.h"
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

#define CALCULATE_HASH(DATA, INDEX, LEN, REAL, REAL_END, MAYBE_MAX, OUT)       \
  uint32_t OUT = 0;                                                            \
  uint32_t INDEX = 0;                                                          \
                                                                               \
  bpf_for(INDEX, 0, MAYBE_MAX) {                                               \
    if (INDEX >= LEN)                                                          \
      break;                                                                   \
    if (DATA + INDEX + 1 > REAL_END)                                           \
      break;                                                                   \
    uint8_t val;                                                               \
                                                                               \
    if (bpf_xdp_load_bytes(ctx, (long)(DATA - REAL + INDEX), &val, 1) < 0)     \
      break;                                                                   \
                                                                               \
    OUT += val;                                                                \
    OUT += OUT << 10;                                                          \
    OUT ^= OUT >> 6;                                                           \
  }                                                                            \
  OUT += OUT << 3;                                                             \
  OUT ^= OUT >> 11;                                                            \
  OUT += OUT << 15;

#define OVER(x, d) (x + 1 > (typeof(x))d)
//
//
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u8);
  __uint(max_entries, 64);
} blocked SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u8);
  __uint(max_entries, 64);
} pass_hash SEC(".maps");

// TODO: combat tcp splitting
// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __type(key, __u32);
//   __type(value, __u32);
//   __uint(max_entries, 64);
// } xdp_stats_map SEC(".maps");

SEC("prog") int xdp_sock_prog(struct xdp_md *ctx) {
  uint8_t *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  if (OVER(ip, data_end))
    return XDP_PASS;

  // routers often drop packets with ip extensions so why bother parsing
  if (ip->ihl > 5)
    return XDP_PASS;

#ifndef RELEASE
  bpf_printk("%pI4 -> %pI4 %i", &ip->saddr, &ip->daddr, ip->protocol);
#endif

  if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_IP) {
    struct tcphdr *tcp =
        (struct tcphdr *)((unsigned char *)ip + sizeof(struct iphdr));

    if (OVER(tcp, data_end))
      return XDP_PASS;

#ifndef RELEASE
    bpf_printk("D Off: %i", tcp->doff);
#endif

    void *start_payload = ((uint8_t *)tcp) + (tcp->doff * 4);

    if (OVER(start_payload, data_end)) {
#ifndef RELEASE
      bpf_printk("no payload\n");
#endif
      return XDP_PASS;
    }

    if (OVER(start_payload + 120, data_end)) {
#ifndef RELEASE
      bpf_printk("payload too small\n");
#endif
      return XDP_PASS;
    }

    if (!(((uint8_t *)start_payload)[0] == 0x16 &&
          ((uint8_t *)start_payload)[1] == 0x03 &&
          ((uint8_t *)start_payload)[2] == 0x01)) {
#ifndef RELEASE
      bpf_printk("not tls %i, %i, %i", ((uint8_t *)start_payload)[0],
                 ((uint8_t *)start_payload)[1], ((uint8_t *)start_payload)[2]);
#endif
      return XDP_PASS;
    }

    struct tlshdr1 *tlsh = start_payload;

    if (OVER(tlsh, data_end)) {
#ifndef RELEASE
      bpf_printk("tls to small\n");
#endif
      return XDP_PASS;
    }

#ifndef RELEASE
    bpf_printk("%i", tlsh->handshake);
    bpf_printk("%i", tlsh->session_id_length);
    bpf_printk("%i", bpf_ntohs(tlsh->cyphercount));
#endif
    uint16_t real_count = bpf_ntohs(tlsh->cyphercount);

    if (tlsh->handshake != 1) {

#ifndef RELEASE
      bpf_printk("not hello\n");
#endif
      return XDP_PASS;
    }

    if (real_count <= 1) {
#ifndef RELEASE
      bpf_printk("ciphers too small\n");
#endif
      return XDP_PASS;
    }

    uint8_t *ciphers = (uint8_t *)tlsh + sizeof(struct tlshdr1);

    if (OVER(ciphers, data_end)) {
#ifndef RELEASE
      bpf_printk("ciphers too small\n");
#endif
      return XDP_PASS;
    }

    uint8_t *ciphers_end = (void *)ciphers + real_count;
    if (OVER(ciphers_end, data_end) && ciphers > data) {
      return XDP_PASS;
    }

    if (real_count > 800) {
#ifndef RELEASE
      bpf_printk("ciphers too big\n");
#endif
      return XDP_PASS;
    }

    uint32_t my_hash = 0;
    uint32_t j = 0;
    uint16_t lowest = 0;
    bpf_for(j, 0, 800) {
      if (j * 2 >= real_count)
        break;

      uint32_t i = 0;
      uint16_t lowest_high = UINT16_MAX;
      bpf_for(i, 0, 800) {
        if (i * 2 >= real_count)
          break;
        uint16_t val = 0;

        if (ciphers + i * 2 + 1 > data_end)
          break;
        if (bpf_xdp_load_bytes(ctx, (long)(ciphers - data + i * 2), &val, 2) <
            0)
          break;

        if (val < lowest_high && val > lowest) {
          lowest_high = val;
        }
      }

      lowest = lowest_high;
#ifndef RELEASE
      bpf_printk("lowest %i", lowest);
#endif

      my_hash += lowest;
      my_hash += my_hash << 10;
      my_hash ^= my_hash >> 6;
    }
    my_hash += my_hash << 3;
    my_hash ^= my_hash >> 11;
    my_hash += my_hash << 15;

#ifndef RELEASE
    bpf_printk("%u", my_hash);
#endif

    uint32_t base_key = 0;
    uint8_t *block_type = bpf_map_lookup_elem(&blocked, &base_key);

    if (block_type == NULL) {
#ifndef RELEASE
      bpf_printk("passing no base");
#endif
      return XDP_PASS;
    }

#ifndef RELEASE
    bpf_printk("block type %i", *block_type);
#endif

    uint8_t *rec = bpf_map_lookup_elem(&blocked, &my_hash);

    if (rec == NULL) {
      if (*block_type == BLOCK_WHITE) {

        return XDP_DROP;
      }
#ifndef RELEASE
      bpf_printk("passing not on list");
#endif
      return XDP_PASS;
    }

    if (*rec == HASH_ACTIVATE) {
#ifndef RELEASE
      bpf_printk("on list");
#endif
      if (*block_type == BLOCK_LOG) {
        uint8_t *passes = bpf_map_lookup_elem(&pass_hash, &my_hash);

#ifndef RELEASE
        bpf_printk("kept\n");
#endif

        if (passes == NULL || *passes == 0) {
          return bpf_redirect_map(&xsks_map, 0, 0);
        }

        (*passes) -= 1;

        bpf_map_update_elem(&pass_hash, &my_hash, passes, 0);

#ifndef RELEASE
        bpf_printk("skipped\n");
#endif

      } else if (*block_type == BLOCK_BLACK) {
        return XDP_DROP;
      }
    }

#ifndef RELEASE
    bpf_printk("passed\n");
#endif
    return XDP_PASS;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
