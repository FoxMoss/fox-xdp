
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
#include <string.h>
#include <sys/types.h>
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

// slow
// void memory_copy(uint8_t *dest, uint8_t *src, size_t length) {
//   for (size_t i = 0; i < length; i++) {
//     dest[i] = src[i];
//   }
// }
//
// int rotateright(uint32_t x, int n) {
//   int shifted = x >> n;
//   int rot_bits = x << (32 - n);
//   int combined = shifted | rot_bits;
//   return combined;
// }
// handrolling sha256 today
// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
// int sha256_hash(uint8_t *start, uint8_t *end) {
//
//   uint32_t L = (uint32_t)(end - start) * 8;
//   int64_t int_L = (uint32_t)(end - start) * 8;
//   uint64_t byte_L = (uint32_t)(end - start);
//   uint32_t payload_len = (uint32_t)(end - start);
//
//   uint32_t K_overflow = (L + 1 + 64) % 512;
//   uint32_t K_len = 512 - K_overflow;
//   uint32_t len = (L + 1 + K_len + 64);
//
//   bpf_printk("str len %i", L);
//   bpf_printk(" K_overflow %i", K_overflow);
//   bpf_printk("hash length %i", len);
//
//   int64_t swapped_L = bswap_64(int_L);
//
//   len /= 8; // should be mult of 8 because bits
//
//   char hashable_buffer[1024];
//   if (len > 4096) {
//     return -1;
//   }
//
//   hashable_buffer[byte_L] = 0b10000000;
//
//   for (uint32_t i = byte_L + 1; i < len - sizeof(uint64_t); i++) {
//     hashable_buffer[i] = 0b00000000;
//   }
//
//   memory_copy((void *)hashable_buffer, (void *)start, payload_len);
//   memory_copy((void *)(hashable_buffer + len - sizeof(uint64_t)),
//               (void *)&swapped_L, sizeof(uint64_t));
//
//   uint32_t h0 = 0x6a09e667;
//   uint32_t h1 = 0xbb67ae85;
//   uint32_t h2 = 0x3c6ef372;
//   uint32_t h3 = 0xa54ff53a;
//   uint32_t h4 = 0x510e527f;
//   uint32_t h5 = 0x9b05688c;
//   uint32_t h6 = 0x1f83d9ab;
//   uint32_t h7 = 0x5be0cd19;
//
//   uint32_t k[64] = {
//       0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
//       0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
//       0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
//       0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
//       0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
//       0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
//       0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
//       0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
//       0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
//
//   for (uint32_t chunk = 0; chunk < len; chunk += (512 / 8)) {
//     uint32_t w[64];
//     memcpy(w, (&hashable_buffer[0]) + chunk, 512 / 8);
//     for (uint32_t i = 16; i <= 63; i++) {
//
//       uint32_t s0 = rotateright(w[i - 15], 7) ^ rotateright(w[i - 15], 18) ^
//                     (w[i - 15] >> 3);
//       uint32_t s1 = rotateright(w[i - 2], 17) ^ rotateright(w[i - 2], 19) ^
//                     (w[i - 2] >> 10);
//       w[i] = w[i - 16] + s0 + w[i - 7] + s1;
//     }
//
//     uint32_t a = h0;
//     uint32_t b = h1;
//     uint32_t c = h2;
//     uint32_t d = h3;
//     uint32_t e = h4;
//     uint32_t f = h5;
//     uint32_t g = h6;
//     uint32_t h = h7;
//
//     for (uint32_t i = 0; i < 64; i++) {
//
//       uint32_t S1 = rotateright(e, 6) ^ rotateright(e, 11) ^ rotateright(e,
//       25); uint32_t ch = (e & f) ^ ((~e) & g); uint32_t temp1 = h + S1 + ch +
//       k[i] + w[i]; uint32_t S0 = rotateright(a, 2) ^ rotateright(a, 13) ^
//       rotateright(a, 22); uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
//       uint32_t temp2 = S0 + maj;
//
//       h = g;
//       g = f;
//       f = e;
//       e = d + temp1;
//       d = c;
//       c = b;
//       b = a;
//       a = temp1 + temp2;
//     }
//
//     h0 = h0 + a;
//     h1 = h1 + b;
//     h2 = h2 + c;
//     h3 = h3 + d;
//     h4 = h4 + e;
//     h5 = h5 + f;
//     h6 = h6 + g;
//     h7 = h7 + h;
//   }
//
//   bpf_printk("%x", h0);
//   bpf_printk("%x", h1);
//   bpf_printk("%x", h2);
//   bpf_printk("%x", h3);
//   bpf_printk("%x", h4);
//   bpf_printk("%x", h5);
//   bpf_printk("%x", h6);
//   bpf_printk("%x", h7);
//   return 1;
// }

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

  bpf_printk("%pI4 -> %pI4", &ip->saddr, &ip->daddr);
  //
  // if ((void *)ip + ip_hdr_len > data_end)
  //   return XDP_PASS;
  if (ip->protocol == IPPROTO_TCP) {

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

    void *start_payload =
        ((uint8_t *)tcp) + sizeof(struct tcphdr) + (tcp->doff - 5) * 4;

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
          ((uint8_t *)start_payload)[2] == 0x01 &&
          ((uint8_t *)start_payload)[3] == 0x06 &&
          ((uint8_t *)start_payload)[4] == 0x13)) {

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

    if (real_count <= 1) {
      bpf_printk("cyphers too small\n");
      return XDP_PASS;
    }

    uint8_t *cyphers = (uint8_t *)tlsh + sizeof(struct tlshdr1);
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
      return XDP_DROP;
    }

    unsigned char matching_cyphers[] = {
        0x13, 0x2,  0x13, 0x3,  0x13, 0x1,  0xc0, 0x2c, 0xc0, 0x30, 0x0, 0x9f,
        0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x0, 0x9e,
        0xc0, 0x24, 0xc0, 0x28, 0x0,  0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x0, 0x67,
        0xc0, 0xa,  0xc0, 0x14, 0x0,  0x39, 0xc0, 0x9,  0xc0, 0x13, 0x0, 0x33,
        0x0,  0x9d, 0x0,  0x9c, 0x0,  0x3d, 0x0,  0x3c, 0x0,  0x35, 0x0, 0x2f};

    for (size_t i = 0; i < 60; i++) {
      if (cyphers[i] != matching_cyphers[i]) {
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
    else if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *udp =
          (struct udphdr *)((unsigned char *)ip + sizeof(struct iphdr));

      if (OVER(udp, data_end))
        return XDP_DROP;

      void *start_payload = (uint8_t *)udp + sizeof(struct udphdr);

      if (OVER(start_payload + 8, data_end)) // i need 8 bytes for tracker proto
        return XDP_DROP;

      if (!(((uint8_t *)start_payload)[0] == 0x00 &&
            ((uint8_t *)start_payload)[1] == 0x00 &&
            ((uint8_t *)start_payload)[2] == 0x04 &&
            ((uint8_t *)start_payload)[3] == 0x17 &&
            ((uint8_t *)start_payload)[4] == 0x27 &&
            ((uint8_t *)start_payload)[5] == 0x10 &&
            ((uint8_t *)start_payload)[6] == 0x19 &&
            ((uint8_t *)start_payload)[7] == 0x80)) {

        return XDP_PASS;
      }

      return XDP_PASS;
    }
    else {
    }
    return XDP_PASS;
  }

  char _license[] SEC("license") = "GPL";
