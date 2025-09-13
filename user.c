/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include <arpa/inet.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <net/if.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

const char *ifname = "lo";
static int ifindex = -1;
const char *prog_path = "build/kern.o";
const char *prog_name = "prog";
const __u16 xsk_bind_flags = 0;
enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC;
const int xsk_if_queue = 0;

struct egress_sock {
  int sockfd;
  struct sockaddr_ll *addr;
};

static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;

struct config {
  int xsk_if_queue;
  bool xsk_poll_mode;
  bool unload_all;
};

struct config cfg = {};

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};
struct stats_record {
  uint64_t timestamp;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};
struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;

  struct stats_record stats;
  struct stats_record prev_stats;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
  struct xsk_umem_info *umem;
  int ret;

  umem = calloc(1, sizeof(*umem));
  if (!umem)
    return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret) {
    errno = -ret;
    return NULL;
  }

  umem->buffer = buffer;
  return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
  return xsk->umem_frame_free;
}

static struct xsk_socket_info *
xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem) {
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  uint32_t idx;
  int i;
  int ret;
  uint32_t prog_id;

  xsk_info = calloc(1, sizeof(*xsk_info));
  if (!xsk_info)
    return NULL;

  xsk_info->umem = umem;
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.xdp_flags = 0;
  xsk_cfg.bind_flags = xsk_bind_flags;
  xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
  ret = xsk_socket__create(&xsk_info->xsk, ifname, xsk_if_queue, umem->umem,
                           &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
  if (ret)
    goto error_exit;

  if (custom_xsk) {
    ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
    if (ret)
      goto error_exit;
  } else {
    /* Getting the program ID must be after the xdp_socket__create() call */
    if (bpf_xdp_query_id(ifindex, 0, &prog_id))
      goto error_exit;
  }

  /* Initialize umem frame allocation */
  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Stuff the receive path with buffers, we assume we have enough */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                               XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    goto error_exit;

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
        xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;

error_exit:
  errno = -ret;
  return NULL;
}

static void complete_tx(
    struct xsk_socket_info *xsk) { // Initiate starting variables (completed
                                   // amount and completion ring index).
  unsigned int completed;
  uint32_t idx_cq;

  // If outstanding is below 1, it means we have no packets to TX.
  if (!xsk->outstanding_tx) {
    return;
  }

  // If we need to wakeup, execute syscall to wake up socket.
  if (!(xsk_bind_flags & XDP_USE_NEED_WAKEUP) ||
      xsk_ring_prod__needs_wakeup(&xsk->tx)) {
    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
  }

  // Try to free a bunch of frames on the completion ring.
  completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                  XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

  if (completed > 0) {
    // Free frames and comp.
    for (int i = 0; i < completed; i++) {
      xsk_free_umem_frame(xsk,
                          *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));
    }

    // Release "completed" frames.
    xsk_ring_cons__release(&xsk->umem->cq, completed);

    xsk->outstanding_tx -=
        completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
  }
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
  uint16_t res = (uint16_t)csum;

  res += (__u16)addend;
  return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
  return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new) {
  *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static bool process_packet(struct xsk_socket_info *xsk, uint64_t addr,
                           uint32_t len, const struct egress_sock *egress) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  struct ethhdr *eth = (struct ethhdr *)pkt;
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

  // if (ntohs(eth->h_proto) != ETH_P_IP ||
  //     len < (sizeof(*eth) + sizeof(*ip) + sizeof(*tcp)) ||
  //     ip->protocol != IPPROTO_TCP)
  //   return false;

  struct in_addr src_ip, dest_ip, fox_ip;
  src_ip.s_addr = ip->saddr;
  dest_ip.s_addr = ip->daddr;
  inet_aton("205.185.125.167", &fox_ip);

  printf("Source IP: %s\n", inet_ntoa(src_ip));
  printf("Destination IP: %s\n", inet_ntoa(dest_ip));

  // uint8_t tmp_mac[ETH_ALEN];
  // memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
  // memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  // memcpy(eth->h_source, tmp_mac, ETH_ALEN);
  //
  // struct in_addr tmp_ip;
  // memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
  // memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
  // memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));
  //
  // ip->check = 0;
  // __sum16 *ip_sum = (__sum16 *)ip;
  // __sum16 real_check = 0;
  // for (size_t i = 0; i < sizeof(struct iphdr) / sizeof(__sum16); i++) {
  //   real_check = csum16_add(real_check, ip_sum[i]);
  // }
  // ip->check = real_check;
  // ip->ttl = 69;

  // csum_replace2(&icmp->icmp6_cksum, htons(ICMPV6_ECHO_REQUEST << 8),
  //               htons(ICMPV6_ECHO_REPLY << 8));

  /* Here we sent the packet out of the receive port. Note that
   * we allocate one entry and schedule it. Your design would be
   * faster if you do batch processing/transmission */

  // if ((sendto(egress->sockfd, pkt, len, 0, (struct sockaddr *)egress->addr,
  //             sizeof(*egress->addr))) == -1) {
  //   fprintf(stderr, "ERROR: Failed to send packet");
  //   return false;
  // }

  uint32_t tx_idx = 0;
  if (xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx) != 1)
    /* No more transmit slots, drop the packet */
    return false;

  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
  xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;
  //
  // xsk->stats.tx_bytes += len;
  // xsk->stats.tx_packets++;
  //
  // printf("sent!\n");
  return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk,
                                   struct egress_sock *egress) {
  unsigned int i;
  uint32_t idx_rx = 0, idx_fq = 0;

  const unsigned int rcvd =
      xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  /* Stuff the ring with as much frames as possible */
  const unsigned int stock_frames =
      xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {
    uint32_t ret =
        xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    /* This should not happen, but just in case
     * Wait until we can reserve enough space in the fill queue
     */
    while (ret != stock_frames)
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    /* Finally, tell the kernel that it can start writing packets into the rx
     * ring */
    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process received packets */
  for (i = 0; i < rcvd; i++) {
    /* Get the address of the frame from the rx ring */
    const uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    const uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

    /* If the packet was not processed correctly or does not need to be
     * transmitted, free the frame */
    if (!process_packet(xsk, addr, len, egress))
      xsk_free_umem_frame(xsk, addr);

    xsk->stats.rx_bytes += len;
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);
  xsk->stats.rx_packets += rcvd;

  /* Do we need to wake up the kernel for transmission */
  complete_tx(xsk);
}
static void rx_and_process(struct config *cfg,
                           struct xsk_socket_info *xsk_socket,
                           struct egress_sock *egress) {
  struct pollfd fds[2];
  int ret, nfds = 1;

  if ((egress->sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    fprintf(stderr, "ERROR: Failed to open raw socket");
    return;
  }

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
  fds[0].events = POLLIN;

  while (!global_exit) {
    if (cfg->xsk_poll_mode) {
      ret = poll(fds, nfds, -1);
      if (ret <= 0 || ret > 1)
        continue;
    }
    handle_receive_packets(xsk_socket, egress);
  }
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void) {
  struct timespec t;
  int res;

  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
    exit(1);
  }
  return (uint64_t)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p) {
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0)
    period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
  uint64_t packets, bytes;
  double period;
  double pps; /* packets per sec */
  double bps; /* bits per sec */

  char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
              " %'11lld Kbytes (%'6.0f Mbits/s)"
              " period:%f\n";

  period = calc_period(stats_rec, stats_prev);
  if (period == 0)
    period = 1;

  packets = stats_rec->rx_packets - stats_prev->rx_packets;
  pps = packets / period;

  bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
         stats_rec->rx_bytes / 1000, bps, period);

  packets = stats_rec->tx_packets - stats_prev->tx_packets;
  pps = packets / period;

  bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "       TX:", stats_rec->tx_packets, pps,
         stats_rec->tx_bytes / 1000, bps, period);

  printf("\n");
}

static void *stats_poll(void *arg) {
  unsigned int interval = 2;
  struct xsk_socket_info *xsk = arg;
  static struct stats_record previous_stats = {0};

  previous_stats.timestamp = gettime();

  /* Trick to pretty printf with thousands separators use %' */
  setlocale(LC_NUMERIC, "en_US");

  while (!global_exit) {
    sleep(interval);
    xsk->stats.timestamp = gettime();
    stats_print(&xsk->stats, &previous_stats);
    previous_stats = xsk->stats;
  }
  return NULL;
}
void get_mac_address(unsigned char *mac_addr, const char *ifname) {
  struct ifreq ifr;
  if (!ifname) {
    fprintf(stderr, "ERROR: Couldn't get interface name from index");
    exit(EXIT_FAILURE);
  }
  if (!mac_addr) {
    fprintf(stderr, "ERROR: Couldn't get MAC address");
    exit(EXIT_FAILURE);
  }

  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    fprintf(stderr, "ERROR: Couldn't create socket");
    exit(EXIT_FAILURE);
  }

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
    fprintf(stderr, "ERROR: Couldn't get MAC address for interface %s", ifname);
    exit(EXIT_FAILURE);
  }

  close(fd);

  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
}

int af_xdp_send_packet(struct xsk_socket_info *xsk, void *pckt, uint16_t length,
                       int new, uint64_t addr) {
  // This represents the TX index.
  uint32_t tx_idx = 0;
  uint16_t amt;

  // Retrieve the TX index from the TX ring to fill.
  amt = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);

  if (amt != 1) {
#ifdef DEBUG
    fprintf(stdout, "[XSK]No TX slots available.\n");
#endif

    return 1;
  }

  unsigned int idx = 0;

  // Retrieve index we want to insert at in UMEM and make sure it isn't
  // equal/above to max number of frames.
  idx = xsk->outstanding_tx;

  // We must retrieve the next available address in the UMEM.
  uint64_t addrat;

  if (!new) {
    addrat = addr;
  } else {
    // We must retrieve new address space.
    addrat = xsk_alloc_umem_frame(xsk);

    // We must copy our packet data to the UMEM area at the specific index (idx
    // * frame size). We did this earlier.
    memcpy(xsk_umem__get_data(xsk->umem->buffer, addrat), pckt, length);
  }

  // Retrieve TX descriptor at index.
  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);

  // Point the TX ring's frame address to what we have in the UMEM.
  tx_desc->addr = addrat;

  // Tell the TX ring the packet length.
  tx_desc->len = length;

  // Submit the TX batch to the producer ring.
  xsk_ring_prod__submit(&xsk->tx, 1);

  // Increase outstanding.
  xsk->outstanding_tx++;

#ifdef DEBUG
  fprintf(stdout,
          "Sending packet with length %u at location %llu. Outstanding count "
          "=> %u.\n",
          length, tx_desc->addr, xsk->outstanding_tx);
#endif

  // Return successful.
  return 0;
}

int main(int argc, char **argv) {
  ifindex = if_nametoindex(ifname);

  void *packet_buffer;
  uint64_t packet_buffer_size;
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  struct xsk_umem_info *umem;
  struct xsk_socket_info *xsk_socket;
  pthread_t stats_poll_thread;
  int err;
  char errmsg[1024];

  /* Global shutdown handler */

  /* Cmdline options can change progname */
  // parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

  /* Required option */
  // if (ifindex == -1) {
  //   fprintf(stderr, "ERROR: Required option --dev missing\n\n");
  //   usage(argv[0], __doc__, long_options, (argc == 1));
  //   return EXIT_FAIL_OPTION;
  // }

  /* Load custom program if configured */
  struct bpf_map *map;

  custom_xsk = true;
  xdp_opts.open_filename = prog_path;
  xdp_opts.prog_name = prog_name;
  xdp_opts.opts = &opts;

  prog = xdp_program__open_file(prog_path, NULL, &opts);

  err = libxdp_get_error(prog);
  if (err) {
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "ERR: loading program: %s\n", errmsg);
    return err;
  }

  err = xdp_program__attach(prog, ifindex, attach_mode, 0);
  if (err) {
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
            ifname, errmsg, err);
    return err;
  }

  /* We also need to load the xsks_map */
  map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
  xsk_map_fd = bpf_map__fd(map);
  if (xsk_map_fd < 0) {
    fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsk_map_fd));
    exit(EXIT_FAILURE);
  }

  /* Allow unlimited locking of memory, so all memory needed for packet
   * buffers can be locked.
   *
   * NOTE: since kernel v5.11, eBPF maps allocations are not tracked
   * through the process anymore. Now, eBPF maps are accounted to the
   * current cgroup of which the process that created the map is part of
   * (assuming the kernel was built with CONFIG_MEMCG).
   *
   * Therefore, you should ensure an appropriate memory.max setting on
   * the cgroup (via sysfs, for example) instead of relying on rlimit.
   */
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Allocate memory for NUM_FRAMES of the default XDP frame size */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
  if (posix_memalign(&packet_buffer, getpagesize(), /* PAGE_SIZE aligned */
                     packet_buffer_size)) {
    fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Initialize shared packet_buffer for umem usage */
  umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
  if (umem == NULL) {
    fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Open and configure the AF_XDP (xsk) socket */
  xsk_socket = xsk_configure_socket(&cfg, umem);
  if (xsk_socket == NULL) {
    fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct egress_sock ingress;

  ingress.addr = calloc(1, sizeof(*ingress.addr));

  get_mac_address(ingress.addr->sll_addr, ifname);
  ingress.addr->sll_halen = ETH_ALEN;
  ingress.addr->sll_ifindex = if_nametoindex(ifname);

  struct pollfd fds[2];
  int ret, nfds = 1;

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
  fds[0].events = POLLIN;
  /* Start thread to do statistics display */
  /* Receive and count packets than drop them */
  while (1) {
    ret = poll(fds, nfds, -1);

    if (ret != 1) {
      continue;
    }

    __u32 idx_rx = 0, idx_fq = 0;
    unsigned int rcvd = 0;

    rcvd = xsk_ring_cons__peek(&xsk_socket->rx, RX_BATCH_SIZE, &idx_rx);

    if (!rcvd) {
      continue;
    }

    int stock_frames = 0;

    stock_frames = xsk_prod_nb_free(&xsk_socket->umem->fq,
                                    xsk_umem_free_frames(xsk_socket));

    if (stock_frames > 0) {
      ret =
          xsk_ring_prod__reserve(&xsk_socket->umem->fq, stock_frames, &idx_fq);

      while (ret != stock_frames) {
        ret = xsk_ring_prod__reserve(&xsk_socket->umem->fq, rcvd, &idx_fq);
      }

      for (int j = 0; j < stock_frames; j++) {
        *xsk_ring_prod__fill_addr(&xsk_socket->umem->fq, idx_fq++) =
            xsk_alloc_umem_frame(xsk_socket);
      }

      xsk_ring_prod__submit(&xsk_socket->umem->fq, stock_frames);
    }

    for (int j = 0; j < rcvd; j++) {
      __u64 addr = xsk_ring_cons__rx_desc(&xsk_socket->rx, idx_rx)->addr;
      __u32 len = xsk_ring_cons__rx_desc(&xsk_socket->rx, idx_rx++)->len;

      void *pckt = xsk_umem__get_data(xsk_socket->umem->buffer, addr);

      if (pckt == NULL) {
#ifdef DEBUG
        fprintf(stdout, "[XSK] Packet not true; freeing frame.\n");
#endif

        xsk_free_umem_frame(xsk_socket, addr);

        continue;
      }

      unsigned char new_pckt_buff[2048];
      memcpy(new_pckt_buff, pckt, 2048);

      printf("packet attempted to send %i\n", 2048);
      af_xdp_send_packet(xsk_socket, (void *)new_pckt_buff, 2048, 1, 0);
    }

    xsk_ring_cons__release(&xsk_socket->rx, rcvd);

    complete_tx(xsk_socket);
  }

  /* Cleanup */
  xsk_socket__delete(xsk_socket->xsk);
  xsk_umem__delete(umem->umem);

  return 1;
}
