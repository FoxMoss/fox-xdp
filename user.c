#include "shared.h"
#include <assert.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define FQ_REFILL_MAX (RX_BATCH_SIZE * 2)
#define INVALID_UMEM_FRAME UINT64_MAX

#define INTERFACE_SIZE 1024

const char *ifname = "";
static int ifindex = -1;
const char *prog_path = "build/kern.o";
const char *prog_name = "prog";
const __u16 xsk_bind_flags = 0;
enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC;
const int xsk_if_queue = 0;
int pass_hash_map_fd;

static struct xdp_program *prog;
int xsk_map_fd;

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;
};

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
xsk_configure_socket(struct xsk_umem_info *umem) {
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
  xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
  ret = xsk_socket__create(&xsk_info->xsk, ifname, xsk_if_queue, umem->umem,
                           &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
  if (ret)
    goto error_exit;

  ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
  if (ret)
    goto error_exit;

  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

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

void unload() {
  struct xdp_multiprog *multi_prog = xdp_multiprog__get_from_ifindex(ifindex);
  if (multi_prog != NULL) {
    if (!xdp_multiprog__detach(multi_prog))
      printf("Unloaded BPF program\n");
  }
}

void catch_close() {
  unload();
  exit(0);
}

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

uint32_t calculate_hash(uint16_t *data, size_t len) {
  uint32_t hash = 0;
  uint16_t lowest = 0;
  for (size_t i = 0; i < len; i++) {
    uint16_t lowest_high = UINT16_MAX;
    for (size_t j = 0; j < len; j++) {
      if (data[j] < lowest_high && data[j] > lowest) {
        lowest_high = data[j];
      }
    }
    lowest = lowest_high;
    hash += lowest;
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

void handle_packet(uint8_t *data, size_t len) {
  void *data_end = data + len;

  struct ethhdr *eth = data;

  struct iphdr *ip = (struct iphdr *)(eth + 1);

  struct tcphdr *tcp =
      (struct tcphdr *)((unsigned char *)ip + sizeof(struct iphdr));

  void *start_payload = ((uint8_t *)tcp) + (tcp->doff * 4);
  struct tlshdr1 *tlsh = start_payload;

  uint16_t real_count = ntohs(tlsh->cyphercount);

  uint16_t *ciphers = (uint16_t *)(tlsh + 1);

  uint8_t *ciphers_end = (void *)ciphers + real_count;

  uint16_t lowest = 0;
  uint32_t my_hash = calculate_hash(ciphers, real_count / 2);

  uint8_t passed_count = 0;

#ifdef PASS_LOG
  if (0 == bpf_map_lookup_elem(pass_hash_map_fd, &my_hash, &passed_count)) {
    passed_count = 0;
  }
  passed_count++;
  bpf_map_update_elem(pass_hash_map_fd, &my_hash, &passed_count, 0);
#endif

  printf("Blocked request with hash %u\n", my_hash);
}

int main(int argc, char *argv[]) {

  if (argc != 4) {
    fprintf(stderr, "Usage: %s [FILE] [INTERFACE] [FILTER]\n", argv[0]);
    fprintf(stderr, "Block all incoming traffic with specific TLS hashes\n");
    fprintf(stderr, "[FILE] Hash config file\n");
    fprintf(stderr, "[INTERFACE] Interface name (eg. wlan0, lo, etc)\n");
    fprintf(stderr, "[FILTER] fox.bpf file\n");
    exit(EXIT_FAILURE);
  }
  char *config_file = argv[1];
  ifname = argv[2];

  ifindex = if_nametoindex(ifname);
  unload();
  signal(SIGINT, catch_close);

  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
  xdp_opts.open_filename = argv[3];
  xdp_opts.prog_name = prog_name;
  xdp_opts.opts = &opts;
  prog = xdp_program__open_file(argv[3], NULL, &opts);

  char errmsg[1024];
  int err = libxdp_get_error(prog);
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

  struct bpf_map *socket_map;
  socket_map =
      bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
  xsk_map_fd = bpf_map__fd(socket_map);
  if (xsk_map_fd < 0) {
    fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsk_map_fd));
    exit(EXIT_FAILURE);
  }

  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
  void *packet_buffer;
  if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
    fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct xsk_umem_info *umem =
      configure_xsk_umem(packet_buffer, packet_buffer_size);
  if (umem == NULL) {
    fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct xsk_socket_info *xsk_socket = xsk_configure_socket(umem);
  if (xsk_socket == NULL) {
    fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct pollfd fds[2];
  int ret, nfds = 1;

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
  fds[0].events = POLLIN;

  struct bpf_map *blocked_map =
      bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "blocked");
  int blocked_map_fd = bpf_map__fd(blocked_map);

  uint8_t block = BLOCK_NONE;

  FILE *config_fd = fopen(config_file, "r");
  if (config_fd == NULL) {
    fprintf(stderr, "ERROR: Can't read config file. \"%s\"\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (fread(&block, 1, sizeof(uint8_t), config_fd) != sizeof(uint8_t) &&
      (block != BLOCK_BLACK || block != BLOCK_WHITE)) {
    fprintf(stderr, "ERROR: Can't read block type. \"%s\"\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  printf("Block type %i\n", block);

  uint32_t base_key = 0;
  bpf_map_update_elem(blocked_map_fd, &base_key, &block, 0);

  struct bpf_map *pass_hash_map =
      bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "pass_hash");
  pass_hash_map_fd = bpf_map__fd(pass_hash_map);

  uint32_t hash = 1; // not zero in case it overides the blocktype
  uint8_t activate = HASH_ACTIVATE;

  while (fread(&hash, 1, sizeof(uint32_t), config_fd) == sizeof(uint32_t)) {
    printf("Adding hash %u\n", hash);
    bpf_map_update_elem(blocked_map_fd, &hash, &activate, 0);
  }
  fclose(config_fd);

  printf("Starting filtering!\n");

  while (1) {
    ret = poll(fds, nfds, -1);

    uint32_t idx_rx;
    int rcvd = xsk_ring_cons__peek(&xsk_socket->rx, RX_BATCH_SIZE, &idx_rx);

    uint32_t idx_fq;
    int rsvd = xsk_ring_prod__reserve(&xsk_socket->umem->fq, rcvd, &idx_fq);

#ifdef PASS_LOG
    uint32_t tx_idx;
    int txrsvd = xsk_ring_prod__reserve(&xsk_socket->tx, rcvd, &tx_idx);
#endif

    if (rsvd != rcvd) {
      printf("Warning: Ring size mismatch %i %i\n", rcvd, rsvd);
      continue;
    }

    for (int i = 0; i < rcvd; i++) {
      struct xdp_desc *rx_desc =
          xsk_ring_cons__rx_desc(&xsk_socket->rx, idx_rx++);

      char *packet =
          xsk_umem__get_data(xsk_socket->umem->buffer, rx_desc->addr);

#ifdef PASS_LOG
      uint64_t tx_addr = xsk_alloc_umem_frame(xsk_socket);
      if (tx_addr == INVALID_UMEM_FRAME) {
        printf("whoops\n");
        continue;
      }
      char *tx_packet = xsk_umem__get_data(xsk_socket->umem->buffer, tx_addr);
      memcpy(tx_packet, packet, rx_desc->len);
#endif

      handle_packet(packet, rx_desc->len);

#ifdef PASS_LOG
      xsk_ring_prod__tx_desc(&xsk_socket->tx, tx_idx + i)->addr = tx_addr;
      xsk_ring_prod__tx_desc(&xsk_socket->tx, tx_idx + i)->len = rx_desc->len;

      *xsk_ring_prod__fill_addr(&xsk_socket->umem->fq, idx_fq + i) =
          rx_desc->addr;
#endif
    }

    // xsk_ring_prod__submit(&xsk_socket->tx, rcvd);
    xsk_ring_prod__submit(&xsk_socket->umem->fq, rcvd);
    xsk_ring_cons__release(&xsk_socket->rx, rcvd);

#ifdef PASS_LOG
    int s =
        sendto(xsk_socket__fd(xsk_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (s < 0 && errno != EAGAIN) {
      fprintf(stderr, "sendto() to kick TX ring failed: %s\n", strerror(errno));
    }

    uint32_t idx_cq;
    int completed = xsk_ring_cons__peek(
        &xsk_socket->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

    if (completed > 0) {
      for (int i = 0; i < completed; i++) {
        uint64_t addr;

        addr = *xsk_ring_cons__comp_addr(&xsk_socket->umem->cq, idx_cq++);
        xsk_free_umem_frame(xsk_socket, addr);
        // pr_addr_info(__func__, addr, xsk->umem);
      }

      xsk_ring_cons__release(&xsk_socket->umem->cq, completed);
    }
  }
#endif
}

xsk_socket__delete(xsk_socket->xsk);
xsk_umem__delete(umem->umem);

catch_close();

return 1;
}
