#include "shared.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// jenkins hash, fast but insecure
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

void usage(char *argv[]) {
  fprintf(stderr, "Usage: %s [OUTPUT] [BLOCKTYPE] [FILES]\n", argv[0]);
  fprintf(stderr, "Hash the ciphers of a TLS packet.\n");
  fprintf(stderr, "[OUTPUT] the file in which your hashes will be stored.\n");
  fprintf(stderr, "[BLOCKTYPE] \"whitelist\" or \"blacklist\"\n");
  fprintf(stderr, "[FILES] the ciphers feild of a tls packet.\n");
  exit(0);
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    usage(argv);
  }

  uint8_t blocktype = BLOCK_NONE;
  if (strcmp(argv[2], "whitelist") == 0) {
    blocktype = BLOCK_WHITE;
  } else if (strcmp(argv[2], "blacklist") == 0) {
    blocktype = BLOCK_BLACK;
  } else {
    fprintf(stderr, "Error: BLOCKTYPE invalid\n\n");
    usage(argv);
  }

  FILE *output = fopen(argv[1], "w");
  fwrite(&blocktype, sizeof(uint8_t), 1, output);

  for (size_t i = 3; i < argc; i++) {
    FILE *f = fopen(argv[i], "r");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    uint8_t file[len];
    fseek(f, 0, SEEK_SET);
    fread(file, len, 1, f);
    uint32_t hash = calculate_hash(file, len / 2);
    printf("%s %u\n", argv[i], hash);

    fwrite(&hash, sizeof(uint32_t), 1, output);
  }
  fclose(output);
}
