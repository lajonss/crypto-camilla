#define _GNU_SOURCE

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <openssl/camellia.h>

#define BLOCK_SIZE 16

#define ECB_MODE 1
#define CBC_MODE 2

static char *program_name = 0;

static int working_mode = 0;
static int decrypt = 0;
static char *output = 0;
static char *input = 0;
static uint64_t total_time = 0; 
static struct timespec start, end;


// http://stackoverflow.com/a/10192994
void start_measure_time() {
  clock_gettime(CLOCK_MONOTONIC_RAW, &start);
}

uint64_t stop_measure_time() {
  clock_gettime(CLOCK_MONOTONIC_RAW, &end);
  uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
  return delta_us;
}


int invalid_usage(char *reason, char *argument) {
  if (reason) {
    if (argument)
      printf("%s: %s\n", reason, argument);
    else
      printf("Invalid usage: %s\n", reason);
  }
  printf("Usage: %s -m <mode> <input file name>\n", program_name);
  return -1;
}

void do_encrypt() {
  unsigned const char pass[16] = {'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd',
                                  'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd'};
  CAMELLIA_KEY key;
  Camellia_set_key(pass, 128, &key);
  FILE *file_in = fopen(input, "rb");
  if (!file_in) {
    printf("Failed to open input file: %s\n", input);
    exit(-1);
  }
  FILE *file_out = fopen(output, "wb");
  if (!file_out) {
    printf("Failed to open output file: %s\n", output);
    exit(-1);
  }
  unsigned char bufor_in[BLOCK_SIZE];
  unsigned char bufor_out[BLOCK_SIZE];
  unsigned char ivec[BLOCK_SIZE];
  memset(ivec, 0, BLOCK_SIZE);

  int operation_mode;
  if (decrypt)
    operation_mode = CAMELLIA_DECRYPT;
  else
    operation_mode = CAMELLIA_ENCRYPT;

  size_t rd;
  int bufor_out_ready = 0;
  while ((rd = fread(bufor_in, sizeof(char), BLOCK_SIZE, file_in))) {
    if (ferror(file_in)) {
      printf("Reading error\n");
      exit(-1);
    }
    if (operation_mode == CAMELLIA_DECRYPT && bufor_out_ready)
      fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
    if (rd < BLOCK_SIZE) {
      printf("filling: %zd\n", BLOCK_SIZE - rd);
      for (size_t i = BLOCK_SIZE; i > rd; i--)
        bufor_in[i - 1] = BLOCK_SIZE - rd;
    }
    if (working_mode == ECB_MODE) {
      start_measure_time();
      Camellia_ecb_encrypt(bufor_in, bufor_out, &key, operation_mode);
      total_time += stop_measure_time();
    }
    else {
      start_measure_time();
      Camellia_cbc_encrypt(bufor_in, bufor_out, BLOCK_SIZE, &key, ivec,
                           operation_mode);
      total_time += stop_measure_time();
    }
    bufor_out_ready = 1;
    if (operation_mode == CAMELLIA_ENCRYPT)
      fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
    if (ferror(file_out)) {
      printf("Writing error\n");
      exit(-1);
    }
    if (rd < BLOCK_SIZE)
      break;
  }
  if (operation_mode == CAMELLIA_DECRYPT) {
    fwrite(bufor_out, sizeof(char), BLOCK_SIZE - bufor_out[BLOCK_SIZE - 1],
           file_out);
    printf("decrypt fill: %d\n", bufor_out[BLOCK_SIZE - 1]);
  } else if (!rd) {
    // Pawle, zakomentowanie tego bloku kodu nie zaburza dzialania programu, sprawdz :)
    memset(bufor_in, BLOCK_SIZE, BLOCK_SIZE);
    if (working_mode == ECB_MODE) {
      start_measure_time();
      Camellia_ecb_encrypt(bufor_in, bufor_out, &key, operation_mode);
      total_time += stop_measure_time();
    }
    else {
      start_measure_time();
      Camellia_cbc_encrypt(bufor_in, bufor_out, BLOCK_SIZE, &key, ivec,
                           operation_mode);
      total_time += stop_measure_time();
    }
    fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
  }

  fclose(file_in);
  fclose(file_out);
  printf("done\n");
}

int main(int argc, char **argv) {
  int c;
  program_name = argv[0];

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {"decrypt", no_argument, 0, 'd'},
        {0, 0, 0, 0}};
    c = getopt_long(argc, argv, "dm:o:h?", long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
    case 'm':
      if (optarg[0] == 'c' || optarg[0] == 'C')
        working_mode = CBC_MODE;
      else if (optarg[0] == 'e' || optarg[0] == 'E')
        working_mode = ECB_MODE;
      else
        return invalid_usage("Unsupported mode", optarg);
      break;
    case 'o':
      output = optarg;
      break;
    case 'd':
      decrypt = 1;
      break;
    case 'h':
    case '?':
      return invalid_usage(0, 0);
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  if (!working_mode)
    return invalid_usage("Mode parameter is required!", 0);
  if (optind >= argc)
    return invalid_usage("Input file name is required!", 0);
  input = (char *)malloc(strlen(argv[optind]) + 1);
  strcpy(input, argv[optind]);
  if (!output) {
    output = (char *)malloc(strlen(input) + 5);
    strcpy(output, input);
    strcat(output, ".out");
  }
  printf("%s -> %s\n", input, output);
  do_encrypt();
  printf("It took %" PRIu64 " microseconds\n", total_time);
  return 0;
}
