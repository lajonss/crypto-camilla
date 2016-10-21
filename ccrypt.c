#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>


#include <openssl/camellia.h>

#define BLOCK_SIZE 16

#define ECB_MODE 1
#define CBC_MODE 2

static char *program_name = 0;

static int working_mode = 0;
static int decrypt = 0;
static char *output = 0;
static char *input = 0;

int invalid_usage(char *reason, char *argument) {
  if(reason) {
    if(argument)
      printf("%s: %s\n", reason, argument);
    else
      printf("Invalid usage: %s\n", reason);
  }
  printf("Usage: %s -m <mode> <input file name>\n", program_name);
  return -1;
}


void do_encrypt() {
  unsigned const char pass[16] = { 'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd', 'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd'};
  CAMELLIA_KEY key;
  printf("Set key: %d\n", Camellia_set_key(pass, 128, &key));
  FILE *file_in = fopen(input, "rb");
  FILE *file_out = fopen(output, "wb");
  unsigned char bufor_in[BLOCK_SIZE];
  unsigned char bufor_out[BLOCK_SIZE];

  int operation_mode;
  if(decrypt)
    operation_mode = CAMELLIA_DECRYPT;
  else
    operation_mode = CAMELLIA_ENCRYPT;

  printf("operation_mode: %d\n", operation_mode);

  if (working_mode == ECB_MODE) {
    int work = 1;
    while(work) {
      //printf("Filename: %s", input);
      size_t rd = fread(bufor_in, sizeof(char), BLOCK_SIZE, file_in);
      if(ferror(file_in)) {
          printf("Reading error");
          exit(-1);
      }
      //printf("ferror: %d\n", ferror(file_in));
      //printf("feof: %d\n", feof(file_in));
      //printf("reading: %zd\n", rd);
      for(size_t i = BLOCK_SIZE; i > rd; i--) {
        if(i-1 == 0)
          break;
        bufor_in[i-1] = rd;
        work = 0;
      }
      Camellia_ecb_encrypt(bufor_in, bufor_out, &key, operation_mode);
      fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
      if(ferror(file_out)) {
          printf("Writing error");
          exit(-1);
      }
      //printf("writing: %zd\n", fwrite(bufor_out, sizeof(char), 8, file_out));
    }
  } else {
    printf("unsigned\n");
  }

  fclose(file_in);
  fclose(file_out);
  printf("done\n");
}

void do_decrypt() {
  printf("Unsupported\n");
}

int main(int argc, char **argv) {
  int c;
  program_name = argv[0];

  while (1) {
    //int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      {   "mode", required_argument, 0, 'm'},
      { "output", required_argument, 0, 'o'},
      {   "help",       no_argument, 0, 'h'},
      {"decrypt",       no_argument, 0, 'd'},
      {        0,                 0, 0,   0}
    };
    c = getopt_long(argc, argv, "dm:o:h?", long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
      case 'm':
        if(optarg[0] == 'c' || optarg[0] == 'C')
          working_mode = CBC_MODE;
        else if(optarg[0] == 'e' || optarg[0] == 'E')
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
  if(!working_mode)
    return invalid_usage("Mode parameter is required!", 0);
  if(optind >= argc)
    return invalid_usage("Input file name is required!", 0);
  input = (char*) malloc(strlen(argv[optind]) + 1);
  strcpy(input, argv[optind]);
  if(!output) {
    output = (char*) malloc(strlen(input) + 5);
    strcpy(output, input);
    strcat(output, ".out");
  }
  printf("%s -> %s\n", input, output);
  do_encrypt();
  return 0;
}
