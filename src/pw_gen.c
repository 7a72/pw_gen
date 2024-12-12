#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmac/hmac_sha2.h"

#define MAX_INPUT_LENGTH 1024
#define MIN_PASSWORD_LENGTH 8
#define MAX_PASSWORD_LENGTH 32
#define DEFAULT_PASSWORD_LENGTH 12
#define ALGORITHM_NAME_MAX 8

typedef struct {
  char algorithm[ALGORITHM_NAME_MAX];
  int password_length;
  const char *input;
  const char *key;
  const char *case_type;
} Options;

static void print_usage(void) {
  printf("Usage: pw_gen [OPTIONS] INPUT KEY\n"
         "\nOptions:\n"
         "  -a, --algorithm ALGO    Hash algorithm (SHA256 or SHA512, default: "
         "SHA256)\n"
         "  -l, --length LENGTH     Password length (8-32, default: 12)\n"
         "  -c, --case CASE         Case conversion (none, lower, upper, "
         "default: none)\n"
         "  -h, --help              Show this help message\n"
         "\nExample:\n"
         "  pw_gen -a SHA512 -l 16 -c lower \"user@example.com\" \"mykey\"\n"
         "  pw_gen \"user@example.com\" \"mykey\"\n");
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

static bool base64_encode(const unsigned char *input, size_t length,
                          char *output, size_t output_size) {
  if (!input || !output || length == 0 || output_size == 0) {
    return false;
  }

  size_t i = 0, j = 0;
  unsigned char array_3[3];
  unsigned char array_4[4];

  while (length--) {
    array_3[i++] = *(input++);
    if (i == 3) {
      array_4[0] = (array_3[0] & 0xfc) >> 2;
      array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
      array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
      array_4[3] = array_3[2] & 0x3f;

      for (i = 0; (i < 4) && (j < output_size - 1); i++) {
        output[j++] = base64_chars[array_4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    for (int k = i; k < 3; k++) {
      array_3[k] = '\0';
    }

    array_4[0] = (array_3[0] & 0xfc) >> 2;
    array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
    array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
    array_4[3] = array_3[2] & 0x3f;

    for (int k = 0; (k < i + 1) && (j < output_size - 1); k++) {
      output[j++] = base64_chars[array_4[k]];
    }

    while (i++ < 3) {
      if (j < output_size - 1) {
        output[j++] = '=';
      }
    }
  }
  output[j] = '\0';

  return true;
}

static void rail_fence_encrypt(const char *const text, char *const output) {
  if (!text || !output) {
    return;
  }

  const size_t len = strlen(text);
  size_t pos = 0;

  for (size_t i = 0; i < len; i += 2) {
    output[pos++] = text[i];
  }

  for (size_t i = 1; i < len; i += 2) {
    output[pos++] = text[i];
  }

  output[len] = '\0';
}

static char *generate_password(const char *const input, const char *const key,
                               const char *const algorithm,
                               const int password_length) {
  if (!input || !key || !algorithm || password_length <= 0) {
    return NULL;
  }

  unsigned char result[SHA512_DIGEST_SIZE];
  unsigned int mac_size = (strcmp(algorithm, "SHA256") == 0)
                              ? SHA256_DIGEST_SIZE
                              : SHA512_DIGEST_SIZE;

  if (strcmp(algorithm, "SHA256") == 0) {
    hmac_sha256((const unsigned char *)key, strlen(key),
                (const unsigned char *)input, strlen(input), result, mac_size);
  } else if (strcmp(algorithm, "SHA512") == 0) {
    hmac_sha512((const unsigned char *)key, strlen(key),
                (const unsigned char *)input, strlen(input), result, mac_size);
  } else {
    fprintf(stderr, "Error: Unsupported algorithm '%s'\n", algorithm);
    return NULL;
  }

  char *hex = calloc(SHA512_DIGEST_SIZE * 2 + 1, sizeof(char));
  if (!hex) {
    return NULL;
  }

  for (int i = 0; i < mac_size; i++) {
    sprintf(hex + (i * 2), "%02x", result[i]);
  }

  char *rail_fence = calloc(strlen(hex) + 1, sizeof(char));
  if (!rail_fence) {
    free(hex);
    return NULL;
  }

  rail_fence_encrypt(hex, rail_fence);
  free(hex);

  char *base64 = calloc(password_length + 1, sizeof(char));
  if (!base64) {
    free(rail_fence);
    return NULL;
  }

  int encoded_length =
      base64_encode((unsigned char *)rail_fence, strlen(rail_fence), base64,
                    password_length + 1);
  if (encoded_length <= 0) {
    free(rail_fence);
    free(base64);
    return NULL;
  }

  free(rail_fence);
  base64[password_length] = '\0';

  return base64;
}

static void convert_case(char *const str, const char *const case_type) {
  if (!str || !case_type) {
    return;
  }

  if (strcmp(case_type, "lower") == 0) {
    for (char *c = str; *c; c++) {
      *c = tolower((unsigned char)*c);
    }
  } else if (strcmp(case_type, "upper") == 0) {
    for (char *c = str; *c; c++) {
      *c = toupper((unsigned char)*c);
    }
  }
}

static bool validate_options(const Options *const opts) {
  if (!opts) {
    return false;
  }

  if (opts->password_length < MIN_PASSWORD_LENGTH ||
      opts->password_length > MAX_PASSWORD_LENGTH) {
    fprintf(stderr, "Error: Password length must be between %d and %d\n",
            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    return false;
  }

  if (!opts->input || !opts->key || strlen(opts->input) == 0 ||
      strlen(opts->key) == 0) {
    fprintf(stderr, "Error: Input and key cannot be empty\n");
    return false;
  }

  if (strcmp(opts->algorithm, "SHA256") != 0 &&
      strcmp(opts->algorithm, "SHA512") != 0) {
    fprintf(stderr, "Error: Invalid algorithm\n");
    return false;
  }

  if (strcmp(opts->case_type, "none") != 0 &&
      strcmp(opts->case_type, "lower") != 0 &&
      strcmp(opts->case_type, "upper") != 0) {
    fprintf(stderr, "Error: Invalid case type\n");
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  Options opts = {.algorithm = "SHA256",
                  .password_length = DEFAULT_PASSWORD_LENGTH,
                  .input = NULL,
                  .key = NULL,
                  .case_type = "none"};

  const struct option long_options[] = {
      {"algorithm", required_argument, NULL, 'a'},
      {"length", required_argument, NULL, 'l'},
      {"case", required_argument, NULL, 'c'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "a:l:c:h", long_options, NULL)) != -1) {
    switch (opt) {
    case 'a':
      if (strlen(optarg) < ALGORITHM_NAME_MAX) {
        char temp[ALGORITHM_NAME_MAX];
        strncpy(temp, optarg, ALGORITHM_NAME_MAX - 1);
        temp[ALGORITHM_NAME_MAX - 1] = '\0';
        for (int i = 0, j = 0; temp[i]; i++) {
          if (temp[i] != '-') {
            temp[j++] = toupper((unsigned char)temp[i]);
          }
        }
        temp[strlen(temp)] = '\0';
        strncpy(opts.algorithm, temp, ALGORITHM_NAME_MAX - 1);
      }
      break;
    case 'l': {
      char *endptr;
      const long length = strtol(optarg, &endptr, 10);
      if (*endptr == '\0' && length >= MIN_PASSWORD_LENGTH &&
          length <= MAX_PASSWORD_LENGTH) {
        opts.password_length = (int)length;
      }
      break;
    }
    case 'c':
      opts.case_type = optarg;
      break;
    case 'h':
      print_usage();
      return EXIT_SUCCESS;
    default:
      print_usage();
      return EXIT_FAILURE;
    }
  }

  if (argc - optind != 2) {
    fprintf(stderr, "Error: Missing required arguments\n");
    print_usage();
    return EXIT_FAILURE;
  }

  opts.input = argv[optind];
  opts.key = argv[optind + 1];

  if (!validate_options(&opts)) {
    return EXIT_FAILURE;
  }

  char *input_processed = strdup(opts.input);
  if (!input_processed) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    return EXIT_FAILURE;
  }

  convert_case(input_processed, opts.case_type);

  char *password = generate_password(input_processed, opts.key, opts.algorithm,
                                     opts.password_length);
  free(input_processed);

  if (!password) {
    fprintf(stderr, "Error: Failed to generate password\n");
    return EXIT_FAILURE;
  }

  printf("%s\n", password);
  free(password);

  return EXIT_SUCCESS;
}
