#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#include "encryptor.h"
#include "util.h"

#define ENCRYPT 0
#define DECRYPT 1
#define SIGN    2
#define VERIFY  3


static int   opt;                /* used for command line arguments */
static char *input_file  = NULL; /* path to the input file          */
static char *output_file = NULL; /* path to the output file         */
static int   op_mode  = -1;      /* operation mode                  */
static int   bit_mode = -1;      /* defines the key-size 128 or 256 */
static unsigned char *password = NULL; /* the user defined password */

static unsigned char *plaintext  = NULL;
static unsigned char *ciphertext = NULL;
static int plaintext_len  = 0;
static int ciphertext_len = 0;

static unsigned char cmac[16];
static unsigned char new_cmac[16];


static void toolkit_encrypt(unsigned char *key)
{
    FILE *file = NULL;

    if (!(file = fopen(input_file, "r"))) {
        fprintf(stderr, "ERROR opening input file for encryption\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    plaintext_len = ftell(file);
    rewind(file);

    plaintext =
        (unsigned char *)malloc((plaintext_len)*sizeof(unsigned char));

    if (!plaintext) {
        fprintf(stderr, "ERROR can not allocate memory for plaintext\n");
        exit(EXIT_FAILURE);
    }
    fread(plaintext, 1, plaintext_len, file);
    fclose(file);

    /* Adjust ciphertext length */
    while (ciphertext_len < plaintext_len)
        ciphertext_len += 16;

    ciphertext =
        (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));

    if (!ciphertext) {
        fprintf(stderr, "ERROR can not allocate memory for ciphertext\n");
        exit(EXIT_FAILURE);
    }

    if (encrypt(plaintext, plaintext_len, key,
                NULL, ciphertext, bit_mode)) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    if (!(file = fopen(output_file, "w"))) {
        fprintf(stderr, "ERROR opening output file for encryption\n");
        exit(EXIT_FAILURE);
    }
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);
}


static void toolkit_decrypt(unsigned char *key)
{
    FILE *file = NULL;

    if (!(file = fopen(input_file, "r"))) {
        fprintf(stderr, "ERROR opening input file for encryption\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    ciphertext_len = ftell(file);
    rewind(file);

    ciphertext =
        (unsigned char *)malloc((ciphertext_len)*sizeof(unsigned char));

    if (!ciphertext) {
        fprintf(stderr, "ERROR can not allocate memory for ciphertext\n");
        exit(EXIT_FAILURE);
    }
    fread(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    plaintext =
        (unsigned char *)malloc((ciphertext_len)*sizeof(unsigned char));

    if (plaintext == NULL) {
        fprintf(stderr, "ERROR can not allocate memory for plaintext\n");
        exit(EXIT_FAILURE);
    }

    plaintext_len = decrypt(ciphertext, ciphertext_len,
            key, NULL, plaintext, bit_mode);

    if (!plaintext_len) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    if (!(file = fopen(output_file, "w"))) {
        fprintf(stderr, "ERROR opening output file for encryption\n");
        exit(EXIT_FAILURE);
    }
    fwrite(plaintext, 1, plaintext_len, file);
    fclose(file);
}



static void toolkit_sign(unsigned char *key)
{
    FILE *file = NULL;

    if (!(file = fopen(input_file, "r"))) {
        fprintf(stderr, "ERROR opening input file for signing\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    plaintext_len = ftell(file);
    rewind(file);

    plaintext =
        (unsigned char *)malloc((plaintext_len)*sizeof(unsigned char));

    if (!plaintext) {
        fprintf(stderr, "ERROR can not allocate memory for plaintext\n");
        exit(EXIT_FAILURE);
    }
    fread(plaintext, 1, plaintext_len, file);
    fclose(file);

    /* Adjust ciphertext length */
    while (ciphertext_len < plaintext_len)
        ciphertext_len += 16;

    ciphertext =
        (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));

    if (!ciphertext) {
        fprintf(stderr, "ERROR can not allocate memory for ciphertext\n");
        exit(EXIT_FAILURE);
    }

    if (encrypt(plaintext, plaintext_len, key,
                NULL, ciphertext, bit_mode)) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    if (gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode)) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        exit(EXIT_FAILURE);
    }

    if (!(file = fopen(output_file, "w"))) {
        fprintf(stderr, "ERROR opening output file for encryption\n");
        exit(EXIT_FAILURE);
    }
    fwrite(ciphertext, 1, ciphertext_len, file);
    fwrite(cmac, 1, 16, file);
    fclose(file);
}


static void toolkit_verify(unsigned char *key)
{
    FILE *file = NULL;

    if (!(file = fopen(input_file, "r"))) {
        fprintf(stderr, "ERROR opening input file for verification\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    ciphertext_len = ftell(file);
    rewind(file);

    ciphertext =
        (unsigned char *)malloc((ciphertext_len-16)*sizeof(unsigned char));

    if (!ciphertext) {
        fprintf(stderr, "ERROR can not allocate memory for ciphertext\n");
        exit(EXIT_FAILURE);
    }
    fread(ciphertext, 1, ciphertext_len-16, file);
    fread(cmac, 1, 16, file);
    fclose(file);

    plaintext =
        (unsigned char *)malloc((ciphertext_len-16)*sizeof(unsigned char));

    if (!plaintext) {
        fprintf(stderr, "ERROR can not allocate memory for plaintext\n");
        exit(EXIT_FAILURE);
    }

    plaintext_len = decrypt(ciphertext, ciphertext_len-16,
            key, NULL, plaintext, bit_mode);

    if (!plaintext_len) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        free(ciphertext);
        exit(EXIT_FAILURE);
    }

    /* Generate new cmac from decrypted text */
    if (gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode)) {
        ERR_print_errors_fp(stderr);
        free(key);
        free(plaintext);
        exit(EXIT_FAILURE);
    }

    /* Check if the cmac's match */
    if (verify_cmac(cmac, new_cmac)) {
        printf("CMACs match\n");

        if (!(file = fopen(output_file, "w"))) {
            fprintf(stderr, "ERROR opening output file for decryption\n");
            exit(EXIT_FAILURE);
        }
        fwrite(plaintext, 1, plaintext_len, file);
        fclose(file);
    }
    else {
        printf("CMACs don't match\n");
    }
}


void toolkit_init(int argc, char *argv[])
{
    while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
        switch (opt) {
            case 'b':
                bit_mode = atoi(optarg);
                break;
            case 'i':
                input_file = strdup(optarg);
                break;
            case 'o':
                output_file = strdup(optarg);
                break;
            case 'p':
                password = (unsigned char *)strdup(optarg);
                break;
            case 'e':
                op_mode = ENCRYPT;
                break;
            case 'd':
                op_mode = DECRYPT;
                break;
            case 's':
                op_mode = SIGN;
                break;
            case 'v':
                op_mode = VERIFY;
                break;
            case 'h':
            default:
                usage();
        }
    }

    check_args(input_file, output_file, password, bit_mode, op_mode);

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}


void toolkit_keygen(unsigned char **key)
{
    *key = (unsigned char *)malloc(bit_mode/8*sizeof(unsigned char));

    if (*key == NULL) {
        fprintf(stderr, "ERROR Cannot allocate memory for key.\n");
        exit(EXIT_FAILURE);		
    }

    if (keygen(password, *key, NULL, bit_mode)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


void toolkit_run(unsigned char *key)
{
    switch(op_mode) {
        case ENCRYPT:
            toolkit_encrypt(key);
            break;
        case DECRYPT:
            toolkit_decrypt(key);
            break;
        case SIGN:
            toolkit_sign(key);
            break;
        case VERIFY:
            toolkit_verify(key);
            break;
    }
}


void toolkit_exit(unsigned char *key)
{
    free(input_file);
    free(output_file);
    free(password);

    free(key);
    free(plaintext);
    free(ciphertext);
}
