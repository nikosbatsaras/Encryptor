#include <stdio.h>
#include <stdlib.h>
#include "util.h"


void print_hex(unsigned char *data, size_t len)
{
    size_t i;

    if (!data) {
        printf("NULL data\n");
    }
    else {
        for (i = 0; i < len; i++) {
            if (!(i % 16) && (i != 0))
                printf("\n");
            printf("%02X ", data[i]);
        }
        printf("\n");
    }
}


void usage(void)
{
    printf(
            "\n"
            "Usage:\n"
            "    encryptor -i in_file -o out_file -p passwd -b bits" 
            " [-d | -e | -s | -v] [-h]\n"
          );
    printf(
            "\n"
            "Options:\n"
            " -i    path    Path to input file\n"
            " -o    path    Path to output file\n"
            " -p    psswd   Password for key generation\n"
            " -b    bits    Bit mode (128 or 256 only)\n"
            " -d            Decrypt input and store results to output\n"
            " -e            Encrypt input and store results to output\n"
            " -s            Encrypt+sign input and store results to output\n"
            " -v            Decrypt+verify input and store results to output\n"
            " -h            This help message\n"
            "\n"
          );
    exit(EXIT_FAILURE);
}


void check_args(char *input_file, char *output_file,
        unsigned char *password, int bit_mode, int op_mode)
{
    if (!input_file) {
        printf("Error: No input file!\n");
        usage();
    }

    if (!output_file) {
        printf("Error: No output file!\n");
        usage();
    }

    if (!password) {
        printf("Error: No user key!\n");
        usage();
    }

    if ((bit_mode != 128) && (bit_mode != 256)) {
        printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
        usage();
    }

    if (op_mode == -1) {
        printf("Error: No mode\n");
        usage();
    }
}
