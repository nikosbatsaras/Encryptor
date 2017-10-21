/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */

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

int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
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
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */
	int plaintext_len = 0;
	int ciphertext_len = 0;
	unsigned char *key = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *plaintext = NULL;
	unsigned char cmac[16];
	unsigned char new_cmac[16];
	FILE *file = NULL;

	/* Initialize the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Allocate memory for key */
	key = (unsigned char *)malloc(bit_mode/8*sizeof(unsigned char));
	if (key == NULL)
	  {
	    printf("ERROR Cannot allocate memory for key.\n");
	    exit(EXIT_FAILURE);		
	  }

	/* Generate key */
        if (keygen(password, key, NULL, bit_mode)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

	/* Operate on the data according to the mode */
	/* encrypt */
	if (op_mode == 0)
	  {
	    /* Open file for encryption */
	    file = fopen(input_file, "r");
	    if (file == NULL)
	      {
		printf("ERROR opening input file for encryption\n");
		exit(EXIT_FAILURE);
	      }

	    /* Find file size */
	    fseek(file, 0, SEEK_END);
	    plaintext_len = ftell(file);
	    rewind(file);

	    /* Allocate memory for plaintext */
	    plaintext =
	      (unsigned char *)malloc((plaintext_len)*sizeof(unsigned char));
	    if (plaintext == NULL)
	      {
		printf("ERROR can not allocate memory for plaintext\n");
		exit(EXIT_FAILURE);
	      }
	    
	    /* Store the contents */
	    fread(plaintext, 1, plaintext_len, file);
	    fclose(file);

	    /* Adjust ciphertext length */
	    while (ciphertext_len < plaintext_len)
	      ciphertext_len += 16;

	    /* Allocate memory for ciphertext */
	    ciphertext =
	      (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));
	    if (ciphertext == NULL)
	      {
		printf("ERROR can not allocate memory for ciphertext\n");
		exit(EXIT_FAILURE);
	      }

	    /* Encrypt contents */
	    if (encrypt(plaintext, plaintext_len, key,
                        NULL, ciphertext, bit_mode)) {
                ERR_print_errors_fp(stderr);
                free(key);
                free(plaintext);
                free(ciphertext);
                exit(EXIT_FAILURE);
            }

	    /* Open file to write encrypted contents and close it */
	    file = fopen(output_file, "w");
	    if (file == NULL)
	      {
		printf("ERROR opening output file for encryption\n");
		exit(EXIT_FAILURE);
	      }
	    fwrite(ciphertext, 1, ciphertext_len, file);
	    fclose(file);
	  }

	/* decrypt */
	if (op_mode == 1)
	  {
	    /* Open file for decryption */
	    file = fopen(input_file, "r");
	    if (file == NULL)
	      {
		printf("ERROR opening input file for decryption\n");
		exit(EXIT_FAILURE);
	      }
	    
	    /* Find file size */
	    fseek(file, 0, SEEK_END);
	    ciphertext_len = ftell(file);
	    rewind(file);

	    /* Allocate memory for ciphertext */
	    ciphertext =
	      (unsigned char *)malloc((ciphertext_len)*sizeof(unsigned char));
	    if (ciphertext == NULL)
	      {
		printf("ERROR can not allocate memory for ciphertext\n");
		exit(EXIT_FAILURE);
	      }
	    
	    /* Store the contents */
	    fread(ciphertext, 1, ciphertext_len, file);
	    fclose(file);

	    /* Allocate memory for plaintext */
	    plaintext =
	      (unsigned char *)malloc((ciphertext_len)*sizeof(unsigned char));
	    if (plaintext == NULL)
	      {
		printf("ERROR can not allocate memory for plaintext\n");
		exit(EXIT_FAILURE);
	      }

	    /* Decrypt contents */
	    plaintext_len = decrypt(ciphertext, ciphertext_len,
				    key, NULL, plaintext, bit_mode);
            if (!plaintext_len) {
                ERR_print_errors_fp(stderr);
                free(key);
                free(plaintext);
                free(ciphertext);
                exit(EXIT_FAILURE);
            }

	    /* Open file to write decrypted contents and close it */
	    file = fopen(output_file, "w");
	    if (file == NULL)
	      {
		printf("ERROR opening output file for decryption\n");
		exit(EXIT_FAILURE);
	      }
	    fwrite(plaintext, 1, plaintext_len, file);
	    fclose(file);
	  }

	/* sign */
	if (op_mode == 2)
	  {
	    /* Open file for signing */
	    file = fopen(input_file, "r");
	    if (file == NULL)
	      {
		printf("ERROR opening input file for signing\n");
		exit(EXIT_FAILURE);
	      }

	    /* Find file size */
	    fseek(file, 0, SEEK_END);
	    plaintext_len = ftell(file);
	    rewind(file);

	    /* Allocate memory for plaintext */
	    plaintext =
	      (unsigned char *)malloc((plaintext_len)*sizeof(unsigned char));
	    if (plaintext == NULL)
	      {
		printf("ERROR can not allocate memory for plaintext\n");
		exit(EXIT_FAILURE);
	      }

	    /* Store the contents */
	    fread(plaintext, 1, plaintext_len, file);
	    fclose(file);

	    /* Adjust ciphertext length */
	    while (ciphertext_len < plaintext_len)
	      ciphertext_len += 16;

	    /* Allocate memory for ciphertext */
	    ciphertext =
	      (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));
	    if (ciphertext == NULL)
	      {
		printf("ERROR can not allocate memory for ciphertext\n");
		exit(EXIT_FAILURE);
	      }
	
	    /* Encrypt contents */
	    if (encrypt(plaintext, plaintext_len, key,
                        NULL, ciphertext, bit_mode)) {
                ERR_print_errors_fp(stderr);
                free(key);
                free(plaintext);
                free(ciphertext);
                exit(EXIT_FAILURE);
            }

	    /* Generate sign */
            if (gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode)) {
                ERR_print_errors_fp(stderr);
                free(key);
                free(plaintext);
                exit(EXIT_FAILURE);
            }
	    
	    /* Open file to write encrypted contents and close it */
	    file = fopen(output_file, "w");
	    if (file == NULL)
	      {
		printf("ERROR opening output file for encryption\n");
		exit(EXIT_FAILURE);
	      }
	    fwrite(ciphertext, 1, ciphertext_len, file);
	    fwrite(cmac, 1, 16, file);
	    fclose(file);
	  }
	
	/* verify */
	if (op_mode == 3)
	  {
	    /* Open file for decryption */
	    file = fopen(input_file, "r");
	    if (file == NULL)
	      {
		printf("ERROR opening input file for verification\n");
		exit(EXIT_FAILURE);
	      }
	    
	    /* Find file size */
	    fseek(file, 0, SEEK_END);
	    ciphertext_len = ftell(file);
	    rewind(file);

	    /* Allocate memory for ciphertext */
	    ciphertext =
	      (unsigned char *)malloc((ciphertext_len-16)*sizeof(unsigned char));
	    if (ciphertext == NULL)
	      {
		printf("ERROR can not allocate memory for ciphertext\n");
		exit(EXIT_FAILURE);
	      }
	    
	    /* Store the contents */
	    fread(ciphertext, 1, ciphertext_len-16, file);
	    fread(cmac, 1, 16, file);
	    fclose(file);

	    /* Allocate memory for plaintext */
	    plaintext =
	      (unsigned char *)malloc((ciphertext_len-16)*sizeof(unsigned char));
	    if (plaintext == NULL)
	      {
		printf("ERROR can not allocate memory for plaintext\n");
		exit(EXIT_FAILURE);
	      }

	    /* Decrypt contents */
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
	    if (verify_cmac(cmac, new_cmac))
	      {
		printf("CMACs match\n");
		
		/* Open file to write decrypted contents and close it */
		file = fopen(output_file, "w");
		if (file == NULL)
		  {
		    printf("ERROR opening output file for decryption\n");
		    exit(EXIT_FAILURE);
		  }
		fwrite(plaintext, 1, plaintext_len, file);
		fclose(file);
	      }
	    else
	      {
		printf("CMACs don't match\n");
	      }
	  }
	
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	free(key);
	free(plaintext);
	free(ciphertext);


	/* END */
	return 0;
}
