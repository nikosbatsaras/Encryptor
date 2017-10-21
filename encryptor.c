#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#include "encryptor.h"

#define BLOCK_SIZE 16


static void usage(void);
static void print_hex(unsigned char *, size_t);
static void check_args(char *, char *, unsigned char *, int, int);

int verify_cmac(unsigned char *, unsigned char *);



static void print_hex(unsigned char *data, size_t len)
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


static void usage(void)
{
    printf(
            "\n"
            "Usage:\n"
            "    encryptor -i in_file -o out_file -p passwd -b bits" 
            " [-d | -e | -s | -v]\n"
            "    encryptor -h\n"
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


static void check_args(char *input_file, char *output_file,
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


int keygen(unsigned char *password,
           unsigned char *key,
           unsigned char *iv,
           unsigned int   bit_mode)
{
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *digest = NULL;

    if (bit_mode == 128)
        cipher = EVP_aes_128_ecb();
    else
        cipher = EVP_aes_256_ecb();

    if(!cipher) return 1;

    digest = EVP_sha1();

    if(!digest) return 1;

    if (!EVP_BytesToKey(cipher, digest, NULL,
                (unsigned char *) password,
                strlen((const char *) password), 1, key, iv))
        return 1;

    return 0;
}


int encrypt(unsigned char *plaintext,
            unsigned int   plaintext_len,
            unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, 
            unsigned int   bit_mode)
{
    int len;
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) return 1;

    switch (bit_mode) {
        case 128:
            if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                return 1;
            }
            break;
        case 256:
            if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                return 1;
            }
            break;
        default:
            return 1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
}


int decrypt(unsigned char *ciphertext,
            unsigned int   ciphertext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *plaintext,
            unsigned int   bit_mode)
{
    int plaintext_len, len;
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;

    switch (bit_mode) {
        case 128:
            if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                return 0;
            }
            break;
        case 256:
            if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                return 0;
            }
            break;
        default:
            return 0;
    }

  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
      EVP_CIPHER_CTX_free(ctx);
      return 0;
  }
  plaintext_len = len;

  if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
      EVP_CIPHER_CTX_free(ctx);
      return 0;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


int gen_cmac(unsigned char *plaintext,
             size_t         plaintext_len,
             unsigned char *key, 
             unsigned char *cmac,
             unsigned int   bit_mode)
{
    size_t temp;
    CMAC_CTX *ctx = NULL;

    ctx = CMAC_CTX_new();
    if (ctx == NULL) return 1;

    switch (bit_mode) {
        case 128:
            if (!CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL)) {
                CMAC_CTX_free(ctx);
                return 1;
            }
            break;
        case 256:
            if (!CMAC_Init(ctx, key, 32, EVP_aes_256_ecb(), NULL)) {
                CMAC_CTX_free(ctx);
                return 1;
            }
            break;
        default:
            return 1;
    }

    if (!CMAC_Update(ctx, data, data_len)) {
        CMAC_CTX_free(ctx);
        return 1;
    }
  
    if (!CMAC_Final(ctx, cmac, &temp)) {
        CMAC_CTX_free(ctx);
        return 1;
    }

    CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
  int verify = 0;

  /* print_hex(cmac1, 16); */
  /* print_hex(cmac2, 16); */

  verify = memcmp(cmac1, cmac2, 16);
  if (verify == 0)
    {
      return 1;
    }
  else
    {
      return 0;
    }
}



/* TODO Develop your functions here... */



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
int
main(int argc, char **argv)
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
