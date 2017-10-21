#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#include "encryptor.h"
#include "util.h"

#define BLOCK_SIZE 16


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
             unsigned int   plaintext_len,
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

    if (!CMAC_Update(ctx, plaintext, plaintext_len)) {
        CMAC_CTX_free(ctx);
        return 1;
    }
  
    if (!CMAC_Final(ctx, cmac, &temp)) {
        CMAC_CTX_free(ctx);
        return 1;
    }

    CMAC_CTX_free(ctx);
}


int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
  if (!memcmp(cmac1, cmac2, 16))
      return 1;

  return 0;
}
