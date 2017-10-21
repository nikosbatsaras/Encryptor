#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

int keygen(unsigned char *password,
           unsigned char *key,
           unsigned char *iv,
           unsigned int   bit_mode);

int encrypt(unsigned char *plaintext,
            unsigned int   plaintext_len,
            unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, 
            unsigned int   bit_mode);

int decrypt(unsigned char *ciphertext,
            unsigned int   ciphertext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *plaintext,
            unsigned int   bit_mode);

int gen_cmac(unsigned char *plaintext,
             size_t         plaintext_len,
             unsigned char *key, 
             unsigned char *cmac,
             unsigned int   bit_mode);

#endif /* ENCRYPTOR_H */
