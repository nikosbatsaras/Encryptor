#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

int keygen(unsigned char *password,
           unsigned char *key,
           unsigned char *iv,
           unsigned int   bit_mode);

int encrypt(unsigned char *plaintext,
            int            plaintext_len,
            unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, 
            int            bit_mode);


#endif /* ENCRYPTOR_H */
