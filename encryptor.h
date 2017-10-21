#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

int keygen(unsigned char *password,
           unsigned char *key,
           unsigned char *iv,
           unsigned int   bit_mode);

#endif /* ENCRYPTOR_H */
