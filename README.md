# Encryptor
A toolkit used to encrypt/decrypt/sign/verify text files, made with OpenSSL/EVP

# Description
The current implementation encrypts only in ECB mode. So don't use it for anything serious !

# Usage
```
encryptor -i in_file -o out_file -p passwd -b bits [-d | -e | -s | -v] [-h]

   Options:
     -i    path    Path to input file
     -o    path    Path to output file
     -p    psswd   Password for key generation
     -b    bits    Bit mode (128 or 256 only)
     -d            Decrypt input and store results to output
     -e            Encrypt input and store results to output
     -s            Encrypt+sign input and store results to output
     -v            Decrypt+verify input and store results to output
     -h            This help message
```
