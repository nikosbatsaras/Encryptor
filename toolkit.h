#ifndef TOOLKIT_H
#define TOOLKIT_H

void toolkit_init   (int argc, char *argv[]);
void toolkit_keygen (unsigned char **key);
void toolkit_run    (unsigned char *key);
void toolkit_exit   (unsigned char *key);

#endif /* TOOLKIT_H */
