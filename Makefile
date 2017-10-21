CC = gcc
DBUG = -g
LIBSSL = -lssl -lcrypto

TARGETS = encryptor


all: $(TARGETS)

encryptor: encryptor.c encryptor.h
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS) *.o
