CC = gcc
CFLAGS = -g -Wall
LIBSSL = -lssl -lcrypto
OBJECTS = main.o util.o encryptor.o

.PHONY: all clean

all: encryptor

encryptor: $(OBJECTS)
	$(CC) $(CFLAGs) -o encryptor $(OBJECTS) $(LIBSSL)

main.o: main.c util.o encryptor.o
	$(CC) $(CFLAGs) -c main.c $(LIBSSL)
	
util.o: util.c util.h
	$(CC) $(CFLAGs) -c util.c

encryptor.o: util.o encryptor.c encryptor.h
	$(CC) $(CFLAGs) -c encryptor.c $(LIBSSL)

clean:
	rm *.o encryptor
