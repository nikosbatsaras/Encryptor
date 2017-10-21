CC = gcc
CFLAGS = -g -Wall
LIBSSL = -lssl -lcrypto
OBJECTS = main.o encryptor.o util.o

.PHONY: all clean

all: encryptor

encryptor: $(OBJECTS)
	$(CC) $(CFLAGS) -o encryptor $(OBJECTS) $(LIBSSL)

main.o: main.c encryptor.o util.o
	$(CC) $(CFLAGS) -c main.c
	
encryptor.o: encryptor.c encryptor.h util.o
	$(CC) $(CFLAGS) -c encryptor.c

util.o: util.c util.h
	$(CC) $(CFLAGS) -c util.c

clean:
	@rm *.o encryptor 2> /dev/null || true
