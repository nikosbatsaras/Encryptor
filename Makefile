CC = gcc
CFLAGS = -g -Wall
LIBSSL = -lssl -lcrypto
OBJECTS = main.o toolkit.o encryptor.o util.o

.PHONY: all clean

all: encryptor

encryptor: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBSSL)

main.o: main.c toolkit.o
	$(CC) $(CFLAGS) -o $@ -c main.c

toolkit.o: toolkit.c toolkit.h encryptor.o util.o
	$(CC) $(CFLAGS) -o $@ -c toolkit.c
	
encryptor.o: encryptor.c encryptor.h util.o
	$(CC) $(CFLAGS) -o $@ -c encryptor.c

util.o: util.c util.h
	$(CC) $(CFLAGS) -o $@ -c util.c

clean:
	@rm *.o encryptor 2> /dev/null || true
