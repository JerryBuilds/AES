CC = gcc
CFLAGS = -g
# LDFLAGS

all: aes

aes: aes.c
	$(CC) $(CFLAGS) aes.c -o aes

clean:
	rm -f aes
