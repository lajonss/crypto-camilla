SHELL=/bin/bash
CC=gcc
CFLAGS=-g -Wall -std=c99
LFLAGS=-lcrypto

all:ccrypt

ccrypt:ccrypt.c
	$(CC) $(CFLAGS) $(LFLAGS) -o $@ $<

delete:
	rm ccrypt

clean:
	rm -f *.o
