CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto

test.out:	test.o	form.o
	$(CC) -o	test.out	test.o	form.o	$(LDPATH) $(LDFLAGS) 

test.o:	form.h	test.c
	$(CC) -c -o	test.o	test.c	$(CFLAGS)
 
form.o:	form.h	form.c
	$(CC) -c -o	form.o	form.c	$(CFLAGS)
 
clean:
	rm test.o form.o test.out