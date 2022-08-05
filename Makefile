CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto -lpthread

build: test

test:	node.o	form.o test.o 
	$(CC) -o	test	node.o	form.o	test.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

test.o:	test.c
	$(CC) -c -o	test.o	test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

form.o:	node.o  form.c
	$(CC) -c -o	form.o	form.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

node.o:	node.h	node.c
	$(CC) -c -o	node.o	node.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)
 
clean:
	rm -f node.o	test.o	form.o	test