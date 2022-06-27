CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto

test.out:	test.o	form.o
	$(CC) -o	test.out	test.o	form.o	$(LDPATH) $(LDFLAGS) 

test.o:	form.h	test.c
	$(CC) -c -o	test.o	test.c	$(CFLAGS)
 

server:	server.o	form.o
	$(CC) -o	server	server.o	form.o	$(LDPATH) $(LDFLAGS) 

server.o:	server.c
	$(CC) -c -o	server.o	server.c	$(LDPATH) $(LDFLAGS) 

client:	client.o form.o
	$(CC) -o	client		client.o	form.o	$(LDPATH) $(LDFLAGS) 

client.o:	client.c
	$(CC) -c -o	client.o	client.c	$(LDPATH) $(LDFLAGS) 

form.o:	form.h	form.c
	$(CC) -c -o	form.o		form.c	$(CFLAGS)
 
clean:
	rm -f test.o form.o test.out client.o server.o client server
