CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto -lpthread

build: server client

server:	node.o	form.o server.o
	$(CC) -o	server	node.o	form.o	server.o	$(LDPATH) $(LDFLAGS) 

server.o:	server.c
	$(CC) -c -o	server.o	server.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

client:	node.o	form.o client.o 
	$(CC) -o	client		node.o	form.o	client.o	$(LDPATH) $(LDFLAGS) 

client.o:	client.c
	$(CC) -c -o	client.o	client.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

client_test:	node.o	cbc_test.o ctr_test.o	client.o 
	$(CC) -o	client		node.o	cbc_test.o ctr_test.o	client.o	$(LDPATH) $(LDFLAGS) 

client_test.o:	client_test.c
	$(CC) -c -o	client_test.o	client_test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

cbc_test.o: node.o	cbc_test.c
	$(CC) -c -o	cbc_test.o	cbc_tset.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

ctr_test.o: node.o	ctr_test.c
	$(CC) -c -o	ctr_test.o	ctr_tset.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

form.o:	node.o  form.c
	$(CC) -c -o	form.o	form.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

node.o:	node.h	node.c
	$(CC) -c -o	node.o	node.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)
 
clean:
	rm -f node.o test.o cbc_test.o ctr_test.o form.o test.out client.o server.o client server client_test.o server_test.o client_test server_test
