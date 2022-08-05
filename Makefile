CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto -lpthread

build: cbc_bench	ctr_bench	test

test:	node.o	form.o test.o 
	$(CC) -o	test	node.o	form.o	test.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

test.o:	test.c
	$(CC) -c -o	test.o	test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

form.o:	node.o  form.c
	$(CC) -c -o	form.o	form.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

cbc_bench:	node.o cbc_test.o cbc_bench.o
	$(CC) -o	cbc_bench	node.o cbc_test.o cbc_bench.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

ctr_bench:	node.o ctr_test.o ctr_bench.o 
	$(CC) -o	ctr_bench	node.o ctr_test.o ctr_bench.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

cbc_bench.o:	cbc_bench.c node.o cbc_test.o
	$(CC) -c -o	cbc_bench.o	cbc_bench.c node.o cbc_test.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

ctr_bench.o:	ctr_bench.c node.o ctr_test.o
	$(CC) -c -o	ctr_bench.o	ctr_bench.c node.o ctr_test.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

cbc_test.o: node.o	cbc_test.h cbc_test.c
	$(CC) -c -o	cbc_test.o cbc_test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

ctr_test.o: node.o	ctr_test.h ctr_test.c
	$(CC) -c -o	ctr_test.o ctr_test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)


node.o:	node.h	node.c
	$(CC) -c -o	node.o	node.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)
 
clean:
	rm -f node.o	test.o	form.o	ctr_test.o	cbc_test.o	ctr_bench.o	cbc_bench.o	cbc_bench	ctr_bench	test