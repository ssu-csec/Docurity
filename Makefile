CC = gcc
CFLAGS = -g
LDPATH = -L/usr/local/lib
LDFLAGS = -lssl -lcrypto -lpthread

build: cbc_bench	ctr_bench	dl-ecb_bench

# bench: dl_ecb_bench	cbc_bench	ctr_bench string_printer
# 	echo $@



# dl_ecb_bench: dl_ecb_bench_enc dl_ecb_bench_dec dl_ecb_bench_ins dl_ecb_bench_del
# 	echo $@

# dl_ecb_bench_enc:	node.o	form.o dl_ecb_bench_enc.o 
# 	$(CC) -o	dl_ecb_bench_enc	node.o	form.o	dl_ecb_bench_enc.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_enc.o:	dl_ecb_bench_enc.c
# 	$(CC) -c -o	dl_ecb_bench_enc.o	dl_ecb_bench_enc.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_dec:	node.o	form.o dl_ecb_bench_dec.o 
# 	$(CC) -o	dl_ecb_bench_dec	node.o	form.o	dl_ecb_bench_dec.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_dec.o:	dl_ecb_bench_dec.c
# 	$(CC) -c -o	dl_ecb_bench_dec.o	dl_ecb_bench_dec.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_ins:	node.o	form.o dl_ecb_bench_ins.o 
# 	$(CC) -o	dl_ecb_bench_ins	node.o	form.o	dl_ecb_bench_ins.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_ins.o:	dl_ecb_bench_ins.c
# 	$(CC) -c -o	dl_ecb_bench_ins.o	dl_ecb_bench_ins.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_del:	node.o	form.o dl_ecb_bench_del.o 
# 	$(CC) -o	dl_ecb_bench_del	node.o	form.o	dl_ecb_bench_del.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# dl_ecb_bench_del.o:	dl_ecb_bench_del.c
# 	$(CC) -c -o	dl_ecb_bench_del.o	dl_ecb_bench_del.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)



# cbc_bench: cbc_bench_enc cbc_bench_dec	cbc_bench_ins cbc_bench_del
# 	echo $@

# cbc_bench_enc:	node.o	cbc_test.o cbc_bench_enc.o 
# 	$(CC) -o	cbc_bench_enc	node.o	cbc_test.o	cbc_bench_enc.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_enc.o:	cbc_bench_enc.c
# 	$(CC) -c -o	cbc_bench_enc.o	cbc_bench_enc.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_dec:	node.o	cbc_test.o cbc_bench_dec.o 
# 	$(CC) -o	cbc_bench_dec	node.o	cbc_test.o	cbc_bench_dec.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_dec.o:	cbc_bench_dec.c
# 	$(CC) -c -o	cbc_bench_dec.o	cbc_bench_dec.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_ins:	node.o	cbc_test.o cbc_bench_ins.o 
# 	$(CC) -o	cbc_bench_ins	node.o	cbc_test.o	cbc_bench_ins.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_ins.o:	cbc_bench_ins.c
# 	$(CC) -c -o	cbc_bench_ins.o	cbc_bench_ins.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_del:	node.o	cbc_test.o cbc_bench_del.o 
# 	$(CC) -o	cbc_bench_del	node.o	cbc_test.o	cbc_bench_del.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# cbc_bench_del.o:	cbc_bench_del.c
# 	$(CC) -c -o	cbc_bench_del.o	cbc_bench_del.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)


# ctr_bench: ctr_bench_enc ctr_bench_dec	ctr_bench_ins ctr_bench_del
# 	echo $@

# ctr_bench_enc:	node.o	ctr_test.o ctr_bench_enc.o 
# 	$(CC) -o	ctr_bench_enc	node.o	ctr_test.o	ctr_bench_enc.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_enc.o:	ctr_bench_enc.c
# 	$(CC) -c -o	ctr_bench_enc.o	ctr_bench_enc.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_dec:	node.o	ctr_test.o ctr_bench_dec.o 
# 	$(CC) -o	ctr_bench_dec	node.o	ctr_test.o	ctr_bench_dec.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_dec.o:	ctr_bench_dec.c
# 	$(CC) -c -o	ctr_bench_dec.o	ctr_bench_dec.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_ins:	node.o	ctr_test.o ctr_bench_ins.o 
# 	$(CC) -o	ctr_bench_ins	node.o	ctr_test.o	ctr_bench_ins.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_ins.o:	ctr_bench_ins.c
# 	$(CC) -c -o	ctr_bench_ins.o	ctr_bench_ins.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_del:	node.o	ctr_test.o ctr_bench_del.o 
# 	$(CC) -o	ctr_bench_del	node.o	ctr_test.o	ctr_bench_del.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# ctr_bench_del.o:	ctr_bench_del.c
# 	$(CC) -c -o	ctr_bench_del.o	ctr_bench_del.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)


string_printer: ./scripts/string_printer.c
	$(CC) -o ./scripts/string_printer ./scripts/string_printer.c


# test:	node.o	form.o test.o 
# 	$(CC) -o	test	node.o	form.o	test.o	$(LDPATH) $(LDFLAGS) $(CFLAGS)

# test.o:	test.c
# 	$(CC) -c -o	test.o	test.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

dl-ecb_bench:	node.o form.o dl-ecb_bench.o
	$(CC) -o	dl-ecb_bench	node.o form.o dl-ecb_bench.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

dl-ecb_bench.o:	dl-ecb_bench.c node.o form.o
	$(CC) -c -o	dl-ecb_bench.o	dl-ecb_bench.c node.o form.o $(LDPATH) $(LDFLAGS) $(CFLAGS)

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

form.o:	node.o  form.c
	$(CC) -c -o	form.o	form.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

node.o:	node.h	node.c
	$(CC) -c -o	node.o	node.c	$(LDPATH) $(LDFLAGS) $(CFLAGS)

clean:
	rm -f node.o	test.o	form.o	ctr_test.o	cbc_test.o	ctr_bench.o	cbc_bench.o	cbc_bench	ctr_bench	test	