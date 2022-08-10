#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "node.h"
#include "packet.h"

void ctr_encrypt(const unsigned char *in, List *out, size_t len, unsigned char *ivec, unsigned int *last_num, const void *enc_key);

void ctr_decrypt(List *in, unsigned char *out, unsigned char *ivec, unsigned int *last_num, const void *dec_key);

void ctr_insert(unsigned char *in, List *out, unsigned char *ivec, int index, unsigned int *last_num, int ins_len, const void *enc_key);

void ctr_delete(List *out, unsigned char *ivec, int index, int del_len, unsigned int *last_num, const void *enc_key);

void ctr_modify(unsigned char* in, List* out, unsigned char* ivec, int index, unsigned int* last_num, const void* key);
