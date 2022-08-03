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

void cbc_encrypt(const unsigned char *in, List *out, size_t len, unsigned char *ivec, const void *enc_key);

void cbc_decrypt(List *in, unsigned char *out, unsigned char *ivec, const void *dec_key);

void cbc_insert(unsigned char *in, List *out, unsigned char *ivec, int index, int ins_len, const void *enc_key, const void *dec_key);

void cbc_delete(List *out, unsigned char *ivec, int index, int del_len, const void *enc_key, const void *dec_key);