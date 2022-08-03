#include <stdlib.h>
#include <openssl/modes.h>
#include "packet.h"
#include "node.h"
#define LINK_LENGTH 1
#define METADATA_LENGTH 2
#define BITMAP_SEED 2048

void global_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                    const void *enc_key);

void global_decrypt(const unsigned char *in, unsigned char *out, size_t len, 
                            const void *dec_key);

void insert_global(unsigned char *in, unsigned char *insert, int index);

void delete_global(unsigned char *in, int index, int length);

void encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec);

void decrypt(List *in, unsigned char *out, const void *dec_key);

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket);

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket);

void packing_data(PACKET *packet, unsigned char *msg);

void unpacking_global(unsigned char *msg, unsigned char *global_meta);

void unpacking_data(unsigned char *msg, Node *node, List *list);