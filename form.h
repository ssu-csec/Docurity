#include <stdlib.h>
#include <openssl/modes.h>
#include "packet.h"
#include "node.h"
#define LINK_LENGTH 1
#define METADATA_LENGTH 2
#define BITMAP_SEED 2048
#define LINKLESS_BLOCK_SIZE (AES_BLOCK_SIZE - (2*LINK_LENGTH))
#define DATA_SIZE_IN_BLOCK  (LINKLESS_BLOCK_SIZE - METADATA_LENGTH)
#define DATA_START          (LINK_LENGTH + METADATA_LENGTH)

void encrypt_global_metadata(const unsigned char *in, unsigned char *out, size_t size, const void *enc_key);

unsigned char *decrypt_global_metadata(const unsigned char *in, size_t size, const void *dec_key);

void insert_global(unsigned char *in, unsigned char *insert, int index);

void delete_global(unsigned char *in, int index, int length);

void encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec);

void decrypt(List *in, unsigned char *out, const void *dec_key);

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta);

void case1(List *out, int del_len, unsigned char front_link, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta);

void case2(List *out, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta);

void case3(List *out, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta);

void case4(List *out, int index, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta);

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta);

void first_insertion(unsigned char *in, List *out, int insert_length, const void *enc_key, unsigned char *global_meta);

void update_metadata(unsigned char *global_metadata, int insert_size);

int get_aes_block_count(int data_size);

void free_node_safely(Node *prev_node, Node *next_node);

void packing_data(PACKET *packet, unsigned char *msg);

void unpacking_global(unsigned char *msg, unsigned char *global_meta);

void unpacking_data(unsigned char *msg, Node *node, List *list);