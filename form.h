#include <stdlib.h>
#include <openssl/modes.h>
#include "packet.h"
#include "node.h"
#define LINK_LENGTH sizeof(link_t)
#define BITMAP_LENGTH sizeof(bitmap_t)
#define BITMAP_SEED 2048
#define LINKLESS_BLOCK_SIZE (AES_BLOCK_SIZE - (2*LINK_LENGTH))
#define DATA_SIZE_IN_BLOCK  (LINKLESS_BLOCK_SIZE - METADATA_LENGTH)
#define DATA_START          (LINK_LENGTH + METADATA_LENGTH)

void encrypt_global_metadata(unsigned char *in, unsigned char *out, size_t size, const void *enc_key);

unsigned char *decrypt_global_metadata(unsigned char *enc_global_metadata, size_t size, const void *dec_key);

void print_global_metadata(unsigned char *enc_global_metadata, size_t size, const void *dec_key);

void insert_global(unsigned char *global_metadata, unsigned char *metadata, int index);

void delete_global(unsigned char *global_metadata, int index, int size);

void update_metadata(unsigned char *global_metadata, int insert_size);

void encrypt(List *list, const unsigned char *input, size_t size, const void *enc_key, 
                           link_t front_ivec, link_t back_ivec);

void decrypt(unsigned char *dst, List *list, const void *dec_key);

void deletion(List *list, int index, int size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata);

void deletion_single_block(List *list, int block_index, int index, int size, unsigned char *global_metadata,
                            const void *enc_key, const void *dec_key);

int delete_data_single_block(bitmap_t *bitmap, unsigned char *block_data, int index, int size);

void delete_after_all(List *list, int index, unsigned char *global_metadata,
                        const void *enc_key, const void *dec_key);

void delete_blocks(List *list, int first_block_num, int last_block_num, int bound_block_num,
                            unsigned char *global_metadata, const void *enc_key, const void *dec_key);

void insertion(List *list, unsigned char *input, int index, int insert_size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata);

void encrypt_block(Node *node, link_t front_link, link_t back_link, bitmap_t bitmap, unsigned char *data,
                    const void *enc_key);

void decrypt_block(Node *node, link_t *front_link, link_t *back_link, bitmap_t *bitmap, unsigned char *data,
                    const void *dec_key);

link_t get_link(Node *node, char index, const void *dec_key);

bitmap_t get_bitmap(Node *node, const void *dec_key);

unsigned char *get_data(Node *node, const void *dec_key);

void replace_link(Node *node, link_t link, char index, const void *enc_key, const void *dec_key);

int copy_data(unsigned char *dst, unsigned char *src, bitmap_t bitmap);

int get_aes_block_count(int data_size);

int find_block_start(int index, int *block_index, unsigned char *global_metadata);

void free_node_safely(Node *prev_node, Node *next_node);

void packing_data(PACKET *packet, unsigned char *msg);

void unpacking_global(unsigned char *msg, unsigned char *global_meta);

void unpacking_data(unsigned char *msg, Node *node, List *list);