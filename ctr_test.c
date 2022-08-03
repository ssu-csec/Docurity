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
#include "ctr_test.h"

void ctr_encrypt(const unsigned char *in, List *out, size_t len, unsigned char *ivec, unsigned int *last_num, const void *enc_key)
{
    unsigned char *data = calloc(BUFSIZE*10, sizeof(unsigned char));
    if(len%AES_BLOCK_SIZE == 0)
        out->count = len/AES_BLOCK_SIZE;
    else
        out->count = len/AES_BLOCK_SIZE + 1;
    unsigned char ecount_buf[16] = {0, };
    CRYPTO_ctr128_encrypt(in, data, len, enc_key, ivec, ecount_buf, &last_num, (block128_f)AES_encrypt);
    for(int i = 0; i < out->count; i++)
    {
        Node *node = calloc(1, sizeof(Node));
        memcpy(node->data, data, AES_BLOCK_SIZE);
        insertNode(node, out->tail);
        data+=AES_BLOCK_SIZE;
    }
}

void ctr_decrypt(List *in, unsigned char *out, unsigned char *ivec, unsigned int *last_num, const void *dec_key)
{
    unsigned char *data = calloc(in->count*AES_BLOCK_SIZE, sizeof(unsigned char));
    unsigned char ecount_buf[16] = {0, };
    Node *node = calloc(1, sizeof(Node));
    node = in->head;
    for(int i = 0; i < in->count; i++)
    {
        node = node->next;
        memcpy(data, node->data, AES_BLOCK_SIZE);
        data += 16;
    }
    CRYPTO_ctr128_encrypt(in, data, in->count * AES_BLOCK_SIZE, dec_key, ivec, ecount_buf, &last_num, (block128_f)AES_encrypt);
}

void ctr_insert(unsigned char *in, List *out, unsigned char *ivec, int index, unsigned int *last_num, int ins_len, const void *enc_key)
{
    List *list;
    list = calloc(1, sizeof(List));
    InitList(list);
    if(out->count == 0)
    {
        unsigned char *data = calloc(ins_len, sizeof(unsigned char));
        memcpy(data, in, ins_len);
        ctr_encrypt(data, list, (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
    }
    else
    {
        unsigned char *data = calloc(out->count, sizeof(unsigned char));
        ctr_decrypt(out, data, ivec, last_num, enc_key);
        unsigned char *new_data = calloc(out->count + (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, sizeof(unsigned char));
        memcpy(new_data, data, index - 1);
        memcpy(new_data + index, in, ins_len);
        memcpy(new_data + index + ins_len, data + index, out->count * AES_BLOCK_SIZE - index);
        
        ctr_encrypt(new_data, list, out->count + (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
        ResetList(out);
        
    }
    Node *node = list->head;
    for(int i = 0; i < list->count; i++)
    {
        node = node->next;
        insertNode(node, out->tail);
    }
    free(node);
    free(list);
}

void ctr_delete(List *out, unsigned char *ivec, int index, int del_len, unsigned int *last_num, const void *dec_key)
{
    unsigned char *data = calloc(out->count, sizeof(unsigned char));
    ctr_decrypt(out, data, ivec, last_num, dec_key);
    unsigned char *new_data = calloc(out->count - (del_len/AES_BLOCK_SIZE) * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, data, index - 1);
    memcpy(new_data + index , data + index + del_len, out->count * AES_BLOCK_SIZE - index - del_len);
    List *list;
    InitList(list);
    ctr_encrypt(new_data, list,  - (del_len/AES_BLOCK_SIZE) * AES_BLOCK_SIZE, ivec, last_num, dec_key);
    ResetList(out);
    Node *node = list->head;
    for(int i = 0; i < list->count; i++)
    {
        node = node->next;
        insertNode(node, out->tail);
    }
    free(node);
    free(list);
}
