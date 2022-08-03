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
#include "cbc_test.h"

void cbc_encrypt(const unsigned char *in, List *out, size_t len, unsigned char *ivec, const void *enc_key)
{
    unsigned char *data = calloc(BUFSIZE*10, sizeof(unsigned char));
    if(len%AES_BLOCK_SIZE == 0)
        out->count = len/AES_BLOCK_SIZE;
    else
        out->count = len/AES_BLOCK_SIZE + 1;
    CRYPTO_cbc128_encrypt(in, data, len, enc_key, ivec, (block128_f)AES_encrypt);
    for(int i = 0; i < out->count; i++)
    {
        Node *node = calloc(1, sizeof(Node));
        memcpy(node->data, data, AES_BLOCK_SIZE);
        insertNode(node, out->tail);
        data+=AES_BLOCK_SIZE;
    }
}

void cbc_decrypt(List *in, unsigned char *out, unsigned char *ivec, const void *dec_key)
{
    unsigned char *data = calloc(in->count*AES_BLOCK_SIZE, sizeof(unsigned char));
    Node *node = calloc(1, sizeof(Node));
    node = in->head;
    for(int i = 0; i < in->count; i++)
    {
        node = node->next;
        memcpy(data, node->data, AES_BLOCK_SIZE);
        data += 16;
    }
    CRYPTO_cbc128_decrypt(data, out, in->count * AES_BLOCK_SIZE, dec_key, ivec, (block128_f)AES_decrypt);
}

void cbc_insert(unsigned char *in, List *out, unsigned char *ivec, int index, int ins_len, const void *enc_key, const void *dec_key, int socket)
{
    unsigned char *data = calloc(out->count, sizeof(unsigned char));
    cbc_decrypt(out, data, ivec, dec_key);
    unsigned char *new_data = calloc(out->count + (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, data, index - 1);
    memcpy(new_data + index, in, ins_len);
    memcpy(new_data + index + ins_len, data + index, out->count * AES_BLOCK_SIZE - index);
    List *list;
    InitList(list);
    cbc_encrypt(new_data, list, out->count + (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, enc_key);
    ResetList(list);
    Node *node = list->head;
    for(int i = 0; i < list->count; i++)
    {
        node = node->next;
        insertNode(node, out->tail);
    }
    free(node);
    free(list);
}

void cbc_delete(List *out, unsigned char *ivec, int index, int del_len, const void *enc_key, const void *dec_key, int socket)
{
    unsigned char *data = calloc(out->count, sizeof(unsigned char));
    cbc_decrypt(out, data, ivec, dec_key);
    unsigned char *new_data = calloc(out->count - (del_len/AES_BLOCK_SIZE) * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, data, index - 1);
    memcpy(new_data + index , data + index + del_len, out->count * AES_BLOCK_SIZE - index - del_len);
    List *list;
    InitList(list);
    cbc_encrypt(new_data, list,  - (del_len/AES_BLOCK_SIZE) * AES_BLOCK_SIZE, ivec, enc_key);
    ResetList(list);
    Node *node = list->head;
    for(int i = 0; i < list->count; i++)
    {
        node = node->next;
        insertNode(node, out->tail);
    }
    free(node);
    free(list);
}
