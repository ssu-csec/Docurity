#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "packet.h"
#include "ctr_test.h"

void ctr_encrypt(const unsigned char *in, List *out, size_t len, unsigned char *ivec, unsigned int *last_num, const void *enc_key)
{
    unsigned char* tmp_data = calloc(BUFSIZE * 10, sizeof(unsigned char));

    unsigned char* ivec_enc[16] = {0, };
    memcpy(ivec_enc, ivec, AES_BLOCK_SIZE);

    if((len % AES_BLOCK_SIZE) == 0)
        out->count = len / AES_BLOCK_SIZE;
    else
        out->count = (len / AES_BLOCK_SIZE) + 1;

    unsigned char ecount_buf[16] = {0, };
    CRYPTO_ctr128_encrypt(in, tmp_data, len, enc_key, ivec_enc, ecount_buf, last_num, (block128_f)AES_encrypt);

    Node* tmp_node = NULL;
    for(int i = 0; i < out->count; i++)
    {
        tmp_node = calloc(1, sizeof(Node));
        memcpy(tmp_node->data, tmp_data, AES_BLOCK_SIZE);
        insertNode(tmp_node, out->tail);
        tmp_data += AES_BLOCK_SIZE;
    }
}

void ctr_decrypt(List *in, unsigned char *out, unsigned char *ivec, unsigned int *last_num, const void *dec_key)
{
    unsigned char* data = calloc(in->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    unsigned char* tmp_data = data;
    unsigned char ecount_buf[16] = {0, };

    unsigned char* ivec_dec[16] = {0, };
    memcpy(ivec_dec, ivec, AES_BLOCK_SIZE);

    Node* tmp_node = calloc(1, sizeof(Node));
    tmp_node = in->head;

    for(int i = 0; i < in->count; i++)
    {
        tmp_node = tmp_node->next;
        memcpy(tmp_data, tmp_node->data, AES_BLOCK_SIZE);
        tmp_data += AES_BLOCK_SIZE;
    }

    CRYPTO_ctr128_encrypt(data, out, (in->count) * AES_BLOCK_SIZE, dec_key, ivec_dec, ecount_buf, last_num, (block128_f)AES_encrypt);

}

void ctr_insert(unsigned char *in, List *out, unsigned char *ivec, int index, unsigned int *last_num, int ins_len, const void *enc_key)
{
    if(out->count == 0)
    {
        unsigned char* data = calloc(ins_len, sizeof(unsigned char));
        memcpy(data, in, ins_len);
        ctr_encrypt(data, out, (ins_len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
    }
    else
    {
        unsigned char* tmp_data = calloc(out->count, sizeof(unsigned char));
        ctr_decrypt(out, tmp_data, ivec, last_num, enc_key);

        unsigned char* new_data = calloc((out->count + (ins_len/AES_BLOCK_SIZE + 1)) * AES_BLOCK_SIZE, sizeof(unsigned char));

        memcpy(new_data, tmp_data, index - 1);
        memcpy(new_data + index - 1, in, ins_len);
        memcpy(new_data + index + ins_len - 1, tmp_data + index - 1, out-> count * AES_BLOCK_SIZE - index);

        ResetList(out);
        ctr_encrypt(new_data, out, (strlen(new_data)/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
    }
}

void ctr_delete(List *out, unsigned char *ivec, int index, int del_len, unsigned int *last_num, const void *dec_key)
{
    unsigned char* tmp_data = calloc(out->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    ctr_decrypt(out, tmp_data, ivec, last_num, dec_key);
    unsigned char* new_data = calloc((out->count - (del_len/AES_BLOCK_SIZE)) * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, tmp_data, index - 1);
    memcpy(new_data + index - 1, tmp_data + index + del_len - 1, strlen(tmp_data + index + del_len - 1));

    ResetList(out);

    ctr_encrypt(new_data, out, (strlen(new_data) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, dec_key);
}
