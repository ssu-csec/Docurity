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

void ctr_encrypt(const unsigned char *input_data, List *list, size_t block_count, unsigned char *ivec, unsigned int *last_num, const void *enc_key)
{
    unsigned char ivec_enc[16] = {0, };
    memcpy(ivec_enc, ivec, AES_BLOCK_SIZE);

    if((block_count % AES_BLOCK_SIZE) == 0)
        list->count = block_count / AES_BLOCK_SIZE;
    else
        list->count = (block_count / AES_BLOCK_SIZE) + 1;

    unsigned char ecount_buf[16] = {0, };
    unsigned char* encrypt_data = calloc(block_count * AES_BLOCK_SIZE*10, sizeof(unsigned char));
    CRYPTO_ctr128_encrypt(input_data, encrypt_data, block_count, enc_key, ivec_enc, ecount_buf, last_num, (block128_f)AES_encrypt);

    unsigned char *node_data = calloc(AES_BLOCK_SIZE, sizeof(unsigned char));

    for(int i = 0; i < list->count; i++)
    {
        memcpy(node_data, encrypt_data, AES_BLOCK_SIZE);
        insertNode(createNode(node_data), list->tail);
        encrypt_data += AES_BLOCK_SIZE;
    }

    free(node_data);
}

void ctr_decrypt(List *list, unsigned char *decrypt_data, unsigned char *ivec, unsigned int *last_num, const void *enc_key)
{
    unsigned char *data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    unsigned char *data_ptr = data;
    unsigned char ecount_buf[16] = {0, };

    unsigned char ivec_dec[16] = {0, };
    memcpy(ivec_dec, ivec, AES_BLOCK_SIZE);

    Node *aes_block = calloc(1, sizeof(Node));
    aes_block = list->head;

    for(int i = 0; i < list->count; i++)
    {
        aes_block = aes_block->next;
        memcpy(data_ptr, aes_block->data, AES_BLOCK_SIZE);
        data_ptr += AES_BLOCK_SIZE;
    }
    
    CRYPTO_ctr128_encrypt(data, decrypt_data, (list->count) * AES_BLOCK_SIZE, enc_key, ivec_dec, ecount_buf, last_num, (block128_f)AES_encrypt);
    free(data);
}

void ctr_insert(unsigned char *input, List *list, unsigned char *ivec, int index, unsigned int *last_num, int size, const void *enc_key)
{
   
    if(list->count == 0)
    {
        unsigned char *data = calloc(size, sizeof(unsigned char));
        memcpy(data, input, size);
        ctr_encrypt(data, list, (size/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
    }
    else
    {
        unsigned char *decrypt_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
        ctr_decrypt(list, decrypt_data, ivec, last_num, enc_key);

        unsigned char *new_data = calloc((list->count + (size/AES_BLOCK_SIZE + 1)) * AES_BLOCK_SIZE, sizeof(unsigned char));
        
        memcpy(new_data, decrypt_data, index - 1);
        memcpy(new_data + index - 1, input, size);
        memcpy(new_data + index + size - 1, decrypt_data + index - 1, list->count * AES_BLOCK_SIZE - index);

        ResetList(list);
        ctr_encrypt(new_data, list, (strlen(new_data) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, enc_key);
    }
}

void ctr_delete(List *list, unsigned char *ivec, int index, int delete_size, unsigned int *last_num, const void *dec_key)
{
    int max_index = list->count * AES_BLOCK_SIZE;
    if(index >= max_index){
        index = max_index;
    }

    unsigned char* decrypt_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    ctr_decrypt(list, decrypt_data, ivec, last_num, dec_key);

    unsigned char* new_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, decrypt_data, index - 1);

    ResetList(list);

    ctr_encrypt(new_data, list, (strlen(new_data) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, dec_key);

}

// void ctr_delete(List *out, unsigned char *ivec, int index, int del_len, unsigned int *last_num, const void *dec_key)
// {
//     unsigned char* tmp_data = calloc(out->count * AES_BLOCK_SIZE, sizeof(unsigned char));
//     ctr_decrypt(out, tmp_data, ivec, last_num, dec_key);
//     unsigned char* new_data = calloc((out->count - (del_len/AES_BLOCK_SIZE)) * AES_BLOCK_SIZE, sizeof(unsigned char));
//     memcpy(new_data, tmp_data, index - 1);
//     memcpy(new_data + index - 1, tmp_data + index + del_len - 1, strlen(tmp_data + index + del_len - 1));

//     ResetList(out);

//     ctr_encrypt(new_data, out, (strlen(new_data) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, dec_key);
// }

void ctr_modify(unsigned char* in, List* out, unsigned char* ivec, int index, unsigned int* last_num, const void* key)
{
    unsigned char* tmp_data = calloc(out->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    ctr_decrypt(out, tmp_data, ivec, last_num, key);

    memcpy(tmp_data + index - 1, in, strlen(in));

    ResetList(out);

    ctr_encrypt(tmp_data, out, (strlen(tmp_data) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, last_num, key);
}