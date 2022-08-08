#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "packet.h"
#include "cbc_test.h"

void cbc_encrypt(const unsigned char *input_data, List *list, size_t block_count, unsigned char *ivec, const void *enc_key)
{
    unsigned char ivec_enc[16] = {0, };
    memcpy(ivec_enc, ivec, AES_BLOCK_SIZE);

    if((block_count % AES_BLOCK_SIZE) == 0)
        list->count = block_count / AES_BLOCK_SIZE;
    else
        list->count = (block_count / AES_BLOCK_SIZE) + 1;

    unsigned char* encrypt_data = calloc(block_count * AES_BLOCK_SIZE, sizeof(unsigned char));
    CRYPTO_cbc128_encrypt(input_data, encrypt_data, block_count, enc_key, ivec_enc, (block128_f)AES_encrypt);

    unsigned char *node_data = calloc(AES_BLOCK_SIZE, sizeof(unsigned char));

    for(int i = 0; i < list->count; i++)
    {
        memcpy(node_data, encrypt_data, AES_BLOCK_SIZE);
        insertNode(createNode(node_data), list->tail);
        encrypt_data += AES_BLOCK_SIZE;
    }

    free(node_data);
}

void cbc_decrypt(List *list, unsigned char *decrypt_data, unsigned char *ivec, const void *dec_key)
{
    unsigned char *data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    unsigned char *data_ptr = data;

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
    
    CRYPTO_cbc128_decrypt(data, decrypt_data, (list->count) * AES_BLOCK_SIZE, dec_key, ivec_dec, (block128_f)AES_decrypt);
    free(data);
}

void cbc_insert(unsigned char *input, List *list, unsigned char *ivec, int index, int size, const void *enc_key, const void *dec_key)
{
   
    if(list->count == 0)
    {
        unsigned char *data = calloc(size, sizeof(unsigned char));
        memcpy(data, input, size);
        cbc_encrypt(data, list, (size/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, ivec, enc_key);
    }
    else
    {
        unsigned char *decrypt_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
        cbc_decrypt(list, decrypt_data, ivec, dec_key);

        unsigned char *new_data = calloc((list->count + (size/AES_BLOCK_SIZE + 1)) * AES_BLOCK_SIZE, sizeof(unsigned char));
        
        memcpy(new_data, decrypt_data, index - 1);
        memcpy(new_data + index - 1, input, size);
        memcpy(new_data + index + size - 1, decrypt_data + index - 1, list->count * AES_BLOCK_SIZE - index);

        ResetList(list);
        cbc_encrypt(new_data, list, strlen(new_data), ivec, enc_key);
    }
}







void cbc_delete(List *list, unsigned char *ivec, int index, int del_len, const void *enc_key, const void *dec_key)
{
    unsigned char* tmp_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    cbc_decrypt(list, tmp_data, ivec, dec_key);

    unsigned char* new_data = calloc((list->count - (del_len/AES_BLOCK_SIZE)) * AES_BLOCK_SIZE, sizeof(unsigned char));
    memcpy(new_data, tmp_data, index - 1);
    memcpy(new_data + index - 1, tmp_data + index + del_len - 1, strlen(tmp_data + index + del_len - 1));

    ResetList(list);

    cbc_encrypt(new_data, list, strlen(new_data), ivec, enc_key);
}

void cbc_modify(unsigned char* in, List* list, unsigned char* ivec, int index, const void* enc_key, const void* dec_key)
{
    unsigned char* tmp_data = calloc(list->count * AES_BLOCK_SIZE, sizeof(unsigned char));
    cbc_decrypt(list, tmp_data, ivec, dec_key);

    memcpy(tmp_data + index - 1, in, strlen(in));

    ResetList(list);

    cbc_encrypt(tmp_data, list, strlen(tmp_data), ivec, enc_key);
}
