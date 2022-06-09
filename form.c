#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "form.h"

void global_encrypt(const const unsigned char *in, unsigned char *out, size_t len,
                    const void *enc_key)
{
    srand(time(NULL));
    int n = 0;
    unsigned char link_front = rand() % 256;
    unsigned char link_back = rand() % 256;
    unsigned char ivec = link_front;

    if(len == 0)
        return 0;
    
    while (len > AES_BLOCK_SIZE - (2*LINK_LENGTH)) 
    {
        out[0] = link_front;
        for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
            out[n] = in[n - LINK_LENGTH];
        out[15] = link_back;
        AES_encrypt(out, out, enc_key);
        len -= (AES_BLOCK_SIZE - (2*LINK_LENGTH));
        in += (AES_BLOCK_SIZE - (2*LINK_LENGTH));
        out += AES_BLOCK_SIZE;
        link_front = link_back;
        link_back = rand() % 256;       
    }

    out[0] = link_front;
    for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH) && n < len + (LINK_LENGTH); ++n)
        out[n] = in[n - (LINK_LENGTH)];
    for (; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
        out[n] = 0;
    out[15] = ivec;

    AES_encrypt(out, out, enc_key);

    return;
}

void global_decrypt(const unsigned char *in, unsigned char *out, size_t len, 
                            const void *dec_key)
{
    int n = 0;
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    int first_check = len;

    if (len == 0 || len % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return;
    }
    while (len) {
        AES_decrypt(in, tmp, dec_key);
        //print_array(tmp, 16);
        link_front = tmp[0];
        if(first_check != len && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %ld\n", link_front, link_back, len);
            return;
        }
        link_back = tmp[15];

        for (n = LINK_LENGTH; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n)
                out[n - LINK_LENGTH] = tmp[n];
        len -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        out += (AES_BLOCK_SIZE - (2*LINK_LENGTH));
    }
}

int encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec)
{
    srand(time(NULL));
    int n = 0;
    unsigned char link_front = front_ivec;
    unsigned char link_back = rand() % 256;
    unsigned short *meta;
    int block_num = 0;

    if(len == 0)
        return 0;
    
    while (len > AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH)) 
    {
        meta = &out[1];
        *meta = 0;
        out[0] = link_front;
        for (n = LINK_LENGTH + METADATA_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
        {
            out[n] = in[n - (LINK_LENGTH + METADATA_LENGTH)];
            *meta = *meta >> 1;
            *meta = *meta | (unsigned short)BITMAP_SEED;

        }
        out[15] = link_back;
        //print_array(out, 16);
        AES_encrypt(out, out, enc_key);
        block_num++;
        len -= (AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH));
        in += (AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH));
        out += AES_BLOCK_SIZE;
        link_front = link_back;
        link_back = rand() % 256;
        
    }

    meta = &out[1];
    *meta = 0;
    out[0] = link_front;
    for (n = LINK_LENGTH + METADATA_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH) && n < len + (LINK_LENGTH + METADATA_LENGTH); ++n)
    {
        out[n] = in[n - (LINK_LENGTH + METADATA_LENGTH)];
        *meta = *meta >> 1;
        *meta = *meta | (unsigned short)BITMAP_SEED;
    }

    for (; n < (AES_BLOCK_SIZE - LINK_LENGTH + METADATA_LENGTH); ++n)
        out[n] = 0;
    out[15] = back_ivec;
    //print_array(out, 16);
    AES_encrypt(out, out, enc_key);
    block_num++;

    return block_num*16;
}

void decrypt(const unsigned char *in, unsigned char *out, size_t len, 
                            const void *dec_key)
{
    int n = 0;
    int cnt = 0;
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned short meta;

    if (len == 0 || len % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return;
    }
    while (len) {
        AES_decrypt(in, tmp, dec_key);
        //print_array(tmp, 16);
        link_front = tmp[0];
        if(cnt != 0 && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %ld\n", link_front, link_back, len);
            return;
        }
        link_back = tmp[15];
        memcpy(&meta, &tmp[1], 2);
        cnt = 0;
        for (n = LINK_LENGTH + METADATA_LENGTH; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n)
        {
            if((meta & BITMAP_SEED) != 0)
            {
                out[cnt] = tmp[n];
                cnt++;
                meta = meta << 1;
            }
        }
        //printf("%d is cnt\n", cnt);
        len -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        out += cnt;
    }
}

void deletion(unsigned char *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int gmeta_len)
{

}

void insertion(const unsigned char *in, unsigned char *out, int index, int ins_len, const void *enc_key, const void *dec_key, unsigned char *global_meta)
{}


void print_array(char *array, size_t size){
    for(int i = 0; i < size; i++)
    {
        printf("%hhx", array[i]);
    }
    printf("\n");
}