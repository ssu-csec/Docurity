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
        return;
    
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

int encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec)
{
    srand(time(NULL));
    int n = 0;
    unsigned char tmp[16] = {0. };
    unsigned char link_front = front_ivec;
    unsigned char link_back = rand() % 256;
    unsigned short *meta;
    meta = &tmp[1];

    if(len == 0)
        return 0;
    
    while (len > AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH)) 
    {
        *meta = 0;
        tmp[0] = link_front;
        for (n = LINK_LENGTH + METADATA_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
        {
            tmp[n] = in[n - (LINK_LENGTH + METADATA_LENGTH)];
            *meta = *meta >> 1;
            *meta = *meta | (unsigned short)BITMAP_SEED;

        }
        tmp[15] = link_back;

        AES_encrypt(tmp, tmp, enc_key);
        out->count++;
        len -= (AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH));
        in += (AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH));

        Node *new_node = createNode(tmp);
        insertNode(new_node, out);

        link_front = link_back;
        link_back = rand() % 256;
        
    }

    *meta = 0;
    tmp[0] = link_front;
    for (n = LINK_LENGTH + METADATA_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH) && n < len + (LINK_LENGTH + METADATA_LENGTH); ++n)
    {
        tmp[n] = in[n - (LINK_LENGTH + METADATA_LENGTH)];
        *meta = *meta >> 1;
        *meta = *meta | (unsigned short)BITMAP_SEED;
    }

    for (; n < (AES_BLOCK_SIZE - LINK_LENGTH + METADATA_LENGTH); ++n)
        tmp[n] = 0;
    tmp[15] = back_ivec;

    AES_encrypt(tmp, tmp, enc_key);
    out->count++;

    Node *new_node = createNode(tmp);
    insertNode(new_node, out);

    return (out->count)*16;
}

void decrypt(List *in, unsigned char *out, size_t len, 
                            const void *dec_key)
{
    int n = 0;
    int cnt = 0;
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned short meta;
    Node *new_node;

    if (len == 0 || len % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return;
    }
    while (len) {
        new_node = in->head->next;
        memcpy(tmp, new_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);

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
        out += cnt;

        new_node = new_node->next;
    }
}

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int gmeta_len)                                          // gmeta_len is the number of blocks
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    int enc_gmeta_len;
    if(gmeta_len%(AES_BLOCK_SIZE - 2*LINK_LENGTH) == 0)
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH))*AES_BLOCK_SIZE;
    else
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH)+1)*AES_BLOCK_SIZE;
    
    unsigned char *plain_gmeta;
    plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);

    int check = 0;
    int block_num = 0;

    while(check < index)
    {
        check += (int)plain_gmeta[block_num];
        block_num++;
    }
    block_num--;
    check -= (int)plain_gmeta[block_num];
    if(check == index)
    {
        out += (block_num - 1)*16;
        AES_decrypt(out, out, dec_key);
    }

}

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int gmeta_len)                                                                      // gmeta_len is the number of blocks
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    int push = 0;
    int gmeta_push = 0;

    int enc_gmeta_len;
    if(gmeta_len%(AES_BLOCK_SIZE - 2*LINK_LENGTH) == 0)
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH))*AES_BLOCK_SIZE;
    else
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH)+1)*AES_BLOCK_SIZE;
        
    unsigned char *plain_gmeta;
    plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);

    int enc_ins_len;

    int check = 0;
    int block_num = 0;

    while(check <= index)
    {
        check += (int)plain_gmeta[block_num];
        block_num++;
    }
    block_num--;
    check -= (int)plain_gmeta[block_num];

    if(check != index)
    {
        unsigned char tmp[16] = {0, };
        out += block_num * AES_BLOCK_SIZE;
        decrypt(out, tmp, AES_BLOCK_SIZE, dec_key);

        for(int i = ins_len; i > 0; i--)
            in[i + (index - check)] = in[i];
        
        ins_len += (int)plain_gmeta[block_num];




    }

    // if(check == index)
    // {

    //     if(ins_len%(AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH)) == 0)
    //     {
    //         enc_ins_len = (ins_len/(AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH)))*AES_BLOCK_SIZE;
    //         gmeta_push = ins_len/(AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH));
    //     }
    //     else
    //     {
    //         enc_ins_len = (ins_len/(AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH))+1)*AES_BLOCK_SIZE;
    //         gmeta_push = ins_len/(AES_BLOCK_SIZE - (2*LINK_LENGTH + METADATA_LENGTH))+1;
    //     }
    //     out += (block_num - 1)*16;
    //     AES_decrypt(out, out, dec_key);
    //     out[15] = front_link;
    //     AES_encrypt(out, out, enc_key);
    //     out += 16;
    //     AES_decrypt(out, out, dec_key);
    //     out[0] = back_link;
    //     AES_encrypt(out, out, enc_key);
    //     out -= block_num*16;

    //     push = (gmeta_len + gmeta_push)*AES_BLOCK_SIZE;
    //     while(push > block_num * AES_BLOCK_SIZE + enc_ins_len)
    //     {
    //         out[push] = out[push - enc_ins_len];
    //         push --;
    //     }

    //     encrypt(in, out, ins_len, enc_key, front_link, back_link);

    // }
}

void InitList(List *list)
{
    unsigned char data[16] = {0, };
    list->head = createNode(data);
    list->tail = createNode(data);
    list->head->next = list->tail;
    list->tail->prev = list->head;

    return;  
}

Node *createNode(unsigned char data[16])
{
    Node *new_node = (Node *)calloc(1, sizeof(Node));

    memcpy(new_node->data, data, 16); 

    return new_node;
}

void insertNode(Node *this, List *list)
{
    this->prev = list->tail->prev;
    this->next = list->tail;
    list->tail->prev->next = this;
    list->tail->prev = this;
    return;
}

void insertMiddle(Node *this, Node *prev, List *list)
{


    return;
}

