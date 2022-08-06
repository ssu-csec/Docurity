#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "form.h"
#include "packet.h"

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
    
    while (len > LINKLESS_BLOCK_SIZE) 
    {
        out[0] = link_front;

        // Fill data from *in to *out
        // [{link_front}{data...data}{link_back}]
        for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n){
            out[n] = in[n - LINK_LENGTH];
        }

        out[15] = link_back;

        AES_encrypt(out, out, enc_key);

        len -= LINKLESS_BLOCK_SIZE;
        in += LINKLESS_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;

        link_front = link_back;
        link_back = rand() % 256;       
    }

    // Handle the last block
    out[0] = link_front;

    for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH) && n < len + (LINK_LENGTH); ++n){
        out[n] = in[n - (LINK_LENGTH)];
    }

    for (; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n){
        out[n] = 0;
    }

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

    if (len % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return;
    }

    while (len) {
        AES_decrypt(in, tmp, dec_key);

        link_front = tmp[0];

        if(first_check != len && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %ld\n", link_front, link_back, len);
            return;
        }

        link_back = tmp[15];

        for (n = LINK_LENGTH; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n){
            out[n - LINK_LENGTH] = tmp[n];
        }

        len -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        out += LINKLESS_BLOCK_SIZE;
    }
}

void insert_global(unsigned char *in, unsigned char *insert, int index)
{
    // [global]
    // [gl][insert][bal]
    // [gl]: front chunck, [insert]: inserted chunk, [bal]: back chunk

    int insert_position = in + index;
    int back_chunk_start = insert_position+strlen(insert);
    int back_chunk_size = strlen(in) - index;
    unsigned char *temp = calloc(back_chunk_size, sizeof(unsigned char));
 
    memcpy(temp, insert_position, back_chunk_size);         // save temporary for back chunk
    memcpy(insert_position, insert, strlen(insert));        // insert global
    memcpy(back_chunk_start, temp, back_chunk_size);        // restore back chunk

    free(temp);
}

void delete_global(unsigned char *in, int index, int length)
{
    index--;

    int delete_position = in + index;
    int back_chunk_start = delete_position + length;
    int back_chunk_size = strlen(in) - index - length;
    unsigned char *temp = calloc(back_chunk_size, sizeof(unsigned char));

    memcpy(temp, back_chunk_start, back_chunk_size);
    memcpy(delete_position, temp, back_chunk_size);

    free(temp);
}

void encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec)
{
    srand(time(NULL));
    int n = 0;
    unsigned char tmp[16] = {0. };
    unsigned char link_front = front_ivec;
    unsigned char link_back = rand() % 256;
    unsigned short *meta;
    meta = &tmp[1];

    printf("insert length is %d\n", len);

    if(len == 0)
        return;
    
    while (len > DATA_SIZE_IN_BLOCK) 
    {
        *meta = 0;
        tmp[0] = link_front;

        for (n = DATA_START; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
        {
            tmp[n] = in[n - DATA_START];       // Insert data, tmp[] start at DATA_START and in[] start at 0

            // Record metadata (Bitmap)
            *meta = *meta >> 1;
            *meta = *meta | (unsigned short)BITMAP_SEED;

        }

        tmp[15] = link_back;

        AES_encrypt(tmp, tmp, enc_key);

        out->count += 1;

        len -= DATA_SIZE_IN_BLOCK;
        in += DATA_SIZE_IN_BLOCK;

        insertNode(createNode(tmp), out->tail);

        link_front = link_back;
        link_back = rand() % 256;
        
    }

    // Handle the last block
    *meta = 0;
    tmp[0] = link_front;

    for (n = DATA_START; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
    {
        if (n < len + DATA_START){
            tmp[n] = in[n - DATA_START];

            *meta = *meta >> 1;
            *meta = *meta | (unsigned short)BITMAP_SEED;
        }
        else{
            tmp[n] = 0;
        }
    }

    tmp[15] = back_ivec;

    AES_encrypt(tmp, tmp, enc_key);
    out->count += 1;

    insertNode(createNode(tmp), out->tail);

    return;
}

void decrypt(List *in, unsigned char *out, const void *dec_key)
{
    int index = 0;
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned short meta;
    Node *new_node = in->head;

    for (int count = in->count; count > 0; count--){
        new_node = new_node->next;
        memcpy(tmp, &(new_node->data), 16);
        AES_decrypt(tmp, tmp, dec_key);

        link_front = tmp[0];

        if(index != 0 && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %d\n", link_front, link_back, count);
            return;
        }

        link_back = tmp[15];

        memcpy(&meta, &tmp[1], 2);
        index = 0;

        for (int n = DATA_START; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n)
        {
            if((meta & BITMAP_SEED) != 0)
            {
                out[index] = tmp[n];
                index++;
                meta = meta << 1;
            }
        }

        out += index;
    }
}

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta)                                          
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    unsigned char msg[BUFSIZE] = {0, };

    unsigned short meta = 0;

    int gmeta_len = out->count;
    index--;

    // decrypt global metadata
    int enc_gmeta_len;
    if(gmeta_len % LINKLESS_BLOCK_SIZE == 0)
        enc_gmeta_len = (gmeta_len / LINKLESS_BLOCK_SIZE) * AES_BLOCK_SIZE;
    else
        enc_gmeta_len = (gmeta_len / LINKLESS_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    unsigned char *plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);

    // check 1 process
    int check1 = 0;
    int front_block_num = 0;

    while(check1 <= index)
    {
        check1 += (int) plain_gmeta[front_block_num];
        front_block_num++;
    }

    front_block_num--;
    check1 -= (int) plain_gmeta[front_block_num];

    // check 2 process
    int check2 = 0;
    int back_block_num = 0;

    while(check2 < index + del_len)
    {
        check2 += (int)plain_gmeta[back_block_num];
        back_block_num++;
    }
    back_block_num--;
    check2 -= (int)plain_gmeta[back_block_num];


    if(check1 == index && check2 == index + del_len)
    {
        case1(out, del_len, front_link, front_block_num, back_block_num, enc_key, dec_key, plain_gmeta);
    }
    else if(check1 == index && check2 != index + del_len)
    {
        case2(out, del_len, front_block_num, back_block_num, enc_key, dec_key, plain_gmeta);
    }
    else if(check1 != index && check2 == index + del_len)
    {
        case3(out, del_len, front_block_num, back_block_num, enc_key, dec_key, plain_gmeta);
    }
    else
    {
        case4(out, index, del_len, front_block_num, back_block_num, enc_key, dec_key, plain_gmeta);
    }

    global_encrypt(plain_gmeta, global_meta, out->count, enc_key);
}

void case1(List *out, int del_len, unsigned char front_link, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num - 1);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    tmp[15] = front_link;
    AES_encrypt(tmp, &(front_node->data), enc_key);

    AES_decrypt(&(back_node->data), tmp, dec_key);
    tmp[0] = front_link;
    AES_encrypt(tmp, &(back_node->data), enc_key);

    out->count = out->count - (back_block_num - front_block_num);
    delete_global(plain_gmeta, front_block_num, back_block_num - front_block_num);
}

void case2(List *out, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned short meta = 0;
    int cnt = 0, front_link, back_link;
    int index = front_block_num;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];
    memcpy(&meta, &tmp[1], 2);

    while(del_len > 0)
    {
        del_len -= plain_gmeta[index];
        index++;
    }

    index--;
    del_len += plain_gmeta[index];

    unsigned short check_bitmap = (unsigned short)BITMAP_SEED;
    for(int i = DATA_START; i < AES_BLOCK_SIZE; i++)
    {
        if((meta & check_bitmap) != 0 && del_len > 0)
        {
            tmp[i] = 0;
            meta = meta ^ check_bitmap;
            cnt++;
            del_len--;
        }
        check_bitmap = check_bitmap >> 1;
    }

    memcpy(&tmp[1], &meta, 2);

    tmp[0] = front_link;
    tmp[15] = back_link;
    plain_gmeta[back_block_num - 1] = (unsigned char)cnt;
    AES_encrypt(tmp, tmp, 16);

    for(int i = front_block_num; i < back_block_num; i++)
    {
        removeNode(seekNode(out, front_block_num));
    }

    Node *new_node = calloc(1, sizeof(Node));
    memcpy(new_node->data, tmp, 16);

    insertNode(new_node, seekNode(out, front_block_num));

    delete_global(plain_gmeta, front_block_num, back_block_num - front_block_num - 2);
}

void case3(List *out, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned short meta = 0;
    int cnt = 0, front_link, back_link;
    int index = back_block_num;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num - 1);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];
    memcpy(&meta, &tmp[1], 2);

    while(del_len > 0)
    {
        del_len -= plain_gmeta[index];
        index--;
    }

    index++;
    del_len += plain_gmeta[index];

    unsigned short check_bitmap = (unsigned short)1;

    for(int i = AES_BLOCK_SIZE - 1; i >= DATA_START; i--)
    {
        if((meta & check_bitmap) != 0 && del_len > 0)
        {
            tmp[i] = 0;
            meta = meta ^ check_bitmap;
        }
        check_bitmap = check_bitmap << 1;
    }

    memcpy(&tmp[1], &meta, 2);

    tmp[0] = front_link;
    tmp[15] = back_link;

    plain_gmeta[front_block_num] = (char)cnt;
    AES_encrypt(tmp, tmp, 16);

    for(int i = front_block_num; i < back_block_num; i++)
    {
        removeNode(seekNode(out, front_block_num));
    }

    Node *new_node = calloc(1, sizeof(Node));
    memcpy(new_node->data, tmp, 16);
    insertNode(new_node, seekNode(out, front_block_num));

    delete_global(plain_gmeta, front_block_num + 1, back_block_num - front_block_num - 1);
}

void case4(List *out, int index, int del_len, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned char *data;
    unsigned short meta = 0;
    int front_len = 0;
    int back_len = 0;
    int cnt = 0, front_link, back_link;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num - 1);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    memcpy(&meta, &tmp[1], 2);

    for(int i = 0; i < front_block_num; i++)
    {
        front_len += (int)plain_gmeta[i];
    }
    front_len = index - front_len;

    for(int i = 0; i < back_block_num; i++)
    {
        back_len += (int)plain_gmeta[i];
    }
    back_len = back_len - (index + del_len);

    data = calloc(front_len + back_len, sizeof(unsigned char));
    unsigned short check_bitmap = (unsigned short)BITMAP_SEED;

    int data_index = 0;

    while(data_index < 12 && cnt < front_len)
    {
        if(meta & check_bitmap != 0)
        {
            data[cnt] = tmp[data_index + DATA_START];
            cnt++;
        }

        check_bitmap = check_bitmap >> 1;
        data_index++;

    }

    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];

    memcpy(&meta, &tmp[1], 2);

    check_bitmap = (unsigned short)1;
    data_index = 11;
    cnt = front_len + back_len -1;
    while(data_index >= 0 && cnt >= front_len)
    {
        if(meta & check_bitmap != 0)
        {
            data[cnt] = tmp[data_index + DATA_START];
            cnt--;
        }

        check_bitmap = check_bitmap << 1;
        data_index--;
    }

    for(cnt = front_block_num; cnt < back_block_num; cnt++)
    {
        removeNode(seekNode(out, front_block_num));
    }

    List *new_list = calloc(1, sizeof(List));
    InitList(new_list);
    encrypt(data, new_list, front_len + back_len, enc_key, front_link, back_link);

    unsigned char *add_global = calloc((front_len + back_len)/12 + 1, sizeof(unsigned char));

    int len = front_len + back_len;
    int i = 0;

    while(len > 0)
    {
        if(len > 12)
            add_global[i] = (unsigned char)12;

        else
            add_global[i] = (unsigned char)len;
        len -= 12;
    }

    delete_global(plain_gmeta, front_block_num, back_block_num - front_block_num);
    insert_global(plain_gmeta, add_global, front_block_num);
}

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta)                                                                      
{
    srand(time(NULL));

    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    unsigned char *insert_data;
    unsigned char *plain_gmeta;

    List *list = calloc(1, sizeof(List));
    InitList(list);

    Node *node;
    unsigned short meta;

    // First time of insertion
    if(index == 0 && out->count == 0)
    {
        int cnt = 0;
        encrypt(in, out, ins_len, enc_key, front_link, front_link);
        plain_gmeta = calloc(out->count, sizeof(unsigned char));

        while(ins_len > 12)
        {
            plain_gmeta[cnt] = 12;
            ins_len -=12;
            cnt++;
        }

        plain_gmeta[cnt] = ins_len;
        global_encrypt(plain_gmeta, global_meta, out->count, enc_key);
        return;
    }

    // decrypt global metadata
    int enc_gmeta_len;
    if((out->count) % LINKLESS_BLOCK_SIZE == 0)
        enc_gmeta_len = ((out->count) / LINKLESS_BLOCK_SIZE) * AES_BLOCK_SIZE;
    else
        enc_gmeta_len = ((out->count) / LINKLESS_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    plain_gmeta = calloc((out->count), sizeof(unsigned char));

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);
    memset(global_meta, 0, BUFSIZE);

    int check = 0;
    int block_num = 0;

    while(check <= index)
    {
        check += (int)plain_gmeta[block_num];
        block_num++;
    }

    block_num--;
    check -= (int)plain_gmeta[block_num];

    if(check != index)                                              // index is located in the middle of one block
    {
        unsigned char *add_data = calloc((int)plain_gmeta[block_num], sizeof(unsigned char));
        unsigned char tmp[16] = {0, };

        ins_len += (int)plain_gmeta[block_num];
        insert_data = calloc(ins_len + (int)plain_gmeta[block_num], sizeof(unsigned char));
        node = seekNode(out, block_num + 1);
        AES_decrypt(&(node->data), tmp, dec_key);
        front_link = tmp[0];
        back_link = tmp[15];
        memcpy(&meta, &tmp[1], 2);

        removeNode(seekNode(out, block_num + 1));

        int cnt = 0;

        for (int n = DATA_START; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n)
        {
            if((meta & BITMAP_SEED) != 0)
            {
                add_data[cnt] = tmp[n];
                cnt++;
                meta = meta << 1;
            }
        }

        int data_size = index - check;
        memcpy(insert_data, add_data, data_size);
        memcpy(insert_data + data_size, in, ins_len - (int) plain_gmeta[block_num]);
        memcpy(insert_data - ((int) plain_gmeta[block_num] - data_size), add_data + data_size, (int) plain_gmeta[block_num] - data_size);

        ins_len = ins_len + strlen(add_data);
        block_num++;
        
        delete_global(plain_gmeta, block_num, 1);
    }

    else                                                                // index is located between two blocks
    {
        insert_data = calloc(ins_len + (int)plain_gmeta[block_num], sizeof(unsigned char));
        Node *prev_node = seekNode(out, block_num);
        unsigned char tmp[16] = {0, };
        AES_decrypt(&(prev_node->data), tmp, dec_key);
        tmp[15] = front_link;
        AES_encrypt(tmp, &(prev_node->data), enc_key);

        Node *next_node = seekNode(out, block_num);
        AES_decrypt(&(next_node->data), tmp, dec_key);
        tmp[0] = back_link;
        AES_encrypt(tmp, &(prev_node->data), enc_key);

        memcpy(insert_data, in, ins_len);

        free_node_safely(prev_node, next_node);
    }

    encrypt(insert_data, list, ins_len, enc_key, front_link, back_link);

    Node *prev_node = seekNode(out, block_num - 1);
    Node *next_node = seekNode(out, block_num);

    list->head->next->prev = prev_node;
    list->tail->prev->next = next_node;
    prev_node->next = list->head->next;
    next_node->prev = list->tail->prev;
    out->count += list->count;

    free_node_safely(prev_node, next_node);

    unsigned char *add_global = calloc(ins_len/12 + 1, sizeof(unsigned char));

    int i = 0;
    while(ins_len > 0)
    {
        if(ins_len > 12)
            add_global[i] = (unsigned char)12;

        else
            add_global[i] = (unsigned char)ins_len;

        i++;
        ins_len -= 12;
    }

    insert_global(plain_gmeta, add_global, block_num);
    
    global_encrypt(plain_gmeta, global_meta, out->count, enc_key);

}

void free_node_safely(Node *prev_node, Node *next_node){
    free(prev_node);
    if(prev_node != next_node){
        free(next_node);
    }
}

void packing_data(PACKET *packet, unsigned char *msg)
{
    memcpy(msg, &(packet->msgType), 1);
    msg++;
    if(packet->msgType == 0x00)
        memcpy(msg, packet->data, sizeof(packet->data));
    else
    {
        memcpy(msg, &(((NODE_SEND*)packet->data)->inst), 1);
        msg++;
        memcpy(msg, &(((NODE_SEND*)packet->data)->index), sizeof(int));
        msg += sizeof(int);
        memcpy(msg, ((NODE_SEND*)packet->data)->data, sizeof(((NODE_SEND*)packet->data)->data));
    }
}

void unpacking_global(unsigned char *msg, unsigned char *global_meta)
{
    memcpy(global_meta, msg+1, BUFSIZE - 1);
}

void unpacking_data(unsigned char *msg, Node *new_node, List *list)
{
    if(msg[1] == DELETE)
        {
            Node *node = calloc(1, sizeof(Node));
            int index;
            memcpy(index, msg+2, sizeof(int));
            node = seekNode(list, index);
            node->next->prev = node->prev;
            node->prev->next = node->next;
            free(node);
        }
        else if(msg[1] == INSERT)
        {
            memcpy(&(new_node->data), msg+6, AES_BLOCK_SIZE);
            Node *node = calloc(1, sizeof(Node));
            int index;
            memcpy(&index, msg+2, sizeof(int));
            node = seekNode(list, index);
            node->prev = new_node;
            new_node->next = node;
            free(node);
        }
}
