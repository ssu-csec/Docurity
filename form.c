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

void encrypt_global_metadata(const const unsigned char *in, unsigned char *out, size_t size, const void *enc_key)
{
    srand(time(NULL));
    int n = 0;
    unsigned char link_front = rand() % 256;
    unsigned char link_back = rand() % 256;
    unsigned char ivec = link_front;

    if(size == 0)
        return;
    
    while (size > LINKLESS_BLOCK_SIZE) 
    {
        out[0] = link_front;

        // Fill data from *in to *out
        // [{link_front}{data...data}{link_back}]
        for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n){
            out[n] = in[n - LINK_LENGTH];
        }

        out[15] = link_back;

        AES_encrypt(out, out, enc_key);

        size -= LINKLESS_BLOCK_SIZE;
        in += LINKLESS_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;

        link_front = link_back;
        link_back = rand() % 256;       
    }

    // Handle the last block
    out[0] = link_front;

    for (n = LINK_LENGTH; n < (AES_BLOCK_SIZE - LINK_LENGTH) && n < size + (LINK_LENGTH); ++n){
        out[n] = in[n - (LINK_LENGTH)];
    }

    for (; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n){
        out[n] = 0;
    }

    out[15] = ivec;

    AES_encrypt(out, out, enc_key);

    return;
}

unsigned char *decrypt_global_metadata(const unsigned char *origin, size_t size, const void *dec_key)
{
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned char *global_metadata = calloc(size, sizeof(unsigned char));
    int aes_block_count = get_aes_block_count(size);
    int first_check = aes_block_count;

    if (aes_block_count % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return -1;
    }

    while (aes_block_count) {
        AES_decrypt(origin, tmp, dec_key);

        link_front = tmp[0];

        if(first_check != aes_block_count && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %ld\n", link_front, link_back, aes_block_count);
            return -1;
        }

        link_back = tmp[15];

        for (int n = LINK_LENGTH; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n){
            global_metadata[n - LINK_LENGTH] = tmp[n];
        }

        aes_block_count -= AES_BLOCK_SIZE;
        origin += AES_BLOCK_SIZE;
        global_metadata += LINKLESS_BLOCK_SIZE;
    }

    return global_metadata;
}

void insert_global(unsigned char *in, unsigned char *insert, int index)
{
    unsigned char *insert_position = in + index;
    unsigned char *back_chunk_start = insert_position+strlen(insert);
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

void encrypt(List *dst, const unsigned char *src, size_t len, const void *enc_key,
                unsigned char front_ivec, unsigned char back_ivec)
{
    srand(time(NULL));
    int n = 0;
    unsigned char data[16] = {0. };
    unsigned char link_front = front_ivec;
    unsigned char link_back = rand() % 256;
    unsigned short *bitmap;
    bitmap = &data[1];

    if(len == 0)
        return;
    
    while (len > DATA_SIZE_IN_BLOCK) 
    {
        *bitmap = 0;
        data[0] = link_front;

        for (n = DATA_START; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
        {
            data[n] = src[n - DATA_START];       // Insert data, data[] start at DATA_START and src[] start at 0

            // Record metadata (Bitmap)
            *bitmap = *bitmap >> 1;
            *bitmap = *bitmap | (unsigned short)BITMAP_SEED;
        }

        data[15] = link_back;

        AES_encrypt(data, data, enc_key);

        dst->count += 1;

        len -= DATA_SIZE_IN_BLOCK;
        src += DATA_SIZE_IN_BLOCK;

        insertNode(createNode(data), dst->tail);

        link_front = link_back;
        link_back = rand() % 256;
        
    }

    // Handle the last block
    *bitmap = 0;
    data[0] = link_front;

    for (n = DATA_START; n < (AES_BLOCK_SIZE - LINK_LENGTH); ++n)
    {
        if (n < len + DATA_START){
            data[n] = src[n - DATA_START];

            *bitmap = *bitmap >> 1;
            *bitmap = *bitmap | (unsigned short)BITMAP_SEED;
        }
        else{
            data[n] = 0;
        }
    }

    data[15] = back_ivec;

    AES_encrypt(data, data, enc_key);
    dst->count += 1;

    insertNode(createNode(data), dst->tail);

    return;
}

void decrypt(unsigned char *dst, List *src, const void *dec_key)
{
    unsigned char node_data[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned short bitmap;
    int index = 0;

    Node *node = src->head;

    for (int count = src->count; count > 0; count--){
        node = node->next;

        memcpy(node_data, &(node->data), 16);
        AES_decrypt(node_data, node_data, dec_key);

        link_front = node_data[0];

        if(index != 0 && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! %d block is wrong! \n", link_front, link_back, count);
            for(int i = 0; i < AES_BLOCK_SIZE; i++)
            {
                dst[i] = " ";
            }
            dst += AES_BLOCK_SIZE;
        }
        else
        {
            link_back = node_data[15];

            memcpy(&bitmap, &node_data[1], 2);
            index = copy_data(dst, node_data, &bitmap);

            dst += index;
        }
    }

    return;
}

void deletion(List *out, int index, int size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata)                                          
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;
    unsigned char msg[BUFSIZE] = {0, };
    unsigned short bitmap = 0;

    unsigned char *global_metadata = decrypt_global_metadata(enc_global_metadata, out->count, dec_key);

    int front_block_num = 0;
    int start_point = find_point(index, &front_block_num, global_metadata);

    int back_block_num = 0;
    int end_point = find_point(index + size, &back_block_num, global_metadata);

    if(start_point == index && end_point == index + size)
    {
        case1(out, size, front_link, front_block_num, back_block_num, enc_key, dec_key, global_metadata);
    }
    else if(start_point == index && end_point != index + size)
    {
        case2(out, size, front_block_num, back_block_num, enc_key, dec_key, global_metadata);
    }
    else if(start_point != index && end_point == index + size)
    {
        case3(out, size, front_block_num, back_block_num, enc_key, dec_key, global_metadata);
    }
    else
    {
        case4(out, index, size, front_block_num, back_block_num, enc_key, dec_key, global_metadata);
    }

    encrypt_global_metadata(global_metadata, enc_global_metadata, out->count, enc_key);
}

void case1(List *out, int size, unsigned char front_link, int front_block_num, int back_block_num,
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

void case2(List *out, int size, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned short bitmap = 0;
    int cnt = 0, front_link, back_link;
    int index = front_block_num;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];
    memcpy(&bitmap, &tmp[1], 2);

    while(size > 0)
    {
        size -= plain_gmeta[index];
        index++;
    }

    index--;
    size += plain_gmeta[index];

    unsigned short check_bitmap = (unsigned short)BITMAP_SEED;
    for(int i = DATA_START; i < AES_BLOCK_SIZE; i++)
    {
        if((bitmap & check_bitmap) != 0 && size > 0)
        {
            tmp[i] = 0;
            bitmap = bitmap ^ check_bitmap;
            cnt++;
            size--;
        }
        check_bitmap = check_bitmap >> 1;
    }

    memcpy(&tmp[1], &bitmap, 2);

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

void case3(List *out, int size, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned short bitmap = 0;
    int cnt = 0, front_link, back_link;
    int index = back_block_num;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num - 1);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];
    memcpy(&bitmap, &tmp[1], 2);

    while(size > 0)
    {
        size -= plain_gmeta[index];
        index--;
    }

    index++;
    size += plain_gmeta[index];

    unsigned short check_bitmap = (unsigned short)1;

    for(int i = AES_BLOCK_SIZE - 1; i >= DATA_START; i--)
    {
        if((bitmap & check_bitmap) != 0 && size > 0)
        {
            tmp[i] = 0;
            bitmap = bitmap ^ check_bitmap;
        }
        check_bitmap = check_bitmap << 1;
    }

    memcpy(&tmp[1], &bitmap, 2);

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

void case4(List *out, int index, int size, int front_block_num, int back_block_num,
            const void *enc_key, const void *dec_key, unsigned char *plain_gmeta){
    unsigned char tmp[16] = {0, };
    unsigned char *data;
    unsigned short bitmap = 0;
    int front_len = 0;
    int back_len = 0;
    int cnt = 0, front_link, back_link;

    Node *front_node = seekNode(out, front_block_num);
    Node *back_node = seekNode(out, back_block_num - 1);

    AES_decrypt(&(front_node->data), tmp, dec_key);
    front_link = tmp[0];
    memcpy(&bitmap, &tmp[1], 2);

    for(int i = 0; i < front_block_num; i++)
    {
        front_len += (int)plain_gmeta[i];
    }
    front_len = index - front_len;

    for(int i = 0; i < back_block_num; i++)
    {
        back_len += (int)plain_gmeta[i];
    }
    back_len = back_len - (index + size);

    data = calloc(front_len + back_len, sizeof(unsigned char));
    unsigned short check_bitmap = (unsigned short)BITMAP_SEED;

    int data_index = 0;

    while(data_index < 12 && cnt < front_len)
    {
        if(bitmap & check_bitmap != 0)
        {
            data[cnt] = tmp[data_index + DATA_START];
            cnt++;
        }

        check_bitmap = check_bitmap >> 1;
        data_index++;

    }

    AES_decrypt(&(back_node->data), tmp, dec_key);
    back_link = tmp[15];

    memcpy(&bitmap, &tmp[1], 2);

    check_bitmap = (unsigned short)1;
    data_index = 11;
    cnt = front_len + back_len -1;
    while(data_index >= 0 && cnt >= front_len)
    {
        if(bitmap & check_bitmap != 0)
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

void insertion(unsigned char *input, List *list, int index, int insert_size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata)                                                                      
{
    srand(time(NULL));

    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;
    unsigned char *insert_data;

    unsigned short bitmap;
    int filled_block_count = list->count;

    // First time of insertion
    if(index == 0 && filled_block_count == 0)
    {
        first_insertion(input, list, insert_size, front_link, enc_key, enc_global_metadata);
        return;
    }

    unsigned char *global_metadata = decrypt_global_metadata(enc_global_metadata, filled_block_count, dec_key);
    memset(enc_global_metadata, 0, BUFSIZE);        // clear original global metadata

    int block_num = 0;
    int point = find_point(index, &block_num, global_metadata);

    if(point == index)  // index is located between two blocks
    {
        insert_data = calloc(insert_size, sizeof(unsigned char));
        Node *prev_node = seekNode(list, block_num);

        unsigned char tmp[16] = {0, };

        // Replace back link of prev_node
        AES_decrypt(&(prev_node->data), tmp, dec_key);
        tmp[15] = front_link;
        AES_encrypt(tmp, &(prev_node->data), enc_key);

        // Replace front link of next_node
        Node *next_node = seekNode(list, block_num);
        AES_decrypt(&(next_node->data), tmp, dec_key);
        tmp[0] = back_link;
        AES_encrypt(tmp, &(prev_node->data), enc_key);

        // Copy data we want to insert
        memcpy(insert_data, input, insert_size);
    }
    else                // index is located in the middle of one block
    {
        block_num++;
        int origin_size = (int)global_metadata[block_num];

        unsigned char *front_origin = calloc(origin_size, sizeof(unsigned char));
        unsigned char tmp[16] = {0, };

        insert_data = calloc(insert_size + origin_size, sizeof(unsigned char));

        Node *node = seekNode(list, block_num);            // block_num + 1 means the block we want to modify
        AES_decrypt(&(node->data), tmp, dec_key);
        front_link = tmp[0];
        back_link = tmp[15];
        memcpy(&bitmap, &tmp[1], 2);

        removeNode(seekNode(list, block_num));

        copy_data(tmp, front_origin, &bitmap);      // Copy data from previous node

        int front_origin_size = index - point;
        int back_origin_size = origin_size - front_origin_size;
        unsigned char *insert_position = front_origin_size + insert_data;
        unsigned char *back_origin = insert_data + insert_size + front_origin_size;

        memcpy(insert_data, front_origin, front_origin_size);
        memcpy(insert_position, in, insert_size);
        memcpy(back_origin, front_origin + front_origin_size, back_origin_size);

        insert_size += origin_size;
        
        delete_global(global_metadata, block_num, 1);
    }

    encrypt(insert_data, list, insert_size, enc_key, front_link, back_link);

    Node *prev_node = seekNode(list, block_num - 1);
    Node *next_node = seekNode(list, block_num);

    list->head->next->prev = prev_node;
    list->tail->prev->next = next_node;
    prev_node->next = list->head->next;
    next_node->prev = list->tail->prev;
    filled_block_count += list->count;

    unsigned char *new_metadata = calloc(insert_size/12 + 1, sizeof(unsigned char));

    update_metadata(new_metadata, insert_size);

    insert_global(global_metadata, new_metadata, block_num);

    encrypt_global_metadata(global_metadata, enc_global_metadata, filled_block_count, enc_key);

}

void first_insertion(unsigned char *input, List *list, int insert_size, unsigned char front_link, 
                        const void *enc_key, unsigned char *global_meta){
    int index;
    int filled_block_count = list->count;

    encrypt(input, list, insert_size, enc_key, front_link, front_link);
    unsigned char *plain_gmeta = calloc(filled_block_count, sizeof(unsigned char));
    update_metadata(plain_gmeta, insert_size);
    encrypt_global_metadata(plain_gmeta, global_meta, filled_block_count, enc_key);
}

void update_metadata(unsigned char *global_metadata, int insert_size){
    for (int index = 0; insert_size > 0; index++){
        if (insert_size > DATA_SIZE_IN_BLOCK){
            global_metadata[index] = DATA_SIZE_IN_BLOCK;
        }
        else{
            global_metadata[index] = insert_size;
        }

        insert_size -= DATA_SIZE_IN_BLOCK;
    }
}

int copy_data(unsigned char *dst, unsigned char *src, unsigned short *bitmap){
    int index = 0;

    for (int data_index = DATA_START; data_index < AES_BLOCK_SIZE - LINK_LENGTH; ++data_index)
    {
        if((*bitmap & BITMAP_SEED) != 0)
        {
            dst[index] = src[data_index];
            index++;
            *bitmap = *bitmap << 1;
        }
    }

    return index;
}

int get_aes_block_count(int data_size){
    if(data_size % LINKLESS_BLOCK_SIZE == 0)
        return (data_size / LINKLESS_BLOCK_SIZE) * AES_BLOCK_SIZE;
    else
        return(data_size / LINKLESS_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
}

int find_point(int index, int *block_num, unsigned char *global_metadata){
    int point = 0;

    while(point <= index)
    {
        point += (int) global_metadata[*block_num];
        *block_num++;
    }

    *block_num--;
    point -= (int) global_metadata[*block_num];

    return point;
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
