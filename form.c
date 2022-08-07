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
    int index = 0;
    link_t link_front = rand() % 256;
    link_t link_back = rand() % 256;
    link_t ivec = link_front;

    if(size == 0)
        return;
    
    while(1){
        out[0] = link_front;

        for (index = LINK_LENGTH; index < (AES_BLOCK_SIZE - LINK_LENGTH); ++index){
            if (index < size + LINK_LENGTH){
                out[index] = in[index - LINK_LENGTH];
            }
            else{
                out[index] = 0;
            }
        }

        if (size > LINKLESS_BLOCK_SIZE){
            out[15] = link_back;

            AES_encrypt(out, out, enc_key);
        }
        else{
            // Handle the last block
            out[15] = ivec;

            AES_encrypt(out, out, enc_key);
            break;
        }

        link_front = link_back;
        link_back = rand() % 256;

        size -= LINKLESS_BLOCK_SIZE;
        in += LINKLESS_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
}

unsigned char *decrypt_global_metadata(const unsigned char *enc_global_metadata, size_t size, const void *dec_key)
{
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char *global_metadata = calloc(size, sizeof(unsigned char));
    unsigned char *metadata_ptr = global_metadata;
    int aes_block_count = get_aes_block_count(size);
    int first_check = aes_block_count;
    link_t link_front = 0;
    link_t link_back = 0;

    if (aes_block_count % AES_BLOCK_SIZE != 0)
    {
        printf("size error!\n");
        return -1;
    }

    while (aes_block_count) {
        AES_decrypt(enc_global_metadata, tmp, dec_key);

        link_front = tmp[0];

        if(first_check != aes_block_count && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %ld\n", link_front, link_back, aes_block_count);
            return -1;
        }

        link_back = tmp[15];

        for (int index = 0; index < LINKLESS_BLOCK_SIZE; index++){
            metadata_ptr[index] = tmp[index + sizeof(link_t)];
        }

        aes_block_count -= AES_BLOCK_SIZE;
        enc_global_metadata += AES_BLOCK_SIZE;
        metadata_ptr += LINKLESS_BLOCK_SIZE;
    }

    return global_metadata;
}

void insert_global(unsigned char *global_metadata, unsigned char *metadata, int index)
{
    int metadata_size = strlen(metadata);
    int next_data_size = strlen(global_metadata) - index;
    int temp_size = next_data_size + metadata_size;
    unsigned char *temp = calloc(temp_size, sizeof(unsigned char));
 
    memcpy(temp, metadata, metadata_size);
    memcpy(temp + metadata_size, global_metadata + index, next_data_size);

    memcpy(global_metadata + index, temp, temp_size);       // Overwrite origin global metadata

    free(temp);
}

void delete_global(unsigned char *global_metadata, int index, int size)
{
    int global_metadata_size = strlen(global_metadata);
    int delete_position = global_metadata + index;
    int next_data_start = delete_position + size;
    int next_data_size = global_metadata_size - (index + size);

    memcpy(delete_position, next_data_start, next_data_size);
    memset(global_metadata + global_metadata_size, 0, size);      // clear moved data
}

void update_metadata(unsigned char *global_metadata, int insert_size){
    for (int index = 0; 0 < insert_size; index++){
        if (insert_size > DATA_SIZE_IN_BLOCK){
            global_metadata[index] = DATA_SIZE_IN_BLOCK;
        }
        else{
            global_metadata[index] = insert_size;
        }

        insert_size -= DATA_SIZE_IN_BLOCK;
    }
}


void encrypt(List *list, const unsigned char *input, size_t size, const void *enc_key,
                link_t front_ivec, link_t back_ivec)
{
    srand(time(NULL));
    int index = 0;
    unsigned char data[16] = {0. };
    link_t link_front = front_ivec;
    link_t link_back = rand() % 256;
    bitmap_t *bitmap = &data[1];

    if (size == 0)
        return;
    
    while (1){
        *bitmap = 0;
        data[0] = link_front;

        for (index = DATA_START; index < (AES_BLOCK_SIZE - LINK_LENGTH); ++index)
        {
            if (index < size + DATA_START){
                data[index] = input[index - DATA_START];       // Insert data, data[] start at DATA_START and input[] start at 0

                // Record metadata (Bitmap)
                *bitmap = *bitmap >> 1;
                *bitmap = *bitmap | (bitmap_t) BITMAP_SEED;
            }
            else{
                data[index] = 0;
            }
        }

        if (size > DATA_SIZE_IN_BLOCK){
            data[15] = link_back;

            AES_encrypt(data, data, enc_key);

            list->count += 1;
            insertNode(createNode(data), list->tail);
        }
        else{
            // Handle the last block
            data[15] = back_ivec;

            AES_encrypt(data, data, enc_key);

            list->count += 1;
            insertNode(createNode(data), list->tail);
            break;
        }

        memset(data, 0, 16);

        link_front = link_back;
        link_back = rand() % 256;
        size -= DATA_SIZE_IN_BLOCK;
        input += DATA_SIZE_IN_BLOCK;
    }
}

void decrypt(unsigned char *dst, List *list, const void *dec_key)
{
    char is_valid_block;
    unsigned char node_data[AES_BLOCK_SIZE] = {0, };
    int index = 0;
    link_t link_front = 0;
    link_t link_back = 0;
    bitmap_t bitmap;
    Node *node = list->head->next;

    for (int count = 0; count < list->count; count++){

        memcpy(node_data, &(node->data), 16);
        AES_decrypt(node_data, node_data, dec_key);

        link_front = node_data[0];

        is_valid_block = index > 0 && link_front != link_back;

        if(is_valid_block)
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

        node = node->next;
    }

    return;
}

void deletion(List *list, int index, int size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata)                                          
{
    srand(time(NULL));
    unsigned char msg[BUFSIZE] = {0, };
    unsigned char tmp[16] = {0, };
    int deleted_blocks = 0;
    int delete_start = index;
    int delete_end = index + size;
    int bound = index + size + 1;
    link_t front_link = rand()%256;
    link_t back_link = rand()%256;
    bitmap_t bitmap = 0;

    unsigned char *global_metadata = decrypt_global_metadata(enc_global_metadata, list->count, dec_key);

    // first block to be delete
    int first_block_num = 0;
    int first_block_start = find_block_start(delete_start, &first_block_num, global_metadata);

    // last block to be delete
    int last_block_num = 0;
    int last_block_start = find_block_start(delete_end, &last_block_num, global_metadata);

    // last block to be delete
    int bound_block_num = 0;
    find_block_start(bound, &bound_block_num, global_metadata);

    char delete_from_block_start = first_block_start == delete_start ? 1 : 0;
    char delete_to_block_end = last_block_num != bound_block_num ? 1 : 0;

    if(delete_from_block_start && delete_to_block_end)     // delete entire blocks
    {
        deleted_blocks = bound_block_num - first_block_num;

        if(first_block_num > 0){
            Node *front_block = seekNode(list, first_block_num - 1);
            Node *bound_block = seekNode(list, bound_block_num);

            replace_link(front_block, front_link, -1, enc_key, dec_key);
            replace_link(bound_block, front_link, 0, enc_key, dec_key);

            removeNode(seekNode(list, first_block_num));
            removeNode(seekNode(list, last_block_num));
        }
        else{   // from head of list to a block deleted
            Node *new_head_block = seekNode(list, bound_block_num);
            Node *last_block = list->tail;

            removeNode(seekNode(list, first_block_num));
            removeNode(seekNode(list, last_block_num));

            link_t ivec = get_link(last_block, -1, dec_key);
            replace_link(new_head_block, ivec, 0, enc_key, dec_key);

            list->head = new_head_block;
            list->head->prev = list->tail;
            list->tail->next = new_head_block;
        }

        list->count -= deleted_blocks;
        delete_global(global_metadata, first_block_num, deleted_blocks);
    }
    else if(delete_from_block_start && !delete_to_block_end)   // delete from a block to a part of the other block
    {
        int delete_count = 0;
        int delete_size_in_block = size - last_block_start;
        deleted_blocks = last_block_num - first_block_num - 1;  // save last block

        Node *front_block = seekNode(list, first_block_num - 1);
        Node *back_block = seekNode(list, last_block_num);

        unsigned char *block_data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));

        front_link = get_link(front_block, -1, dec_key);
        decrypt_block(back_block, NULL, &back_link, &bitmap, block_data, dec_key);

        bitmap_t check_bitmap = (bitmap_t) BITMAP_SEED;
        for (int data_index = 0; data_index < DATA_SIZE_IN_BLOCK; data_index++){
            if(delete_count > delete_size_in_block){
                break;
            }

            if((bitmap & check_bitmap) != 0){
                block_data[data_index] = 0;
                bitmap = bitmap ^ check_bitmap;
                delete_count++;
            }

            check_bitmap = check_bitmap >> 1;
        }

        replace_link(front_block, back_link, -1, enc_key, dec_key);
        replace_link(back_block, front_link, 0, enc_key, dec_key);

        Node *new_node = calloc(1, sizeof(Node));

        encrypt_block(new_node, front_link, back_link, bitmap, block_data, enc_key);

        for(int block_num = first_block_num; block_num < last_block_num; block_num++)
        {
            removeNode(seekNode(list, block_num));
        }

        insertNode(new_node, seekNode(list, first_block_num));

        list->count -= deleted_blocks;
        delete_global(global_metadata, first_block_num, deleted_blocks);
    }
    else if(!delete_from_block_start && delete_to_block_end)   // delete from a part of a block to the other block
    {
        int delete_count = 0;
        int delete_start_in_block = delete_start - first_block_start;
        deleted_blocks = last_block_num - first_block_num;  // save last block

        Node *front_block = seekNode(list, first_block_num);
        Node *bound_block = seekNode(list, bound_block_num);

        unsigned char *block_data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));

        front_link = get_link(bound_block, 0, dec_key);
        decrypt_block(front_block, NULL, &back_link, &bitmap, block_data, dec_key);

        bitmap_t check_bitmap = (bitmap_t) BITMAP_SEED >> delete_start_in_block;
        for (int data_index = delete_start_in_block; data_index < DATA_SIZE_IN_BLOCK; data_index++){
            if((bitmap & check_bitmap) != 0){
                block_data[data_index] = 0;
                bitmap = bitmap ^ check_bitmap;
                delete_count++;
            }
            check_bitmap = check_bitmap >> 1;
        }

        replace_link(front_block, back_link, -1, enc_key, dec_key);
        replace_link(bound_block, front_link, 0, enc_key, dec_key);

        Node *new_node = calloc(1, sizeof(Node));

        encrypt_block(new_node, front_link, back_link, bitmap, block_data, enc_key);

        for(int block_num = first_block_num + 1; block_num < bound_block_num; block_num++)
        {
            removeNode(seekNode(list, block_num));
        }

        insertNode(new_node, seekNode(list, first_block_num));

        list->count -= deleted_blocks;
        global_metadata[first_block_num] -= delete_count;
        delete_global(global_metadata, first_block_num + 1, deleted_blocks);
    }
    else                           // delete from a part of a block to a part of the other block
    {
        int delete_count = 0;
        int delete_start_in_block = delete_start - first_block_start;
        int delete_size_in_block = size - last_block_start;
        deleted_blocks = last_block_num - first_block_num - 2;  // save first and last block
        link_t old_front_link, old_back_link;
        bitmap_t front_bitmap, back_bitmap, check_bitmap;

        Node *front_block = seekNode(list, first_block_num - 1);
        Node *back_block = seekNode(list, last_block_num);

        unsigned char *front_block_data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));
        unsigned char *back_block_data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));

        decrypt_block(front_block, &old_front_link, &back_link, &front_bitmap, front_block_data, dec_key);
        decrypt_block(back_block, &front_link, &old_back_link, &back_bitmap, back_block_data, dec_key);

        check_bitmap = (bitmap_t) BITMAP_SEED >> delete_start_in_block;
        for (int data_index = delete_start_in_block; data_index < DATA_SIZE_IN_BLOCK; data_index++){
            if((front_bitmap & check_bitmap) != 0){
                front_block_data[data_index] = 0;
                front_bitmap = front_bitmap ^ check_bitmap;
                delete_count++;
            }
            check_bitmap = check_bitmap >> 1;
        }

        global_metadata[first_block_num] -= delete_count;
        delete_count = 0;

        check_bitmap = (bitmap_t) BITMAP_SEED;
        for (int data_index = 0; data_index < DATA_SIZE_IN_BLOCK; data_index++){
            if(delete_count > delete_size_in_block){
                break;
            }

            if((back_bitmap & check_bitmap) != 0){
                back_block_data[data_index] = 0;
                back_bitmap = back_bitmap ^ check_bitmap;
                delete_count++;
            }

            check_bitmap = check_bitmap >> 1;
        }

        encrypt_block(front_block, old_front_link, back_link, front_bitmap, front_block_data, enc_key);
        encrypt_block(back_block, front_link, old_back_link, back_bitmap, back_block_data, enc_key);

        for(int block_num = first_block_num + 1; block_num < last_block_num; block_num++)
        {
            removeNode(seekNode(list, block_num));
        }

        list->count -= deleted_blocks;
        delete_global(global_metadata, first_block_num, deleted_blocks);
    }

    encrypt_global_metadata(global_metadata, enc_global_metadata, list->count, enc_key);
}


void insertion(List *list, unsigned char *input, int index, int insert_size, const void *enc_key, const void *dec_key, 
                unsigned char *enc_global_metadata)                                                                      
{
    srand(time(NULL));

    link_t front_link = rand() % 256;
    link_t back_link = rand() % 256;
    unsigned char *global_metadata, *insert_data;

    int block_index = 0;
    int filled_block_count = list->count;

    // First time of insertion
    if(index == 0 && filled_block_count == 0)
    {
        encrypt(list, input, insert_size, enc_key, front_link, front_link);
        global_metadata = calloc(insert_size/12 + 1, sizeof(unsigned char));
        update_metadata(global_metadata, insert_size);
    }
    else{
        global_metadata = decrypt_global_metadata(enc_global_metadata, filled_block_count, dec_key);
        memset(enc_global_metadata, 0, BUFSIZE);        // clear original global metadata

        int start_point = find_block_start(index, &block_index, global_metadata);
        char is_block_start = start_point == index ? 1 : 0;

        if(is_block_start)  // allocate new block
        {
            insert_data = calloc(insert_size, sizeof(unsigned char));
            // Copy data we want to insert
            memcpy(insert_data, input, insert_size);

        }
        else                // index is located in the middle of one block
        {
            // 1. get block
            // 2. divide block at index
            // 3. fill data into insert_data && bitmap

            unsigned char *block_data, *insert_point;
            int block_data_size = (int)global_metadata[block_index];
            int block_front_size = index - start_point;
            int block_back_size = block_data_size - block_front_size;
            insert_data = calloc(insert_size + block_data_size, sizeof(unsigned char));

            Node *block = seekNode(list, block_index);

            block_data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));
            decrypt_block(block, &front_link, &back_link, NULL, block_data, dec_key);

            removeNode(block);

            insert_point = insert_data + block_front_size;

            memcpy(insert_data, block_data, block_front_size);
            memcpy(insert_point, input, insert_size);
            memcpy(insert_point + insert_size, block_data + block_front_size, block_back_size);

            free(block_data);
            delete_global(global_metadata, block_index, 1);
            
            insert_size += block_data_size;
        }
        Node *prev_node = seekNode(list, block_index-1);
        Node *next_node = seekNode(list, block_index);

        replace_link(prev_node, front_link, -1, enc_key, dec_key);
        replace_link(next_node, back_link, 0, enc_key, dec_key);

        List *tmp_list = calloc(1, sizeof(List));
        InitList(tmp_list);

        encrypt(tmp_list, insert_data, insert_size, enc_key, front_link, back_link);

        // join tmp_list to list[index]
        Node *prev_node = seekNode(list, block_index - 1);
        Node *next_node = seekNode(list, block_index);
        Node *tmp_head_node = tmp_list->head->next;
        Node *tmp_tail_node = tmp_list->head->next;
        tmp_head_node->prev = prev_node;
        tmp_tail_node->next = next_node;
        prev_node->next = tmp_head_node;
        next_node->prev = tmp_tail_node;
        list->count += tmp_list->count;

        free(tmp_list);

        unsigned char *new_metadata = calloc(insert_size/12 + 1, sizeof(unsigned char));
        update_metadata(new_metadata, insert_size);
        insert_global(global_metadata, new_metadata, block_index);
        free(new_metadata);
    }

    encrypt_global_metadata(global_metadata, enc_global_metadata, list->count, enc_key);
}

void encrypt_block(Node *node, link_t front_link, link_t back_link, bitmap_t bitmap, unsigned char *data,
                    const void *enc_key){
    unsigned char tmp_data[sizeof(node->data)] = {0, };
    int index = 0;

    tmp_data[index] = front_link;
    index += sizeof(link_t);

    tmp_data[index] = bitmap;
    index += sizeof(bitmap_t);

    memcpy(data, tmp_data + index, DATA_SIZE_IN_BLOCK);
    index += DATA_SIZE_IN_BLOCK;

    tmp_data[index] = back_link;

    AES_encrypt(tmp_data, &(node->data), enc_key);
}

void decrypt_block(Node *node, link_t *front_link, link_t *back_link, bitmap_t *bitmap, unsigned char *data,
                    const void *dec_key){
    unsigned char tmp_data[sizeof(node->data)] = {0, };

    AES_decrypt(&(node->data), tmp_data, dec_key);

    if(front_link){
        memcpy(front_link, tmp_data, sizeof(link_t));
    }

    if(back_link){
        memcpy(back_link, tmp_data + sizeof(node->data) - 1, sizeof(link_t));
    }

    if(bitmap){
        memcpy(bitmap, tmp_data + sizeof(link_t), sizeof(bitmap_t));
    }

    if(data){
        memcpy(data, tmp_data + DATA_START, DATA_SIZE_IN_BLOCK);
    }
}

link_t get_link(Node *node, char index, const void *dec_key){
    unsigned char tmp_data[sizeof(node->data)] = {0, };
    index = index < 0 ? (sizeof(node->data) + index) : index;

    AES_decrypt(&(node->data), tmp_data, dec_key);
    return tmp_data[index];
}

bitmap_t get_bitmap(Node *node, const void *dec_key){
    unsigned char tmp_data[sizeof(node->data)] = {0, };
    unsigned char index = sizeof(link_t);                       // bitmap is next of front link

    AES_decrypt(&(node->data), tmp_data, dec_key);
    return tmp_data[index];                                     // Todo: check return size
}

unsigned char *get_data(Node *node, const void *dec_key){
    unsigned char tmp_data[sizeof(node->data)] = {0, };
    AES_decrypt(&(node->data), tmp_data, dec_key);

    unsigned char *data = calloc(DATA_SIZE_IN_BLOCK, sizeof(unsigned char));
    memcpy(data, tmp_data[DATA_START], DATA_SIZE_IN_BLOCK);
    return data;
}

void replace_link(Node *node, link_t link, char index, const void *enc_key, const void *dec_key){
    unsigned char data[sizeof(node->data)] = {0, };
    index = index < 0 ? (sizeof(node->data) + index) : index;

    AES_decrypt(&(node->data), data, dec_key);
    data[index] = link;
    AES_encrypt(data, &(node->data), enc_key);
}

int copy_data(unsigned char *dst, unsigned char *src, bitmap_t *bitmap){
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

int find_block_start(int index, int *block_index, unsigned char *global_metadata){
    int block_start = 0;

    while(block_start <= index)
    {
        block_start += (int) global_metadata[*block_index];
        (*block_index)++;
    }

    (*block_index)--;
    block_start -= (int) global_metadata[*block_index];

    return block_start;
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
