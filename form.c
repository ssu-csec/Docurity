#include <string.h>
#include <stdlib.h>
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
        insertNode(new_node, out->tail);

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
    insertNode(new_node, out->tail);

    return;
}

void decrypt(List *in, unsigned char *out, const void *dec_key)
{
    int n = 0;
    int cnt = 0;
    int c = in->count;
    unsigned char tmp[AES_BLOCK_SIZE] = {0, };
    unsigned char link_front = 0;
    unsigned char link_back = 0;
    unsigned short meta;
    Node *new_node = in->head;

    while(c) {
        new_node = new_node->next;
        memcpy(tmp, new_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);

        link_front = tmp[0];
        if(cnt != 0 && link_front != link_back)
        {
            printf("front: %x / back: %x => link unmatch! Something is wrong! %d\n", link_front, link_back, c);
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
        c--;
        out += cnt;
    }
}

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket)                                          // gmeta_len is the number of blocks
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    unsigned char msg[BUFSIZE] = {0, };

    unsigned short meta = 0;

    int gmeta_len = out->count;

    int enc_gmeta_len;
    if(gmeta_len%(AES_BLOCK_SIZE - 2*LINK_LENGTH) == 0)
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH))*AES_BLOCK_SIZE;
    else
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH)+1)*AES_BLOCK_SIZE;
    
    unsigned char *plain_gmeta;
    plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));

    unsigned char *modify_gmeta;

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);

    int check1 = 0;
    int front_block_num = 0;

    while(check1 <= index)
    {
        check1 += (int)plain_gmeta[front_block_num];
        front_block_num++;
    }
    front_block_num--;
    check1 -= (int)plain_gmeta[front_block_num];

    int check2 = 0;
    int back_block_num = 0;

    while(check2 < index + del_len)
    {
        check2 += (int)plain_gmeta[back_block_num];
        back_block_num++;
    }
    // back_block_num--;
    // check2 -= (int)plain_gmeta[back_block_num];


    if(check1 == index && check2 == index + del_len)
    {
        Node *front_node = seekNode(out, front_block_num);
        Node *back_node = seekNode(out, back_block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        unsigned char tmp[16] = {0, };
        memcpy(tmp, front_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = front_block_num - 1;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);
        tmp[15] = front_link;
        AES_encrypt(tmp, tmp, enc_key);
        memcpy(front_node->data, tmp, 16);
        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = front_block_num - 2;
        packet->data = node_send;
        memcpy(node_send->data, tmp, 16);
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        memcpy(tmp, back_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = back_block_num;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);
        tmp[0] = front_link;
        AES_encrypt(tmp, tmp, enc_key);
        memcpy(back_node->data, tmp, 16);
        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = back_block_num;
        packet->data = node_send;
        memcpy(node_send->data, tmp, 16);
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        front_node->prev->next = back_node->next;
        back_node->next->prev = front_node->prev;
        for(int i = front_block_num; i < back_block_num; i++)
        {
            packet->msgType = DATA;
            node_send->inst = DELETE;
            node_send->index = front_block_num;
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
        }

        out->count = out->count - (back_block_num - front_block_num);

        modify_gmeta = calloc(out->count, sizeof(unsigned char));
        memcpy(modify_gmeta, plain_gmeta, front_block_num);
        memcpy(modify_gmeta, plain_gmeta+back_block_num, out->count - front_block_num);

        free(packet);
        free(node_send);
    }

    else if(check1 == index && check2 != index + del_len)
    {
        Node *front_node = seekNode(out, front_block_num);
        Node *back_node = seekNode(out, back_block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        unsigned char tmp[16] = {0, };
        memcpy(tmp, front_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        front_link = tmp[0];
        memcpy(tmp, back_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        back_link = tmp[15];
        memcpy(&meta, &tmp[1], 2);
        int n = front_block_num;
        while(del_len > 0)
        {
            del_len -= plain_gmeta[n];
            n++;
        }

        n--;
        del_len += plain_gmeta[n];
        unsigned short check_bitmap = (unsigned short)BITMAP_SEED;
        for(int i = LINK_LENGTH + METADATA_LENGTH; i < AES_BLOCK_SIZE; i++)
        {
            if((meta & check_bitmap) != 0 && del_len > 0)
            {
                tmp[i] = 0;
                meta = meta ^ check_bitmap;
            }
            check_bitmap = check_bitmap >> 1;
        }
        memcpy(&tmp[1], &meta, 2);
        AES_encrypt(tmp, back_node->data, 16);

        front_node->prev->next = back_node;
        back_node->prev = front_node->prev;
        for(int i = front_block_num; i < back_block_num; i++)
        {
            packet->msgType = DATA;
            node_send->inst = DELETE;
            node_send->index = front_block_num;
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
        }

        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = front_block_num - 1;
        memcpy(node_send->data, tmp, 16);
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);


        free(packet);
        free(node_send);
    }

    else if(check1 != index && check2 == index + del_len)
    {
        Node *front_node = seekNode(out, front_block_num);
        Node *back_node = seekNode(out, back_block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        unsigned char tmp[16] = {0, };
        memcpy(tmp, front_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        front_link = tmp[0];
        memcpy(tmp, back_node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        back_link = tmp[15];
        memcpy(&meta, &tmp[1], 2);

        int n = back_block_num;
        while(del_len > 0)
        {
            del_len -= plain_gmeta[n];
            n--;
        }

        n++;
        del_len += plain_gmeta[n];

        unsigned short check_bitmap = (unsigned short)1;
        for(int i = AES_BLOCK_SIZE - 1; i >= LINK_LENGTH + METADATA_LENGTH; i--)
        {
            if((meta & check_bitmap) != 0 && del_len > 0)
            {
                tmp[i] = 0;
                meta = meta ^ check_bitmap;
            }
            check_bitmap = check_bitmap << 1;
        }
        memcpy(&tmp[1], &meta, 2);

        front_node->next = back_node->next;
        back_node->next->prev = front_node;
        for(int i = front_block_num; i < back_block_num; i++)
        {
            packet->msgType = DATA;
            node_send->inst = DELETE;
            node_send->index = front_block_num;
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
        }

        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = front_block_num - 1;
        memcpy(node_send->data, tmp, 16);
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        free(packet);
        free(node_send);
    }

    else
    {
        Node *front_node = seekNode(out, front_block_num);
        Node *back_node = seekNode(out, back_block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        int front_len = 0;
        int back_len = 0;
        unsigned char *data;
        unsigned char tmp[16] = {0, };
        AES_decrypt(front_node->data, tmp, dec_key);
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

        int n = 0;
        int i = 0;
        while(n < 12 && i < front_len)
        {
            if(meta & check_bitmap != 0)
            {
                data[i] = tmp[n + LINK_LENGTH + METADATA_LENGTH];
                i++;
            }

            check_bitmap = check_bitmap >> 1;
            n++;

        }

        AES_decrypt(back_node->data, tmp, dec_key);
        back_link = tmp[15];

        memcpy(&meta, &tmp[1], 2);

        check_bitmap = (unsigned short)1;
        n = 11;
        i = front_len + back_len -1;
        while(n >= 0 && i >= front_len)
        {
            if(meta & check_bitmap != 0)
            {
                data[i] = tmp[n + LINK_LENGTH + METADATA_LENGTH];
                i--;
            }

            check_bitmap = check_bitmap << 1;
            n--;
        }

        for(i = front_block_num; i < back_block_num; i++)
        {
            packet->msgType = DATA;
            node_send->inst = DELETE;
            node_send->index = front_block_num;
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
        }

        List *new_list;
        InitList(new_list);
        encrypt(data, new_list, front_len + back_len, enc_key, front_link, back_link);
        front_node->prev->next = new_list->head->next;
        new_list->head = front_node->prev;
        back_node->next->prev = new_list->tail->prev;
        new_list->tail = back_node->next;

        free(packet);
        free(node_send);
    }

}

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket)                                                                      // gmeta_len is the number of blocks
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    unsigned char *insert_data;
    unsigned char *plain_gmeta;

    Node *node;
    unsigned short meta;

    unsigned char msg[BUFSIZE] = {0, };

    int gmeta_len = out->count;

    if(index == 0 && gmeta_len == 0)
    {
        int cnt = 0;
        encrypt(in, out, ins_len, enc_key, front_link, front_link);
        for(int i = 0; i < out->count; i++)
        {
            node = seekNode(out, i);
            PACKET *packet = calloc(1, sizeof(PACKET));
            packet->msgType = DATA;
            NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
            node_send->inst = INSERT;
            node_send->index = i;
            node_send->data = calloc(16, sizeof(unsigned char));
            memcpy(node_send->data, node->data, 16);
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
            free(packet);
            free(node_send);
        }
        gmeta_len = out->count;
        plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));
        while(ins_len > 12)
        {
            plain_gmeta[cnt] = 12;
            ins_len -=12;
            cnt++;
        }
        plain_gmeta[cnt] = ins_len;

        global_encrypt(plain_gmeta, global_meta, gmeta_len, enc_key);
        PACKET *packet = calloc(1, sizeof(PACKET));
        packet->msgType = GLOBAL_META;
        packet->data = global_meta;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        return;
    }

    int gmeta_push = 0;

    int enc_gmeta_len;
    if(gmeta_len%(AES_BLOCK_SIZE - 2*LINK_LENGTH) == 0)
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH))*AES_BLOCK_SIZE;
    else
        enc_gmeta_len = (gmeta_len/(AES_BLOCK_SIZE - 2*LINK_LENGTH)+1)*AES_BLOCK_SIZE;
        
    
    plain_gmeta = calloc(gmeta_len, sizeof(unsigned char));

    global_decrypt(global_meta, plain_gmeta, enc_gmeta_len, dec_key);

    int check = 0;
    int block_num = 0;

    unsigned char *modify_gmeta;

    while(check <= index)
    {
        check += (int)plain_gmeta[block_num];
        block_num++;
    }
    block_num--;
    check -= (int)plain_gmeta[block_num];

    if(check != index)
    {
        unsigned char *add_data = calloc((int)plain_gmeta[block_num], sizeof(unsigned char));
        unsigned char tmp[16] = {0, };
        ins_len += (int)plain_gmeta[block_num];
        insert_data = calloc(ins_len, sizeof(unsigned char));
        node = seekNode(out, block_num);

        memcpy(tmp, node->data, 16);
        AES_decrypt(tmp, tmp, dec_key);
        front_link = tmp[0];
        back_link = tmp[15];
        memcpy(&meta, &tmp[1], 2);
        int cnt = 0;

        for (int n = LINK_LENGTH + METADATA_LENGTH; n < AES_BLOCK_SIZE - LINK_LENGTH; ++n)
        {
            if((meta & BITMAP_SEED) != 0)
            {
                add_data[cnt] = tmp[n];
                cnt++;
                meta = meta << 1;
            }
        }
        memcpy(insert_data, add_data, index - check);
        memcpy(insert_data+(index - check), in, ins_len - (int)plain_gmeta[block_num]);
        memcpy(insert_data - ((int)plain_gmeta[block_num] - (index - check)), add_data+(index - check), (int)plain_gmeta[block_num] - (index - check));

        if(ins_len%12 == 0)
            gmeta_push = ins_len/12;
        else
            gmeta_push = ins_len/12+1;
        
        modify_gmeta = calloc(out->count + gmeta_push, sizeof(unsigned char));
        memcpy(modify_gmeta, plain_gmeta, block_num);
        memcpy(modify_gmeta + block_num + gmeta_push, plain_gmeta + block_num + 1, out->count - block_num - 1);

    }

    else
    {
        Node *prev_node = seekNode(out, block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        unsigned char tmp[16] = {0, };
        AES_decrypt(prev_node->data, tmp, dec_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = block_num - 1;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        tmp[15] = front_link;
        AES_encrypt(tmp, tmp, enc_key);
        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = block_num - 2;
        memcpy(node_send->data, tmp, 16);
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        Node *next_node = seekNode(out, block_num);
        AES_decrypt(next_node->data, tmp, dec_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = block_num;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        tmp[0] = back_link;
        AES_encrypt(tmp, prev_node->data, enc_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = block_num - 1;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);
        memcpy(insert_data, in, ins_len);

        if(ins_len%12 == 0)
            gmeta_push = ins_len/12;
        else
            gmeta_push = ins_len/12+1;
        
        modify_gmeta = calloc(out->count + gmeta_push, sizeof(unsigned char));
        memcpy(modify_gmeta, plain_gmeta, block_num);
        memcpy(modify_gmeta + block_num + gmeta_push, plain_gmeta + block_num, out->count - block_num);
        
        free(packet);
        free(prev_node);
        free(next_node);
    }

    List *list;
    InitList(list);
    encrypt(insert_data, list, ins_len, enc_key, front_link, back_link);
    list->head = seekNode(out, block_num-1);
    list->tail = seekNode(out, block_num);
    for(int i = 0; i < list->count; i++)
    {
        node = seekNode(list, i);
        PACKET *packet = calloc(1, sizeof(PACKET));
        packet->msgType = DATA;
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        node_send->inst = INSERT;
        node_send->index = i + block_num;
        node_send->data = calloc(16, sizeof(unsigned char));
        memcpy(node_send->data, node->data, 16);
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);
        free(packet);
        free(node_send); 
    }
    out->count += list->count;

    int cnt = 0;
    while(ins_len > 12)
    {
        modify_gmeta[block_num + cnt] = 12;
        ins_len -=12;
        cnt++;
    }
    plain_gmeta[block_num + cnt] = ins_len;
    global_encrypt(modify_gmeta, global_meta, out->count, enc_key);
    PACKET *packet = calloc(1, sizeof(PACKET));
    packet->msgType = GLOBAL_META;
    packet->data = global_meta;
    packing_data(packet, msg);
    write(socket, msg, BUFSIZE);
    free(packet);

}

void InitList(List *list)
{
    unsigned char data[16] = {0, };
    list->head = createNode(data);
    list->tail = createNode(data);
    list->head->next = list->tail;
    list->tail->prev = list->head;
    list->count = 0;

    return;  
}

Node *createNode(unsigned char data[16])
{
    Node *new_node = (Node *)calloc(1, sizeof(Node));

    memcpy(new_node->data, data, 16); 

    return new_node;
}

void removeNode(Node *this)
{
    this->prev->next = this->next;
    this->next->prev = this->prev;
    free(this);
}

Node *seekNode(List *list, int index)
{
    Node *seek = list->head;
    for(int i = 0; i < index; i++)
    {
        seek = seek->next;
    }
    return seek;
}

void insertNode(Node *this, Node *next)
{    
    this->prev = next->prev;
    this->next = next;
    next->prev->next = this;
    next->prev = this;



    return;
}

void packing_data(PACKET *packet, unsigned char *msg)
{
    memcpy(msg, packet->msgType, 1);
    msg++;
    if(packet->msgType == 0x00)
        memcpy(msg, packet->data, sizeof(packet->data));
    else
    {
        memcpy(msg, ((NODE_SEND*)packet->data)->inst, 1);
        msg++;
        memcpy(msg, ((NODE_SEND*)packet->data)->index, sizeof(int));
        msg += sizeof(int);
        memcpy(msg, ((NODE_SEND*)packet->data)->data, sizeof(((NODE_SEND*)packet->data)->data));
    }
}

void unpacking_data(unsigned char *msg, unsigned char *global_meta, List *list, Node *new_node)
{
    if(msg[0] == GLOBAL_META)
        memcpy(global_meta, msg+1, BUFSIZE - 1);
    else if(msg[0] == DATA)
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
            memcpy(new_node->data, msg+6, AES_BLOCK_SIZE);
            Node *node = calloc(1, sizeof(Node));
            int index;
            memcpy(index, msg+2, sizeof(int));
            node = seekNode(list, index);
            node->prev = new_node;
            new_node->next = node;
            free(node);
        }
    }


}