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

void insert_global(unsigned char *in, unsigned char *insert, int index)
{
    unsigned char *temp = calloc(strlen(in) - index, sizeof(unsigned char));
    memcpy(temp, in+index, strlen(in) - index);
    memcpy(in+index, insert, strlen(insert));
    memcpy(in+index+strlen(insert), temp, strlen(in) - index);

    free(temp);
}

void delete_global(unsigned char *in, int index, int length)
{
    unsigned char *temp = calloc(strlen(in) - index - length, sizeof(unsigned char));
    memcpy(temp, in + index + length, strlen(in) - index - length);
    memcpy(in+index, temp, strlen(in) - index - length);
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

    if(len == 0)
        return;
    
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
        memcpy(tmp, &(new_node->data), 16);
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
        memcpy(tmp, &(front_node->data), 16);
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
        memcpy(&(front_node->data), tmp, 16);
        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = front_block_num - 2;
        packet->data = node_send;
        memcpy(node_send->data, tmp, 16);
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        memcpy(tmp, &(back_node->data), 16);
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
        memcpy(&(back_node->data), tmp, 16);
        packet->msgType = DATA;
        node_send->inst = INSERT;
        node_send->index = back_block_num;
        packet->data = node_send;
        memcpy(node_send->data, tmp, 16);
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

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

        delete_global(plain_gmeta, front_block_num, back_block_num - front_block_num);

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
        int cnt = 0;
        AES_decrypt(&(front_node->data), tmp, dec_key);
        front_link = tmp[0];
        AES_decrypt(&(back_node->data), tmp, dec_key);
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
                cnt++;
            }
            check_bitmap = check_bitmap >> 1;
        }
        memcpy(&tmp[1], &meta, 2);
        tmp[0] = front_link;
        tmp[15] = back_link;
        plain_gmeta[back_block_num - 1] = (char)cnt;
        AES_encrypt(tmp, tmp, 16);

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

        delete_global(plain_gmeta, front_block_num, back_block_num - front_block_num - 2);


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
        int cnt = 0;
        AES_decrypt(&(front_node->data), tmp, dec_key);
        front_link = tmp[0];
        AES_decrypt(&(back_node->data), tmp, dec_key);
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
        tmp[0] = front_link;
        tmp[15] = back_link;
        plain_gmeta[front_block_num] = (char)cnt;
        AES_encrypt(tmp, tmp, 16);
 
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

        delete_global(plain_gmeta, front_block_num + 1, back_block_num - front_block_num - 1);

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

        int n = 0;
        int cnt = 0;
        while(n < 12 && cnt < front_len)
        {
            if(meta & check_bitmap != 0)
            {
                data[cnt] = tmp[n + LINK_LENGTH + METADATA_LENGTH];
                cnt++;
            }

            check_bitmap = check_bitmap >> 1;
            n++;

        }

        AES_decrypt(&(back_node->data), tmp, dec_key);
        back_link = tmp[15];

        memcpy(&meta, &tmp[1], 2);

        check_bitmap = (unsigned short)1;
        n = 11;
        cnt = front_len + back_len -1;
        while(n >= 0 && cnt >= front_len)
        {
            if(meta & check_bitmap != 0)
            {
                data[cnt] = tmp[n + LINK_LENGTH + METADATA_LENGTH];
                cnt--;
            }

            check_bitmap = check_bitmap << 1;
            n--;
        }

        for(cnt = front_block_num; cnt < back_block_num; cnt++)
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


        free(packet);
        free(node_send);
    }

    global_encrypt(plain_gmeta, global_meta, out->count, enc_key);
    PACKET *packet = calloc(1, sizeof(PACKET));
    packet->msgType = GLOBAL_META;
    memcpy(packet->data, global_meta, gmeta_len);
    packing_data(packet, msg);
    write(socket, msg, BUFSIZE);
    memset(msg, 0, BUFSIZE);
    write(socket, "finish", BUFSIZE);
}

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket)                                                                      // gmeta_len is the number of blocks
{
    srand(time(NULL));
    unsigned char front_link = rand()%256;
    unsigned char back_link = rand()%256;

    unsigned char *insert_data;
    unsigned char *plain_gmeta;

    List *list;
    InitList(list);

    Node *node;
    unsigned short meta;

    unsigned char msg[BUFSIZE] = {0, };

    if(index == 0 && out->count == 0)
    {
        int cnt = 0;
        encrypt(in,list, ins_len, enc_key, front_link, front_link);
        for(int i = 0; i < list->count; i++)
        {
            node = seekNode(out, i);
            PACKET *packet = calloc(1, sizeof(PACKET));
            packet->msgType = DATA;
            NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
            node_send->inst = INSERT;
            node_send->index = i;
            node_send->data = calloc(16, sizeof(unsigned char));
            memcpy(node_send->data, &(node->data), 16);
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
            free(packet);
            free(node_send);
        }
        plain_gmeta = calloc(list->count, sizeof(unsigned char));
        while(ins_len > 12)
        {
            plain_gmeta[cnt] = 12;
            ins_len -=12;
            cnt++;
        }
        plain_gmeta[cnt] = ins_len;

        global_encrypt(plain_gmeta, global_meta, list->count, enc_key);
        PACKET *packet = calloc(1, sizeof(PACKET));
        packet->msgType = GLOBAL_META;
        packet->data = global_meta;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);

        write(socket, "finish", BUFSIZE);
        return;
    }

    int enc_gmeta_len;
    if((out->count)%(AES_BLOCK_SIZE - 2*LINK_LENGTH) == 0)
        enc_gmeta_len = ((out->count)/(AES_BLOCK_SIZE - 2*LINK_LENGTH))*AES_BLOCK_SIZE;
    else
        enc_gmeta_len = ((out->count)/(AES_BLOCK_SIZE - 2*LINK_LENGTH)+1)*AES_BLOCK_SIZE;
        
    
    plain_gmeta = calloc((out->count), sizeof(unsigned char));

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

        AES_decrypt(&(node->data), tmp, dec_key);
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

        int len = strlen(insert_data);
        unsigned char *add_global = calloc(len/12 + 1, sizeof(unsigned char));
        if(len > 12)
        {
            plain_gmeta[block_num] += (index - check);
            len -= (index - check);
        }
        int i = 0;
        while(len > 0)
        {
            if(len > 12)
                add_global[i] = (unsigned char)12;

            else
                add_global[i] = (unsigned char)len;
            len -= 12;
        }

        encrypt(insert_data, list, ins_len + strlen(add_data), enc_key, front_link, back_link);
        for(int i = 0; i < list->count; i++)
        {
            node = seekNode(out, i);
            PACKET *packet = calloc(1, sizeof(PACKET));
            packet->msgType = DATA;
            NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
            node_send->inst = INSERT;
            node_send->index = i + block_num;
            node_send->data = calloc(16, sizeof(unsigned char));
            memcpy(node_send->data, &(node->data), 16);
            packet->data = node_send;
            packing_data(packet, msg);
            write(socket, msg, BUFSIZE);
            memset(msg, 0, BUFSIZE);
            free(packet);
            free(node_send);
        }

        insert_global(plain_gmeta, insert_data, index);
    }

    else
    {
        Node *prev_node = seekNode(out, block_num - 1);
        PACKET *packet = calloc(1, sizeof(PACKET));
        NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
        unsigned char tmp[16] = {0, };
        AES_decrypt(&(prev_node->data), tmp, dec_key);
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
        memcpy(&(node_send->data), tmp, 16);
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        Node *next_node = seekNode(out, block_num);
        AES_decrypt(&(next_node->data), tmp, dec_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = block_num;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);

        tmp[0] = back_link;
        AES_encrypt(tmp, &(prev_node->data), enc_key);
        packet->msgType = DATA;
        node_send->inst = DELETE;
        node_send->index = block_num - 1;
        packet->data = node_send;
        packing_data(packet, msg);
        write(socket, msg, BUFSIZE);
        memset(msg, 0, BUFSIZE);
        memcpy(insert_data, in, ins_len);
        
        free(packet);
        free(prev_node);
        free(next_node);
    }

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
        memcpy(node_send->data, &(node->data), 16);
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

    write(socket, "finish", BUFSIZE);

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
