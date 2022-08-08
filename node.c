#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "node.h"
#include "packet.h"

void InitList(List *list)
{
    unsigned char empty_data[16] = {0, };
    Node *dummy_head = createNode(empty_data);
    Node *dummy_tail = createNode(empty_data);
    list->head = dummy_head;
    list->tail = dummy_tail;
    list->head->next = list->tail;
    list->tail->prev = list->head;
    list->count = 0;

    return;  
}

void ResetList(List *list)
{
    for(int i = 0; i < list->count; i++)
    {
        removeNode(list->head->next);
    }
    list->count = 0;
}

Node *createNode(unsigned char data[16])
{
    Node *new_node = (Node *)calloc(1, sizeof(Node));

    memcpy(&(new_node->data), data, 16); 

    return new_node;
}

void removeNode(Node *this)
{
    this->prev->next = this->next;
    this->next->prev = this->prev;
    free(this);
}

void removeNodes(List *list, int start, int size){
    for(int block_num = start; block_num < size; block_num++)
    {
        removeNode(seekNode(list, block_num));
    }
}

Node *seekNode(List *list, int index)
{
    Node *seek = list->head->next;
    if (index == -1){
        return list->head;
    }
    else if (index < -1 || index >= list->count){
        return seek;
    }

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
