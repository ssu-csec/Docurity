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
    unsigned char data[16] = {0, };
    list->head = createNode(data);
    list->tail = createNode(data);
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

Node *seekNode(List *list, int index)
{
    Node *seek = list->head->next;
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
