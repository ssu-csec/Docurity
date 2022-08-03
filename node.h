#include <stdlib.h>
#include <openssl/modes.h>
#include "packet.h"
#define LINK_LENGTH 1
#define METADATA_LENGTH 2
#define BITMAP_SEED 2048

typedef struct _node
{
    unsigned char data[16];
    struct _node *prev;
    struct _node *next;
} Node;

typedef struct _list
{
    Node *head;
    Node *tail;
    int count; 
} List;

void InitList(List *list);

void ResetList(List *list);

Node *createNode(unsigned char data[16]);

void removeNode(Node *this);

void insertNode(Node *this, Node *next);

Node *seekNode(List *list, int index);
