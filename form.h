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

void global_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                    const void *enc_key);

void global_decrypt(const unsigned char *in, unsigned char *out, size_t len, 
                            const void *dec_key);

void encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec);

void decrypt(List *in, unsigned char *out, const void *dec_key);

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket);

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int socket);
void InitList(List *list);

Node *createNode(unsigned char data[16]);

void removeNode(Node *this);

void insertNode(Node *this, Node *next);

Node *seekNode(List *list, int index);

void insertMiddle(Node *this, Node *prev);

void packing_data(PACKET *packet, unsigned char *msg);
