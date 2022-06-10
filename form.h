#include <stdlib.h>
#include <openssl/modes.h>
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

int encrypt(const unsigned char *in, List *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec);

void decrypt(List *in, unsigned char *out, size_t len, 
                            const void *dec_key);

void deletion(List *out, int index, int del_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int gmeta_len);

void insertion(unsigned char *in, List *out, int index, int ins_len, const void *enc_key, const void *dec_key, 
                unsigned char *global_meta, int gmeta_len);
void InitList(List *list);

Node *createNode(unsigned char data[16]);

void insertNode(Node *this, List *list);

void insertMiddle(Node *this, Node *prev, List *list);
