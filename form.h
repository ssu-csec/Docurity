#include <stdlib.h>
#include <openssl/modes.h>
#define LINK_LENGTH 1
#define METADATA_LENGTH 2
#define BITMAP_SEED 2048

int encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *enc_key, 
                           unsigned char front_ivec, unsigned char back_ivec);

void decrypt(const unsigned char *in, unsigned char *out, size_t len, 
                            const void *dec_key);

void deletion();

void insertion();