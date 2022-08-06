#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "form.h"

int main()
{
    srand(time(NULL));

    List *cipherText = (List *)calloc(1, sizeof(List));
    InitList(cipherText);

    AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan-539";
    AES_set_encrypt_key(cts128_test_key, 128, enc_key);

    AES_KEY *dec_key;
    dec_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, dec_key);

    unsigned char ivec[16] = {0, };

    for(int i = 0; i < 16; i++)
    {
        ivec[i] = (unsigned char)(rand()%256);
    }

    unsigned char input[BUFSIZE];
    unsigned char inst[10] = {0, };
    int index = 0;

    while(1)
    {
        printf("Insert or Delete? : ");
        scanf("%s", inst);
        if(strncmp(inst, "finish", 6) == 0)
            break;
        printf("input index : ");
        scanf("%d", &index);
        if(strncmp(inst, "Insert", 6) == 0)
        {
            printf("input data : ");
            scanf("%s", input);
            cbc_insert(input, cipherText, ivec, index, strlen(input), enc_key, dec_key);
        }
        else if(strncmp(inst, "Delete", 6) == 0)
        {
            int length = 0;
            printf("input delete length : ");
            scanf("%d", &length);
            cbc_delete(cipherText, ivec, index, length, enc_key, dec_key);
        } 
    }

    unsigned char result[BUFSIZE * 10] = {0, };
    cbc_decrypt(cipherText, result, ivec, dec_key);

    printf("decrypted data : %s", result);

    return 0;
}