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

    clock_t start, end;
    double cpu_time_used;

    while(1)
    {
        scanf("%s", inst);
        if(strncmp(inst, "finish", 6) == 0)
            break;
        scanf("%d", &index);
        if(strncmp(inst, "Insert", 6) == 0)
        {
            scanf("%s", input);
            start = clock();
            cbc_insert(input, cipherText, ivec, index, strlen(input), enc_key, dec_key);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        }
        else if(strncmp(inst, "Delete", 6) == 0)
        {
            int length = 0;
            scanf("%d", &length);
            start = clock();
            cbc_delete(cipherText, ivec, index, length, enc_key, dec_key);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        } 
    }

    unsigned char result[BUFSIZE * 10] = {0, };
    cbc_decrypt(cipherText, result, ivec, dec_key);


    return 0;
}
