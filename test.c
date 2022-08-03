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

    size_t plainTextLen = 0;
    size_t cipherTextLen = 0;
    unsigned char *plainText;
    

    List *cipherText = (List *)calloc(1, sizeof(List));
    InitList(cipherText);
    unsigned char global_meta[128] = {0, };

    unsigned char front_ivec = rand() % 256;
    unsigned char back_ivec = front_ivec;

    AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
    AES_set_encrypt_key(cts128_test_key, 128, enc_key);

    AES_KEY *dec_key;
    dec_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, dec_key);

    unsigned char input[BUFSIZE];
    unsigned char inst[10] = {0, };
    int index = 0;
    printf("Insert or Delete? ");
    scanf("%s", &inst);
    printf("input index: ");
    scanf("%d", &index);
    if(strncmp(inst, "Insert", 6) == 0)
    {
        printf("input data: ");
        scanf("%s", &input);
        insertion(input, cipherText, index, strlen(input), enc_key, dec_key, global_meta);
    }
    else if(strncmp(inst, "Delete", 6) == 0)
    {
        int length = 0;
        printf("input delete length");
        scanf("%d", &length);
        deletion(cipherText, index, length, enc_key, dec_key, global_meta);
    }



    unsigned char result[BUFSIZE * 10];
    decrypt(cipherText, result, dec_key);

    printf("decrypted data : %s", result);

    return 0;
}