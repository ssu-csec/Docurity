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
    unsigned char global_meta[BUFSIZE] = {0, };

    unsigned char front_ivec = rand() % 256;
    unsigned char back_ivec = front_ivec;

    AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
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
    unsigned char result[BUFSIZE * 10];
    int index = 0;


    while(1)
    {
        printf("\nInsert or Delete? ");
        scanf("%s", inst);

        if(strncmp(inst, "f", 1) == 0)
            break;

        printf("\ninput index: ");
        scanf("%d", &index);

        if(strncmp(inst, "i", 1) == 0)
        {
            printf("\ninput data: ");
            scanf("%s", input);

            insertion(cipherText, input, index, strlen(input), enc_key, dec_key, global_meta);
        }
        else if(strncmp(inst, "d", 1) == 0)
        {
            int length = 0;
            printf("\ninput delete length");
            scanf("%d", &length);

            deletion(cipherText, index, length, enc_key, dec_key, global_meta);
        }

        printf("list size: %d\n", cipherText->count);

	    decrypt(result, cipherText, dec_key);
	    printf("decrypted data : %s\n", result);
        memset(result, 0, BUFSIZE * 10);
    }

    decrypt(result, cipherText, dec_key);

    printf("decrypted data : %s", result);

    return 0;
}
