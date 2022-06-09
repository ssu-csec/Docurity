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
    

    unsigned char cipherText[2048] = {0, };

    unsigned char front_ivec = rand() % 256;
    unsigned char back_ivec = front_ivec;

    AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
    AES_set_encrypt_key(cts128_test_key, 128, enc_key);

    AES_KEY *dec_key;
    dec_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, dec_key);

    FILE *fp;
    fp = fopen("test.txt", "r");

    fseek(fp, 0, SEEK_END);
    plainTextLen = ftell(fp);

    int outlen;

    fseek(fp, 0, SEEK_SET);

    plainText = (unsigned char*)calloc(plainTextLen, sizeof(unsigned char));

    fread(plainText, plainTextLen, 1, fp);
    fclose(fp);

    cipherTextLen = encrypt(plainText, cipherText, plainTextLen, enc_key, front_ivec, back_ivec, (block128_f) AES_encrypt);

    fp = fopen("cipher.txt", "w+");


    for(int i = 0; i < cipherTextLen; i++)
    {
        fprintf(fp, "%c", cipherText[i]);
    }

 
    fclose(fp);
    

    fp = fopen("cipher.txt", "r+");
    unsigned char *out;

    out = calloc(plainTextLen, sizeof(unsigned char));    

    char buf[4096] = {0,};
    
    
    fread(buf, 1, cipherTextLen, fp);
    printf("buff : %s\n", buf);
    decrypt(buf, out, cipherTextLen, dec_key, (block128_f) AES_decrypt);

    printf("Decrypted data: ");
    for(int i = 0; i < plainTextLen; i++)
    {
        printf("%c", out[i]);
    }
    printf("\n\n");
    
    fclose(fp);

    return 0;
}