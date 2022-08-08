#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "form.h"

AES_KEY *gen_enc_key(const char *cts128_test_key){
    AES_KEY *key;
    key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_encrypt_key(cts128_test_key, 128, key);
    return key;
}

AES_KEY *gen_dec_key(const char *cts128_test_key){
    AES_KEY *key;
    key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, key);
    return key;
}

unsigned char *gen_ivec(){
    unsigned char *ivec = (unsigned char*)malloc(16 *sizeof(unsigned char));

    for(int i = 0; i < 16; i++)
    {
        ivec[i] = (unsigned char)(rand()%256);
    }

    return ivec;
}


int main(int argc, char **argv)
{
    if(argc < 1){
        printf("Wrong argument: ./<binary> <input file>");
        return ;
    }

    // buffer fread from file(argv[1])
    // 1. open file
    // 2. fread to buffer if not EOF

    char *file_name = argv[1];
    FILE *input_file = fopen(file_name, "r");
    if (input_file == NULL) {
        fputs("File error", stderr);
        exit(1);
    }

    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    rewind(input_file);

    srand(time(NULL));

    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
    AES_KEY *enc_key = gen_enc_key(cts128_test_key);
    AES_KEY *dec_key = gen_dec_key(cts128_test_key);
    unsigned char ivec = gen_ivec();

    List *cipherText = (List *)calloc(1, sizeof(List));
    InitList(cipherText);

    int global_metadata_size = file_size;
    int result_size = global_metadata_size * 12;

    unsigned char *global_metadata = (unsigned char*)calloc(global_metadata_size, sizeof(unsigned char));
    unsigned char *result = (unsigned char*)calloc(result_size, sizeof(unsigned char));

    unsigned char *buffer = (unsigned char*)calloc(file_size, sizeof(unsigned char));
    unsigned char operation[10] = {0, };

    int is_data_read = 0;
    int index = 0;
    long current_seek = 0;
    while(1)
    {
        // read operation
        current_seek = ftell(input_file);
        if(current_seek == file_size)
            break;

        fgets(buffer, file_size, input_file);

        strcpy(operation, buffer);


        // read index
        fgets(buffer, file_size, input_file);
        index = atoi(buffer);

        // read data
        fgets(buffer, file_size, input_file);

        // do something!
        if(strncmp(operation, "Insert", 6) == 0)
        {
            start = clock();
            cbc_insert(buffer, cipherText, ivec, index, strlen(buffer), enc_key, dec_key);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("%f\n", cpu_time_used);
        }
        else if(strncmp(operation, "Modify", 6) == 0)
        {
            cbc_modify(buffer, cipherText, ivec, index, strlen(buffer), enc_key, dec_key);
        }
        else if(strncmp(operation, "Delete", 6) == 0)
        {
            cbc_delete(cipherText, ivec, index, length, enc_key, dec_key);
        }

        memset(buffer, 0, 1); //clear buffer
    }

    cbc_decrypt(cipherText, result, ivec, dec_key);

    return 0;
}