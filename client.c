#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "form.h"
void error_handling(char *message);

int main(int argc, char *argv[])
{

	int sock;
	struct sockaddr_in serv_addr;

    List *cipherText = (List *)calloc(1, sizeof(List));
    InitList(cipherText);

    AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
    AES_set_encrypt_key(cts128_test_key, 128, enc_key);

    AES_KEY *dec_key;
    dec_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, dec_key);

    unsigned char global_meta[256] = {0, };
	unsigned char message[2048] = {0, };
    int index = 0;
	int str_len;

	if(argc != 3)
	{
		printf("Usage : %s <IP> <port>\n:", argv[0]);
		exit(1);
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1)
		error_handling("socket() error");
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error!");
	
    while(1)
    {
        if (read(sock, global_meta, 256) == -1)
            error_handling("read() error!");
        printf("insert data: ");
        scanf("%s", &message);
        printf("insert index: ");
        scanf("%d", index);
    }

	close(sock);
	return 0;
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}