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
	unsigned char writeBuf[BUFSIZE];
	unsigned char readBuf[BUFSIZE];
	unsigned char input[BUFSIZE];

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
	
	AES_KEY *enc_key;
    enc_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    unsigned char cts128_test_key[16] = "Jeonsan-Gwan 539";
    AES_set_encrypt_key(cts128_test_key, 128, enc_key);

    AES_KEY *dec_key;
    dec_key = (AES_KEY*)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(cts128_test_key, 128, dec_key);

	List *list;
	list = calloc(1, sizeof(List));
	InitList(list);
	unsigned char *global_meta;
	global_meta = calloc(BUFSIZE, sizeof(unsigned char));

	while(1)
	{
		while(1)
		{
			memset(global_meta, 0, BUFSIZE);
			ResetList(list);
			read(sock, &readBuf, sizeof(readBuf));
			if(strncmp(readBuf, "finish", 6) == 0)
				break;
			else if(readBuf[0] == GLOBAL_META)
				unpacking_global(readBuf, global_meta);
			else if(readBuf[0] == DATA)
			{
				Node *new_node = calloc(1, sizeof(Node));
				unpacking_data(readBuf, new_node, list);
			}
			memset(&readBuf, 0, BUFSIZE);
		}
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
			insertion(input, list, index, strlen(input), enc_key, dec_key, global_meta, sock);
		}
		else if(strncmp(inst, "Delete", 6) == 0)
		{
			int length = 0;
			printf("input delete length");
			scanf("%d", &length);
			deletion(list, index, length, enc_key, dec_key, global_meta, sock);
		}
		else
		{
			printf("Wrong instruction!\n");
			break;
		}

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
