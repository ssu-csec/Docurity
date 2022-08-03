#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "form.h"
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int serv_sock;
	int clnt_sock;
    int i = 0;

	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;

	unsigned char writeBuf[BUFSIZE] = {0, };
	unsigned char readBuf[BUFSIZE] = {0, };

	if(argc != 2)
	{
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1)
		error_handling("socket() error");
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		error_handling("bind() error");
	
	if(listen(serv_sock, 5) == -1)
		error_handling("listen() error");
	
	clnt_addr_size = sizeof(clnt_addr);

	List *list;
	list = calloc(1, sizeof(List));
	InitList(list);
	unsigned char *global_meta;
	global_meta = calloc(BUFSIZE, sizeof(unsigned char));

	while(1)
	{
		clnt_sock=accept(serv_sock, (struct sockaddr_in*)&clnt_addr, &clnt_addr_size);
		if(clnt_sock==-1)
			continue;
		else
			printf("Connected client %d \n", ++i);
		while(1)
		{
			writeBuf[0] = GLOBAL_META;
			memcpy(&writeBuf+1, global_meta, BUFSIZE -1);
			write(clnt_sock, &writeBuf, sizeof(writeBuf));
			memset(&writeBuf, 0, BUFSIZE);
			Node *node = calloc(1, sizeof(Node));
			node = list->head->next;
			for(int i = 0; i < list->count; i++)
			{
				PACKET *packet = calloc(1, sizeof(packet));
				packet->msgType = DATA;
				NODE_SEND *node_send = calloc(1, sizeof(NODE_SEND));
				packet->data = node_send;
				node_send->inst = INSERT;
				node_send->index = i;
				memcpy(node_send->data, node->data, 16);
				packing_data(packet, &writeBuf);
				write(clnt_sock, &writeBuf, sizeof(writeBuf));
				memset(&writeBuf, 0, BUFSIZE);
				node = node->next;
				free(packet);
				free(node_send);
			}
			write(clnt_sock, "finish", BUFSIZE);
			while(1)
			{
				read(clnt_sock, &readBuf, sizeof(readBuf));
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
			//printf("%s\n", readBuf);

		}
	}

	close(serv_sock);
	return 0;
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}
