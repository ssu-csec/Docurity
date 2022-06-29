#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include "form.h"

#define CLIENT_MAX 30

void server(int socket);
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int serv_sock;
	int clnt_sock;
    int connectCnt = 0;

	pthread_t thread_id;

	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;

    unsigned char msg[BUFSIZE] = {0, };

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

	while(1)
	{
		clnt_sock=accept(serv_sock, (struct sockaddr_in*)&clnt_addr, &clnt_addr_size);
		if(clnt_sock==-1)
			continue;
		else
			printf("Connected client %d \n", ++connectCnt);

		pthread_create(&thread_id, NULL, server, clnt_sock);
	}

	close(serv_sock);
	return 0;
}

void server(int socket)
{
	char writeBuf[256] = "received well!";
	char readBuf[256];

	while(1)
	{
		read(socket, &readBuf, sizeof(readBuf));
		printf("%s\n", readBuf);
		write(socket, &writeBuf, sizeof(writeBuf));

		if((strcmp(readBuf, "quit"))==0)
			break;
	}

	close(socket);
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}
