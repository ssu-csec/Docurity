#ifndef PACKET_H_
#define PACKET_H_

#define DELETE 0x00
#define INSERT 0x01

#define GLOBAL_META 0x00
#define DATA 0x01

#define BUFSIZE 1024

typedef struct _packet{
	unsigned char msgType;
	void *data;
} PACKET;

typedef struct _node_send{
	unsigned char inst;
    int index;
	unsigned char *data;
} NODE_SEND;

#endif 
