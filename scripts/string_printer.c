#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main (int argc, char **argv) {
    if(argc < 1){
        printf("Wrong argument: ./<binary> <size>");
        return ;
    }

	srand((unsigned int)(time(NULL)));
	unsigned int size = atoi(argv[1]);

	char char1[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/,.-+=~`<>:";
	for(int index = 0; index < size; index++)
	{
		printf("%c", char1[rand() % (sizeof char1 - 1)]);
	}
	printf("\n");
	return 0;
}
