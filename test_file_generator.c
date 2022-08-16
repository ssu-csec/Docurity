#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define buf_size 1024

#define index 20

#define iteration 40

int main (int argc, char **argv)
{
    if(argc < 1){
        printf("Wrong argument: ./<binary> <input file>");
        return -1;
    }
    srand(time(NULL));

    int size = atoi(argv[1]);

    char char1[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/,.-+=~`<>:";

    char insert_data[buf_size] = {0, };

    for(int i = 0; i < buf_size; i++)
	{
		insert_data[i] = char1[rand() % (sizeof char1 - 1)];
	}
	
    char file_name[25];
    if(size/1024 == 0)
    {
        sprintf(file_name, "test_%s_%s.txt", argv[1], argv[2]);
    }
    else if(size/(1024*1024) == 0)
    {
        sprintf(file_name, "test_%dkb_%s.txt", size/1024, argv[2]);
    }
    else
    {
        sprintf(file_name, "test_%dmb_%s.txt", size/(1024*1024), argv[2]);
    }
    FILE *input_file = fopen(file_name, "w");
    if (input_file == NULL) {
        fputs("File error", stderr);
        exit(1);
    }
    
    fprintf(input_file, "Insert\n0\n");
    for(int i = 0; i < size; i++)
	{
		fprintf(input_file, "%c", char1[rand() % (sizeof char1 - 1)]);
	}
	fprintf(input_file, "\n");
    if(strncmp(argv[2], "Insert", 6) == 0)
    {
        for(int i = 0; i < iteration; i++)
        {
            fprintf(input_file, "Insert\n%d\n%s\n", index, insert_data);
        }
        
    }
    else if(strncmp(argv[2], "Delete", 6) == 0)
    {
        for(int i = 0; i < iteration; i++)
        {
            fprintf(input_file, "Delete\n%d\n%d\n", index, size/100);
        }
    }


    return 0;
}