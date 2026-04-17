//File: encode.c
//Author: Marina Kania
//////////////////////////////////

#include "cbc_lib.h"
#include <stdio.h>
#include <stdlib.h>

//Reads from stdin and writes CBC-encrypted output to file
int main(int argc, char *argv[]){
    if(argc != 2){
        fprintf(stderr, "usage: encode to-file-name  # from standard input\n");
        return EXIT_FAILURE;
    }
    if(encode(argv[1]) != 0){
        fprintf(stderr, "FAILED\n");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "ok\n");
    return EXIT_SUCCESS;
}
