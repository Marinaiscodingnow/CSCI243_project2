//File: decode.c
//Author: Marina Kania
////////////////////////////////

#include "cbc_lib.h"
#include <stdio.h>
#include <stdlib.h>

//Reads a CBC-encrypted file and writes a plaintext to stdout
int main(int argc, char *argv[]){
    if(argc != 2){
        fprintf(stderr, "usage: decode from-file-name\n");
        return EXIT_FAILURE;
    }

    if(decode(argv[1]) != 0){
        fprintf(stderr, "FAILED\n");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "ok\n");
    return EXIT_SUCCESS;
}
