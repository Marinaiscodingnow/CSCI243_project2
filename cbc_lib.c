//File: cbc_lib.c
//Author: Marina Kania
////////////////////////

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "cbc_lib.h"

static block64 key = 0x1234DeadBeefCafe; // each hex digit is 4 bits
static const block64 INITIALIZATION_VECTOR = 0x0L; // initial IV value


//Barrel roll right on block, by count number of bits,
//returning the resulting block value
static block64 roll_right(block64 block, size_t count){
    const size_t bits = sizeof(block64) * 8;
    //Handles if count is bigger than size
    count %= bits;

    return (block >> count) | (block << (bits - count));
}

//Barrel roll left on block, by count number of bits,
//returning the resulting block value
static block64 roll_left(block64 block, size_t count){
    const size_t bits = sizeof(block64)*8;
    //Handles if count is bigger than word size
    count %= bits;

    return (block << count) | (block >> (bits - count));
}

//Implements block cipher cncryption to encrypt the block using the key,
//returning the resulting block value. Input being plain text
//Output cipher text
static block64 block_cipher_encrypt(block64 block, block64 key){
    //For 4 rounds
    for(int i = 0; i < 4; i++){
        //First Operation: Rolls bits 10 to the left
        block = roll_left(block, 10);
        //Second Operation: XORs the rolled result with the key value
        block = block ^ key;
    }
    return block;
}

//Implements block cipher decryption, decrypt the block using the key,
//returning the resulting block value. Input ciphertext, Output plaintext.
static block64 block_cipher_decrypt( block64 block, block64 key){
    //For 4 rounds
    for(int i = 0; i < 4; i++){
        //First Operation: XORs the block with the key value
        block = block ^ key;
        //Second Operation: Rolls bits 10 to the right
        block = roll_right(block, 10);
    }
    return block;
}

//Fills the data character array with bytes from txt. Txt is plaintext 
//that is not NUL-terminated. Data array must be allocated and big enough
//to contain the block content plus a NUL byte. After execution data is a
//NULL-terminated string, representing a translation of txt
static void block64_to_string( block64 txt, char * data){
    size_t n = sizeof(block64);
    for(size_t i = 0; i < n; i++){
        data[i] = char((txt >> (8*i)) & 0xFF);
    }

    data[n] = '\0';
}

//Encrypts the text string using pIV and key, and returns the point to an 
//array of block64. pIV refering to either the initialization vector or 
//the ciphertext block of the prior stage. Returning the updated *pIV that is
//the ciphertext input of the next stage, the length of the returned array
//depending on the length of the text argument.
static block64 * cbc_encrypt( char * text, block64 * pIV, block64 key){
    int len = strlen(text);

    //Number of 64-bit blocks
    int num_blocks = (len +7)/8;

    block64 *cipher = malloc(num_blocks * sizeof(block64));
    if(!cipher) return NULL;

    unsigned char *padded = calloc(num_blocks * 8, 1);
    if (!padded) { free(ciphertext); return NULL; }
    memcpy(padded, text, text_len);

    for (size_t i = 0; i < num_blocks; i++) {
        
        //Load plain text bytes into a block64
        block64 pi = 0;
        for(int b = 0; b < 8; b++){
            pi = (pi << 8 | padded[i*8 + b];
        }

        //When i = 0, *pIV holds the IV playing the role of C(-1)
        block64 ci = block_cipher_encrypt(pi ^ *pIV, key);

        cipher[i] = ci;
        *pIV = ci;
    }
    free(padded);
    return cipher;
}

//Decrypts the ciphertext array of count blocks using pIV and key. Returning
//a text string representing the concatenation of the decrypted plaintexts
//of all the blocks within the array and an updated *pIV. With pIV reffering 
//to the initialization vector of the ciphertext block to feed forward to the 
//next stage
static char * cbc_decrypt(block64 *ciphertext, size_t count, block64 *pIV, 
block64 key){
    //Allocate output string
    char *text = calloc(count * 8 + 1, 1);
    if (!text) return NULL;

    for (size_t i = 0; i < count; i++) {

        block64 di = block_cipher_decrypt(ciphertext[i], key);
        //When i = 0, *pIV holds the IV playing the role of C(-1)
        block64 pi = di ^ *pIV;

        //Unpack pi into 8 bytes of the output string
        for (int b = 0; b < 8; b++)
            text[i * 8 + b] = (pi >> (56 - b * 8)) & 0xFF;

        //Update pIV
        *pIV = ciphertext[i];
    }

    return text;
}

//Encode standard input to a dile named in destpath, the function prints
//'ok' or 'FAILED' to stderr on completion, returning EXIT_SUCCESS or 
//EXIT_FAILURE
int encode(const char*destpath){
    //Read stdin
    size_t capacity = 4096;
    size_t length = 0;
    char *buf = malloc(capacity);
    if(!buf){
        fprintf(stderr, "out of memory \n");
        return EXIT_FAILURE;
    }

    int c;
    while((c = fgetc(stdin)) != EOF){
        if(length +1 >= capacity){
            capacity *= 2;
            char *tmp realloc(buf, capacity);
            if(!tmp){
                free(buf);
                fprintf(stderr, "out of memory\n");
                return EXIT_FAILURE;
            }
            buf = tmp;
        }
        buf[length++] = char(c);
    }
    buf[length] = '\0';

    //encrypt
    block64 iv = INITIALIZATION_VECTOR;
    block64 *cipherblocks = cbc_encrypt(buf, &iv, key);
    free(buf);
    if(!cipherblocks){
        fprintf(stderr, "encryption failed: out of memory\n");
        return EXIT_FAILURE;
    }
    //Number of blocks = (length/8)+1
    size_t nblocks = (length / (size_t)sizeof(block64));

    //Write to file
    FILE *fp = fopen(destpath, "wb");
    if(!fp){
        fprintf(stderr, "%s: %s\n", destpath, strerror(errno));
        free(cipherblocks);
        return EXIT_FAILURE;
    }

    size_t written = fwrite(cipherblocks, sizeof(block64), nblocks, fp);
    fclose(fp);
    free(cipherblcoks);

    if(written != nblocks){
        fprintf(stderr, "%s: write error\n", destpath);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

//Decode content of a file named in sourcepath to standard output, the function
//prints 'ok' or 'FAILED' to stderr, and returns EXIT_SUCCESS OR EXIT_FAILURE
int decode(const char*sourcepath){

}
