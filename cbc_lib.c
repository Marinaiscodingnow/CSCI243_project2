//File: cbc_lib.c
//Author: Marina Kania
////////////////////////

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "cbc_lib.h"
#define BYTES_PER_BLOCK 8


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
        data[i] = (char)((txt >> (8*i)) & 0xFF);
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
    if (!padded) { free(cipher); return NULL; }
    memcpy(padded, text, len);

    for (int i = 0; i < num_blocks; i++) {
        
        //Load plain text bytes into a block64
        block64 pi = 0;
        for(int b = 0; b < 8; b++){
            pi = (pi << 8 | padded[i*8 + b]);
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
    size_t bufsize = count *BYTES_PER_BLOCK + 1;
    char *text = malloc(bufsize);
    if (!text) return NULL;
    block64 prev = *pIV;
    char tmp[BYTES_PER_BLOCK+1];

    for (size_t i = 0; i < count; i++) {
        block64 cipher = ciphertext[i];
        block64 di = block_cipher_decrypt(cipher, key);
        //When i = 0, *pIV holds the IV playing the role of C(-1)
        block64 pi = di ^ prev;
        block64_to_string(pi, tmp);
        //Unpack pi into 8 bytes of the output string
        memcpy(text + i *BYTES_PER_BLOCK, tmp, BYTES_PER_BLOCK);
        //Update pIV
        prev = cipher;
    }
    text[count * BYTES_PER_BLOCK] = '\0';
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
        return -1;
    }

    int c;
    while((c = fgetc(stdin)) != EOF){
        if(length +1 >= capacity){
            capacity *= 2;
            char *tmp = realloc(buf, capacity);
            if(!tmp){
                free(buf);
                fprintf(stderr, "out of memory\n");
                return -1;
            }
            buf = tmp;
        }
        buf[length++] = (char)c;
    }
    buf[length] = '\0';

    //encrypt
    block64 iv = INITIALIZATION_VECTOR;
    block64 *cipherblocks = cbc_encrypt(buf, &iv, key);
    free(buf);
    if(!cipherblocks){
        fprintf(stderr, "encryption failed: out of memory\n");
        return -1;
    }
    //Number of blocks = (length/8)+1
    size_t nblocks = (length / BYTES_PER_BLOCK);

    //Write to file
    FILE *fp = fopen(destpath, "wb");
    if(!fp){
        fprintf(stderr, "%s: %s\n", destpath, strerror(errno));
        free(cipherblocks);
        return -1;
    }

    size_t written = fwrite(cipherblocks, sizeof(block64), nblocks, fp);
    fclose(fp);
    free(cipherblocks);

    if(written != nblocks){
        fprintf(stderr, "%s: write error\n", destpath);
        return -1;
    }

    return 0;
}

//Decode content of a file named in sourcepath to standard output, the function
//prints 'ok' or 'FAILED' to stderr, and returns EXIT_SUCCESS OR EXIT_FAILURE
int decode(const char*sourcepath){
    FILE *fp = fopen(sourcepath, "rb");
    if(!fp){
        fprintf(stderr," %s: %s\n", sourcepath, strerror(errno));
        return -1;
    }

    //Determine file size
    fseek(fp,0,SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    if(fsize<0) {
        fprintf(stderr, "%s: seek error\n", sourcepath);
        fclose(fp);
        return -1;
    }

    size_t nblocks = (size_t)fsize / sizeof(block64);

    //Empty file means no output
    if(nblocks == 0){
        fclose(fp);
        return -1;
    }
    
    block64 *cipherblocks = malloc(nblocks * sizeof(block64));
    if(!cipherblocks){
        fprintf(stderr, "out of memory \n");
        fclose(fp);
        return -1;
    }

    size_t nread = fread(cipherblocks, sizeof(block64), nblocks, fp);
    fclose(fp);

    if(nread != nblocks){
        fprintf(stderr, "%s: read error\n", sourcepath);
        free(cipherblocks);
        return -1;
    }

    //Decrypt
    block64 iv = INITIALIZATION_VECTOR;
    char *plaintext = cbc_decrypt(cipherblocks, nblocks, &iv, key);
    free(cipherblocks);

    if(!plaintext){
        fprintf(stderr, "decryption failed: out of memory\n");
        return -1;
    }

    //Print without trailing NUL padding
    fputs(plaintext, stdout);
    free(plaintext);

    return 0;
}
