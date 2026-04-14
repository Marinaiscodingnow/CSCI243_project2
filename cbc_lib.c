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

    }
    return block;
}

//Implements block cipher decryption, decrypt the block using the key,
//returning the resulting block value. Input ciphertext, Output plaintext.
static block64 block_cipher_decrypt( block64 block, block64 key){
    //For 4 rounds
    for(int i = 0; i < 4; i++){
        //First Operation: XORs the block with the key value
        
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

}

//Encrypts the text string using pIV and key, and returns the point to an 
//array of block64. pIV refering to either the initialization vector or 
//the ciphertext block of the prior stage. Returning the updated *pIV that is
//the ciphertext input of the next stage, the length of the returned array
//depending on the length of the text argument.
static block64 * cbc_encrypt( char * text, block64 * pIV, block64 key){

}

//Encode standard input to a dile named in destpath, the function prints
//'ok' or 'FAILED' to stderr on completion, returning EXIT_SUCCESS or 
//EXIT_FAILURE
int encode(const char*destpath){

}

//Decode content of a file named in sourcepath to standard output, the function
//prints 'ok' or 'FAILED' to stderr, and returns EXIT_SUCCESS OR EXIT_FAILURE
int decode(const char*sourcepath){

}
