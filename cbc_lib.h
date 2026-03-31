// 
// File: cbc_lib.h 
// description: public interface functions of cbc_lib.c
// @author csci243 AT cs.rit.edu
// // // // // // // // // // // // // // // // // // // // // // // // 

#ifndef CBC_LIB_H
#define CBC_LIB_H

/// The type of each encrypted block is an unsigned 64-bit value, as
/// are the key value and the initialization vector (IV).

typedef unsigned long  block64;

/// encode standard input to a file whose path is in destpath.
/// The function prints "ok" or "FAILED" to stderr upon completion, and
/// the return code indicates whether or not the call succeeded.
///
/// @param destpath string name of output file path for storing encoded data
/// @return EXIT_SUCCESS or EXIT_FAILURE
/// @pre destpath is a non-empty, NUL-terminated C string.

int encode( const char * destpath );

/// decode from a file path named in sourcepath to standard output.
/// The function prints "ok" or "FAILED" to stderr upon completion, and
/// the return code indicates whether or not the call succeeded.
///
/// @param sourcepath string name of input file path containing encoded data
/// @return EXIT_SUCCESS or EXIT_FAILURE
/// @pre sourcepath is a non-empty, NUL-terminated C string.

int decode( const char * sourcepath );

#endif // CBC_LIB_H

