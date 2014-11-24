#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

unsigned char* generate_aes_key(unsigned short int size){
	unsigned char* key = (unsigned char*) malloc( size ) ;
	RAND_bytes(key, (size / 8));
	return key;
}

unsigned char* generate_sk1(){
	 return generate_aes_key(128);
}
