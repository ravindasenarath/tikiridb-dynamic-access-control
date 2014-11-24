#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <stdbool.h>

#include "base64.h"

#define PADDING RSA_PKCS1_PADDING

unsigned char* makeAlphaString( int dataSize )
{
  unsigned char* s = (unsigned char*) malloc( dataSize ) ;
  
  int i;
  for( i = 0 ; i < dataSize ; i++ )
    s[i] = 65 + i ;
  s[i-1]=0;//NULL TERMINATOR ;)
  
  return s ;
}

unsigned char* rsaEncrypt( RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen )
{
  int rsaLen = RSA_size( pubKey ) ;
  unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;
  
  // RSA_public_encrypt() returns the size of the encrypted data
  // (i.e., RSA_size(rsa)). RSA_private_decrypt() 
  // returns the size of the recovered plaintext.
  *resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, pubKey, PADDING ) ; 
  if( *resultLen == -1 )
    printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
  printf("Encrypted data length : %d\n\n",*resultLen);
  return ed ;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
char* rsaEncryptThenBase64( RSA *pubKey, unsigned char* binaryData, int binaryDataLen, int *outLen )
{
  int encryptedDataLen ;
  
  // RSA encryption with public key
  unsigned char* encrypted = rsaEncrypt( pubKey, binaryData, binaryDataLen, &encryptedDataLen ) ;
  
  // To base 64
  int asciiBase64EncLen ;
  char* asciiBase64Enc = base64( encrypted, encryptedDataLen, &asciiBase64EncLen ) ;
  
  // Destroy the encrypted data (we are using the base64 version of it)
  free( encrypted ) ;
  
  // Return the base64 version of the encrypted data
  return asciiBase64Enc ;
}

RSA* loadPUBLICKeyFromString( const char* publicKeyStr )
{
  // A BIO is an I/O abstraction (Byte I/O?)
  
  // BIO_new_mem_buf: Create a read-only bio buf with data
  // in string passed. -1 means string is null terminated,
  // so BIO_new_mem_buf can find the dataLen itself.
  // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
  BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ; // -1: assume string is null terminated
  
  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
  
  // Load the RSA key from the BIO
  RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
  if( !rsaPubKey )
    printf( "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) ) ;
  
  BIO_free( bio ) ;
  return rsaPubKey ;
}

unsigned char*generate_128_bit_aes_key(){
	unsigned char* key = (unsigned char*) malloc( 128 ) ;
	//unsigned char key[16];
    	RAND_bytes(key, 16);
    	/*printf("Generated key in hex :\t");
    	int j = 0;
	while(j < 16)
	{
    		printf("%02X ", key[j]);
    		j++;
	}
	printf("\n");*/
	return key;
}


unsigned char * encrypt_with_ha_pub_key(unsigned char * str)
{

	//testing purpose
	int dataSize=37 ; // 128 for NO PADDING, __ANY SIZE UNDER 128 B__ for RSA_PKCS1_PADDING
  	//unsigned char *str = makeAlphaString( dataSize ) ;
  	//strcpy(str, "Susitha Ravinda Senarath\0");
  	//unsigned char *str = "Susitha Ravinda Senarath";
	//HA's public key
	const char *b64_pKey = "-----BEGIN PUBLIC KEY-----\n"
  	"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCp2w+8HUdECo8V5yuKYrWJmUbL\n"
  	"tD6nSyVifN543axXvNSFzQfWNOGVkMsCo6W4hpl5eHv1p9Hqdcf/ZYQDWCK726u6\n"
  	"hsZA81AblAOOXKaUaxvFC+ZKRJf+MtUGnv0v7CrGoblm1mMC/OQI1JfSsYi68Epn\n"
  	"aOLepTZw+GLTnusQgwIDAQAB\n"
  	"-----END PUBLIC KEY-----\n";
  	
  	//Data to encrypt
  	//printf( "\nThe original data is:\n%s\n\n", (char*)str ) ;
  	// LOAD PUBLIC KEY
	RSA *pubKey = loadPUBLICKeyFromString( b64_pKey ) ;
	//Do encryption
	int encryptedDataLen ;
	unsigned char* encrypted = rsaEncrypt( pubKey, str, dataSize, &encryptedDataLen ) ;
	//printf("Data length after encryption - %d\n",encryptedDataLen);
	// free the public key when you are done all your encryption
	RSA_free( pubKey ) ; 
	
	//printf( "Sending base64_encoded ( rsa_encrypted ( <<binary data>> ) ):\n%s\n", asciiB64E ) ;
	return encrypted;
	
}
