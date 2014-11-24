#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "security.h"

/*****************  Generate session key of size 128 bits  *********************/
unsigned char* generate_128_bit_aes_key(){
	unsigned char* key = (unsigned char*) malloc( 128 );
    	RAND_bytes(key, 16);
	return key;
}

/*************************** RSA Encrypt **********************************/
unsigned char* rsa_encrypt(unsigned char *msg, size_t **enc_msg_len, unsigned char **sym_key, int *sym_key_len, unsigned char **iv) {

    //Read public key
    FILE *rsa_pubkey_file;
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pub_key = EVP_PKEY_new();
    rsa_pubkey_file = fopen("newkey.pub", "rb");
    
    if (!rsa_pubkey_file)
    {
        perror("mykey2.pub");
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        exit(2);
    }
    
    if (!PEM_read_RSA_PUBKEY(rsa_pubkey_file, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Public Key File.\n");
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    
    if (!EVP_PKEY_assign_RSA(pub_key, rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        exit(2);
    }

    size_t msg_len = strlen((char*)msg);
    unsigned char *encrypt = malloc(EVP_PKEY_size(pub_key));

    EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);

    *sym_key = malloc(EVP_PKEY_size(pub_key));
    *iv = malloc(EVP_MAX_IV_LENGTH);

    **enc_msg_len = 0;
    int outl = 0;
    
    if(!EVP_SealInit(ctx, EVP_aes_128_cbc(), sym_key, sym_key_len, *iv, &pub_key, 1)) {
        ERR_print_errors_fp(stderr);
        encrypt = NULL;
        goto return_free;
    }


    if(!EVP_SealUpdate(ctx, encrypt + **enc_msg_len, &outl, msg, (int)msg_len)) {
        ERR_print_errors_fp(stderr);
        encrypt = NULL;
        goto return_free;
    }
    **enc_msg_len += outl;

    if(!EVP_SealFinal(ctx, encrypt + **enc_msg_len, &outl)) {
        ERR_print_errors_fp(stderr);
        encrypt = NULL;
        goto return_free;
    }
    **enc_msg_len += outl;

    return_free:
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    EVP_PKEY_free(pub_key);
    ctx = NULL;

    return encrypt;
}

/*****************  Encrypt ticket by using SK1  *********************/
unsigned char * encrypt_ticket (USR_TICKET ticket, unsigned char* sk1)
{
	
	EVP_CIPHER_CTX en;
	EVP_CIPHER_CTX_init(&en);
	const EVP_CIPHER *cipher_type;
	unsigned char *ciphertext = NULL;
	int input_len = 0;

	unsigned char iv[] = { 	0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b,
				0x0c, 0x0d, 0x0e, 0x0f };

	cipher_type = EVP_aes_128_cbc();

	EVP_EncryptInit_ex(&en, cipher_type, NULL, sk1, iv);

	static const int MAX_PADDING_LEN = 16;

	input_len = sizeof(USR_TICKET) + 1;
	ciphertext = (unsigned char *) malloc(input_len + MAX_PADDING_LEN);
	
	if(!EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL)){
		printf("ERROR in EVP_EncryptInit_ex \n");
		return;
	}

	int bytes_written = 0;
	int ciphertext_len = 0;
	if(!EVP_EncryptUpdate(&en,ciphertext, &bytes_written, (unsigned char *) &ticket, input_len) ) {
		printf("ERROR in EVP_EncryptUpdate \n");
		return;
	}
	ciphertext_len += bytes_written;

	//printf("Input len: %d, ciphertext_len: %d\n", input_len, ciphertext_len);

	if(!EVP_EncryptFinal_ex(&en, ciphertext + bytes_written, &bytes_written)){
		printf("ERROR in EVP_EncryptFinal_ex \n");
		return;
	}
	ciphertext_len += bytes_written;

	EVP_CIPHER_CTX_cleanup(&en);

	//printf("Input len: %d, ciphertext_len: %d\n", input_len, ciphertext_len);
	printf("\nTicket is encrypted\n");
	printf("Encrypted ticket's length: %d\n", ciphertext_len);

	return ciphertext;
} 

/*****************  Debug purpose function *************************/
void decryptTicketAndPrint(unsigned char * ciphertext, unsigned char* sk1){

	unsigned char iv[] = { 	0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b,
				0x0c, 0x0d, 0x0e, 0x0f };

	EVP_CIPHER_CTX de;
	EVP_CIPHER_CTX_init(&de);
	const EVP_CIPHER *cipher_type;
	unsigned char *plaintext = NULL;
	cipher_type = EVP_aes_128_cbc();
	EVP_DecryptInit_ex(&de, cipher_type, NULL, sk1, iv);
	int ciphertext_len = 16*((sizeof(USR_TICKET) / 16) + 1);
	printf("==========================> %d\n",ciphertext_len);
	int bytes_written = 0;
	plaintext = (unsigned char *) malloc(ciphertext_len);

	if(!EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL)){
		printf("ERROR in EVP_DecryptInit_ex \n");
		return;
	}

	int plaintext_len = 0;
	if(!EVP_DecryptUpdate(&de, plaintext, &bytes_written, ciphertext, ciphertext_len)){
		printf("ERROR in EVP_DecryptUpdate\n");
		return;
	}
	plaintext_len += bytes_written;

	if(!EVP_DecryptFinal_ex(&de, plaintext + bytes_written, &bytes_written)){
		printf("ERROR in EVP_DecryptFinal_ex\n");
		return;
	}
	plaintext_len += bytes_written;

	EVP_CIPHER_CTX_cleanup(&de);

	
	USR_TICKET * dyc = (USR_TICKET *)plaintext;
	printf("Username - %s\n", dyc->username);
	printf("Ticket Id - %d\n", dyc->ticketId);
	printf("Date - %s\n", ctime((time_t *)&dyc->ticket_time));
	printf("Validity period: %d\n", dyc->validityPeriod);  
	printf("SK2: \n"); printBinaryInHex(dyc->sk2, 128);
	printf("\n\n");
	printf("Ticket is valid for 1 day only from %s.\n", ctime((time_t *)&dyc->ticket_time)); 
	free(plaintext);
}
