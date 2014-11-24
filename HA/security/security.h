#include "../generateTicket.h"
unsigned char* generate_128_bit_aes_key();

unsigned char* rsa_encrypt(unsigned char *msg, size_t **enc_msg_len, unsigned char **sym_key, int *sym_key_len, unsigned char **iv);

unsigned char * encrypt_ticket (USR_TICKET ticket, unsigned char* sk1);

void decryptTicketAndPrint(unsigned char * ciphertext, unsigned char* sk1);
