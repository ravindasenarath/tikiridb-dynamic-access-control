#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "DB/createDb.h"
#include "DB/getUsrPubKey.h"
//#include "generateTicket.h"
#include "security/security.h"
#include <openssl/evp.h>

#include <openssl/aes.h>

#include <netdb.h>
#include <sys/timex.h>
#include <time.h>


#define BUFSIZE 8096
#define REGISTERED 1
#define NONREGISTERED 0


static int count;


typedef struct ticketReq {
	char username[10];
	char password[10];
} packet_ticketReq_t;

typedef struct rsa_enc_env {
	unsigned char sym_key[256];
	unsigned int sym_key_len;
	unsigned char iv[16];
	unsigned char enc_msg[32];
	unsigned int enc_msg_len;
} rsa_enc_env_t;

typedef struct packet_from_ha {
	char ticket[64];
	rsa_enc_env_t sk2_enc;
	uint8_t usrValidity;
} packet_from_ha_t;

//unsigned char * encrypt_ticket (USR_TICKET ticket, unsigned char* sk1);
void handle_request(int socketfd);
//void decryptTicketAndPrint(unsigned char * encryptedTicket, unsigned char* sk1);//Debug purpose
//unsigned char* rsa_encrypt(unsigned char *msg, size_t **enc_msg_len, unsigned char **sym_key, int *sym_key_len, unsigned char **iv);


double timevaldiff(struct timeval x , struct timeval y)
{
    double x_ms , y_ms , diff;
     
    x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
     
    diff = (double)y_ms - (double)x_ms;
     
    return diff;
}


int main(int argc, char **argv){
		
	char *configfd = "wserver.cfg";
	FILE *infile;
	char line_buffer[BUFSIZE];
	char line_number;
	int para1=0,para2=0;
	char webroot[256],portInS[10];

	int port,listenfd,length,socketfd,pid;
	
	static struct sockaddr_in server_addr;
	static struct sockaddr_in client_addr;
	
	memset(&server_addr, '0', sizeof(server_addr));
        memset(&client_addr, '0', sizeof(client_addr));

	/*if( argc < 3  || argc > 3 || !strcmp(argv[1], "-?") ){
		printf("argument problem\n");
		exit(0);
	}*/
	
	//==========================  Read Config file for parameters  ================================
	
	infile = fopen(configfd, "r");
	if (!infile) {
		printf("Couldn't open file %s for reading.\n", configfd);
		return 0;
	}
	
	while(fgets(line_buffer, sizeof(line_buffer), infile) != NULL){
		char key[256], value[256];

		line_number++;
		if(line_buffer[0] == '#') continue;

		if(sscanf(line_buffer, "%s %s", key, value) != 2)
		{
			fprintf(stderr, "Syntax error reading config file, line %d\n", line_number);
			continue;
		}

		//printf("Line %d:  Key %s Value %s\n", line_number, key, value);
		
		if(strcmp(key,"webroot") == 0){
			strcpy(webroot, value);
			para1 = 1;
			//printf("Webroot stored -> %s\n",webroot);
		}else if(strcmp(key,"port") == 0){
			strcpy(portInS, value);
			para2 = 1;
			//printf("Port stored -> %s\n",portInS);
		}else{
			fprintf(stderr, "Config file is currupted\n");
			exit(0);
		}
	}
	
	createDatabse();
	
	printf("Webroot file-> %s Port -> %s\n",webroot,portInS);
	if(!para1){
		printf("Couldn't read webroot from config file\n");
		exit(1);
	}
	if(!para2){
		printf("Couldn't read port from config file\n");
		exit(1);
	}
	
	//====================================================================================
	
	/*if(chdir(webroot) == -1){ 
		printf("ERROR: Coudn't Change to web root directory %s\n",argv[2]);
		exit(1);
	}*/
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            	printf("ERROR: System call socket \n");
            	exit(1);
        }
        port = atoi(portInS);
        if(port < 0 || port >60000){
        	printf("ERROR: Invalid port %d, number (try 1->60000)\n", port);
        }
        
	printf("Starting Server.........\n");
        
        server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);
	
	bind(listenfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	
	if( listen(listenfd,64) < 0){
		printf("ERROR: ");
	}
	
	printf("Server waiting on port %d.........\n",port);
	
	while(1){
		length = sizeof(client_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&client_addr, &length)) < 0){
			printf("ERROR: System call accept\n");
		}
		if((pid = fork()) < 0){
			printf("ERROR: System call fork\n");
		}else {
			if(pid == 0) {
				count++;  
				(void)close(listenfd);
				handle_request(socketfd);
			} else { 
				count++;  
				(void)close(socketfd);
			}
		}
	}
}


void handle_request(int socketfd){
	long ret;
	char * publicKey = "";
	char * sk2;
	char *encryptedSk2;
	unsigned char * encryptedTicket;
	packet_from_ha_t mypacket;	
	struct timeval start, finish;
 	double msec;
	static char buffer[BUFSIZE+1];

	/* Read the request into the buffer */
	ret =read(socketfd,buffer,BUFSIZE);
	
	if(ret == 0 || ret == -1){
		printf("ERROR: Failed to read the request\n");
		exit(1);
	}
	
	/* Mark the end of the request with a null character */
	if(ret > 0 && ret < BUFSIZE){
		buffer[ret]=0;
	}else{
		buffer[0]=0;
	}
	
	packet_ticketReq_t *reqPacket = (packet_ticketReq_t *)buffer;
	
	/* Validate username and if valid extract user details */
	publicKey = getPublicKey(reqPacket->username, reqPacket->password); 
		
	/* Decrypt SK1 by using HA's public key  */
	unsigned char sk1[] = { 0x2b, 0x7e, 0x15, 0x16,
                          0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88,
                          0x09, 0xcf, 0x4f, 0x3c };
	
	printf("\n============================================================ \n");
					
	if(strlen(publicKey) != 0)
	{  
	    USR_TICKET ticket;
	    
	    gettimeofday(&start, NULL); ///// 11111111111
	    sk2 = generate_128_bit_aes_key();
	    
	    gettimeofday(&finish, NULL);
	    
	    
	    printf("\nRegistered User \n");
	    printf("Generated Session Key (SK2): \n");
	    printBinaryInHex(sk2, 16);
	    
	    msec = timevaldiff(start, finish);
	    //printf("Time to generate SK2 (128 bits key) = %f milliseconds.\n", msec);
	       
	    /* Encrypt the SK2 by public key */
	    //encryptedSk2 = encrypt_sk2 (sk2, publicKey);
	    	    
	    unsigned char *encrypt = NULL;     // Encrypted message
	    rsa_enc_env_t sk2_enc;

	    // Load error strings in anticipation of error
	    ERR_load_crypto_strings();

	    // Encrypt the message
	    size_t *encrypt_len = malloc(sizeof(size_t));
	    unsigned char *sym_key = NULL;
	    unsigned char *iv = NULL;
	    int sym_key_len;
	    
	    gettimeofday(&start, NULL); ////////// 222222222222
	    encrypt = rsa_encrypt((unsigned char*)sk2, &encrypt_len, &sym_key, &sym_key_len, &iv);	    
	    gettimeofday(&finish, NULL);
	    
	    msec = timevaldiff(start, finish);
	    //printf("Time to RSA encrypt 128 bits key = %f milliseconds.\n", msec);	    
	    
	    //printf("%d bytes encrypted in sk2\n", (int)*encrypt_len);
	    
	    //printf("Size of sym key : %d\n", sym_key_len);
	    //printf("Size of iv : %d\n", EVP_MAX_IV_LENGTH);
	    memcpy (mypacket.sk2_enc.iv, iv, EVP_MAX_IV_LENGTH);
	    memcpy (mypacket.sk2_enc.sym_key, sym_key, sym_key_len);
	    mypacket.sk2_enc.sym_key_len = sym_key_len;
	    memcpy (mypacket.sk2_enc.enc_msg, encrypt, (int)*encrypt_len);
	    mypacket.sk2_enc.enc_msg_len = (int)*encrypt_len;
	    //printf("Whole size : %d\n", sizeof(mypacket.sk2_enc));
	   /*===================================================================*/
	   
	   ticket = generateUsrTicket(reqPacket->username, sk2, count);
	   
	   /* Encrypt the ticket by SK1 - Symmetric encryption */
	   gettimeofday(&start, NULL); ////////// 33333333333333
	   encryptedTicket = encrypt_ticket (ticket, sk1);
	   //decryptTicketAndPrint(encryptedTicket, sk1);
	   gettimeofday(&finish, NULL);
	   
	   msec = timevaldiff(start, finish);
	   //printf("Time to AES encrypt ticket = %f milliseconds.\n", msec);	
	   
	   /* send both ticket and key to the user */
	   //strcpy (sendBuff[0], encryptedSk2);
	   memcpy (mypacket.ticket, encryptedTicket, 64); 
	   
	   mypacket.usrValidity =  REGISTERED;
	
	   //printf("****************************************************************\n");
	   //printBinaryInHex(mypacket.ticket, 1072);
	   //printf("****************************************************************\n");
	   //decryptTicketAndPrint(mypacket.ticket, sk1);

           write(socketfd, (void *)&mypacket, sizeof(mypacket)); 
           
           printf("Size of the whole packet: %d\n", sizeof(mypacket));

           printf("Sent Ticket and SK2 to user.\n");   
          
	   
	} else {
		printf("\nUsername: %s\n",reqPacket->username);
	 	printf("Incorrect login credentials, Access denied.\n");
	 	mypacket.usrValidity =  NONREGISTERED;
		write(socketfd, (void *)&mypacket, sizeof(mypacket)); 
	}
	
	sleep(1);
	close(socketfd);
	exit (1);
}
