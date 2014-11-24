/* Generate a symmetric key SK2 and Create the ticket */

#include <my_global.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "security/security.h"



void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  //mysql_close(con);
  exit(1);        
}


int number_inside(char *ip){
  int p; 
  for(p = 1;p < strlen(ip);p++){
    if(ip[p] >= '0' && ip[p] <= '9'){return 1;} 
  }
  return 0;
}


void printBinaryInHex(unsigned char * data, int size){
	printf("(Data in hex)\t");
    	int j = 0;
	while(j < size)
	{
    		printf("%02X ", data[j]);
    		j++;
	}
	printf("\n");
}


void getAttributes(MYSQL *con, char username[], USR_TICKET *usr1)
{
  usr1->ticket_time = time(NULL); //  - 402500 ----> for expire ticket
  
  /**************************** print ticket ****************************/
  printf("\n---------------- Ticket ---------------------\n"); 
  printf("TicketId: %d\n", usr1->ticketId);
  printf("Username: %s\n", usr1->username);
  printf("Created date & time: %s\n", ctime((time_t *)&usr1->ticket_time));
  printf("Validity period: %d day\n", usr1->validityPeriod);  
  
  printf("SK2\n");
  
  
  char str[200];
  char newstr[] = "'";
  strcpy (str,"SELECT Attribute, Duration FROM HA.AA WHERE Username = '");
  strcat (str, username);
  strcat (str, newstr);
  
  if (mysql_query(con, str)) 
  {
      finish_with_error(con);
  }

  MYSQL_RES *result = mysql_store_result(con);
  
  if (result == NULL) 
  {
      printf("Can't access any attribute.\n"); 
      finish_with_error(con);
  }
 
  int num_fields = mysql_num_fields(result);
  MYSQL_ROW row;
  int i;
  char *attributes; 
  char *duration = "30"; 
  char *field_id = "1";
  
  printf("\nAttribute  |  Duration \n");
  
  usr1->attr[0] = atoi(field_id); // NODE
  usr1->duration[0] = atoi(duration); 
  
  for(i = 1; i < 10; i++){
  	duration = "0";
  	usr1->attr[i] = atoi(duration);
  	usr1->duration[i] = atoi(duration);
  }  
  
  while ((row = mysql_fetch_row(result))) 
  { 	      
      for(i = 0; i < num_fields-1; i++) 
      { 
          //printf("%s \n", row[i] ? row[i] : "NULL"); 
          attributes = row[i*2];
          duration = row[(i*2)+1];
                 
          if (strcmp(duration, "0") != 0){
          
          	if (strcmp(attributes, "temp") == 0)
	        { 
	      		usr1->attr[1] = atoi(field_id);
          		usr1->duration[1] = atoi(duration);
	        }
	        else if (strcmp(attributes, "humid") == 0)
	        {
	      		usr1->attr[2] = atoi(field_id);
          		usr1->duration[2] = atoi(duration);
	        }
	        else if (strcmp(attributes, "light") == 0)
	        {
	      		usr1->attr[3] = atoi(field_id);
          		usr1->duration[3] = atoi(duration);
	        }
	        else if (strcmp(attributes, "accelx") == 0)
	        {
	      		usr1->attr[4] = atoi(field_id);
          		usr1->duration[4] = atoi(duration);
	        }
	        else if (strcmp(attributes, "accely") == 0)
	        {
	      		usr1->attr[5] = atoi(field_id);
          		usr1->duration[5] = atoi(duration);
	        }
	        else if (strcmp(attributes, "magx") == 0)
	        {
	      		usr1->attr[6] = atoi(field_id);
          		usr1->duration[6] = atoi(duration);
	        }
	        else if (strcmp(attributes, "magy") == 0)
	        {
	      		usr1->attr[7] = atoi(field_id);
          		usr1->duration[7] = atoi(duration);
	        }
	        else if (strcmp(attributes, "echo") == 0)
	        {
	      		usr1->attr[8] = atoi(field_id);
          		usr1->duration[8] = atoi(duration);
	        }
		
          	printf("%s       |  %s \n", attributes, duration);  
          }        
      }    
  }
  /*
  for(i = 0; i < 10; i++){
  	printf("usr1->attr[%d]  =  %d  \n", i, usr1->attr[i]); 
  	printf("usr1->duration[%d]  =  %d  \n", i, usr1->duration[i]); 
  }
  */
  printf("\n---------------- End Ticket ------------------\n"); 
  mysql_free_result(result);

}



USR_TICKET generateUsrTicket (char usrname[], char * sk2, int count)
{
  MYSQL *con = mysql_init(NULL);

  if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }

  if (mysql_real_connect(con, "localhost", "root", "root", 
          NULL, 0, NULL, 0) == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      mysql_close(con);
      exit(1);
  } 
   
  USR_TICKET usr1;
  usr1.ticketId = count;
  //usr1.username = usrname;
  strcpy(usr1.username, usrname);
  usr1.validityPeriod = 1; 
  //usr1.sk2 = sk2;
  strcpy(usr1.sk2, sk2);
  
  /**** Get attribute details ****/ 
  getAttributes(con, usrname, &usr1); 
   
  /****************************Debug purpose****************************/
  /*printf("--------------------------------\n");
  printf("Original ticketId: %d\n", usr1.ticketId);
  printf("Original username: %s\n", usr1.username);
  printf("Original date: %s\n", usr1.date);
  printf("Original Validity period: %d\n", usr1.validityPeriod); */ 
  //printf("Original sk2: \n"); printBinaryInHex(usr1.sk2, 128);
  /*********************************************************************/
   
  mysql_close(con);
  
  //exit(0);
  return usr1;
}



