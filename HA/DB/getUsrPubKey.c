#include <my_global.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "getUsrPubKey.h"


void finish_with_err(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  //mysql_close(con);
  exit(1);        
}


char* getPublicKey(char username[], char password[])
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

  char *publicKey = ""; 
  char str[100];
  char newstr[] = "'";
  strcpy (str,"SELECT PubKey FROM HA.CA WHERE Username = '");
  strcat (str, username);
  strcat (str, newstr);
  char newstr1[] = " AND Password = '";
  strcat (str, newstr1);
  strcat (str, password);
  strcat (str, newstr);
  
  if (mysql_query(con, str)) 
  {
      finish_with_err(con);
  }

  MYSQL_RES *result = mysql_store_result(con);
  
  if (result == NULL) 
  {
      //printf("Not a registered user.\n"); 
      finish_with_err(con);
  }
 
  int num_fields = mysql_num_fields(result);
  MYSQL_ROW row;
  int i;  
  
  while ((row = mysql_fetch_row(result)) != NULL) 
  { 
	for(i = 0; i < num_fields; i++) 
	{ 
	     ////printf("%s \n", row[i] ? row[i] : "NULL"); 
	     publicKey = row[i];
	}   
  } 
  mysql_free_result(result);
  
  mysql_close(con);
  return publicKey;
}
