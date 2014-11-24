#include <my_global.h>
#include <mysql.h>

/*void finish_with_err(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  //mysql_close(con);
  //exit(1);        
}*/

void createDatabse()
{  
  printf("MySQL client version: %s\n", mysql_get_client_info());
  
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

  if (mysql_query(con, "DROP DATABASE IF EXISTS HA")) {
      finish_with_err(con);
  }

  if (mysql_query(con, "CREATE DATABASE HA")) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      mysql_close(con);
      exit(1);
  }
  
  /*************************************************      Certificate Authority       *************************************************************/
  if (mysql_query(con, "CREATE TABLE HA.CA(Id INT NOT NULL, Username char(20) NOT NULL, Password char(20) NOT NULL, PubKey TEXT, PrivateKey TEXT, PRIMARY KEY (`Id`,`Username`))")) {      
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO HA.CA VALUES(1,'nelka','1234','2345','1243')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO HA.CA VALUES(2,'ravinda','1234','7127','5466')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO HA.CA VALUES(3,'ruwani','1234','5464','7678')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO HA.CA VALUES(4,'kasuni','1234','3546','6564')")) {
      finish_with_error(con);
  }
  
   /*************************************************      Attribute Authority       *************************************************************/
  
 if (mysql_query(con, "CREATE TABLE `HA`.`AA` (`Index` int(20) NOT NULL DEFAULT '0', `Username` varchar(30) NOT NULL, `Attribute` varchar(30) NOT NULL, `Duration` int(20) NOT NULL, PRIMARY KEY (`Index`))")) {      
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(1,'nelka','temp',10)")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(2,'ravinda','temp',15)")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(3,'ruwani','temp',5)")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(4,'ravinda','humid',5)")) {
      finish_with_error(con);
  }
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(5,'ruwani','light',4)")) {
      finish_with_error(con);
  }


  mysql_close(con);
 
}


/*
if (mysql_query(con, "CREATE TABLE IF NOT EXISTS `HA`.`AA` (`Index` int(20) NOT NULL DEFAULT '0', `Username` varchar(30) NOT NULL, `Attribute` varchar(30) NOT NULL, `Start` date NOT NULL, `End` date NOT NULL, PRIMARY KEY (`Index`))")) {      
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(1,'nelka','temp','2013-09-20','2013-12-30')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(2,'ravinda','temp','2013-10-22','2013-12-09')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(3,'ruwani','temp','2013-08-19','2013-12-12')")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO `HA`.`AA` VALUES(4,'ravinda','humid','2013-09-12','2014-01-24')")) {
      finish_with_error(con);
  }

*/
