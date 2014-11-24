hamake: HA.c DB/createDb.c
	clear
	gcc HA.c DB/getUsrPubKey.c security/security.c generateTicket.c DB/createDb.c -o HA -lcrypto -lssl `mysql_config --cflags --libs`
	./HA
