/*
 * Copyright (c) 2009, Wireless Ad-Hoc Sensor Network Laboratory,
 * University of Colombo School of Computting.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the tikiridb system.
 */

/**
 * \file
 *         Query processor source file
 * \author
 *         Kasun Hewage <kch@ucsc.cmb.ac.lk>
 */

#include "contiki.h"
#include "qprocessor.h"
#include "qmalloc.h"
#include "qtable.h"
#include "packetizer.h"

#include "dev/leds.h"
#include "net/rime.h"
#include "crypto.h"
//#include "dev/rs232.h"

#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#define DEBUG 1

#define TRUE 1
#define FALSE 0

#if DEBUG
#include <stdio.h>
#ifdef PLATFORM_AVR
#include <avr/pgmspace.h>
#define PRINTF(_fmt_, ...) printf_P(PSTR(_fmt_), ##__VA_ARGS__)
#else /* PLATFORM_AVR */
#define PRINTF(...) printf(__VA_ARGS__)
#endif /* PLATFORM_AVR */
#else /* DEBUG  */
#define PRINTF(...)
#endif


static int (* send_data)(const rimeaddr_t *receiver);

/*---------------------------------------------------------------------------*/
//======================================== Nelka ==========================================//
void 
printBinaryInHex(unsigned char * data, int size){
	printf("Data in hex :\t");
	int j = 0;
	while(j < size)
	{
		printf("%02X ", data[j]);
		j++;
	}
	printf("\n");
}
/*---------------------------------------------------------------------------*/

unsigned char * decryptTicketAndPrint(unsigned char * ciphertext, unsigned char* sk1){

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
	//printf("==========================> %d\n",ciphertext_len);
	int bytes_written = 0;
	plaintext = (unsigned char *) malloc(ciphertext_len);

	if(!EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL)){
		printf("ERROR in EVP_DecryptInit_ex \n");
		return NULL;
	}

	int plaintext_len = 0;
	if(!EVP_DecryptUpdate(&de, plaintext, &bytes_written, ciphertext, ciphertext_len)){
		printf("ERROR in EVP_DecryptUpdate\n");
		return NULL;
	}
	plaintext_len += bytes_written;

	if(!EVP_DecryptFinal_ex(&de, plaintext + bytes_written, &bytes_written)){
		printf("ERROR in EVP_DecryptFinal_ex\n");
		return NULL;
	}
	plaintext_len += bytes_written;

	EVP_CIPHER_CTX_cleanup(&de);
	
	printf("\n");
	//free(plaintext);
	
	return plaintext;
}

/*---------------------------------------------------------------------------*/
int 
create_query_result(squery_data_t * squery_data, void * buffer, int buflen)
{
  int qr_size;
  int i;
  message_header_t * message_header;
  field_data_t * field_data;
  qresult_header_t * qresult_header;
  rfield_t * rfield;

  /* Calcualte the size of query result. */
  qr_size = sizeof(message_header_t) + sizeof(qresult_header_t);
  field_data = (field_data_t *)(squery_data + 1);
  for(i=0; i<squery_data->nfields; i++) {
    if((field_data + i)->in_result) {
      qr_size += sizeof(rfield_t);
    }
  }
  /* Not enough space in the buffer. */
  if(qr_size > buflen) {
    PRINTF("[DEBUG] Error! Not enough space in buffer\n");
    return -1;
  }

  message_header = (message_header_t *)buffer;
  /* set message type as query reply. */
  message_header->type = MSG_QREPLY;
  
  qresult_header = (qresult_header_t *)(message_header + 1);
  qresult_header->qid = squery_data->qid;
  qresult_header->type = 1; /* For now we use 1. */
  qresult_header->nrfields = i;


  hton_leuint16(&qresult_header->epoch, ntoh_leuint16(&squery_data->current_epoch));
  rimeaddr_copy(&qresult_header->nodeaddr, &rimeaddr_node_addr); 

  rfield = (rfield_t *)(qresult_header + 1);
  for(i=0; i<squery_data->nfields; i++, field_data++, rfield++) {
    if(field_data->in_result) {
       rfield->id = field_data->id;
       memcpy(rfield->data.data_bytes, field_data->data.data_bytes, 
                                                                ATTR_DATA_SIZE);
    }
  }

  return qr_size;
}

/*---------------------------------------------------------------------------*/
//================================== Nelka ========================================//

int 
create_query_result_ticket_expired(squery_data_t * squery_data, void * buffer, int buflen)
{
  int qr_size;
  message_header_t * message_header;
  qresult_header_t * qresult_header;

  /* Calcualte the size of query result. */
  qr_size = sizeof(message_header_t) + sizeof(qresult_header_t);

  /* Not enough space in the buffer. */
  if(qr_size > buflen) {
    PRINTF("[DEBUG] Error! Not enough space in buffer\n");
    return -1;
  }

  message_header = (message_header_t *)buffer;
  /* set message type as query reply. */
  message_header->type = MSG_QREPLY;
  
  qresult_header = (qresult_header_t *)(message_header + 1);
  qresult_header->qid = squery_data->qid;
  qresult_header->type = 3; /* ticket is expired. */
  qresult_header->nrfields = 0;

  return qr_size;
}

//===================================================================================//

/*---------------------------------------------------------------------------*/
int 
evaluate_expression(expression_data_t * expr_data)
{
  attr_entry_t * attr_entry;

  attr_entry = get_attr_entry(expr_data->l_valuep->id);
  if(attr_entry) {
    return attr_entry->compare_data(&expr_data->l_valuep->data, 
                                   &expr_data->r_value, expr_data->op);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
void 
execute_select_query(void * data)
{
  int i;
  int retval;
  char all_true;
  uint16_t current_epoch, nepochs;
  field_data_t * field_data;
  attr_entry_t * attr_entry;
  expression_data_t * expr_data;
  qtable_entry_t * qtable_entry = (qtable_entry_t *)data;
  squery_data_t * squery_data = (squery_data_t *)qtable_entry->qptr;
  //USR_TICKET * dyc = (USR_TICKET *)(&squery_data->ticket);

  current_epoch = ntoh_leuint16(&squery_data->current_epoch);
  nepochs = ntoh_leuint16(&squery_data->nepochs);

  PRINTF("[DEBUG]: Executing query qid %d\n", squery_data->qid);
  field_data = (field_data_t *)(squery_data + 1);
  
  PRINTF("[DEBUG]: Ticket date&time - %s\n", ctime((time_t *)&squery_data->ticket_time));
  //PRINTF("[DEBUG]: Duration 0(copied) - %d\n", squery_data->duration[0]);
  //PRINTF("[DEBUG]: Duration 1(copied) - %d\n", squery_data->duration[1]);

  /* Read all needed data. */
  for(i=0; i<squery_data->nfields; i++, field_data++) {
    attr_entry = get_attr_entry(field_data->id);
    time_t now = time(NULL);
    localtime(&now);
    PRINTF("[DEBUG]: Duration - %d\n", squery_data->duration[field_data->id - 1]);
    PRINTF("[DEBUG]: Current time - %s\n", ctime((time_t *)&now));
    time_t cutoff = (squery_data->ticket_time + squery_data->duration[field_data->id - 1]);
    PRINTF("[DEBUG]: Cut off - %s\n", ctime((time_t *)&cutoff));
    if((squery_data->ticket_time + squery_data->duration[field_data->id - 1]) + 1 > now){
        PRINTF("[DEBUG]: Attribute authorized %d\n", field_data->id);
    	if(attr_entry && attr_entry->get_data) {
	      attr_entry->get_data(&(field_data->data));
      	}else{
	      PRINTF("[DEBUG]: Warning! get_data not defined attr_id %d\n", 
                                                        field_data->id);
      	}
    } else {
      	//att validation false
      	PRINTF("[DEBUG]: Attribute not authorized %d\n", field_data->id);
    	attr_data_t *invalid = &field_data->data;
    	hton_leuint16(invalid, (uint16_t)999);
    }
  }

  all_true = TRUE;
  expr_data = (expression_data_t *)field_data;
  /* Evaluate expressions.
   * NOTE: Currently, we consider only about simple conjunctions.
   */
  for(i=0; i<squery_data->nexprs; i++, expr_data++) {
    if(!evaluate_expression(expr_data)) {
      PRINTF("[DEBUG]: Expression evalution faild. qid %d\n",squery_data->qid);
      all_true = FALSE;
      break;
    }  
  }
  
  if(all_true) {
    /* Send results to query root. */
    packetbuf_clear();
    retval = create_query_result(squery_data, packetbuf_dataptr(), 64);
    if(retval > 0) {
      packetbuf_set_datalen(retval);
      if(send_data) {  
      /* SendResult(squery_data->qroot); */
      send_data(&qtable_entry->qroot);
      }
      PRINTF("[DEBUG]: Reply send\n");
    } else {
      PRINTF("[DEBUG]: Error! sending data failed qid %d\n", squery_data->qid);
    }
  }

  current_epoch++;
  hton_leuint16(&squery_data->current_epoch, current_epoch);
  if(nepochs == 0 || nepochs > current_epoch) {
    ctimer_reset(&squery_data->timer);
  } else {
    PRINTF("[DEBUG]: Deleting query. qid %d\n", squery_data->qid);
    remove_query_entry(squery_data->qid, &qtable_entry->qroot);
    qfree(squery_data);
  }
  
  leds_toggle(LEDS_YELLOW);
}

void
print_squery(squery_data_t * squery_data)
{
  int i;
  field_data_t * field_data;
  expression_data_t * expr_data; 
  PRINTF("[DEBUG]: id %d, nfields %d, nexprs %d, epoch_duration %d, nepochs %d \n",
          squery_data->qid, 
          squery_data->nfields,
          squery_data->nexprs,
          ntoh_leuint16(&squery_data->epoch_duration),
          ntoh_leuint16(&squery_data->nepochs));
  
  // print fields
  field_data = (field_data_t *)(squery_data + 1);
  for(i=0; i<squery_data->nfields; i++, field_data++) {
     PRINTF("[DEBUG]: attr_id : %d\n", field_data->id);
  }
  // print expressions
  expr_data = (expression_data_t *)field_data;
  for(i=0; i<squery_data->nexprs; i++) {
    PRINTF("[DEBUG]: attr_id : %d, OP : %d, rvalue : %d\n", (expr_data->l_valuep->id),
                                              expr_data->op,
                                              ntoh_leuint16(expr_data->r_value.data_bytes));
  }
}

/*---------------------------------------------------------------------------*/
int 
parse_select_query(qmessage_header_t * qm_header)
{
  int size;
  int i;
  int retval;
  char parsing_failed;
  smessage_header_t * smsg_header;
  squery_data_t * squery_data;
  field_t * field;
  field_data_t * field_data, * fd_tmp;
  expression_t * expr;
  expression_data_t * expr_data; 
  qtable_entry_t * qtable_entry;
  ticket_to_nodes_t * ticket_to_nodes;
  //authentication related

  int noOfAuthAttr;
  time_t now = time(NULL);
  localtime(&now);
  
  USR_TICKET * dyc;
  unsigned char sk1[] = { 0x2b, 0x7e, 0x15, 0x16,
				0x28, 0xae, 0xd2, 0xa6,
				0xab, 0xf7, 0x15, 0x88,
				0x09, 0xcf, 0x4f, 0x3c };
  
  smsg_header = (smessage_header_t *)(qm_header + 1);
 
  /* Check whether a query with same id and same query root exists. */
  if(get_query_entry(qm_header->qid, &qm_header->qroot)) {
    PRINTF("[DEBUG]: A Query exists with the same id and same root.\n");
    return -1;
  }

  /* the memory size needed to be allocated. */
  parsing_failed = FALSE;
  size = sizeof(squery_data_t) + 
         (smsg_header->nfields * sizeof(field_data_t)) + 
         (smsg_header->nexprs * sizeof(expression_data_t));
         
  PRINTF("[DEBUG]: Query size - %d\n", size);

  /* Allocate memory for the SELECT query. */
  squery_data = (squery_data_t *)qmalloc(size);
  if(squery_data == NULL) {
    PRINTF("[DEBUG]: Can not allocate memory. query_id %d\n", qm_header->qid);
    return -1;
  }
  /* set SELECT query header infomations. */
  squery_data->qid = qm_header->qid;
  squery_data->nfields = smsg_header->nfields;
  squery_data->nexprs = smsg_header->nexprs;
  squery_data->in_buffer_id = smsg_header->in_buffer;
  squery_data->out_buffer_id = smsg_header->out_buffer;

  memcpy(&squery_data->epoch_duration, &smsg_header->epoch_duration, sizeof(nw_uint16_t));
  memcpy(&squery_data->nepochs, &smsg_header->nepochs, sizeof(nw_uint16_t));
  memset(&squery_data->current_epoch, 0, sizeof(nw_uint16_t));

  //================================== Nelka ========================================//
  ticket_to_nodes = (ticket_to_nodes_t *)(smsg_header + 1);
  dyc = (USR_TICKET *)decryptTicketAndPrint((unsigned char *)ticket_to_nodes->ticket, sk1);
  PRINTF("[DEBUG]: Username - %s\n", dyc->username);
  PRINTF("[DEBUG]: Ticket date&time(original) - %s\n", ctime((time_t *)&dyc->ticket_time));
  PRINTF("[DEBUG]: Duration 0(original) - %d\n", dyc->duration[0]);
  PRINTF("[DEBUG]: Duration 1(original) - %d\n", dyc->duration[1]);
  
  squery_data->ticket_time = dyc->ticket_time;
  memcpy(&squery_data->duration, &dyc->duration, 10);
  
  /*PRINTF("[DEBUG]: Ticket date&time(copied) - %s\n", ctime((time_t *)&squery_data->ticket_time));
  PRINTF("[DEBUG]: Duration 0(original) - %d\n", squery_data->duration[0]);
  PRINTF("[DEBUG]: Duration 1(original) - %d\n", squery_data->duration[1]);*/
  
  
  /////PRINTF("[DEBUG]: Current time - %s\n", ctime((time_t *)&now)); ///////////////////////
  
  /* Ticket is expired. Send simple result with query expire flag back to user */
  time_t curr = time(NULL);
  if(dyc->ticket_time + 86400 < curr){ 
  	PRINTF("[DEBUG]: Ticket is expired.\n");
  	/* Send results to query root. */
  	packetbuf_clear();
  	retval = create_query_result_ticket_expired(squery_data, packetbuf_dataptr(), 64);
  	if(retval > 0) {
  		packetbuf_set_datalen(retval);
  		if(send_data) {  
  			/* SendResult(squery_data->qroot); */
  			send_data(&qtable_entry->qroot);
  		}
  		PRINTF("[DEBUG]: Ticket expire reply send\n");
  	} else {
  		PRINTF("[DEBUG]: Error! sending data failed qid %d\n", squery_data->qid);
  	}
  	qfree(squery_data);
  	return 0;
  }
  //}else {
  	PRINTF("[DEBUG]: Ticket is valid.\n");
  	/* store field data. */
  	field = (field_t *)(ticket_to_nodes + 1);
  	field_data = (field_data_t *)(squery_data + 1);
  	noOfAuthAttr=0;
  	for(i=0; i<squery_data->nfields; i++, field++) {
  		PRINTF("[DEBUG]: start=====================================\n");
    		PRINTF("[DEBUG]: Attr : %d\n", field->id);
    		PRINTF("[DEBUG]: Ticket auth : %d\n", dyc->attr[field->id - 1]);
    		
    		if(dyc->attr[field->id -1]){
    			PRINTF("[DEBUG]: Attribute is authenticated\n");
    			field_data->id = field->id;
	    		field_data->in_result = field->in_result; 
	    		field_data->op = field->op;
	    		/* fill data value with zero */
	    		memset(&field_data->data, 0, sizeof(attr_data_t));
	    		field_data++;
	    		noOfAuthAttr++;
    		}
    		PRINTF("[DEBUG]: end=====================================\n");
	}
	squery_data->nfields = noOfAuthAttr;

  	/* store expressions */
  	expr = (expression_t *)(field);
  	expr_data = (expression_data_t *)(field_data);
  
  	for(i=0; i<squery_data->nexprs; i++, expr++, expr_data++) {
    		fd_tmp = ((field_data_t *)(squery_data + 1)) + expr->l_value_index;
    		if(!get_attr_entry(fd_tmp->id)) {
      			parsing_failed = TRUE;
      			PRINTF("[DEBUG]: Error! Found unsupported attribute. attribute_id %d\n", 
                                                                    fd_tmp->id);
      			break;
    		}
    		expr_data->l_valuep = fd_tmp;
    		expr_data->op = expr->op;
    		/* copy right value data */
    		memcpy(expr_data->r_value.data_bytes, expr->r_value.data_bytes, 
                                                               ATTR_DATA_SIZE);
  	}

  	if(parsing_failed) {
    		qfree(squery_data);
    		PRINTF("[DEBUG]: Parsing SELECT query failed. query_id %d\n", qm_header->qid);
    		return -1;
  	}
  	print_squery(squery_data);
  	qtable_entry = add_query_entry(squery_data->qid, QTYPE_SELECT,  
                                                   squery_data,
                                                   &qm_header->qroot);
                                                   
  
  	if(!qtable_entry) {
    		qfree(squery_data);
    		PRINTF("[DEBUG]: Error adding to query table. query_id %d\n", qm_header->qid);
    		return -1;
  	}


  	ctimer_set(&squery_data->timer, 
             CLOCK_SECOND * ntoh_leuint16(&squery_data->epoch_duration), 
             execute_select_query, qtable_entry);
  	//}

  return 0;
}

/*---------------------------------------------------------------------------*/

void
process_hello_msg(qmessage_header_t * qm_header){
	PRINTF("init secure comm............\n");
	PRINTF("Q id : %d\n",qm_header->qid);
	sk1_t * sk1;
	sk1 = (sk1_t *)(qm_header + 1);
	//unsigned char *data = sk1->key;
	printBinaryInHex(sk1->key,128);
	//PRINTF("Test number is - %s\n",sk1->key);
	
}

//=========================================================================================//

/*---------------------------------------------------------------------------*/
void 
receive(const rimeaddr_t * from)
{
  
  message_header_t * msg_header = packetbuf_dataptr();
  PRINTF("[DEBUG] Qprocessor! message received from %d.%d, datalen %d, type %d\n", 
         from->u8[0], from->u8[1], packetbuf_datalen(), msg_header->type);
 
  switch(msg_header->type) {
    case MSG_QREQUEST :
      PRINTF("[DEBUG] QREQUEST............\n");
      parse_select_query((qmessage_header_t *)(msg_header+ 1));
      break;
    case MSG_QREPLY :
      PRINTF("[DEBUG] Qprocessor! reply received from %d.%d datalen %d\n",
             from->u8[0], from->u8[1], packetbuf_datalen());
      packetizer_send(packetbuf_dataptr(), packetbuf_datalen());
      break;
    case MSG_HELLO : //  for initial hello message -- added by nelka
      PRINTF("[DEBUG] HELLO MSG............\n");
      process_hello_msg((qmessage_header_t *)(msg_header+ 1));
      break;
  }

}
/*---------------------------------------------------------------------------*/
int 
qprocessor_init(qprocessor_callbacks_t * callbacks)
{
  send_data = callbacks->send;
  callbacks->recv = receive;
  init_qmalloc();
  return 0;
}
/*---------------------------------------------------------------------------*/
