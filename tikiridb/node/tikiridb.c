/*
 * Copyright (c) 2009, Wireless Ad-Hoc Sensor Network Laboratory,
 * University of Colombo School of Computing.
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
 *         Tikiri Database Source file
 * \author
 *         Kasun Hewage <kch@ucsc.cmb.ac.lk>        
 */



#include "tikiridb.h"
#include "contiki.h"
#include "routing.h"
#include "qprocessor.h"
#include "packetizer.h"
#include "crypto.h"

#define DEBUG 1

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

#ifdef CONF_ROUTING_CHANNEL
#define ROUTING_CHANNEL CONF_ROUTING_CHANNEL
#else
#define ROUTING_CHANNEL 129
#endif

static void routing_recv(struct routing_conn *c, const rimeaddr_t *from);
int qprocessor_send_data(const rimeaddr_t *receiver);

static qprocessor_callbacks_t qprocessor_callbacks = {NULL, qprocessor_send_data};
static struct routing_conn routing_conn;
static const struct routing_callbacks routing_callbacks = {routing_recv};

PROCESS(tikiridb_process, "Tikiridb Process");

/*---------------------------------------------------------------------------*/
int 
qprocessor_send_data(const rimeaddr_t *receiver)
{
  return routing_send(&routing_conn, receiver);
}

/*---------------------------------------------------------------------------*/
static void
routing_recv(struct routing_conn *c, const rimeaddr_t *from)
{
  if(qprocessor_callbacks.recv) {
    qprocessor_callbacks.recv(from);  
  }
}

//======================================== Nelka ==========================================//

/*printing received data from tikirdb hello reply*/
int
print_rsv_packet_hello_reply(void * data)
{

  message_header_t * message_header = (message_header_t *) data;
  qmessage_header_t * qmessage_header = (qmessage_header_t *) (message_header + 1);

  char node_id[16];
  bzero(node_id, 16);


  //sprintf(tmp, "%d", qresult_header->type);
  printf("########### Type - %d\n", message_header->type);
  printf("########### Id - %d\n", qmessage_header->qid);
  return 0;
}


/*---------------------------------------------------------------------------*/
/* Reply packet generator for "Hello" message */
int
generate_hello_reply_packet(void * data, char *key)
{
  int size;
   /*Declare the variable structs*/
  /*message_header points to the data section of the packet*/
  message_header_t * message_header;
  qmessage_header_t * qmessage_header;
  sk1_t * sk1;
  
  message_header = (message_header_t *)data;
  /*query REPLY message*/
  message_header->type = MSG_HELLO_REPLY;
  
  /*adding message header for carrying query messages*/
  qmessage_header = (qmessage_header_t *) (message_header + 1);
  qmessage_header->qid = 1;
  qmessage_header->qtype = 2; // this is a SELECT query
  qmessage_header->qroot.u8[0] = rimeaddr_node_addr.u8[0];
  qmessage_header->qroot.u8[1] = rimeaddr_node_addr.u8[1];
  
  /* key field */
  sk1 =  (sk1_t *)(qmessage_header + 1);
  strncpy ((char *)sk1->key, (char *)key, 16);
  
  /*calculating the size of the message*/
  size = sizeof(message_header_t) + sizeof(qmessage_header_t) + 16;
  return size;

} 

//=========================================================================================//

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(tikiridb_process, ev, data)
{
  PROCESS_BEGIN();
  qmessage_header_t * qmessage_header;
  message_header_t * message_header;
  sk1_t * sk1;
  int packet_length;
  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(ev == packet_data_event_message);
    packet_length = get_packet_data_len();
    PRINTF("[Basestation] Packet length : %d\n",packet_length);

    // The query message should be larger than the message header + query message header
    /*if(packet_length <= (sizeof(message_header_t) + sizeof(qmessage_header_t))) {
      PRINTF("Length of query message should be more than %d.\n", 
              (sizeof(message_header_t) + sizeof(qmessage_header_t)));
      continue;
    }

    if(packet_length != get_message_length((message_header_t *)data)) {
      PRINTF("Invalid query message.\n");
      continue;
    }
*/
    message_header = (message_header_t *)data;
    qmessage_header = (qmessage_header_t *)(message_header + 1);
    
    
    unsigned char* skey;
    
    switch(message_header->type) {
    case MSG_QREQUEST :
      PRINTF("[Basestation] QREQUEST............\n");
      qmessage_header = (qmessage_header_t *)((message_header_t *)data + 1);
      // Set query root address to the node's address
      rimeaddr_copy(&qmessage_header->qroot, &rimeaddr_node_addr);
      packetbuf_clear();
      packetbuf_reference(data, packet_length);

      qprocessor_send_data(&rimeaddr_null);
      break;
      
    //======================================== Nelka ==========================================//
    case MSG_HELLO : //  for initial hello message
      PRINTF("[Basestation] HELLO MSG............\n");
      sk1 =  (sk1_t *)(qmessage_header + 1);
      PRINTF("[Basestation] >> %s\n", sk1->key);
      skey = generate_sk1();
      strncpy ((char *)sk1->key, (char *)skey, 16);
      packet_length = packet_length + 16;
      
          
      //Send Hello Response to the user
      int pck_size;
      //qmessage_header_t * hello_qmessage_header;
      pck_size = generate_hello_reply_packet(packetbuf_dataptr(), (char *)skey);
      packetbuf_set_datalen(pck_size);
    
      print_rsv_packet_hello_reply(packetbuf_dataptr());
      //Send it
      packetizer_send(packetbuf_dataptr(), packetbuf_datalen());
      packetbuf_clear();
      break;
      
      /*
      int pck_size;
      qmessage_header_t * hello_qmessage_header;
      unsigned char *hello_packet_ptr;
      pck_size = generate_hello_reply_packet((void *)hello_packet_ptr, skey);
    
      print_rsv_packet_hello_reply(hello_packet_ptr);
      //Send it
      packetizer_send(hello_packet_ptr, pck_size);
      packetbuf_clear();
      break;
      */
    //=========================================================================================// 
     
    case MSG_QREPLY : 
      PRINTF("[Basestation] QREPLY\n");
      qmessage_header = (qmessage_header_t *)((message_header_t *)data + 1);
      // Set query root address to the node's address
      rimeaddr_copy(&qmessage_header->qroot, &rimeaddr_node_addr);
      packetbuf_clear();
      packetbuf_reference(data, packet_length);

    qprocessor_send_data(&rimeaddr_null);
      break;
    }
    
  }
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
void 
tikiridb_init()
{
  routing_open(&routing_conn, ROUTING_CHANNEL, &routing_callbacks);
  qprocessor_init(&qprocessor_callbacks);
  process_start(&tikiridb_process, NULL);
  packetizer_init();
  tikiridb_arch_init();
}


