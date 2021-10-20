/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

static void sr_handle_arpreq(struct sr_instance* sr, uint8_t* packet /* lent */, unsigned int len, char* interface/* lent */);
static void sr_handle_arpreply(struct sr_instance* sr, uint8_t* packet /* lent */, unsigned int len);
static void sr_handle_ippacket(struct sr_instance* sr, uint8_t* packet /* lent */, unsigned int len, char* interface/* lent */);
static void sr_forward_ippacket(struct sr_instance* sr, uint64_t* packet /* lent */, unsigned int len, char* interface/* lent */);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  sr_ethernet_hdr_t* ether_hdr = 0;
  char* if_macaddr = 0;
  char* ether_destaddr = 0;
  uint16_t ethertype;
  uint8_t* load = 0;
  int load_len;

  /* Extract ethernet header*/
  ether_hdr = (sr_ethernet_hdr_t*) packet;

  /* Ensure that ethernet destination address is correct */
  ether_destaddr = ether_hdr->ether_dhost;
  if_macaddr = sr_get_interface(sr, interface)->addr;

  if (strncmp(ether_destaddr, if_macaddr) != 0) {
    fprintf(stderr, "Ethernet destination address does not match interface");
    return;
  }

  /* Check protocol of ethernet destination address */
  ethertype = ether_hdr->ether_type;
  load = packet + sizeof(sr_ethernet_hdr_t);
  load_len = len-sizeof(sr_ethernet_hdr_t);
  switch(ethertype) {
    /* If it is ARP, check if it request or reply.  If it is request, send our reply. If
     * it is a reply, process the associated ARP req queue.*/
    case ethertype_arp:
        unsigned short arp_type = ((sr_arp_packet_t*)load)->ar_op;
        if (arp_type == arp_op_request) {
          sr_handle_arpreq(sr, load, load_len, interface);
        } else {
          sr_handle_arpreply(sr, load, load_len);
        }
        break;
    /*If it is IP, handle the IP packet.*/
    case ethertype_ip:
        sr_handle_ippacket(sr, load, load_len, interface);
        break;
  }

}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_create_etherpacket (unsigned int load_len, uint8_t* load,
 * uint8_t* dest_ether_ddr, uint8_t* source_ether_addr, uint16_t ether_type)
 * Output: uint8_t* (pointer to allocated frame)
 * Scope:  Global
 *
 * This method allocates space for an ethernet frame given a particular
 * load, load_len, source and destination MAC addresses and ethernet type.
 * The frame is return as a pointer to the buffer in network byte order.
 *---------------------------------------------------------------------*/

uint8_t* sr_create_etherframe (unsigned int load_len,
                                uint8_t* load,
                                uint8_t* dest_ether_addr,
                                uint8_t* source_ether_addr,
                                uint16_t ether_type)
{
  sr_ethernet_hdr_t* frame = 0;

  /*Allocate space for the ethernet frame*/
  frame = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t) + load_len);

  /* fill in the required fields*/
  memcpy(frame->ether_dhost, dest_ether_addr, ETHER_ADDR_LEN);
  memcpy(frame->ether_shost, source_ether_addr, ETHER_ADDR_LEN);
  frame->ether_type=htons(ether_type);

  /*Add load and return pointer*/
  frame = (uint8_t*) frame;
  memcpy(frame + sizeof(sr_ethernet_hdr_t), load, load_len);

  return frame;
}

/*---------------------------------------------------------------------
 * Method: sr_arppacket (unsigned int* len, enum sr_arp_opcode arp_type,
 * unsigned char* source_ether_addr, uint32_t source_protocol_addr,
 * unsigned char* dest_ether_addr, uint32_t dest_protocol_addr)
 * Output: sr_arp_packet_t* (Pointer to allocated arp packet)
 * Scope:  Local
 *
 * This method allocates space for an arp packet given the arp type,
 * source hardware and protocol addresses and destination hardware and
 * protocol addresses. It returns a pointer to the packet with all fields
 * in network byte order.
 * 
 * It also fills in the length of the packet in bytes using "len".
 *---------------------------------------------------------------------*/
uint8_t* sr_create_arppacket(unsigned int* len,
                             unsigned short arp_type,
                             unsigned char* source_ether_addr,
                             uint32_t source_protocol_addr,
                             unsigned char* dest_ether_addr,
                             uint32_t dest_protocol_addr)
{
  
  sr_arp_packet_t* arp_packet = 0;
  arp_packet = (sr_arp_packet_t*)malloc(sizeof(sr_arp_packet_t));
  
  if (arp_packet) {
    /* Set hardware, protocol type and length */
    arp_packet->ar_hrd = htons(arp_hrd_ethernet);
    arp_packet->ar_pro = htons(arp_pro_ip);
    arp_packet->ar_hln = ETHER_ADDR_LEN;
    arp_packet->ar_pln = IP_ADDR_LEN;

    /* Set ARP op code*/
    arp_packet-> ar_op = htons(arp_type);

    /*Set hardware, protocol source and destination
     *Note assumes ethernet addresses are in network byte order*/
    memcpy(arp_packet->ar_sha, source_ether_addr, ETHER_ADDR_LEN);
    arp_packet->ar_sip = htonl(source_protocol_addr);

    memcpy(arp_packet->ar_tha, dest_ether_addr, ETHER_ADDR_LEN);
    arp_packet->ar_tip = htonl(dest_protocol_addr);

    /* Set length of packet*/
    *len=sizeof(sr_arp_packet_t);
  }
  
  return (uint8_t*)arp_packet;
}; /* end sr_create_arppacket */
