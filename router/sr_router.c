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
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Helper function and global variable declarations*/
static uint8_t* sr_create_etherframe(unsigned int load_len,
                                     uint8_t* load,
                                     char* dest_ether_addr,
                                     char* source_ether_addr,
                                     uint16_t ether_type);
static uint8_t* sr_create_arppacket(unsigned int* len,
                                    unsigned short arp_type,
                                    char* source_ether_addr,
                                    uint32_t source_ip_addr,
                                    char* dest_ether_addr,
                                    uint32_t dest_ip_addr);
static uint8_t* sr_create_ippacket (unsigned int load_len,
                                    uint8_t* load,
                                    uint8_t protocol,
                                    uint32_t source_ip,
                                    uint32_t dest_ip);
static uint8_t* sr_create_icmppacket(unsigned int *len,
                                     uint8_t* data,
                                     uint8_t icmp_type,
                                     uint8_t icmp_code);

static void sr_handle_arpreq(struct sr_instance* sr,
                             uint8_t* packet /* lent */,
                             unsigned int len,
                             char* interface/* lent */);
static void sr_handle_arpreply(struct sr_instance* sr,
                               uint8_t* packet /* lent */,
                               unsigned int len);
static void sr_handle_ippacket(struct sr_instance* sr,
                               uint8_t* packet /* lent */,
                               unsigned int len,
                               char* interface/* lent */);
static void sr_forward_ippacket(struct sr_instance* sr,
                                uint8_t* packet /* lent */,
                                unsigned int len,
                                char* interface/* lent */);

char ether_broadcast_addr[ETHER_ADDR_LEN];
uint32_t ip_broadcast_addr;

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

    /* Define broadcast address external variables */
    char temp[ETHER_ADDR_LEN] = {0xFF};
    strncpy(ether_broadcast_addr, temp, ETHER_ADDR_LEN);
    ip_broadcast_addr = 0xFFFFFFFF;

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket
 * Input: struct sr_instance* sr, uint8_t* packet,unsigned int len,
 * char* interface
 * Output: void
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
  char if_macaddr[ETHER_ADDR_LEN];
  char dest_macaddr[ETHER_ADDR_LEN];
  uint16_t ethertype;
  uint8_t* load = 0;
  unsigned int load_len;

  /* Extract ethernet header*/
  ether_hdr = (sr_ethernet_hdr_t*) packet;

  /* Ensure that ethernet destination address is correct */
  /* TODO: Do a mininmum length check as well*/
  memcpy(dest_macaddr, ether_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(if_macaddr,
          sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);

  if (strncmp(dest_macaddr, ether_broadcast_addr, ETHER_ADDR_LEN != 0) &&
          strncmp(dest_macaddr, if_macaddr, ETHER_ADDR_LEN) != 0) {
    fprintf(stderr, "Destination MAC address does not match interface \n");
    return;
  }

  /* Check protocol of ethernet destination address */
  ethertype = ntohs(ether_hdr->ether_type);
  load = packet + sizeof(sr_ethernet_hdr_t);
  load_len = len - sizeof(sr_ethernet_hdr_t);
  /*Debug Functions*/
  fprintf(stderr, "Confirmed destination of following frame \n");
  print_hdr_eth(packet);

  if (ethertype == ethertype_arp) {
    /* If it is ARP, check if it request or reply.  If it is request,
     * send our reply. If it is a reply, process the associated ARP 
     * req queue.*/
    unsigned short arp_type;
    arp_type = ntohs(((sr_arp_packet_t*)load)->ar_op);
    if (arp_type == arp_op_request) {
      sr_handle_arpreq(sr, load, load_len, interface);
    } else if (arp_type == arp_op_reply) {
      sr_handle_arpreply(sr, load, load_len);
    } else {
      fprintf(stderr, "Invalid ARP type \n");
      return;
    }
  } else if (ethertype == ethertype_ip) {
    sr_handle_ippacket(sr, load, load_len, interface);
  } else {
    fprintf(stderr, "Unsupported Ethernet Type \n");
  }
}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq
 * Input: struct sr_instance* sr, uint8_t* packet, unsigned int len,
 * char* interface
 * Output: void
 * Scope:  Local
 *
 * This method handles extracting information from an arpreq and then
 * sending the appropriate reply given a pointer to the arpreq received,
 * the length of the arpreq and the interface it came from.
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance* sr,
                      uint8_t* packet /* lent */,
                      unsigned int len,
                      char* interface/* lent */)
{
  /* Note assumes that ip address is destined for us*/
  /*TODO: Should add check to ensure hardware format is eth and protocol format is ip*/
  sr_arp_packet_t* arpreq = 0;
  char source_ether_addr[ETHER_ADDR_LEN];
  uint32_t source_ip_addr;
  uint32_t dest_ip_addr;

  /*Extract data from arp packet, ip addresses kept in nbo*/
  arpreq = (sr_arp_packet_t*) packet;
  memcpy(source_ether_addr, arpreq->ar_sha, ETHER_ADDR_LEN);
  source_ip_addr = arpreq->ar_sip;
  dest_ip_addr = arpreq->ar_tip;

  /*Create arp reply*/
  uint8_t* arpreply = 0;
  uint8_t* frame = 0;
  unsigned int load_len;
  char dest_ether_addr[ETHER_ADDR_LEN];
  memcpy(dest_ether_addr, sr_get_interface(sr, interface)->addr,
          ETHER_ADDR_LEN);
  /*TODO: Error handling for case of malloc failure*/
  /* note dest and source reversed since we are replying to sender*/
  arpreply = sr_create_arppacket(&load_len, arp_op_reply, dest_ether_addr,
          dest_ip_addr, source_ether_addr, source_ip_addr);
  print_hdr_arp(arpreply); /*DEBUG*/
  
  /*Create ethernet header*/
  frame = sr_create_etherframe(load_len, arpreply, source_ether_addr,
          dest_ether_addr, ethertype_arp);
  print_hdr_eth(frame); /*DEBUG*/

  /*Pass to sr_send_packet()*/
  if (sr_send_packet(sr, frame, sizeof(sr_ethernet_hdr_t) + load_len,
          interface) != 0) {
    fprintf(stderr, "Packet could not be sent \n");

    free(arpreply);
    free(frame);
    return;
  }

  /* Ensure memory is freed*/
  free(arpreply);
  free(frame);

  /*TODO: Cache sender mapping in arp table*/

}; /* end sr_handle_arpreq */

void sr_handle_arpreply(struct sr_instance* sr,
                        uint8_t* packet /* lent */,
                        unsigned int len)
{
  return;
};

/*---------------------------------------------------------------------
 * Method: sr_handle_ippacket
 * Input: struct sr_instance* sr,uint8_t* packet, unsigned int len,
 * char* interface
 * Output: uint8_t* (Pointer to allocated ip packet)
 * Scope:  Local
 *
 * Given a pointer to an ippacket, length of the ip packet and the
 * interface where it came from this method checks the integrity of
 * the packet and decides whether to forward the packet, send an
 * icmp response or do nothing.
 *---------------------------------------------------------------------*/
void sr_handle_ippacket(struct sr_instance* sr,
                        uint8_t* packet /* lent */,
                        unsigned int len,
                        char* interface/* lent */)
{
  sr_ip_hdr_t* ip_header = 0;
  uint16_t packet_sum;
  unsigned int header_len;

  /* Check length of packet */
  ip_header = (sr_ip_hdr_t*)packet;
  if (len > IP_MAXPACKET || len <= sizeof(sr_ip_hdr_t)){
    fprintf(stderr, "Invalid IP packet size \n");
    return;
  }

  /* Perform checksum check
   * Note that cksum returns network byte order of the result*/
  packet_sum = ip_header->ip_sum;
  header_len = (ip_header->ip_hl)*4;
  ip_header->ip_sum = 0;
  if (cksum(packet, header_len) != packet_sum) {
    fprintf(stderr, "Checksum incorrect, header corrupt\n");
    sr_send_icmp(sr, packet, len, interface, 12, 0);
    return;
  }
  ip_header->ip_sum = packet_sum; /* Reset original checksum*/

  /*Decrement TTL, send type 11 ICMP if it is 0*/
  (ip_header->ip_ttl)--;
  if (ip_header->ip_ttl == 0) {
    fprintf(stderr, "Packet has expired, TTL=0 \n");
    sr_send_icmp(sr, packet, len, interface, 11, 0);
    return;
  }

  fprintf(stderr, "Confirmed integrity of following packet:\n");
  print_hdr_ip(packet);

  /* Check the destination of the packet
   * Note that router interface ips are stored in
   * network byte order. */
  uint8_t* load = packet + header_len;
  uint8_t protocol = ip_header->ip_p;
  uint32_t dest_ip = ip_header->ip_dst;
  if (dest_ip == (sr_get_interface(sr, interface)->ip) ||
        dest_ip == ip_broadcast_addr) {
    /* Packet is meant for me! */
    if (protocol == ip_protocol_icmp) {
      /* Handle icmp request*/
      fprintf(stderr, "Received ICMP messge \n");
      print_hdr_icmp(load);
      sr_icmp_hdr_t* icmp_header = 0;
      uint16_t icmp_sum;

      /* Perform ICMP checksum*/
      icmp_header = (sr_icmp_hdr_t*)load;
      icmp_sum = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      
      if (cksum(load, len-header_len) != icmp_sum) {
        fprintf(stderr, "ICMP checksum incorrect, data corrupt \n");
        return;
      }
      icmp_header->icmp_sum = icmp_sum; /* Reset original checksum*/

      /* Check if it is an echo request*/
      if (icmp_header->icmp_type == 8) {
        /* If it is an echo, reply*/
        sr_send_icmp(sr, packet, len, interface, 0, 0);
      } else {
        /* Otherwise, we don't handle it*/
        fprintf(stderr, "ICMP message received, no action taken \n");
        return;
      }
    } else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) {
      /* Send ICMP port unreacheable for traceroute
       * in case of udp or tcp protocol*/
      sr_send_icmp(sr, packet, len, interface, 3, 3);
    } else {
      /* Otherwise send ICMP protocol unrecognized*/
      sr_send_icmp(sr, packet, len, interface, 3, 2);
    }
  } else {
    /* Destined somewhere else so we forward packet!*/
    sr_forward_ippacket(sr, packet, len, interface);
  }
  return;
} /* end sr_handle_ippacket */

void sr_send_arp(struct sr_instance* sr,
                 unsigned int len,
                 char* interface/*lent*/,
                 unsigned short arp_type,
                 char* dest_ether_addr,
                 uint32_t dest_ip_addr)
{
  return;
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ippacket
 * Input: struct sr_instance* sr,uint8_t* packet, unsigned int len,
 * char* interface
 * Output: uint8_t* (Pointer to allocated ip packet)
 * Scope:  Local
 *
 * Given a pointer to an ippacket, length of the ip packet and the
 * interface where it came from this method checks the integrity of
 * the packet and decides whether to forward the packet, send an
 * icmp response or do nothing.
 *---------------------------------------------------------------------*/

void sr_send_icmp(struct sr_instance* sr,
                  uint8_t* packet /* lent */,
                  unsigned int len,
                  char* interface/* lent */,
                  uint8_t type,
                  uint8_t code)
{
  fprintf(stderr, "Sending ICMP Type: %d , Code: %d \n", type, code);
  uint8_t* icmp_packet = 0;
  uint8_t* ip_packet = 0;
  uint32_t source_ip;
  unsigned int load_len;
  sr_if_t* interface_info = sr_get_interface(sr, interface);

  /* Construct the ip packet for sending out */
  icmp_packet = sr_create_icmppacket(&load_len, packet, type, code);
  source_ip = ((sr_ip_hdr_t*)packet)->ip_src;

  ip_packet = sr_create_ippacket(load_len, icmp_packet,
          ip_protocol_icmp, interface_info->ip, source_ip);
  /* Get destination ip from packet and attempt to do ARP lookup */
  sr_arpentry_t* arpentry = sr_arpcache_lookup(&sr->cache, source_ip);
  if (arpentry) {
    uint8_t* frame = 0;
    /* If ARP was found, wrap in ethernet frame */
    frame = sr_create_etherframe(sizeof(ip_packet), ip_packet,
            arpentry->mac, interface_info->addr, ethertype_ip);
    /* Send packet out of given interface*/
    if (sr_send_packet(sr, frame, sizeof(frame), interface) != 0) {
      fprintf(stderr, "Packet could not be sent \n");

      free(icmp_packet);
      free(ip_packet);
      free(frame);
      return;
    }
    /* Ensure that memory is freed*/
    free(arpentry);
    free(icmp_packet);
    free(ip_packet);
    free(frame);
  } else {
    /* Otherwise, add to arp cache*/
    free(sr_arpcache_queuereq(&sr->cache, source_ip, ip_packet,
            sizeof(ip_packet), interface));
    free(icmp_packet);
  }

  return;
}

void sr_forward_ippacket(struct sr_instance* sr,
                         uint8_t* packet /* lent */,
                         unsigned int len,
                         char* interface/* lent */)
{
  fprintf(stderr, "Forwarding packet ... \n");
  return;
};


/*---------------------------------------------------------------------
 * Method: sr_create_etherframe
 * Input: unsigned int load_len, uint8_t* load,
 * uint8_t* dest_ether_addr, uint8_t* source_ether_addr,
 * uint16_t ether_type
 * Output: uint8_t* (pointer to allocated frame)
 * Scope:  Global
 *
 * This method allocates space for an ethernet frame given a pointer to
 * the data and length of data, source and destination MAC addresses
 * and ethernet type. The frame is return as a pointer to the buffer in
 * network byte order.
 *---------------------------------------------------------------------*/

uint8_t* sr_create_etherframe (unsigned int load_len,
                               uint8_t* load,
                               char* dest_ether_addr,
                               char* source_ether_addr,
                               uint16_t ether_type)
{
  fprintf(stderr, "Wrapping in ethernet frame \n");
  sr_ethernet_hdr_t* frame = 0;

  /*Allocate space for the ethernet frame*/
  frame = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t) +
          load_len);

  /* fill in the required fields*/
  memcpy(frame->ether_dhost, dest_ether_addr, ETHER_ADDR_LEN);
  memcpy(frame->ether_shost, source_ether_addr, ETHER_ADDR_LEN);
  frame->ether_type=htons(ether_type);

  /*Add load and return pointer*/
  memcpy((uint8_t*)frame + sizeof(sr_ethernet_hdr_t), load, load_len);

  return (uint8_t*) frame;
} /* end sr_create_etherframe */

/*---------------------------------------------------------------------
 * Method: sr_arppacket
 * Input: unsigned int* len, enum sr_arp_opcode arp_type,
 * unsigned char* source_ether_addr, uint32_t source_protocol_addr,
 * unsigned char* dest_ether_addr, uint32_t dest_protocol_addr)
 * Output: sr_arp_packet_t* (Pointer to allocated arp packet)
 * Scope:  Local
 *
 * This method allocates space for an arp packet given the arp type,
 * source hardware and protocol addresses (in network byte order) and
 * destination hardware and protocol addresses. It returns a pointer
 * to the packet with all fields in network byte order and fills in
 * the length of the packet in bytes (len).
 * 
 * Note: This function only creates arp packets where hardware type is 
 * ethernet and protocol type is ip.
 *---------------------------------------------------------------------*/
uint8_t* sr_create_arppacket(unsigned int* len,
                             unsigned short arp_type,
                             char* source_ether_addr,
                             uint32_t source_ip_addr,
                             char* dest_ether_addr,
                             uint32_t dest_ip_addr)
{
  fprintf(stderr, "Generating arp packet \n");
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

    /*Set hardware, protocol source and destination data*/
    memcpy(arp_packet->ar_sha, source_ether_addr, ETHER_ADDR_LEN);
    arp_packet->ar_sip = source_ip_addr;

    memcpy(arp_packet->ar_tha, dest_ether_addr, ETHER_ADDR_LEN);
    arp_packet->ar_tip = dest_ip_addr;

    /* Set length of packet*/
    *len=sizeof(sr_arp_packet_t);
  }
  
  return (uint8_t*)arp_packet;
}; /* end sr_create_arppacket */

/*---------------------------------------------------------------------
 * Method: sr_create_ippacket
 * Input: unsigned int load_len, uint8_t* load, uint8_t protocol,
 * uint32_t source_ip, uint32_t dest_ip
 * Output: uint8_t* (Pointer to allocated ip packet)
 * Scope:  Local
 *
 * This method allocates space and attaches the header for an ip packet
 * naked of options when given a pointer to the data, load_len, protocol
 * type, source ip and destination ip both in nbo.  It returns a pointer
 * to the packet in nbo.
 * 
 * Note: Assigns default values for header length (5), version (ipv4)
 * and ttl (64).
 *---------------------------------------------------------------------*/
uint8_t* sr_create_ippacket (unsigned int load_len,
                             uint8_t* load,
                             uint8_t protocol,
                             uint32_t source_ip,
                             uint32_t dest_ip)
{
  /* Declare variables and allocate space*/
  sr_ip_hdr_t* packet = 0;
  packet = calloc(1, sizeof(sr_ip_hdr_t) + load_len);

  /* Fill in required default fields*/
  packet->ip_hl = DEFAULT_HDRLEN;
  packet->ip_v = IPV4_VERSION;
  packet->ip_ttl = DEFAULT_TTL;
  /* Set packet length and protocol*/
  packet->ip_len = htons(sizeof(sr_ip_hdr_t) + load_len);
  packet->ip_p = protocol;

  /* Set source and destination ip addresses*/
  packet->ip_src = source_ip;
  packet->ip_dst = dest_ip;

  /* Calculate checksum (returned in network order) and fill in*/
  packet->ip_sum = cksum(packet, sizeof(sr_ip_hdr_t));

  /* Copy in the load*/
  memcpy((uint8_t*)packet + sizeof(sr_ip_hdr_t), load, load_len);

  return (uint8_t*) packet;
}

/*---------------------------------------------------------------------
 * Method: sr_create_icmppacket
 * Input: unsigned int* len, uint8_t* data, uint8_t icmp_type, uint8_t
 * icmp_code
 * Output: uint8_t* (Pointer to allocated icmp packet)
 * Scope:  Local
 *
 * This method allocates space for an icmp packet given a pointer to
 * the ip packet to be used as data (data), icmp type and icmp code
 * returning a pointer to the allocated packet in network byte order.
 * The len attribute is used to return the total length of the
 * packet for future processing.
 * 
 * Note: This function is meant for handling Type 0, Type 3, Type 11
 * and Type 12 ICMP packets only.
 *---------------------------------------------------------------------*/
uint8_t* sr_create_icmppacket(unsigned int* len,
                                     uint8_t* data,
                                     uint8_t icmp_type,
                                     uint8_t icmp_code)
{
  fprintf(stderr, "Generating ICMP message \n");
  sr_icmp_hdr_t* icmp_packet = 0;
  icmp_packet = (sr_icmp_hdr_t*)malloc(sizeof(sr_icmp_hdr_t));

  /* Fill in the type and code fields */
  icmp_packet->icmp_code = icmp_code;
  icmp_packet->icmp_type = icmp_type;

  /* Allocate extra space based on type of icmp message */
  if (icmp_type != icmp_type_echoreply) {
    /* Requires */
    assert(data);

    /* Copy in header of ip packet and 8 bytes of data into the
     * icmp_packet data field*/
    *len = sizeof(sr_icmp_packet_t);
    icmp_packet = realloc(icmp_packet, *len);
    memcpy(((sr_icmp_packet_t*)icmp_packet)->data, data, ICMP_DATA_SIZE);
  } else {
    /* If it is an echo reply, only requires the header portion */
    *len = sizeof(sr_icmp_hdr_t);
  }

  /* Calculate checksum, note that sum is in network byte order */
  icmp_packet->icmp_sum = cksum(icmp_packet, *len);
  return (uint8_t*) icmp_packet;
} /* end sr_create_icmppacket */

