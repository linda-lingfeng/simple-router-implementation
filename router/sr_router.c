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
                                     unsigned char* dest_ether_addr,
                                     unsigned char* source_ether_addr,
                                     uint16_t ether_type);
static uint8_t* sr_create_arppacket(unsigned int* len,
                                    unsigned short arp_type,
                                    unsigned char* source_ether_addr,
                                    uint32_t source_ip_addr,
                                    unsigned char* dest_ether_addr,
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

static void sr_handle_arp(struct sr_instance* sr,
                             uint8_t* packet /* lent */,
                             unsigned int len,
                             char* interface/* lent */);
static void sr_handle_ippacket(struct sr_instance* sr,
                               uint8_t* packet /* lent */,
                               unsigned int len,
                               char* interface/* lent */);
static void sr_forward_ippacket(struct sr_instance* sr,
                                sr_ip_hdr_t* packet /* lent */,
                                unsigned int len,
                                char* interface/* lent */);

unsigned char ether_broadcast_addr[ETHER_ADDR_LEN];
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
    unsigned char temp[ETHER_ADDR_LEN] = {0xFF};
    memcpy(ether_broadcast_addr, temp, ETHER_ADDR_LEN);
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
  unsigned char if_macaddr[ETHER_ADDR_LEN];
  unsigned char dest_macaddr[ETHER_ADDR_LEN];
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

  if (memcmp(dest_macaddr, ether_broadcast_addr, ETHER_ADDR_LEN != 0) &&
          memcmp(dest_macaddr, if_macaddr, ETHER_ADDR_LEN) != 0) {
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

  /* Pass off to appropriate helper function based on the ethertype*/
  if (ethertype == ethertype_arp) {
    sr_handle_arp(sr, load, load_len, interface);
  } else if (ethertype == ethertype_ip) {
    sr_handle_ippacket(sr, load, load_len, interface);
  } else {
    fprintf(stderr, "Unsupported Ethernet Type \n");
  }
}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arp
 * Input: struct sr_instance* sr, uint8_t* packet, unsigned int len,
 * char* interface
 * Output: void
 * Scope:  Local
 *
 * This method handles extracting information from an arpreq and then
 * sending the appropriate reply given a pointer to the arpreq received,
 * the length of the arpreq and the interface it came from.
 *---------------------------------------------------------------------*/
void sr_handle_arp(struct sr_instance* sr,
                   uint8_t* packet /* lent */,
                   unsigned int len,
                   char* interface/* lent */)
{
  /*Requires*/
  assert(sr);
  assert(packet);
  assert(interface);

  /* Note assumes that ip address is destined for us*/
  sr_arp_packet_t* arp_packet = 0;
  unsigned char source_ether_addr[ETHER_ADDR_LEN];
  uint32_t source_ip_addr;
  unsigned short arp_type;

  /* Check that protocol is ethernet and ip*/
  arp_packet = (sr_arp_packet_t*) packet;
  fprintf(stderr, "Received the following ARP packet: \n");
  print_hdr_arp(packet); /*DEBUG*/
  if(ntohs(arp_packet->ar_hrd) == arp_hrd_ethernet &&
          ntohs(arp_packet->ar_pro) == arp_pro_ip) {
    /*Extract data from arp packet, ip addresses kept in nbo*/
    memcpy(source_ether_addr, arp_packet->ar_sha, ETHER_ADDR_LEN);
    source_ip_addr = arp_packet->ar_sip;
    arp_type = ntohs(arp_packet->ar_op);

    /* Check whether the arp packet is a request or a reply*/
    if (arp_type == arp_op_request) {
      /* If it is a request, cache arp information from sender */
      sr_arpcache_insert(&(sr->cache), source_ether_addr, source_ip_addr);
      /* Send arp reply*/
      sr_send_arp(sr, interface, arp_op_reply,
              source_ether_addr,source_ip_addr);
    } else if (arp_type == arp_op_reply) {
      /* If it is a reply, send all associated packets based on reply*/
      sr_arpreq_t* arp_req = 0;
      /* Attempts to insert given arp information*/
      arp_req = sr_arpcache_insert(&(sr->cache),
              source_ether_addr, source_ip_addr);
      if (arp_req) {
        /* Since is exists, we can process all queued packets*/
        sr_packet_t* curr = 0;
        uint8_t* frame = 0;
        sr_if_t* curr_iface = 0;
        /* Send out each of the packets in the request queue*/
        curr = arp_req->packets;
        while(curr) {
          /* Create ethernet frame and send out packet
           * Note that source ether addr of received arp is 
           * dest ether address of each packet*/
          curr_iface = sr_get_interface(sr, curr->iface);
          frame = sr_create_etherframe(curr->len, curr->buf,
                  source_ether_addr, curr_iface->addr, ethertype_ip);
          if (sr_send_packet(sr, frame, sizeof(frame), interface) != 0) {
            fprintf(stderr, "A packet could not be sent \n");
          }
          /* Free memory, reset the pointer and move to next packet*/
          free(frame);
          frame = 0;
          curr = curr->next;
        }
        /* Destroy the arp request */
        sr_arpreq_destroy(&(sr->cache), arp_req);
      } else {
        fprintf(stderr, "ARP reply corresponds to non-existant req \n");
        return;
      };
    } else {
      fprintf(stderr, "Invalid ARP type \n");
      return;
    }
  } else {
    fprintf(stderr, "Invalid ARP hardware and protocol type \n");
    return;
  }

  return;
}; /* end sr_handle_arpreq */

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
  /*Requires*/
  assert(sr);
  assert(packet);
  assert(interface);

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
    sr_send_icmp(sr, packet, interface, 12, 0);
    return;
  }
  ip_header->ip_sum = packet_sum; /* Reset original checksum*/

  /*Decrement TTL, send type 11 ICMP if it is 0*/
  (ip_header->ip_ttl)--;
  if (ip_header->ip_ttl == 0) {
    fprintf(stderr, "Packet has expired, TTL=0 \n");
    sr_send_icmp(sr, packet, interface, 11, 0);
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
      fprintf(stderr, "Received ICMP message \n");
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
        sr_send_icmp(sr, packet, interface, 0, 0);
      } else {
        /* Otherwise, we don't handle it*/
        fprintf(stderr, "ICMP message received, no action taken \n");
        return;
      }
    } else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) {
      /* Send ICMP port unreacheable for traceroute
       * in case of udp or tcp protocol*/
      sr_send_icmp(sr, packet, interface, 3, 3);
    } else {
      /* Otherwise send ICMP protocol unrecognized*/
      sr_send_icmp(sr, packet, interface, 3, 2);
    }
  } else {
    /* Destined somewhere else so we forward packet!*/
    sr_forward_ippacket(sr, (sr_ip_hdr_t*) packet, len, interface);
  }
  return;
} /* end sr_handle_ippacket */

/*---------------------------------------------------------------------
 * Method: sr_send_arp
 * Input: struct sr_instance* sr, char* interface,
 * unsigned short arp_type, unsigned char* dest_ether_addr,
 * uint32_t dest_ip_addr
 * Output: void
 * Scope:  Global
 *
 * Given the arp type, destination ethernet address and destination ip
 * address (in nbo) and an interface this function sends out an arp
 * packet through the given interface.
 *---------------------------------------------------------------------*/

void sr_send_arp(struct sr_instance* sr,
                 char* interface/*lent*/,
                 unsigned short arp_type,
                 unsigned char* dest_ether_addr,
                 uint32_t dest_ip_addr)
{
  /*Requires*/
  assert(sr);
  assert(interface);
  assert(dest_ether_addr);
  
  fprintf(stderr, "Sending an arp message:\n");
  /*Declare variables*/
  uint8_t* arp_packet = 0;
  uint8_t* frame = 0;
  unsigned int load_len;
  sr_if_t* interface_info = 0;
  unsigned char source_ether_addr[ETHER_ADDR_LEN];
  uint32_t source_ip_addr;

  /* Extract current interface ip and ethernet address*/
  interface_info = sr_get_interface(sr, interface);
  memcpy(source_ether_addr, interface_info->addr, ETHER_ADDR_LEN);
  source_ip_addr = interface_info->ip;

  /* Create arp packet*/
  arp_packet = sr_create_arppacket(&load_len, arp_op_reply,
          source_ether_addr, source_ip_addr,
          dest_ether_addr, dest_ip_addr);
  print_hdr_arp(arp_packet); /*DEBUG*/
  
  /*Create ethernet header*/
  frame = sr_create_etherframe(load_len, arp_packet, 
          dest_ether_addr,  source_ether_addr, ethertype_arp);
  print_hdr_eth(frame); /*DEBUG*/

  /*Pass to sr_send_packet()*/
  if (sr_send_packet(sr, frame, sizeof(sr_ethernet_hdr_t) + load_len,
          interface) != 0) {
    fprintf(stderr, "Packet could not be sent \n");
  }

  /* Ensure memory is freed*/
  free(arp_packet);
  free(frame);

  return;
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp
 * Input: struct sr_instance* sr, uint8_t* packet,
 * char* interface, uint8_t type, uint8_t code
 * Output: void
 * Scope:  Global
 *
 * Given a the icmp type, code and pointer the the ip packet that
 * triggered the icmp protocol, this function sends the appropriate
 * icmp packet out of the provided interface.
 *---------------------------------------------------------------------*/

void sr_send_icmp(struct sr_instance* sr,
                  uint8_t* packet /* lent */,
                  char* interface/* lent */,
                  uint8_t type,
                  uint8_t code)
{
  /*Requires*/
  assert(sr);
  assert(packet);
  assert(interface);

  fprintf(stderr, "Sending ICMP Type: %d , Code: %d \n", type, code);
  uint8_t* icmp_packet = 0;
  uint8_t* ip_packet = 0;
  uint32_t source_ip;
  unsigned int load_len;
  sr_if_t* interface_info = sr_get_interface(sr, interface);

  /* Construct the ip packet for sending out */
  icmp_packet = sr_create_icmppacket(&load_len, packet, type, code);
  source_ip = ((sr_ip_hdr_t*)packet)->ip_src;
  print_hdr_icmp(icmp_packet);

  ip_packet = sr_create_ippacket(load_len, icmp_packet,
          ip_protocol_icmp, interface_info->ip, source_ip);
  free(icmp_packet);
  print_hdr_ip(ip_packet);

  /* Get destination ip from packet and attempt to do ARP lookup */
  sr_arpentry_t* arpentry = sr_arpcache_lookup(&sr->cache, source_ip);
  if (arpentry) {
    fprintf(stderr, "Found in ARP cache, sending packet...\n");
    uint8_t* frame = 0;
    /* If ARP was found, wrap in ethernet frame */
    frame = sr_create_etherframe(sizeof(ip_packet), ip_packet,
            arpentry->mac, interface_info->addr, ethertype_ip);
    /* Send packet out of given interface*/
    if (sr_send_packet(sr, frame, sizeof(frame), interface) != 0) {
      fprintf(stderr, "Packet could not be sent \n");
    }
    /* Ensure that all memory is freed*/
    free(ip_packet);
    free(frame);
  } else {
    fprintf(stderr, "Not in ARP Cache, packet queued. \n");
    /* Otherwise, add to arp cache*/
    sr_arpcache_queuereq(&sr->cache, source_ip, ip_packet,
            sizeof(ip_packet), interface);
  }

  return;
}

/*---------------------------------------------------------------------
 * Method: sr_forward_ippacket
 * Input: struct sr_instance* sr, sr_ip_hdr_t* packet, unsigned int len,
 * char* interface
 * Output: void
 * Scope:  Local
 *
 * Given a pointer to a specified ip packet and it's length this
 * function looks for the destination ip in the routing table and
 * forwards the packet via the interface found after recalculating
 * the checksum.  If a route is not found, it will send an ICMP type 3
 * message back using the interface passed in.
 *---------------------------------------------------------------------*/

void sr_forward_ippacket(struct sr_instance* sr,
                         sr_ip_hdr_t* packet /* lent */,
                         unsigned int len,
                         char* interface/* lent */)
{
  /* Requires*/
  assert(sr);
  assert(packet);

  fprintf(stderr, "Forwarding packet ... \n");
  uint32_t dest_ip;
  sr_rt_t* lpm = 0;

  /* Look for route in routing table*/
  dest_ip = packet->ip_dst;
  lpm = sr_rt_lookup(sr->routing_table, dest_ip);
  /* If route exists, forward packet */
  if (lpm) {
    sr_arpentry_t* arp_entry = 0;
    /* Recalculate checksum*/
    packet->ip_sum = 0;
    packet->ip_sum = cksum(packet, (packet->ip_hl)*4);

    /* Do ip lookup in arp cache, if found forward*/
    arp_entry = sr_arpcache_lookup(&(sr->cache), (lpm->gw).s_addr);
    if (arp_entry) {
      uint8_t* frame = 0;
      /* Retrieve required information and wrap in ethernet frame */
      sr_if_t* interface_info = sr_get_interface(sr, lpm->interface);
      frame = sr_create_etherframe(len, (uint8_t*)packet, arp_entry->mac,
              interface_info->addr, ethertype_ip);
      /* Send packet out of the route*/
      if (sr_send_packet(sr, frame, len + sizeof(sr_ethernet_hdr_t),
              lpm->interface) != 0) {
        fprintf(stderr, "Packet could not be sent \n");
      }
    } else {
      /* If not found, queue packet*/
      sr_arpcache_queuereq(&(sr->cache), (lpm->gw).s_addr,
              (uint8_t*) packet, len, lpm->interface);
    }
  } else {
    /* Send out ICMP dest unreacheable*/
    sr_send_icmp(sr, (uint8_t*)packet, interface,
            icmp_type_dstunreachable, 0);
  }

  return;
};


/*---------------------------------------------------------------------
 * Method: sr_create_etherframe
 * Input: unsigned int load_len, uint8_t* load,
 * unsigned char* dest_ether_addr, unsigned char* source_ether_addr,
 * uint16_t ether_type
 * Output: uint8_t* (pointer to allocated frame)
 * Scope:  Global
 *
 * This method allocates space for an ethernet frame given a pointer to
 * the data and length of data, source and destination MAC addresses
 * and ethernet type. The frame is return as a pointer to the buffer in
 * network byte order or null if memory allocation was unsuccessful.
 *---------------------------------------------------------------------*/

uint8_t* sr_create_etherframe (unsigned int load_len,
                               uint8_t* load,
                               unsigned char* dest_ether_addr,
                               unsigned char* source_ether_addr,
                               uint16_t ether_type)
{
  /*Requires*/
  assert(load);
  assert(dest_ether_addr);
  assert(source_ether_addr);

  fprintf(stderr, "Wrapping in ethernet frame \n");
  sr_ethernet_hdr_t* frame = 0;

  /*Allocate space for the ethernet frame, then checks it worked*/
  frame = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t) +
          load_len);
  assert(frame);

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
                             unsigned char* source_ether_addr,
                             uint32_t source_ip_addr,
                             unsigned char* dest_ether_addr,
                             uint32_t dest_ip_addr)
{
  /* Requires */
  assert(len);
  assert(source_ether_addr);
  assert(dest_ether_addr);

  /* Allocate space for packet and check it worked*/
  fprintf(stderr, "Generating arp packet \n");
  sr_arp_packet_t* arp_packet = 0;
  arp_packet = (sr_arp_packet_t*)calloc(1, sizeof(sr_arp_packet_t));
  assert(arp_packet);

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

  if (arp_type == arp_op_reply) {
    memcpy(arp_packet->ar_tha, dest_ether_addr, ETHER_ADDR_LEN);
  }
  arp_packet->ar_tip = dest_ip_addr;

  /* Set length of packet*/
  *len=sizeof(sr_arp_packet_t);

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
  /* Requires */
  assert(load);

  /* Declare variables and allocate space, then check for success*/
  fprintf(stderr, "Wrapping in IP Packet \n");
  sr_ip_hdr_t* packet = 0;
  packet = calloc(1, sizeof(sr_ip_hdr_t) + load_len);
  assert(packet);

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

  return (uint8_t*)packet;
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
  /* Requires */
  assert(data);
  assert(len);

  /*Allocated space for packet then check if it worked*/
  fprintf(stderr, "Generating ICMP message \n");
  sr_icmp_hdr_t* icmp_packet = 0;
  icmp_packet = (sr_icmp_hdr_t*)malloc(sizeof(sr_icmp_hdr_t));
  assert(icmp_packet);

  /* Fill in the type and code fields */
  icmp_packet->icmp_code = icmp_code;
  icmp_packet->icmp_type = icmp_type;

  /* Allocate extra space based on type of icmp message */
  if (icmp_type != icmp_type_echoreply) {
    /* Copy in header of ip packet and 8 bytes of data into the
     * icmp_packet data field*/
    *len = sizeof(sr_icmp_packet_t);
    icmp_packet = realloc(icmp_packet, *len);
    icmp_packet->variable_field = 0;
    memcpy(((sr_icmp_packet_t*)icmp_packet)->data, data, ICMP_DATA_SIZE);
  } else {
    sr_icmp_hdr_t* echo_request = 0;
    unsigned int data_len;
    /* If it is an echo reply, obtain required info from echo request*/
    data_len = ntohs((((sr_ip_hdr_t*)data)->ip_len)) - 
            sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
    echo_request = (sr_icmp_hdr_t*)(data + sizeof(sr_ip_hdr_t));
    *len = sizeof(sr_icmp_hdr_t) + data_len;
    /* Copy the data into an appropriately allocated icmp packet*/
    icmp_packet = realloc(icmp_packet, *len);
    icmp_packet->variable_field = echo_request->variable_field;
    memcpy((uint8_t*)icmp_packet + sizeof(sr_icmp_hdr_t),
            (uint8_t*)echo_request + sizeof(sr_icmp_hdr_t), data_len);
  }

  /* Calculate checksum, note that sum is in network byte order */
  icmp_packet->icmp_sum = cksum(icmp_packet, *len);
  return (uint8_t*) icmp_packet;
} /* end sr_create_icmppacket */

