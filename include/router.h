#ifndef _LIST_H_
#define _LIST_H_

#include <cstdint>
#include <lib.h>

/**
 * Searches the ARP table for a given IP address
 * 
 * @param router   Pointer to router state
 * @param given_ip IP address to search for
 * @return Pointer to matching ARP entry or NULL if not found
 */
struct arp_table_entry *get_arp_entry(struct router_t *router, uint32_t given_ip);

/**
 * Generates ICMP responses for error notifications or echo replies
 * 
 * @param frame    Original Ethernet frame
 * @param msg_type ICMP message type (0=Echo Reply, 3=Unreachable, 11=Time Exceeded)
 * @param iface    Interface to send from
 */
void icmp_packet(struct ether_hdr *frame, uint8_t msg_type, uint32_t iface);

/**
 * Creates and sends an ARP packet
 * 
 * @param l2_frame   Ethernet header reference
 * @param opcode     ARP operation code (1=request, 2=reply)
 * @param iface      Interface for incoming packets
 * @param target_ip  Destination IP address
 * @param target_mac Destination MAC (NULL for requests)
 * @param next_route Route entry (only needed for requests)
 */
void send_arp(struct ether_hdr *l2_frame,
  uint16_t opcode,
  uint32_t iface,
  uint32_t target_ip,
  uint8_t *target_mac,
  struct route_table_entry *next_route);

/**
 * Processes ARP packets (requests and replies)
 * 
 * @param l2_frame Ethernet frame containing ARP packet
 * @param iface    Interface the packet was received on
 * @param len      Length of received packet
 * @param router   Router state
 */
void arp_packet(struct ether_hdr *l2_frame,
  uint32_t iface,
  uint32_t len,
  struct router_t *router);

/**
 * Processes IP packets (forwarding or handling locally)
 * 
 * @param frame  Ethernet frame containing IP packet
 * @param iface  Interface the packet was received on
 * @param len    Length of received packet
 * @param router Router state
 */
void ip_packet(struct ether_hdr *frame, uint32_t iface, uint32_t len, struct router_t *router);



#endif /* _LIST_H_ */