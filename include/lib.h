#ifndef _SKEL_H_
#define _SKEL_H_

#include <unistd.h>     // Provides access to POSIX operating system API
#include <stdint.h>     // Provides fixed-width integer types (uint8_t, uint32_t, etc.)
#include <stdio.h>      // Provides standard I/O functions
#include <stdlib.h>     // Provides memory allocation, process control, conversions, etc.
#include <queue.h>

/**
 * Constants used throughout the router implementation
 */
#define MAX_PACKET_LEN 1400      // Maximum packet length the router can process
#define ROUTER_NUM_INTERFACES 3  // Number of network interfaces on the router
#define MAX_RTABLE_LEN 100000    // Maximum number of entries in the routing table
#define MAX_ARP_TABLE_LEN 20     // Maximum number of entries in the ARP table
#define IP_ETHERTYPE 0x0800      // EtherType value for IPv4 packets
#define ARP_ETHERTYPE 0x0806     // EtherType value for ARP packets
#define MAX_TTL 64               // Maximum Time-To-Live for IP packets

/**
 * Error handling macro that terminates the program if a condition is true
 * 
 * @param condition - The condition to check
 * @param message - The error message to display
 * @param ... - Additional format parameters for the message
 */
#define DIE(condition, message, ...) \
    do { \
        if ((condition)) { \
            fprintf(stderr, "[(%s:%d)]: " # message "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
            perror(""); \
            exit(1); \
        } \
    } while (0)

// Forward declaration for trie node structure
struct trie_node;
typedef struct trie_node trie_node_t;

/**
 * Structure representing an entry in the routing table
 * Used for making forwarding decisions based on destination IP
 */
struct route_table_entry {
    uint32_t prefix;    // Network prefix (subnet address)
    uint32_t next_hop;  // Next hop IP address
    uint32_t mask;      // Subnet mask
    int interface;      // Output interface index
} __attribute__((packed));  // Ensures no padding between struct fields

/**
 * Structure representing an entry in the ARP table
 * Maps IP addresses to MAC addresses
 */
struct arp_table_entry {
    uint32_t ip;       // IP address
    uint8_t mac[6];    // MAC address (6 bytes)
};

/**
 * Structure for queuing packets waiting for ARP resolution
 * Used when router needs to forward a packet but doesn't have the MAC
 */
struct waiting_queue_entry {
    char *eth_hdr;                      // Pointer to the Ethernet frame
    int len;                            // Length of the frame
    struct route_table_entry *next_route;  // Route information for forwarding
};

struct router_t{
    trie_node_t *routing_table;  // Root of the routing trie
    struct arp_table_entry *arp_table;  // Pointer to the ARP table
    int arp_table_len;       // Number of entries in the ARP table
    queue waiting_queue;  // Queue for packets waiting for ARP resolution
};

/*
 * @brief Sends a packet on a specific interface.
 *
 * @param length - will be set to the total number of bytes received.
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated
 * @param interface - index of the output interface
 * Returns: the interface it has been received from.
 */
int send_to_link(size_t length, char *frame_data, size_t interface);

/*
 * @brief Receives a packet. Blocking function, blocks if there is no packet to
 * be received.
 *
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated 
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
size_t recv_from_any_link(char *frame_data, size_t *length);

/**
 * Gets the IP address of a specific interface
 *
 * @param interface - The interface index
 * @return A string representation of the interface's IP address
 */
char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(size_t interface, uint8_t *mac);

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * also works as ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.

 * @param data memory area to checksum
 * @param length in bytes
 */
uint16_t checksum(uint16_t *data, size_t length);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/**
 * Reads routing table entries from a file and builds a trie directly
 *
 * @param path - Path to the routing table file
 * @param trie_root - Pointer to the root of the trie to be populated
 * @return Number of entries read and inserted from the file
 */
int read_rtable_to_trie(const char *path, trie_node_t *trie_root);

/* Parses a static mac table from path and populates arp_table.
 * arp_table should be allocated and have enough space. This
 * function returns the size of the arp table.
 * */
int parse_arp_table(char *path, struct arp_table_entry *arp_table);

/**
 * Initializes router interfaces
 *
 * @param argv - Command line arguments containing interface names
 * @param argc - Number of command line arguments
 */
void init(char *argv[], int argc);

#endif /* _SKEL_H_ */
