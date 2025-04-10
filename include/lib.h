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

/**
 * Sends a packet to a specific network interface
 * 
 * @param interface - The interface index to send the packet to
 * @param frame_data - Pointer to the frame data to be sent
 * @param length - The length of the frame in bytes
 * @return 0 on success, -1 on failure
 */
int send_to_link(int interface, char *frame_data, size_t length);

/**
 * Receives a packet from any available network interface
 * This is a blocking function - waits until a packet is received
 *
 * @param frame_data - Buffer where the received packet will be stored
 * @param length - Pointer where the length of the received packet will be stored
 * @return The interface index from which the packet was received
 */
int recv_from_any_link(char *frame_data, size_t *length);

/**
 * Gets the IP address of a specific interface
 *
 * @param interface - The interface index
 * @return A string representation of the interface's IP address
 */
char *get_interface_ip(int interface);

/**
 * Gets the MAC address of a specific interface
 *
 * @param interface - The interface index
 * @param mac - Buffer where the MAC address will be stored (must be pre-allocated)
 */
void get_interface_mac(size_t interface, uint8_t *mac);

/**
 * Calculates IPv4/ICMP checksum per RFC 791/792
 * For proper calculation, the checksum field must be set to 0 beforehand
 *
 * @param data - Pointer to data to calculate checksum for
 * @param len - Length of data in bytes
 * @return The calculated checksum value
 */
uint16_t checksum(uint16_t *data, size_t length);

/**
 * Converts a MAC address from string format to binary
 * 
 * @param txt - MAC address string (format "aa:bb:cc:dd:ee:ff")
 * @param addr - Buffer where the binary MAC will be stored
 * @return 0 on success, -1 on failure
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

/**
 * Parses ARP table entries from a file
 *
 * @param path - Path to the ARP table file
 * @param arp_table - Pre-allocated buffer for storing ARP table entries
 * @return Number of entries read from the file
 */
int parse_arp_table(char *path, struct arp_table_entry *arp_table);

/**
 * Initializes router interfaces
 *
 * @param argv - Command line arguments containing interface names
 * @param argc - Number of command line arguments
 */
void init(char *argv[], int argc);

#endif /* _SKEL_H_ */
