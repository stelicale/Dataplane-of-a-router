// Include custom and system header files for the router implementation
#include "include/list.h"       // Doubly linked list implementation
#include "include/lib.h"        // Custom router utilities and structures
#include "include/protocols.h"  // Protocol definitions and structs
#include "include/trie.h"       // Trie data structure for efficient IP lookups
#include <string.h>             // For memory operations like memcpy, memset
#include <netinet/in.h>         // For network byte order conversions (htons, ntohl)
#include <arpa/inet.h>          // For IP address manipulation (inet_pton)

// Global data structures for the router
static trie_node_t *routing_trie;          // Trie structure for routing lookups

static struct arp_entry *arp_table;        // ARP table - maps IP to MAC addresses
static int arp_table_len;                  // Number of entries in the ARP table

static doubly_linked_list_t *waiting_queue;  // Queue for packets waiting for ARP resolution

/**
 * Converts a string representation of an IP address to its 32-bit integer value
 * Uses inet_pton() from arpa/inet.h to perform the conversion
 */
static uint32_t dr_get_ip_from_char(char *char_ip)
{
    uint32_t int_ip;
    // inet_pton() converts from presentation format (string) to network format (binary)
    // AF_INET specifies IPv4 address family
    inet_pton(AF_INET, char_ip, &int_ip);
    return int_ip;  // Returns the IP address as a 32-bit integer
}

/**
 * Implements Longest Prefix Match (LPM) algorithm to find the best route
 * for a given destination IP address using the trie data structure
 */
static struct route_table_entry *dr_get_next_route(uint32_t ip_dest)
{
    // Use the trie-based longest prefix match implementation
    return trie_longest_prefix_match(routing_trie, ip_dest);
}

/**
 * Searches the ARP table for a given IP address
 * Returns the corresponding ARP entry if found, NULL otherwise
 */
static struct arp_entry *dr_get_arp_entry(uint32_t given_ip)
{
    // Linear search through the ARP table
    for (int i = 0; i < arp_table_len; ++i)
        if (arp_table[i].ip == given_ip)  // Direct comparison of 32-bit IP addresses
            return &arp_table[i];  // Return a pointer to the matching entry

    return NULL;  // IP not found in ARP table
}

/**
 * Creates and sends an ARP request packet
 * Used to discover the MAC address for a known IP address
 */
static void dr_send_arp_request(struct ether_hdr *eth_hdr,
                                struct route_table_entry *next_route,
                                uint32_t interface)
{
    // Position the ARP header right after the Ethernet header
    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr +
                                                 sizeof(*eth_hdr));

    // Configure the ARP header fields
    arp_hdr->hw_type = htons(1);  // Set hardware type to Ethernet (1), convert to network byte order
    
    // Set protocol type to IPv4 (0x0800), convert to network byte order
    arp_hdr->proto_type = htons(IP_ETHERTYPE);
    
    arp_hdr->hw_len = 6;        // MAC address is 6 bytes long
    arp_hdr->proto_len = 4;     // IPv4 address is 4 bytes long
    
    // Set operation code to ARP request (1), convert to network byte order
    arp_hdr->opcode = htons(1);
    
    // Set source MAC address to the router's interface MAC address
    // get_interface_mac is a utility function that retrieves the MAC address
    get_interface_mac(next_route->interface, arp_hdr->shwa);

    // Get the router's IP for the interface and use it as source IP
    // get_interface_ip returns a string, dr_get_ip_from_char converts to uint32_t
    uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));
    arp_hdr->sprotoa = router_ip;

    // Set target MAC address to all zeros (what we're trying to discover)
    // memset fills the memory area with a specified value (0 in this case)
    memset(arp_hdr->thwa, 0, sizeof(arp_hdr->thwa));
    
    // Set target IP address to the next hop's IP from the routing table
    arp_hdr->tprotoa = next_route->next_hop;

    // Set destination MAC to broadcast (all FF) since we don't know target MAC
    // memset fills the memory with 0xFF (broadcast address)
    memset(eth_hdr->ethr_dhost, 0xff, sizeof(eth_hdr->ethr_dhost));
    
    // Set Ethernet type to ARP protocol, convert to network byte order
    eth_hdr->ethr_type = htons(ARP_ETHERTYPE);

    // Send the complete frame (Ethernet header + ARP header) out the interface
    // send_to_link is a utility function that transmits frames
    send_to_link(next_route->interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*arp_hdr));
}

/**
 * Creates and sends an ICMP packet (used for error reporting)
 * Types: 11 for Time Exceeded, 3 for Destination Unreachable
 */
static void dr_icmp_packet(struct ether_hdr *eth_hdr,
                           uint8_t type,
                           uint32_t interface)
{
    // Extract IP and ICMP headers from the received packet
    struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)eth_hdr +
                                              sizeof(*eth_hdr));
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr +
                                                    sizeof(*ip_hdr));

    // Configure the ICMP header with requested type and default code 0
    icmp_hdr->mtype = type;  // 11 for Time Exceeded, 3 for Destination Unreachable
    icmp_hdr->mcode = 0;     // Subcodes are set to 0 (generic error)
    
    // Reset checksum to 0 before calculation (required by checksum algorithm)
    icmp_hdr->check = 0;
    
    // Calculate ICMP header checksum, convert to network byte order (htons)
    // checksum() computes the Internet checksum as per RFC 1071
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr,
                                     sizeof(*icmp_hdr)));
    
    // For ICMP error messages, we include the original IP header and first 8 bytes
    // of the original message in the ICMP body to help recipient diagnose the error
    uint32_t icmp_len = sizeof(*ip_hdr) + 8;
    
    // Allocate memory for ICMP body
    // malloc allocates requested memory space and returns a pointer to it
    int8_t *icmp_body = malloc(icmp_len);
    
    // Check if memory allocation failed and exit if it did
    DIE(!icmp_body, "malloc() failed.\n");
    
    // Copy the original IP header and first 8 bytes of data to ICMP body
    // memcpy copies n bytes from source to destination memory area
    memcpy(icmp_body, ip_hdr, icmp_len);

    // Get router's IP address for the interface
    uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

    // Reverse the packet's direction - swap source and destination IP
    ip_hdr->dest_addr = ip_hdr->source_addr;  // Send back to original source
    ip_hdr->source_addr = router_ip;          // From router's interface
    
    // Set TTL to maximum allowed value and convert to network byte order
    ip_hdr->ttl = htons(MAX_TTL);
    
    // Set protocol field to ICMP (1)
    ip_hdr->proto = IPPROTO_ICMP;
    
    // Update total length field to reflect ICMP message size, convert to network byte order
    ip_hdr->tot_len = htons(sizeof(*icmp_hdr) + sizeof(*ip_hdr) + icmp_len);
    
    // Reset IP header checksum to 0 before calculation
    ip_hdr->checksum = 0;
    
    // Calculate IP header checksum, convert to network byte order
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

    // Swap Ethernet source and destination addresses
    // Send back to original source MAC address
    memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost,
           sizeof(eth_hdr->ethr_shost));
    
    // Set source MAC to router's interface MAC
    get_interface_mac(interface, eth_hdr->ethr_shost);

    // Copy the ICMP body (original packet excerpt) after the ICMP header
    memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

    // Send the complete ICMP error message out the interface
    send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + icmp_len);
    
    // Free the allocated memory for ICMP body
    free(icmp_body);
}

/**
 * Processes an IP packet - handles forwarding, TTL decrement, and error conditions
 */
static void dr_ip_packet(struct ether_hdr *eth_hdr,
                         uint32_t interface,
                         uint32_t len)
{
    // Extract IP header from the Ethernet frame
    struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)eth_hdr +
                                              sizeof(*eth_hdr));
    
    // Get router's interface IP address
    uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

    // Check if packet is not destined to the router itself
    if (ip_hdr->dest_addr != router_ip)
    {
        // Validate IP header checksum
        // Convert from network to host byte order for comparison
        uint16_t received_checksum = ntohs(ip_hdr->checksum); 
        
        // Reset checksum field to zero before calculation
        ip_hdr->checksum = 0;
        
        // Calculate expected checksum (ihl*4 gives header length in bytes)
        uint16_t calculated_checksum = checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4);

        // Drop packet if checksum is invalid - silently discard corrupted packets
        if (received_checksum != calculated_checksum)
        {
            return;
        }

        // Check if TTL is expired or will expire after decrement
        if (ip_hdr->ttl <= 1)
        {
            // Send ICMP Time Exceeded message (type 11)
            dr_icmp_packet(eth_hdr, 11, interface);
            return;
        }

        // Decrement TTL as packet passes through router
        --ip_hdr->ttl;
        
        // Recalculate IP checksum after TTL modification
        ip_hdr->checksum = 0;  // Reset checksum field
        ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));

        // Find next hop using Longest Prefix Match algorithm
        struct route_table_entry *next_route = dr_get_next_route(ip_hdr->dest_addr);

        // If no route found, send ICMP Destination Unreachable (type 3)
        if (!next_route)
        {
            dr_icmp_packet(eth_hdr, 3, interface);
            return;
        }

        // Look up next hop's MAC address in ARP table
        struct arp_entry *next_arp = dr_get_arp_entry(next_route->next_hop);

        // Set source MAC to router's outgoing interface MAC
        get_interface_mac(next_route->interface, eth_hdr->ethr_shost);

        // If MAC address not found for next hop IP
        if (!next_arp)
        {
            // Queue the packet while we resolve the MAC address
            struct waiting_queue_entry *entry = malloc(sizeof(*entry));
            DIE(!entry, "malloc() failed.\n");
            
            // Allocate memory and copy the entire frame
            entry->eth_hdr = malloc(len);
            DIE(!entry->eth_hdr, "malloc() failed.\n");
            memcpy(entry->eth_hdr, eth_hdr, len);
            
            // Store frame length and route information
            entry->len = len;
            entry->next_route = next_route;
            
            // Add to waiting queue (at the end)
            dll_add_nth_node(waiting_queue, waiting_queue->size, entry,
                             sizeof(*entry));

            // Send ARP request to discover the MAC address
            dr_send_arp_request(eth_hdr, next_route, interface);
            return;
        }

        // Set destination MAC to next hop's MAC address
        memcpy(eth_hdr->ethr_dhost, next_arp->mac, sizeof(next_arp->mac));

        // Forward the packet to next hop through appropriate interface
        send_to_link(next_route->interface, (char *)eth_hdr, len);
    }
    else
    {
        // Packet is destined to router itself - handle as ICMP Echo request
        struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr +
                                                        sizeof(*ip_hdr));

        // Create ICMP Echo reply (type 0) from Echo request (type 8)
        icmp_hdr->mtype = 0;  // Echo Reply
        icmp_hdr->mcode = 0;  // Code 0
        icmp_hdr->check = 0;  // Reset checksum field

        // Calculate length of ICMP data - total IP length minus headers
        // ntohs converts from network to host byte order 
        uint32_t icmp_len = ntohs(ip_hdr->tot_len) -
                            sizeof(*ip_hdr) -
                            sizeof(*icmp_hdr);

        // Copy ICMP data to temporary buffer
        int8_t *icmp_body = malloc(icmp_len);
        DIE(!icmp_body, "malloc() failed.\n");
        memcpy(icmp_body, (char *)icmp_hdr + sizeof(*icmp_hdr), icmp_len);

        // Swap IP addresses for the reply
        ip_hdr->dest_addr = ip_hdr->source_addr;  // Send back to original source
        ip_hdr->source_addr = router_ip;          // From router's interface
        
        // Set TTL, protocol, and length
        ip_hdr->ttl = htons(MAX_TTL);
        ip_hdr->proto = IPPROTO_ICMP;
        ip_hdr->tot_len = htons((uint16_t)icmp_len +
                                sizeof(*icmp_hdr) +
                                sizeof(*ip_hdr));
        // Recalculate IP header checksum
        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

        // Swap Ethernet addresses
        memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost,
               sizeof(eth_hdr->ethr_shost));
        get_interface_mac(interface, eth_hdr->ethr_shost);

        // Copy ICMP data back to packet
        memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

        // Calculate ICMP checksum for echo reply (header + data)
        icmp_hdr->check = 0;
        icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr,
                                         sizeof(*icmp_hdr) + icmp_len));

        // Send the ICMP Echo Reply
        send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + icmp_len);
        free(icmp_body);  // Free temporary buffer
    }
}

/**
 * Processes ARP packets - handles both ARP requests and replies
 */
static void dr_arp_packet(struct ether_hdr *eth_hdr,
                          uint32_t interface,
                          uint32_t len)
{
    // Extract ARP header from the Ethernet frame
    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr +
                                                 sizeof(*eth_hdr));

    // Handle ARP request (opcode 1)
    // ntohs converts 16-bit value from network to host byte order
    if (ntohs(arp_hdr->opcode) == 1)
    {
        // Get router's interface IP address
        uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

        // Check if ARP request is for router's IP
        if (arp_hdr->tprotoa != router_ip)
            return;  // Not for us, ignore

        // Prepare ARP reply (opcode 2)
        arp_hdr->opcode = htons(2);  // Convert to network byte order

        // Swap target and source IP addresses
        arp_hdr->tprotoa = arp_hdr->sprotoa;  // Target IP is requester's IP
        arp_hdr->sprotoa = router_ip;         // Source IP is router's IP

        // Swap target and source MAC addresses
        // Copy requester's MAC as target
        memcpy(arp_hdr->thwa, arp_hdr->shwa, sizeof(arp_hdr->shwa));
        
        // Set source MAC to router's interface MAC
        get_interface_mac(interface, arp_hdr->shwa);

        // Update Ethernet header addresses
        memcpy(eth_hdr->ethr_dhost, arp_hdr->thwa, sizeof(arp_hdr->thwa));
        get_interface_mac(interface, eth_hdr->ethr_shost);

        // Send the ARP reply
        send_to_link(interface, (char *)eth_hdr, len);
    }
    else
    {
        // Handle ARP reply - update ARP table with received IP-MAC mapping
        int found = 0;
        
        // Check if IP already exists in ARP table
        for (int i = 0; i < arp_table_len; i++)
        {
            if (arp_table[i].ip == arp_hdr->sprotoa)
            {
                // Update existing entry with new MAC
                memcpy(arp_table[i].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
                found = 1;
                break;
            }
        }

        // If IP not found, add new entry to ARP table
        if (!found)
        {
            arp_table[arp_table_len].ip = arp_hdr->sprotoa;  // Store IP
            memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));  // Store MAC
            ++arp_table_len;  // Increment table size
        }

        // Process waiting queue for packets needing this MAC address
        dll_node_t *node = waiting_queue->head;
        uint32_t i = 0;

        // Iterate through waiting queue
        while (node)
        {
            // Extract entry data
            struct waiting_queue_entry *entry = (struct waiting_queue_entry *)node->data;
            struct ether_hdr *entry_eth_hdr = (struct ether_hdr *)entry->eth_hdr;

            // Check if this packet was waiting for the MAC we just learned
            if (entry->next_route->next_hop == arp_hdr->sprotoa)
            {
                // Update destination MAC address in the queued packet
                memcpy(entry_eth_hdr->ethr_dhost, arp_hdr->shwa,
                       sizeof(arp_hdr->shwa));

                // Forward the packet now that we know the MAC
                send_to_link(entry->next_route->interface,
                             (char *)entry_eth_hdr, entry->len);

                // Remove this entry from the waiting queue
                dll_node_t *node = dll_remove_nth_node(waiting_queue, i);
                
                // Free memory allocated for the entry
                free(((struct waiting_queue_entry *)(node->data))->eth_hdr);
                free(node);

                --i;  // Adjust index since we removed a node
            }
            ++i;
            node = node->next;  // Move to next node in queue
        }
    }
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];  // Buffer for received packets

    // Initialize router interfaces from command line arguments
    // Skip first two arguments (program name and routing table path)
    init(argv + 2, argc - 2);

    // Create the root of the routing trie
    routing_trie = trie_create_node();
    DIE(!routing_trie, "Failed to create trie root\n");
    
    // Load routing table directly into the trie
    int routes_loaded = read_rtable_to_trie(argv[1], routing_trie);
    printf("Loaded %d routes into routing trie\n", routes_loaded);

    // Allocate memory for ARP table
    arp_table = malloc(sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
    DIE(!arp_table, "malloc() failed\n");

    // Create waiting queue for packets pending ARP resolution
    waiting_queue = dll_create(sizeof(struct waiting_queue_entry));

    // Main packet processing loop
    while (1)
    {
        int interface;
        size_t len;

        // Wait for a packet on any interface
        // recv_from_any_link blocks until a packet arrives
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        // Cast buffer to Ethernet header struct for easier access
        struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

        // Dispatch based on EtherType field
        // ntohs converts from network to host byte order
        switch (ntohs(eth_hdr->ethr_type))
        {
        case IP_ETHERTYPE:  // IPv4 packet (0x0800)
            dr_ip_packet(eth_hdr, interface, len);
            break;
        case ARP_ETHERTYPE:  // ARP packet (0x0806)
            dr_arp_packet(eth_hdr, interface, len);
            break;
        }
        // Other EtherTypes are ignored
    }

    // Free allocated memory (this code is never reached in practice)
    free(arp_table);
    trie_free(routing_trie);
    dll_free(&waiting_queue);

    return 0;
}