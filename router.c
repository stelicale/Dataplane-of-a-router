// Include custom and system header files for the router implementation
#include "include/list.h"      // Doubly linked list implementation
#include "include/lib.h"       // Custom router utilities and structures
#include "include/protocols.h" // Protocol definitions and structs
#include "include/trie.h"      // Trie data structure for efficient IP lookups
#include "include/queue.h"     // Queue implementation for waiting packets
#include <string.h>            // For memory operations like memcpy, memset
#include <netinet/in.h>        // For network byte order conversions (htons, ntohl)
#include <arpa/inet.h>         // For IP address manipulation (inet_pton)

/**
 * Searches the ARP table for a given IP address
 * Returns the corresponding ARP entry if found, NULL otherwise
 */
struct arp_table_entry *get_arp_entry(struct router_t *router, uint32_t given_ip)
{
    // Linear search through the ARP table
    for (int i = 0; i < router->arp_table_len; ++i)
        if (router->arp_table[i].ip == given_ip) // Direct comparison of 32-bit IP addresses
            return &router->arp_table[i];        // Return a pointer to the matching entry

    return NULL; // IP not found in ARP table
}

/**
 * Generates ICMP responses for error notifications or echo replies
 * @param frame Pointer to the original Ethernet frame
 * @param msg_type ICMP message type code (e.g., 0=Echo Reply, 3=Unreachable, 11=Time Exceeded)
 * @param iface Interface index to send the ICMP message from
 */
void icmp_packet(struct ether_hdr *frame, uint8_t msg_type, uint32_t iface)
{
    // Locate headers in the received packet
    char *cursor = (char *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(cursor + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(cursor + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    
    // Store original source information before modification
    uint32_t orig_src_ip = ip->source_addr;
    uint8_t orig_src_mac[6];
    memcpy(orig_src_mac, frame->ethr_shost, 6);
    
    // Determine size of data portion to include
    const size_t data_size = sizeof(*ip) + 8;
    
    // Prepare workspace for data
    uint8_t *data_copy = malloc(data_size);
    if (!data_copy) {
        fprintf(stderr, "Failed to allocate memory for ICMP data\n");
        return;
    }
    
    // Preserve original packet headers
    memcpy(data_copy, ip, data_size);
    
    // Set ICMP fields - type, code and reset checksum for calculation
    icmp->mtype = msg_type;
    icmp->mcode = 0;
    icmp->check = 0;
    
    // Calculate correct checksum for the ICMP header
    uint16_t icmp_csum = checksum((uint16_t *)icmp, sizeof(*icmp));
    icmp->check = htons(icmp_csum);
    
    // Get local IP address for source of reply 
    char *local_ip_str = get_interface_ip(iface);
    uint32_t local_ip = inet_addr(local_ip_str);
    
    // Update IP header fields for the response
    ip->ttl = MAX_TTL;                 // Set fresh TTL
    ip->proto = IPPROTO_ICMP;          // Protocol is ICMP
    ip->source_addr = local_ip;        // Source is now router
    ip->dest_addr = orig_src_ip;       // Destination is original sender
    
    // Calculate total packet size and update IP length field
    uint16_t total_ip_size = sizeof(*ip) + sizeof(*icmp) + data_size;
    ip->tot_len = htons(total_ip_size);
    
    // Reset and recalculate IP checksum
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(*ip)));
    
    // Swap Ethernet addresses and update source MAC
    memcpy(frame->ethr_dhost, orig_src_mac, 6);
    get_interface_mac(iface, frame->ethr_shost);
    
    // Place original packet data in the ICMP payload area
    memcpy(cursor + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 
           data_copy, data_size);
           
    // Calculate total frame size for transmission
    uint32_t total_frame_size = sizeof(struct ether_hdr) + total_ip_size;
    
    // Transmit the ICMP message
    send_to_link(iface, cursor, total_frame_size);
    
    // Clean up
    free(data_copy);
}

/**
 * Creates and sends an ARP packet (request or reply)
 * @param eth_hdr Ethernet header to use
 * @param opcode ARP operation code (1=request, 2=reply)
 * @param interface Interface to send on
 * @param target_ip Target IP address
 * @param target_mac Target MAC address (NULL for requests)
 * @param next_route Route entry (only needed for requests)
 */
void send_arp(struct ether_hdr *eth_hdr,
                 uint16_t opcode,
                 uint32_t interface,
                 uint32_t target_ip,
                 uint8_t *target_mac,
                 struct route_table_entry *next_route)
{
    // Create a new buffer for the ARP packet to avoid overwriting original packet
    char buffer[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
    struct ether_hdr *new_eth_hdr = (struct ether_hdr *)buffer;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buffer + sizeof(struct ether_hdr));

    // Determine the correct outgoing interface
    uint32_t out_interface = interface;
    if (opcode == 1)
    {
        out_interface = next_route->interface;
        memset(arp_hdr->thwa, 0, sizeof(arp_hdr->thwa));
        memset(new_eth_hdr->ethr_dhost, 0xff, sizeof(new_eth_hdr->ethr_dhost));
    } else {
        memcpy(arp_hdr->thwa, target_mac, sizeof(arp_hdr->thwa));
        memcpy(new_eth_hdr->ethr_dhost, target_mac, sizeof(new_eth_hdr->ethr_dhost));
    }

    // Configure the ARP header fields
    arp_hdr->hw_type = htons(1);               // Hardware type: Ethernet
    arp_hdr->proto_type = htons(IP_ETHERTYPE); // Protocol: IPv4
    arp_hdr->hw_len = 6;                       // MAC size: 6 bytes
    arp_hdr->proto_len = 4;                    // IPv4 size: 4 bytes
    arp_hdr->opcode = htons(opcode);           // Operation: request or reply

    // Get router's IP for the outgoing interface
    uint32_t router_ip = inet_addr(get_interface_ip(out_interface));

    // Set source IP (router's IP)
    arp_hdr->sprotoa = router_ip;

    // Set target IP address
    arp_hdr->tprotoa = target_ip;

    // Set source MAC (router's MAC)
    get_interface_mac(out_interface, arp_hdr->shwa);

    // Set source MAC in Ethernet header
    get_interface_mac(out_interface, new_eth_hdr->ethr_shost);

    // Set Ethernet type to ARP
    new_eth_hdr->ethr_type = htons(ARP_ETHERTYPE);

    // Send the packet
    send_to_link(out_interface, buffer, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
}

/**
 * Processes ARP packets - handles both ARP requests and replies
 */
void arp_packet(struct ether_hdr *eth_hdr,
                   uint32_t interface,
                   uint32_t len,
                   struct router_t *router)
{
    // Extract ARP header from the Ethernet frame
    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr + sizeof(*eth_hdr));

    // Handle ARP reply
    if (ntohs(arp_hdr->opcode) == 2)
    {
        // Always update the ARP table with received IP-MAC mapping
        int found = 0;

        // Check if IP already exists in ARP table
        struct arp_table_entry *entry = get_arp_entry(router, arp_hdr->sprotoa);
        if (entry) {
            // Update existing entry with new MAC
            memcpy(entry->mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
            found = 1;
        }

        // If IP not found, add new entry to ARP table
        if (!found && router->arp_table_len < MAX_ARP_TABLE_LEN)
        {
            router->arp_table[router->arp_table_len].ip = arp_hdr->sprotoa;
            memcpy(router->arp_table[router->arp_table_len].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
            ++(router->arp_table_len);
        }

        // Create a new queue for packets still waiting for ARP resolution
        queue new_queue = create_queue();

        // Process waiting queue
        while (!queue_empty(router->waiting_queue))
        {
            struct waiting_queue_entry *entry = (struct waiting_queue_entry *)queue_deq(router->waiting_queue);

            // Check if this packet was waiting for the MAC we just learned
            if (entry->next_route->next_hop == arp_hdr->sprotoa)
            {
                // Update destination MAC address in the queued packet
                struct ether_hdr *entry_eth_hdr = (struct ether_hdr *)entry->eth_hdr;
                memcpy(entry_eth_hdr->ethr_dhost, arp_hdr->shwa, sizeof(arp_hdr->shwa));

                // Set source MAC to router's outgoing interface MAC
                get_interface_mac(entry->next_route->interface, entry_eth_hdr->ethr_shost);

                // Forward the packet now that we know the MAC
                send_to_link(entry->next_route->interface, (char *)entry_eth_hdr, entry->len);

                // Free memory for this packet
                free(entry->eth_hdr);
                free(entry);
            }
            else
            {
                // Packet still waiting for another ARP resolution
                queue_enq(new_queue, entry);
            }
        }
        queue_free(router->waiting_queue);
        router->waiting_queue = new_queue;
    } else {
        // Get router's interface IP address
        uint32_t router_ip = inet_addr(get_interface_ip(interface));

        // Check if ARP request is for router's IP
        if (arp_hdr->tprotoa != router_ip)
            return; // Not for us, ignore

        // Send ARP reply
        send_arp(eth_hdr, 2, interface, arp_hdr->sprotoa, arp_hdr->shwa, NULL);
    }
}

/**
 * Router data plane logic for IP packet processing
 * Handles forwarding, error responses, and TTL management
 */
void ip_packet(struct ether_hdr *frame, uint32_t iface, uint32_t size, struct router_t *router)
{
    char *pkt_data = (char *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(pkt_data + sizeof(struct ether_hdr));
    
    // Lookup our interface IP
    uint32_t my_ip = inet_addr(get_interface_ip(iface));
    
    // Check if packet is destined for this router
    int for_me = (ip->dest_addr == my_ip);
    
    if (for_me) {
        // This packet is meant for us - handle as Echo Request if ICMP
        if (ip->proto == IPPROTO_ICMP) {
            struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt_data + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
            
            // Only respond to Echo Requests (type 8)
            if (icmp->mtype != 8) return;
            
            // Calculate ICMP payload size
            uint16_t ip_len = ntohs(ip->tot_len);
            uint16_t icmp_data_len = ip_len - sizeof(*ip) - sizeof(*icmp);
            
            // Save ICMP payload before modifying packet
            uint8_t *echo_data = malloc(icmp_data_len);
            if (!echo_data) return;
            memcpy(echo_data, (uint8_t*)icmp + sizeof(*icmp), icmp_data_len);
            
            // Convert request to reply
            icmp->mtype = 0;                    // Echo Reply
            icmp->mcode = 0;
            icmp->check = 0;
            
            // Swap addresses for the reply
            ip->dest_addr = ip->source_addr;    // Send to original source
            ip->source_addr = my_ip;            // From router's interface
            ip->ttl = MAX_TTL;                  // Fresh TTL
            
            // Reset IP checksum for recalculation
            ip->checksum = 0;
            ip->checksum = htons(checksum((uint16_t *)ip, sizeof(*ip)));
            
            // Swap Ethernet addresses
            uint8_t tmp_mac[6];
            memcpy(tmp_mac, frame->ethr_dhost, 6);
            memcpy(frame->ethr_dhost, frame->ethr_shost, 6);
            get_interface_mac(iface, frame->ethr_shost);
            
            // Restore the ICMP data
            memcpy((uint8_t*)icmp + sizeof(*icmp), echo_data, icmp_data_len);
            free(echo_data);
            
            // Calculate ICMP checksum over header and data
            icmp->check = htons(checksum((uint16_t *)icmp, sizeof(*icmp) + icmp_data_len));
            
            // Send the reply
            send_to_link(iface, pkt_data, size);
        }
        return;
    }
    
    // Packet needs to be forwarded - validate checksum first
    uint16_t orig_csum = ntohs(ip->checksum);
    ip->checksum = 0;
    uint16_t calc_csum = checksum((uint16_t *)ip, ip->ihl * 4);
    
    // Drop corrupted packets
    if (orig_csum != calc_csum) return;
    
    // Check TTL - if 1 or less after decrement, send Time Exceeded
    if (ip->ttl <= 1) {
        icmp_packet(frame, 11, iface);  // Time Exceeded
        return;
    }
    
    // Decrement TTL and update checksum
    ip->ttl--;
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, ip->ihl * 4));
    
    // Find next hop via longest prefix match
    struct route_table_entry *route = trie_longest_prefix_match(router->routing_table, ip->dest_addr);
    
    // No route found - send Destination Unreachable
    if (!route) {
        icmp_packet(frame, 3, iface);
        return;
    }
    
    // Update source MAC address for outgoing interface
    get_interface_mac(route->interface, frame->ethr_shost);
    
    // Look up destination MAC via ARP table
    struct arp_table_entry *next_hop = get_arp_entry(router, route->next_hop);
    
    // If MAC not in ARP table, queue packet and send ARP request
    if (!next_hop) {
        // Allocate queue entry
        struct waiting_queue_entry *pending = malloc(sizeof(*pending));
        if (!pending) return;
        
        // Save packet while waiting for ARP response
        pending->eth_hdr = malloc(size);
        if (!pending->eth_hdr) {
            free(pending);
            return;
        }
        
        // Copy packet and metadata
        memcpy(pending->eth_hdr, frame, size);
        pending->len = size;
        pending->next_route = route;
        
        // Add to waiting queue
        queue_enq(router->waiting_queue, pending);
        
        // Send ARP request to discover next hop's MAC
        send_arp(frame, 1, iface, route->next_hop, NULL, route);
        return;
    }
    
    // Update destination MAC and forward packet
    memcpy(frame->ethr_dhost, next_hop->mac, 6);
    send_to_link(route->interface, pkt_data, size);
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN]; // Buffer for received packets

    // Initialize router interfaces from command line arguments
    // Skip first two arguments (program name and routing table path)
    init(argv + 2, argc - 2);

    struct router_t *router = malloc(sizeof(struct router_t));
    DIE(!router, "malloc() failed\n");
    router->routing_table = trie_create_node();
    DIE(!router->routing_table, "malloc() failed\n");

    // Load routing table directly into the trie
    read_rtable_to_trie(argv[1], router->routing_table);

    // Allocate memory for ARP table
    router->arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_TABLE_LEN);
    DIE(!router->arp_table, "malloc() failed\n");
    router->arp_table_len = 0;

    // Create waiting queue for packets pending ARP resolution
    router->waiting_queue = create_queue();

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
            case IP_ETHERTYPE: // IPv4 packet (0x0800)
                ip_packet(eth_hdr, interface, len, router);
                break;
            case ARP_ETHERTYPE: // ARP packet (0x0806)
                arp_packet(eth_hdr, interface, len, router);
                break;
        }
        // Other EtherTypes are ignored
    }

    // Free allocated memory (this code is never reached in practice)
    free(router->arp_table);
    trie_free(router->routing_table);
    queue_free(router->waiting_queue);
    free(router);
    return 0;
}