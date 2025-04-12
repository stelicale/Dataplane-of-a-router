#include "include/list.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "include/trie.h"
#include "include/queue.h"
#include "include/router.h"
#include <netinet/in.h>
#include <arpa/inet.h>

struct arp_table_entry *get_arp_entry(struct router_t *router, uint32_t given_ip)
{
    for (int i = 0; i < router->arp_table_len; ++i)
        if (router->arp_table[i].ip == given_ip)
            return &router->arp_table[i];
    return NULL;
}

void icmp_packet(struct ether_hdr *frame, uint8_t msg_type, uint32_t iface)
{
    char *cursor = (char *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(cursor + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(cursor + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    
    // Store original source information
    uint32_t orig_src_ip = ip->source_addr;
    uint8_t orig_src_mac[6];
    memcpy(orig_src_mac, frame->ethr_shost, 6);

    const size_t data_size = sizeof(*ip) + 8;
    uint8_t *data_copy = malloc(data_size);
    if (!data_copy) {
        fprintf(stderr, "Failed to allocate memory for ICMP data\n");
        return;
    }

    memcpy(data_copy, ip, data_size);
    
    // Set ICMP fields
    icmp->mtype = msg_type;
    icmp->mcode = 0;
    icmp->check = 0;
    uint16_t icmp_csum = checksum((uint16_t *)icmp, sizeof(*icmp));
    icmp->check = htons(icmp_csum);
    
    // Get router's IP for reply source
    char *local_ip_str = get_interface_ip(iface);
    uint32_t local_ip = inet_addr(local_ip_str);
    
    ip->ttl = MAX_TTL;
    ip->proto = IPPROTO_ICMP;
    ip->source_addr = local_ip;
    ip->dest_addr = orig_src_ip;
    
    uint16_t total_ip_size = sizeof(*ip) + sizeof(*icmp) + data_size;
    ip->tot_len = htons(total_ip_size);
    
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(*ip)));
    
    // Update Ethernet headers
    memcpy(frame->ethr_dhost, orig_src_mac, 6);
    get_interface_mac(iface, frame->ethr_shost);
    
    // Add original data to payload
    memcpy(cursor + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 
           data_copy, data_size);
           
    uint32_t total_frame_size = sizeof(struct ether_hdr) + total_ip_size;
    send_to_link(total_frame_size, cursor, iface);
    
    free(data_copy);
}

void send_arp(struct ether_hdr *eth_hdr,
                 uint16_t opcode,
                 uint32_t interface,
                 uint32_t target_ip,
                 uint8_t *target_mac,
                 struct route_table_entry *next_route)
{
    char buffer[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
    struct ether_hdr *new_eth_hdr = (struct ether_hdr *)buffer;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buffer + sizeof(struct ether_hdr));

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

    // Configure ARP header
    arp_hdr->hw_len = 6;
    arp_hdr->hw_type = htons(1);
    arp_hdr->opcode = htons(opcode);
    arp_hdr->proto_len = 4;
    arp_hdr->proto_type = htons(IP_ETHERTYPE);

    uint32_t router_ip = inet_addr(get_interface_ip(out_interface));
    arp_hdr->sprotoa = router_ip;
    arp_hdr->tprotoa = target_ip;

    get_interface_mac(out_interface, arp_hdr->shwa);
    get_interface_mac(out_interface, new_eth_hdr->ethr_shost);
    new_eth_hdr->ethr_type = htons(ARP_ETHERTYPE);

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buffer, out_interface);
}

void arp_packet(struct ether_hdr *eth_hdr,
                   uint32_t interface,
                   uint32_t len,
                   struct router_t *router)
{
    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr + sizeof(*eth_hdr));

    if (ntohs(arp_hdr->opcode) == 2)
    {
        // Handle ARP reply
        int found = 0;

        // Update ARP table with received mapping
        struct arp_table_entry *entry = get_arp_entry(router, arp_hdr->sprotoa);
        if (entry) {
            memcpy(entry->mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
            found = 1;
        }

        // Add new entry if not found
        if (!found && router->arp_table_len < MAX_ARP_TABLE_LEN)
        {
            router->arp_table[router->arp_table_len].ip = arp_hdr->sprotoa;
            memcpy(router->arp_table[router->arp_table_len].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
            ++(router->arp_table_len);
        }

        // Process waiting packets
        queue new_queue = create_queue();
        while (!queue_empty(router->waiting_queue))
        {
            struct waiting_queue_entry *entry = (struct waiting_queue_entry *)queue_deq(router->waiting_queue);
            if (entry->next_route->next_hop == arp_hdr->sprotoa)
            {
                // Forward packet with resolved MAC
                struct ether_hdr *entry_eth_hdr = (struct ether_hdr *)entry->eth_hdr;
                memcpy(entry_eth_hdr->ethr_dhost, arp_hdr->shwa, sizeof(arp_hdr->shwa));
                get_interface_mac(entry->next_route->interface, entry_eth_hdr->ethr_shost);
                send_to_link(entry->len, (char *)entry_eth_hdr, entry->next_route->interface);

                free(entry->eth_hdr);
                free(entry);
            } else
                queue_enq(new_queue, entry);
        }
        queue_free(router->waiting_queue);
        router->waiting_queue = new_queue;
    } else {
        // Handle ARP request
        uint32_t router_ip = inet_addr(get_interface_ip(interface));
        if (arp_hdr->tprotoa != router_ip)
            return; // Not for us

        send_arp(eth_hdr, 2, interface, arp_hdr->sprotoa, arp_hdr->shwa, NULL);
    }
}

void ip_packet(struct ether_hdr *frame, uint32_t iface, uint32_t size, struct router_t *router)
{
    char *pkt_data = (char *)frame;
    struct ip_hdr *ip = (struct ip_hdr *)(pkt_data + sizeof(struct ether_hdr));
    uint32_t my_ip = inet_addr(get_interface_ip(iface));
    
    if (ip->dest_addr == my_ip) {
        // Handle packets destined for router
        if (ip->proto == IPPROTO_ICMP) {
            struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt_data + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
            
            // Only respond to Echo Requests
            if (icmp->mtype != 8) return;
            
            uint16_t ip_len = ntohs(ip->tot_len);
            uint16_t icmp_data_len = ip_len - sizeof(*ip) - sizeof(*icmp);
            
            // Save ICMP payload
            uint8_t *echo_data = malloc(icmp_data_len);
            if (!echo_data) return;
            memcpy(echo_data, (uint8_t*)icmp + sizeof(*icmp), icmp_data_len);
            
            // Convert request to reply
            icmp->mtype = 0; 
            icmp->mcode = 0;
            icmp->check = 0;
            
            // Update headers
            ip->dest_addr = ip->source_addr;
            ip->source_addr = my_ip;
            ip->ttl = MAX_TTL;
            
            ip->checksum = 0;
            ip->checksum = htons(checksum((uint16_t *)ip, sizeof(*ip)));
            
            // Swap Ethernet addresses
            uint8_t tmp_mac[6];
            memcpy(tmp_mac, frame->ethr_dhost, 6);
            memcpy(frame->ethr_dhost, frame->ethr_shost, 6);
            get_interface_mac(iface, frame->ethr_shost);
            
            memcpy((uint8_t*)icmp + sizeof(*icmp), echo_data, icmp_data_len);
            free(echo_data);
            
            icmp->check = htons(checksum((uint16_t *)icmp, sizeof(*icmp) + icmp_data_len));
            send_to_link(size, pkt_data, iface);
        }
        return;
    }
    
    // Forward packet - validate checksum first
    uint16_t orig_csum = ntohs(ip->checksum);
    ip->checksum = 0;
    uint16_t calc_csum = checksum((uint16_t *)ip, ip->ihl * 4);
    
    if (orig_csum != calc_csum) return;
    
    // Check TTL
    if (ip->ttl <= 1) {
        icmp_packet(frame, 11, iface);  // Time Exceeded
        return;
    }
    
    // Update TTL and checksum
    ip->ttl--;
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, ip->ihl * 4));
    
    // Find next hop
    struct route_table_entry *route = trie_longest_prefix_match(router->routing_table, ip->dest_addr);
    if (!route) {
        icmp_packet(frame, 3, iface);
        return;
    }
    
    get_interface_mac(route->interface, frame->ethr_shost);
    struct arp_table_entry *next_hop = get_arp_entry(router, route->next_hop);
    
    if (!next_hop) {
        // Queue packet and send ARP request
        struct waiting_queue_entry *pending = malloc(sizeof(*pending));
        if (!pending) return;
        
        pending->eth_hdr = malloc(size);
        if (!pending->eth_hdr) {
            free(pending);
            return;
        }
        
        memcpy(pending->eth_hdr, frame, size);
        pending->len = size;
        pending->next_route = route;
        
        queue_enq(router->waiting_queue, pending);
        send_arp(frame, 1, iface, route->next_hop, NULL, route);
        return;
    }
    
    // Forward packet
    memcpy(frame->ethr_dhost, next_hop->mac, 6);
    send_to_link(size, pkt_data, route->interface);
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN]; // Buffer for received packets

    // Initialize router interfaces
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
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    
        if (ntohs(eth_hdr->ethr_type) == ARP_ETHERTYPE)
            arp_packet(eth_hdr, interface, len, router);
        else if (ntohs(eth_hdr->ethr_type) == IP_ETHERTYPE)
            ip_packet(eth_hdr, interface, len, router);
    }

    // Clean up (never reached)
    free(router->arp_table);
    trie_free(router->routing_table);
    queue_free(router->waiting_queue);
    free(router);
    return 0;
}