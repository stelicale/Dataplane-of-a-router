#include "include/list.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static struct route_table_entry *rtable;
static uint32_t rtable_len;

static struct arp_entry *arp_table;
static uint32_t arp_table_len;

static doubly_linked_list_t *waiting_queue;

static inline uint32_t dr_get_ip_from_char(char *char_ip)
{
	uint32_t int_ip;

	inet_pton(AF_INET, char_ip, &int_ip);
	return int_ip;
}

static inline int32_t dr_comparator(const void *p, const void *q)
{
	struct route_table_entry route1 = *(struct route_table_entry *)p;
	struct route_table_entry route2 = *(struct route_table_entry *)q;

	if (ntohl(route1.prefix) > ntohl(route2.prefix))
		return 1;

	if (ntohl(route1.prefix) == ntohl(route2.prefix))
		if (ntohl(route1.mask) > ntohl(route2.mask))
			return 1;

	return -1;
}

static struct route_table_entry *dr_get_next_route(uint32_t ip_dest)
{
    /* Linear search for LPM - garantează găsirea celei mai bune rute */
    struct route_table_entry *best_route = NULL;
    uint32_t best_mask = 0;

    for (uint32_t i = 0; i < rtable_len; i++) {
        if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
            /* Dacă este primul match sau dacă are o mască mai specifică */
            if (best_route == NULL || ntohl(rtable[i].mask) > best_mask) {
                best_route = &rtable[i];
                best_mask = ntohl(rtable[i].mask);
            }
        }
    }
    
    return best_route;
}

static struct arp_entry *dr_get_arp_entry(uint32_t given_ip)
{
	for (uint32_t i = 0; i < arp_table_len; ++i)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];

	return NULL;
}

static void dr_send_arp_request(struct ether_hdr *eth_hdr,
								struct route_table_entry *next_route,
								uint32_t interface)
{
	struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr +
								 sizeof(*eth_hdr));

	arp_hdr->hw_type = htons(1);
	/* Set the ARP protocol format as the one for IPv4. */
	arp_hdr->proto_type = htons(IP_ETHERTYPE);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	/* Set the operation type with the one for ARP request. */
	arp_hdr->opcode = htons(1);
	/*
	 * Set the source mac address as the one of the router interface
	 * the packet will be sent from.
	 */
	get_interface_mac(next_route->interface, arp_hdr->shwa);

	/*
	 * Set the source ip address as the one of the router interface
	 * the packet was received from.
	 */
	uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));
	arp_hdr->sprotoa = router_ip;

	/* Fill with 0 the target MAC address as a place holder. */
	memset(arp_hdr->thwa, 0, sizeof(arp_hdr->thwa));
	arp_hdr->tprotoa = next_route->next_hop;

	/* This packet is sent to everyone, so fill the destination MAC with Fs. */
	memset(eth_hdr->ethr_dhost, 0xff, sizeof(eth_hdr->ethr_dhost));
	eth_hdr->ethr_type = htons(ARP_ETHERTYPE);

	send_to_link(next_route->interface, (char *)eth_hdr, sizeof(*eth_hdr) +
				sizeof(*arp_hdr));
}

static void dr_icmp_packet(struct ether_hdr *eth_hdr,
						   uint8_t type,
						   uint32_t interface)
{
	struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)eth_hdr +
						   sizeof(*eth_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr +
							   sizeof(*ip_hdr));

	/* Prepare the ICMP header based of the custom type (either 11 or 3). */
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr,
							  sizeof(*icmp_hdr)));
	/*
	 * Prepare the ICMP body with the IPv4 header and the first 8 bytes of
	 * its content.
	 */
	uint32_t icmp_len = sizeof(*ip_hdr) + 8; 
	int8_t *icmp_body = malloc(icmp_len);
	DIE(!icmp_body, "malloc() failed.\n");
	memcpy(icmp_body, ip_hdr, icmp_len);

	uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

	/*
	 * Swap the source and destination IP addresses:
	 * 		1. We send the packet back, so the destination gets the source
	 *		   address.
	 *		2. The source is now the IP address of the interface the packet
	 *		   was received from.
	 */
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = router_ip;
	ip_hdr->ttl = htons(MAX_TTL);
	ip_hdr->proto = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(*icmp_hdr) + sizeof(*ip_hdr) + icmp_len);
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

	/*
	 * Swap the source and destinantion MAC addresses as well:
	 *		1. We send the packet back, so the destination gets the source
	 *		   address.
	 *		2. The source is now the MAC address of the interface the packet
	 *		   was received from.
	 */
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost,
		  sizeof(eth_hdr->ethr_shost));
	get_interface_mac(interface, eth_hdr->ethr_shost);

	/*
	 * Copy the ICMP body into the packet thwat gets sent.
	 */
	memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

	send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) +
											 sizeof(*ip_hdr) +
											 sizeof(*icmp_hdr) +
											 icmp_len);
	free(icmp_body);
}

static void dr_ip_packet(struct ether_hdr *eth_hdr,
	uint32_t interface,
	uint32_t len)
{
struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)eth_hdr +
	  sizeof(*eth_hdr));
uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

/*
* If the packet is not an ICMP "Echo request", meaning thwat the final
* destinantion is not the router, we do a bunch of checks.
*/
if (ip_hdr->dest_addr != router_ip) {
/* Checksum integrity check. */
uint16_t received_checksum = ntohs(ip_hdr->checksum);  // Convert to host byte order
ip_hdr->checksum = 0;
uint16_t calculated_checksum = checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4);

/* Drop the packet if checksum is invalid */
if (received_checksum != calculated_checksum) {
return;
}

/* TTL check. */
if (ip_hdr->ttl <= 1) {
/* ICMP "Time exceeded". */
dr_icmp_packet(eth_hdr, 11, interface);
return;
}

--ip_hdr->ttl;
ip_hdr->checksum = 0;
ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));

/*
* Get the next route based of LPM, which was implemented
* via binary search.
*/
struct route_table_entry *next_route = dr_get_next_route(ip_hdr->dest_addr);

if (!next_route) {
/* ICMP "Destination unreachable". */
dr_icmp_packet(eth_hdr, 3, interface);
return;
}

struct arp_entry *next_arp = dr_get_arp_entry(next_route->next_hop);

get_interface_mac(next_route->interface, eth_hdr->ethr_shost);

if (!next_arp) {
/* Insert packet in queue, send ARP request for it. */
struct waiting_queue_entry *entry = malloc(sizeof(*entry));
DIE(!entry, "malloc() failed.\n");
entry->eth_hdr = malloc(len);
DIE(!entry->eth_hdr, "malloc() failed.\n");
memcpy(entry->eth_hdr, eth_hdr, len);
entry->len = len;
entry->next_route = next_route;
dll_add_nth_node(waiting_queue, waiting_queue->size, entry,
	   sizeof(*entry));

dr_send_arp_request(eth_hdr, next_route, interface);
return;
}

memcpy(eth_hdr->ethr_dhost, next_arp->mac, sizeof(next_arp->mac));

send_to_link(next_route->interface, (char *)eth_hdr, len);
} else {
struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr +
			  sizeof(*ip_hdr));

icmp_hdr->mtype = 0;
icmp_hdr->mcode = 0;
icmp_hdr->check = 0;

uint32_t icmp_len = ntohs(ip_hdr->tot_len) -
	   sizeof(*ip_hdr) -
	   sizeof(*icmp_hdr);

int8_t *icmp_body = malloc(icmp_len);
DIE(!icmp_body, "malloc() failed.\n");
memcpy(icmp_body, (char *)icmp_hdr + sizeof(*icmp_hdr), icmp_len);

ip_hdr->dest_addr = ip_hdr->source_addr;
ip_hdr->source_addr = router_ip;
ip_hdr->ttl = htons(MAX_TTL);
ip_hdr->proto = IPPROTO_ICMP;
ip_hdr->tot_len = htons((uint16_t)icmp_len +
	 sizeof(*icmp_hdr) +
	 sizeof(*ip_hdr));
ip_hdr->checksum = 0;
ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost,
sizeof(eth_hdr->ethr_shost));
get_interface_mac(interface, eth_hdr->ethr_shost);

memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

/* Calculate checksum for the entire ICMP message (header + data) */
icmp_hdr->check = 0;
icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, 
			  sizeof(*icmp_hdr) + icmp_len));

send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) +
							sizeof(*ip_hdr) +
							sizeof(*icmp_hdr) +
							icmp_len);
free(icmp_body);
}
}

static void dr_arp_packet(struct ether_hdr *eth_hdr,
                          uint32_t interface,
                          uint32_t len)
{
    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)eth_hdr +
                             sizeof(*eth_hdr));

    /* ARP request. */
    if (ntohs(arp_hdr->opcode) == 1) {
        uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

        if (arp_hdr->tprotoa != router_ip)
            return;

        arp_hdr->opcode = htons(2);

        /* Swap source and destination. */
        arp_hdr->tprotoa = arp_hdr->sprotoa;
        arp_hdr->sprotoa = router_ip;

        memcpy(arp_hdr->thwa, arp_hdr->shwa, sizeof(arp_hdr->shwa));
        get_interface_mac(interface, arp_hdr->shwa);

        memcpy(eth_hdr->ethr_dhost, arp_hdr->thwa, sizeof(arp_hdr->thwa));
        get_interface_mac(interface, eth_hdr->ethr_shost);

        send_to_link(interface, (char *)eth_hdr, len);
    } else {
        /* ARP reply - check if IP already exists in table */
        int found = 0;
        for (uint32_t i = 0; i < arp_table_len; i++) {
            if (arp_table[i].ip == arp_hdr->sprotoa) {
                /* Update existing entry */
                memcpy(arp_table[i].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
                found = 1;
                break;
            }
        }
        
        /* Add new entry only if IP wasn't found */
        if (!found) {
            arp_table[arp_table_len].ip = arp_hdr->sprotoa;
            memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, sizeof(arp_hdr->shwa));
            ++arp_table_len;
        }

        /* Find the packet thwat needs to get sent from the waiting queue. */
        dll_node_t *node = waiting_queue->head;
        uint32_t i = 0;

        while (node) {
            struct waiting_queue_entry *entry = (struct waiting_queue_entry *)node->data;
            struct ether_hdr *entry_eth_hdr = (struct ether_hdr *)entry->eth_hdr;

            if (entry->next_route->next_hop == arp_hdr->sprotoa) {
                memcpy(entry_eth_hdr->ethr_dhost, arp_hdr->shwa,
                      sizeof(arp_hdr->shwa));

                send_to_link(entry->next_route->interface,
                            (char *)entry_eth_hdr, entry->len);

                dll_node_t *node = dll_remove_nth_node(waiting_queue, i);
                free(((struct waiting_queue_entry *)(node->data))->eth_hdr);
                free(node);

                --i;
            }
            ++i;
            node = node->next;
        }
    }
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	DIE(!rtable, "malloc() failed\n");
	rtable_len = read_rtable(argv[1], rtable);

	/* Sort the routing table -> O(nlogn) time complexity. */
	qsort(rtable, rtable_len, sizeof(rtable[0]), dr_comparator);

	arp_table = malloc (sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
	DIE(!arp_table, "malloc() failed\n");

	waiting_queue = dll_create(sizeof(struct waiting_queue_entry));

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		switch (ntohs(eth_hdr->ethr_type)) {
		case IP_ETHERTYPE:
			dr_ip_packet(eth_hdr, interface, len);
			break;
		case ARP_ETHERTYPE:
			dr_arp_packet(eth_hdr, interface, len);
			break;
		}
	}

	free(rtable);
	free(arp_table);
	dll_free(&waiting_queue);

	return 0;
}
