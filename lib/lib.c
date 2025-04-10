// Include our custom header file that defines structures and function prototypes
#include "lib.h"

// Include system headers needed for socket programming and networking
#include <sys/ioctl.h>        // For network interface control operations
#include <net/if.h>           // For network interface structures and constants
#include <netinet/in.h>       // For IPv4 address structures
#include <sys/socket.h>       // For socket API functions
#include <linux/if_packet.h>  // For raw packet handling at link layer
#include <stdio.h>            // For standard I/O operations
#include <stdlib.h>           // For memory allocation and conversion functions
#include <string.h>           // For string manipulation functions
#include <sys/types.h>        // For system data types
#include <unistd.h>           // For POSIX standard functions like read/write
#include <asm/byteorder.h>    // For endianness conversion macros
#include <arpa/inet.h>        // For IP address manipulation functions

#include "../include/trie.h"

// Global array to store socket file descriptors for each router interface
int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
    int res;
    // Create a raw socket at the link layer (Layer 2)
    // AF_PACKET provides access to physical network interface
    // SOCK_RAW gives raw packet access without protocol handling
    // 768 is protocol number (not commonly used value)
    int s = socket(AF_PACKET, SOCK_RAW, 768);
    DIE(s == -1, "socket");  // Check if socket creation failed

    // Create interface request structure to get interface information
    struct ifreq intf;
    strcpy(intf.ifr_name, if_name);  // Copy interface name to the request structure
    // Get the interface index number using ioctl system call
    res = ioctl(s, SIOCGIFINDEX, &intf);
    DIE(res, "ioctl SIOCGIFINDEX");  // Check if ioctl call failed

    // Create socket address structure for link layer
    struct sockaddr_ll addr;
    memset(&addr, 0x00, sizeof(addr));  // Zero out the structure first
    addr.sll_family = AF_PACKET;  // Set the address family to packet interface
    addr.sll_ifindex = intf.ifr_ifindex;  // Set the interface index from earlier ioctl call

    // Bind the socket to the specified network interface
    // This associates our socket with physical network card
    res = bind(s, (struct sockaddr *)&addr, sizeof(addr));
    DIE(res == -1, "bind");  // Check if bind failed
    return s;  // Return the socket file descriptor
}

int send_to_link(int interface, char *frame_data, size_t length)
{
    /*
     * Note that "buffer" should be at least the MTU size of the 
     * interface, eg 1500 bytes 
     */
    int ret;
    // Write data to the network interface using the file descriptor
    // interfaces[interface] is the socket FD for the specified interface
    // frame_data contains the raw Ethernet frame to send
    ret = write(interfaces[interface], frame_data, length);
    DIE(ret == -1, "write");  // Check if write operation failed
    return ret;  // Return number of bytes written
}

ssize_t receive_from_link(int intidx, char *frame_data)
{
    ssize_t ret;
    // Read incoming data from the specified interface
    // frame_data will contain the received Ethernet frame
    // MAX_PACKET_LEN limits the maximum size that can be read
    ret = read(interfaces[intidx], frame_data, MAX_PACKET_LEN);
    return ret;  // Return number of bytes read or -1 on error
}

int socket_receive_message(int sockfd, char *frame_data, size_t *len)
{
    /*
     * Note that "buffer" should be at least the MTU size of the
     * interface, eg 1500 bytes
     * */
    // Read incoming data from the socket
    int ret = read(sockfd, frame_data, MAX_PACKET_LEN);
    DIE(ret < 0, "read");  // Check if read operation failed
    *len = ret;  // Store the number of bytes read through the len pointer
    return 0;  // Return success
}

int recv_from_any_link(char *frame_data, size_t *length) {
    int res;
    fd_set set;  // File descriptor set for select() call

    FD_ZERO(&set);  // Initialize the file descriptor set to empty
    while (1) {  // Loop indefinitely until a packet is received
        // Add all interface sockets to the file descriptor set
        for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
            FD_SET(interfaces[i], &set);  // Mark each interface FD as being monitored
        }

        // Wait until data is available on any interface
        // select() blocks until one of the FDs has data to read
        // The +1 is because select needs max FD value plus 1
        res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set,
                NULL, NULL, NULL);
        DIE(res == -1, "select");  // Check if select failed

        // Check which interface has data available
        for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
            if (FD_ISSET(interfaces[i], &set)) {  // Test if this interface has data
                // Read the data from the interface that has data available
                ssize_t ret = receive_from_link(i, frame_data);
                DIE(ret < 0, "receive_from_link");  // Check if receive failed
                *length = ret;  // Store the number of bytes read
                return i;  // Return the interface index that received data
            }
        }
    }

    return -1;  // This should never be reached due to infinite loop
}

char *get_interface_ip(int interface)
{
    struct ifreq ifr;  // Interface request structure
    int ret;
    
    // Format the interface name based on the interface index
    // Special case for interface 0
    if (interface == 0)
        sprintf(ifr.ifr_name, "rr-0-1");
    else {
        // Format for other interfaces
        sprintf(ifr.ifr_name, "r-%u", interface - 1);
    }
    
    // Use ioctl to get the IP address of the interface
    // SIOCGIFADDR is the request code for getting interface address
    ret = ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
    DIE(ret == -1, "ioctl SIOCGIFADDR");  // Check if ioctl failed
    
    // Extract the IP address from the interface structure and convert to string
    // inet_ntoa converts binary IP to dotted decimal string format
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(size_t interface, uint8_t *mac)
{
    struct ifreq ifr;  // Interface request structure
    int ret;
    
    // Format the interface name, same logic as get_interface_ip
    if (interface == 0)
        sprintf(ifr.ifr_name, "rr-0-1");
    else {
        sprintf(ifr.ifr_name, "r-%lu", interface - 1);
    }
    
    // Use ioctl to get the hardware/MAC address of the interface
    // SIOCGIFHWADDR is the request code for getting hardware address
    ret = ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
    DIE(ret == -1, "ioctl SIOCGIFHWADDR");  // Check if ioctl failed
    
    // Copy the 6-byte MAC address to the provided buffer
    // MAC address is stored in ifr.ifr_addr.sa_data
    memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
    // Convert a single hexadecimal character to its numerical value (0-15)
    if (c >= '0' && c <= '9')
        return c - '0';  // For digits 0-9
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;  // For lowercase a-f (values 10-15)
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;  // For uppercase A-F (values 10-15)

    return -1;  // Return error for invalid hex character
}

int hex2byte(const char *hex)
{
    int a, b;
    // Convert first hex character
    a = hex2num(*hex++);
    if (a < 0)
        return -1;  // Return error if invalid character
        
    // Convert second hex character
    b = hex2num(*hex++);
    if (b < 0)
        return -1;  // Return error if invalid character
        
    // Combine two hex digits into one byte (a*16 + b)
    return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
    int i;
    // Process all 6 bytes of a MAC address (format: xx:xx:xx:xx:xx:xx)
    for (i = 0; i < 6; i++) {
        int a, b;
        // Convert first hex character of this byte
        a = hex2num(*txt++);
        if (a < 0)
            return -1;  // Return error if invalid character
            
        // Convert second hex character of this byte
        b = hex2num(*txt++);
        if (b < 0)
            return -1;  // Return error if invalid character
            
        // Store the byte value in the address buffer
        *addr++ = (a << 4) | b;
        
        // Check for colon separator between bytes (except after last byte)
        if (i < 5 && *txt++ != ':')
            return -1;  // Return error if separator not found
    }
    return 0;  // Return success
}

void init(char *argv[], int argc)
{
    // Initialize all router interfaces based on command line arguments
    for (int i = 0; i < argc; ++i) {
        printf("Setting up interface: %s\n", argv[i]);
        // Create a socket for each interface and store FD in interfaces array
        interfaces[i] = get_sock(argv[i]);
    }
}

uint16_t checksum(uint16_t *data, size_t length)
{
    unsigned long checksum = 0;
    uint16_t extra_byte;
    
    // Sum up 16-bit words from the data
    while (length > 1) {
        // Add current 16-bit word to checksum after converting from network byte order
        checksum += ntohs(*data++);
        length -= 2;  // Move to next 16-bit word
    }
    
    // Handle odd byte if length is odd
    if (length) {
        // Take the remaining byte and handle it separately
        *(uint8_t *)&extra_byte = *(uint8_t *)data;
        checksum += extra_byte;
    }

    // Add carry bits back to lower 16 bits (one's complement sum)
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);  // Add any new carry bit
    
    // Return one's complement of the result (invert all bits)
    return (uint16_t)(~checksum);
}

int read_rtable_to_trie(const char *path, trie_node_t *trie_root)
{
    // Open the routing table file for reading
    FILE *fp = fopen(path, "r");
    DIE(fp == NULL, "Failed to open %s", path);
    
    int j = 0, i;  // j counts entries, i counts fields within an entry
    char *p, line[64];  // p holds tokens, line buffer holds each line from file

    // Read the file line by line
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Create a new route entry for this line
        struct route_table_entry *route = malloc(sizeof(struct route_table_entry));
        DIE(!route, "malloc() failed for route entry");
        
        // Initialize the route entry
        route->prefix = 0;
        route->next_hop = 0;
        route->mask = 0;
        route->interface = 0;
        
        // Split the line into tokens using space and dot as delimiters
        p = strtok(line, " .");
        i = 0;
        
        // Process each token in the line
        while (p != NULL) {
            // First 4 tokens: bytes of the prefix (network address)
            if (i < 4)
                // Store each byte in the correct position within prefix
                *(((unsigned char *)&route->prefix) + i % 4) = (unsigned char)atoi(p);

            // Next 4 tokens: bytes of the next hop IP address
            if (i >= 4 && i < 8)
                // Store each byte in the correct position within next_hop
                *(((unsigned char *)&route->next_hop) + i % 4) = atoi(p);

            // Next 4 tokens: bytes of the subnet mask
            if (i >= 8 && i < 12)
                // Store each byte in the correct position within mask
                *(((unsigned char *)&route->mask) + i % 4) = atoi(p);

            // Final token: interface number
            if (i == 12)
                route->interface = atoi(p);
                
            // Get next token
            p = strtok(NULL, " .");
            i++;
        }
        
        // Insert the route entry into the trie
        if (trie_insert(trie_root, route) != 0) {
            fprintf(stderr, "Failed to insert route into trie\n");
            free(route);
        } else {
            j++;  // Count successful insertion
        }
    }
    
    fclose(fp);
    return j;  // Return the number of routing table entries inserted
}

int parse_arp_table(char *path, struct arp_table_entry *arp_table)
{
    FILE *f;
    fprintf(stderr, "Parsing ARP table\n");
    // Open the ARP table file
    f = fopen(path, "r");
    DIE(f == NULL, "Failed to open %s", path);
    
    char line[100];
    int i = 0;
    
    // Read the file line by line
    for(i = 0; fgets(line, sizeof(line), f); i++) {
        char ip_str[50], mac_str[50];
        // Parse each line for IP and MAC address
        sscanf(line, "%s %s", ip_str, mac_str);
        fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
        
        // Convert IP string to binary format using inet_addr
        arp_table[i].ip = inet_addr(ip_str);
        
        // Convert MAC string to binary format using hwaddr_aton
        int rc = hwaddr_aton(mac_str, arp_table[i].mac);
        DIE(rc < 0, "invalid MAC");  // Check if MAC address format was invalid
    }
    
    fclose(f);
    fprintf(stderr, "Done parsing ARP table.\n");
    return i;  // Return the number of ARP entries read
}
