# Dataplane of a router

##  Assignment

This project was developed as a solution for the **Router** assignment from the **Computer Networks** course at the Faculty of Automatic Control and Computer Science, University Politehnica of Bucharest.

[Official assignment statement (Router)](https://pcom.pages.upb.ro/tema1/ethernet.html)

## Functionalities (Implementation Description)

### 1. **Routing Table with Trie**
- The routing table is parsed at startup from a file and stored in a **binary trie**, optimized for **Longest Prefix Match (LPM)**.
- Each trie node holds up to two children (`0` and `1`), corresponding to the binary representation of the IP address.
- Fast LPM allows for efficient routing decisions for each received IP packet.

### 2. **IP Packet Processing**
- On reception of an IP packet:
  - Validates the **IP header checksum**.
  - Checks if the packet is destined for one of the router's interfaces:
    - If **ICMP Echo Request**, sends back **ICMP Echo Reply**.
  - Otherwise:
    - **Decrements TTL**, drops and replies with **ICMP Time Exceeded** if it becomes 0.
    - Uses the **trie** to determine the best route (LPM).
    - Forwards the packet to the next hop if a route is found.
    - If not, replies with **ICMP Destination Unreachable**.

### 3. **ICMP Handling**
- **Echo Reply (Type 0)**: Responds to ICMP Echo Requests.
- **Time Exceeded (Type 11)**: Sent when a packet’s TTL reaches 0.
- **Destination Unreachable (Type 3)**: Sent when no matching route exists.

### 4. **ARP Table and Resolution**
- Maintains a **dynamic ARP table** that maps IP addresses to MAC addresses.
- If next-hop MAC is missing:
  - Sends **ARP Request**.
  - Stores the packet in a **waiting queue** until the ARP Reply is received.
- When ARP Reply is received:
  - Updates the ARP table.
  - Forwards all waiting packets destined for that IP.

### 5. **ARP Request/Reply Processing**
- On **ARP Request**:
  - If the requested IP matches one of the router’s interfaces, sends **ARP Reply**.
- On **ARP Reply**:
  - Updates the ARP table.
  - Flushes and sends all queued packets waiting for that IP.

### 6. **Waiting Packet Queue**
- Packets waiting for ARP resolution are stored in a queue.
- After MAC resolution, the router:
  - Updates the Ethernet header.
  - Forwards all relevant packets.

### 7. **Ethernet Frame Handling**
- Before forwarding:
  - Updates **source MAC** to interface MAC.
  - Updates **destination MAC** to resolved next-hop MAC.
- Uses `send_to_link()` to send the modified packet on the appropriate interface.

### 8. **Memory and Resource Management**
- Dynamic structures like the ARP table and waiting queue are properly allocated and deallocated.
- Avoids memory leaks by freeing packets and queue entries after use.

---

## How the Router Works

1. **Initialization**:
   - Loads the routing table.
   - Initializes the ARP table and packet queue.

2. **Main Loop**:
   - Receives packets using `get_packet()`.
   - Dispatches based on Ethernet type (IP or ARP).

3. **Packet Processing**:
   - ARP packets go to `arp_packet()`.
   - IP packets go to `ip_packet()`.

4. **Forwarding or Replying**:
   - Based on IP destination, TTL, and protocol type, the router either:
     - Replies (e.g., ICMP Echo Reply).
     - Forwards using ARP.
     - Replies with an ICMP error if necessary.

---

## Educational Scope

This project demonstrates a full-stack understanding of:
- Network layer forwarding (IPv4).
- Data-link layer protocols (Ethernet, ARP).
- ICMP error handling.
- Trie-based prefix search algorithms.
- Realistic networking behaviors using raw packet manipulation.

---

## Limitations

- No support for:
  - Fragmented packets.
  - IPv6.
  - NAT/firewall functionality.
  - Advanced routing protocols (e.g., RIP, OSPF).

---

## Notes

- This implementation is tailored for educational use and learning purposes in controlled network environments.
- It provides a hands-on perspective on how routers operate internally — from LPM and ARP to ICMP messaging and Ethernet frame crafting.

