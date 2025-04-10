#include "../include/trie.h"
#include "../include/lib.h"
#include "../include/protocols.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>

trie_node_t *trie_create_node() {
    trie_node_t *node = (trie_node_t *)malloc(sizeof(trie_node_t));
    if (!node) {
        fprintf(stderr, "Failed to allocate memory for trie node\n");
        return NULL;
    }
    
    // Initialize the node
    node->children[0] = NULL;
    node->children[1] = NULL;
    node->route_entry = NULL;
    
    return node;
}

int trie_insert(trie_node_t *root, struct route_table_entry *route_entry) {
    if (!root || !route_entry) {
        return -1;  // Invalid input
    }
    
    trie_node_t *current = root;
    
    // Convert to host byte order for bit manipulation
    uint32_t prefix = ntohl(route_entry->prefix);
    uint32_t mask = ntohl(route_entry->mask);
    
    // Calculate prefix length from mask
    int prefix_len = 0;
    
    while (mask) {
        prefix_len += (mask & 1);
        mask >>= 1;
    }
    
    // Insert the route by traversing the trie according to the prefix bits
    for (int i = 31; i >= (32 - prefix_len); i--) {
        int bit = (prefix >> i) & 1;  // Extract the current bit
        
        // Create a new node if it doesn't exist
        if (!current->children[bit]) {
            current->children[bit] = trie_create_node();
            if (!current->children[bit]) {
                return -1;  // Memory allocation failed
            }
        }
        
        // Move to the next node
        current = current->children[bit];
    }
    
    // Store the route at the node corresponding to the full prefix
    current->route_entry = route_entry;
    
    return 0;  // Success
}

struct route_table_entry *trie_longest_prefix_match(trie_node_t *root, uint32_t dest_ip) {
    if (!root) {
        return NULL;
    }
    
    trie_node_t *current = root;
    struct route_table_entry *best_match = NULL;
    
    // Convert to host byte order for bit manipulation
    uint32_t ip = ntohl(dest_ip);
    
    // Traverse the trie based on the bits of the destination IP
    for (int i = 31; i >= 0; i--) {
        int bit = (ip >> i) & 1;  // Extract the current bit
        
        // If there's no path for this bit, we've reached the end of possible matches
        if (!current->children[bit]) {
            break;
        }
        
        // Move to the next node
        current = current->children[bit];
        
        // Update best match if this node contains a route
        if (current->route_entry) {
            best_match = current->route_entry;
        }
    }
    
    return best_match;
}

void trie_free(trie_node_t *root) {
    if (!root) {
        return;
    }
    
    // Recursively free children
    trie_free(root->children[0]);
    trie_free(root->children[1]);
    
    // Free the route entry if it exists
    if (root->route_entry) {
        free(root->route_entry);
    }
    
    // Free the node itself
    free(root);
}
