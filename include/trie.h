#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

/**
 * Trie node structure for IPv4 routing
 * Each node represents a bit in the IP address
 */
typedef struct trie_node {
    struct trie_node *children[2];  // Binary trie (0 and 1 children)
    struct route_table_entry *route_entry;  // Routing info stored at this node (NULL if not a prefix end)
} trie_node_t;

/**
 * Creates a new trie node
 * @return pointer to the newly created node
 */
trie_node_t *trie_create_node();

/**
 * Inserts a route entry into the trie
 * @param root the root of the trie
 * @param route_entry the route entry to insert
 * @return 0 on success, -1 on failure
 */
int trie_insert(trie_node_t *root, struct route_table_entry *route_entry);

/**
 * Performs Longest Prefix Match in the trie for a given destination IP
 * @param root the root of the trie
 * @param dest_ip the destination IP to find the best route for
 * @return pointer to the best matching route, or NULL if no match
 */
struct route_table_entry *trie_longest_prefix_match(trie_node_t *root, uint32_t dest_ip);

/**
 * Frees all memory allocated for the trie
 * @param root pointer to the root of the trie
 */
void trie_free(trie_node_t *root);

#endif /* TRIE_H */
