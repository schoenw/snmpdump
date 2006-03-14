/*
 * anon-ipv6.c --
 *
 * Prefix-preserving and lexicographical-order-preserving IPv6 address
 * anonymization library
 *
 * Prefix-preserving anonymization code taken from Crypto-PAn
 * http://www.cc.gatech.edu/computing/Telecomm/cryptopan/Crypto-PAn.1.0.tar.gz
 *
 * Copyright (c) 2005 Matus Harvan
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>

#include "libanon.h"

/*
 * WARNING: We are using the 1-based indexing for bits of IP address,
 * used_i and similar (the notation is consistent with the guided
 * research final report)
 */

/* structure for internal used_i tree */
struct node {
    char complete; /* if complete subtree below node is used */
    struct node* left;
    struct node* right;
    struct node* parent;
};

struct _anon_ipv6 {
    struct node *tree;
    unsigned nodes;
    AES_KEY aes_key;	/* AES key */
    uint8_t m_key[16];	/* 128 bit secret key */
    uint8_t m_pad[16];	/* 128 bit secret pad */
};

#define IPv6LENGTH 128

static int canflip(anon_ipv6_t *a, in6_addr_t ip, int prefixlen);
static void delete_node(struct node* n);
static struct node* add_new_node(struct node* parent, int right);
static void canflip_count_n(struct node* p,int* n, int level);

/*
 * Node allocator and deallocator (factored out to experiment with
 * different allocators).
 */

static inline struct node*
node_alloc()
{
    return (struct node*) malloc(sizeof(struct node));
}

static inline void
node_free(struct node* n)
{
    free(n);
}

/*
 * Create a new IP anonymization object.
 */

anon_ipv6_t*
anon_ipv6_new()
{
    anon_ipv6_t *a;

    a = (anon_ipv6_t *) malloc(sizeof(anon_ipv6_t));
    if (! a) {
	return NULL;
    }
    memset(a, 0, sizeof(anon_ipv6_t));
    a->tree = node_alloc();
    if (!a->tree) {
	free(a);
	return NULL;
    }
    a->tree->parent = NULL;
    a->tree->left = NULL;
    a->tree->right = NULL;
    a->tree->complete = 0;
    a->nodes = 1;
    return a;
}

/*
 * Delete an IP anonymization object and free all its resources.
 */

void
anon_ipv6_delete(anon_ipv6_t *a)
{
    if (! a) {
	return;
    }

    if (a->tree) {
	delete_node(a->tree);
    }
    free(a);
}

/*
 * Set the cryptographic key used for anonymization and initialize it.
 *
 * Key length should be fixed!
 */

void
anon_ipv6_set_key(anon_ipv6_t *a, const uint8_t *key)
{
    assert(a);

    /* initialize the 128-bit secret key */
    memcpy(a->m_key, key, 16);
    /* initialize the AES (Rijndael) cipher */
    AES_set_encrypt_key(key, 128, &(a->aes_key));
    /* initialize the 128-bit secret pad. The pad is encrypted before
     * being used for padding. 
     */
    AES_ecb_encrypt(key + 16, a->m_pad, &(a->aes_key), AES_ENCRYPT);
}

/*
 * Mark IP address prefix as used - create corresponding nodes in the
 * tree and mark the prefix node complete.
 */

int
anon_ipv6_set_used(anon_ipv6_t *a, const struct in6_addr ip, int prefixlen) 
{
    struct node* nodep = a->tree; /* current node */
    struct node* childp = NULL; /* child node to be followed */
    int n = 0;
    int first_bit; /* first (most significant) bit of ip address
		    */
    assert(a);

    /* this should be an assert */
    if (prefixlen > 128) prefixlen = 128;

    while (n < prefixlen) {
	// printf("n: %02d, ip: %d\n",n,ip >> n);
	if (nodep->complete) {
	    // printf("hit complete...\n");
	    return 0;
	}
	first_bit = ip.s6_addr[n / 8]
	    & (((unsigned char) 0x80) >> (n % 8));
	// printf("going %s\n", first_bit ? "right" : "left");
	if (first_bit) {
	    childp = nodep->right;
	} else {
	    childp = nodep->left;
	}	    
	if (!childp) {
	    // printf("adding new node...\n");
	    childp = add_new_node(nodep,first_bit);
	    if (! childp) {
		return -1;
	    }
	    a->nodes++;
	}
	nodep = childp;
	n++;
    }
    nodep->complete = 1;
    return 0;
}

/* 
 * can i-th (1-based indexing) bit in ip be flipped?
 * returns !( used_i(a_1 a_2 ... a_{i-1}0)
 *	&&  used_i(a_1 a_2 ... a_{i-1}1) )
 * where i = prefixlen and ip = a_1 a_2 ...
 */

static int
canflip(anon_ipv6_t *a, const in6_addr_t ip, int prefixlen)
{
    struct node* nodep = a->tree; /* current node */
    struct node* childp = NULL; /* child node to be followed */
    int n = 0;
    prefixlen--; /* need a_1 a_2 ... a_{i-1} [0,1] */
    int first_bit; /* last bit of ip address - currently to be considered */
    while (n < prefixlen) {
	// printf("n: %02d, ip: %d\n",n,ip >> n);
	if (nodep->complete) {
	    // printf("hit complete... (n=%d)\n",n);
	    return 0;
	}
	first_bit = ip.s6_addr[n / 8]
	    & (((unsigned char) 0x80) >> (n % 8));
	if (first_bit) {
	    childp = nodep->right;
	} else {
	    childp = nodep->left;
	}	    
	if (!childp) {
	    // printf("not used...\n");
	    return 0;
	}
	nodep = childp;
	n++;
    }
    if (nodep->complete) {
	// printf("last node is complete... (n=%d)\n",n);
    }
    return ( !(nodep->left && nodep->right) && !nodep->complete);
}

unsigned
anon_ipv6_nodes_count(anon_ipv6_t *a)
{
    return a->nodes;
}

int
canflip_count_ipv6(anon_ipv6_t *a)
{
    int n = 0;
    canflip_count_n(a->tree, &n,0);
    return n;
}

/* warning: not tested with complete !!! */
static void
canflip_count_n(struct node* p,int* n, int level) {
    if (!p)
	return;
    if (p->complete) {
	/* number of addresses in subtree */
	//(*n) += (int) powl(2,IPv4LENGTH-level-1);
	(*n) += 2 << (IPv6LENGTH-level-1);
	(*n) ++;
	return;
    }
    if (!(p->left) && !(p->right)) {
	(*n)++;
    }
    canflip_count_n(p->left, n,level+1);
    canflip_count_n(p->right, n, level+1);
}


/*
 * creates new node and inserts it into the tree as a child of parent
 * if right is non-zero, it become a right child; left otherwise
 * returns pointer to the new child or NULL on error
 */

static struct node*
add_new_node(struct node* parent, int right) {
    if (!parent) {
	return NULL;
    }
    if (parent->complete) {
	return NULL;
    }
    
    struct node* n = node_alloc();
    if (!n) {
	return NULL;
    }
    n->left = NULL;
    n->right = NULL;
    n->parent = parent;
    n->complete = 0;

    if (right) {
	n->right = parent->right;
	parent->right = n;
    } else {
	n->left = parent->left;
	parent->left = n;
    }
    return n;
}

static void
delete_node(struct node* n) {
    if (!n) return;
    delete_node(n->left);
    delete_node(n->right);
    n->left = NULL;
    n->right = NULL;
    node_free(n);
}

/*
 * prefix-preserving anonymization on ip
 * slightly modified version of PAnonymizer::anonymize() from Crypto-PAn
 */
int
anon_ipv6_map_pref(anon_ipv6_t *a, const in6_addr_t ip, in6_addr_t *aip)
{
    uint8_t rin_output[16];
    uint8_t rin_input[16];
    int pos, i;

    assert(a);

    memset(aip, 0, sizeof(in6_addr_t));
    //memcpy(rin_input, a->m_pad, 16);

    /* For each prefix with length from 0 to 31, generate a using
     * bit the Rijndael cipher, which is used as a pseudorandom
     * function here. The bits generated in every round are combined
     * into a pseudorandom one-time-pad.
     */
    for (pos = 0; pos < 128 ; pos++) { 
	/* Padding: The most significant pos bits are taken from
	 * ip. The other 128-pos bits are taken from m_pad.
	 */
	for(i=0;i<pos/8;i++) {
		rin_input[i] = ip.s6_addr[i];
	}
	rin_input[pos/8] = (ip.s6_addr[pos/8] >> (8-pos%8)) << (8-pos%8);
	/* debugging output
	fprintf(stderr, "pos: %d, pos/8: %d , rin_input[%d]: 0x%x, "
		"rin_input[%d]: 0x%x, ip.s6_addr[%d]: 0x%x\n",
		pos, pos/8, pos/8, rin_input[pos/8], 
		(pos/8 > 0) ? pos/8-1 : 0, rin_input[(pos/8 > 0) ? pos/8-1:0],
		(pos/8 > 0) ? pos/8-1:0, ip.s6_addr[(pos/8 > 0) ? pos/8-1:0]);
	*/
	rin_input[pos/8] |= (a->m_pad[pos/8] << (pos%8)) >> (pos%8);
	for(i=(pos/8)+1;i<16;i++) {
	    rin_input[i] = a->m_pad[i];
	}

	/* Encryption: The Rijndael cipher is used as pseudorandom
	 * function. During each round, only the first bit of
	 * rin_output is used.
	 */
	AES_ecb_encrypt(rin_input, rin_output, &(a->aes_key), AES_ENCRYPT);
	/* Combination: the bits are combined into a pseudorandom
	 *  one-time-pad
	 */
	aip->s6_addr[pos/8] |=  (rin_output[0] >> 7) << (7-(pos%8));
    }
    /* XOR the orginal address with the pseudorandom one-time-pad */
    for(i=0;i<16;i++) {
	aip->s6_addr[i] = aip->s6_addr[i] ^ ip.s6_addr[i];
    }
    return 0;
}

/*
 * prefix- and lexicographical-order-preserving anonymization on
 * ip
 */

int
anon_ipv6_map_pref_lex(anon_ipv6_t *a, const in6_addr_t ip, in6_addr_t *aip)
{
    uint8_t rin_output[16];
    uint8_t rin_input[16];
    int pos, i;

    assert(a);

    memset(aip, 0, sizeof(in6_addr_t));
    //memcpy(rin_input, a->m_pad, 16);

    /* For each prefix with length from 0 to 31, generate a using
     * bit the Rijndael cipher, which is used as a pseudorandom
     * function here. The bits generated in every round are combined
     * into a pseudorandom one-time-pad.
     */
    for (pos = 0; pos < 128 ; pos++) { 
	/* Padding: The most significant pos bits are taken from
	 * ip. The other 128-pos bits are taken from m_pad.
	 */
	for(i=0;i<pos/8;i++) {
		rin_input[i] = ip.s6_addr[i];
	}
	rin_input[pos/8] = (ip.s6_addr[pos/8] >> (8-pos%8)) << (8-pos%8);
	/* debugging output
	fprintf(stderr, "pos: %d, pos/8: %d , rin_input[%d]: 0x%x, "
		"rin_input[%d]: 0x%x, ip.s6_addr[%d]: 0x%x\n",
		pos, pos/8, pos/8, rin_input[pos/8], 
		(pos/8 > 0) ? pos/8-1 : 0, rin_input[(pos/8 > 0) ? pos/8-1:0],
		(pos/8 > 0) ? pos/8-1:0, ip.s6_addr[(pos/8 > 0) ? pos/8-1:0]);
	*/
	rin_input[pos/8] |= (a->m_pad[pos/8] << (pos%8)) >> (pos%8);
	for(i=(pos/8)+1;i<16;i++) {
	    rin_input[i] = a->m_pad[i];
	}

	/* Encryption: The Rijndael cipher is used as pseudorandom
	 * function. During each round, only the first bit of
	 * rin_output is used.
	 */
	AES_ecb_encrypt(rin_input, rin_output, &(a->aes_key), AES_ENCRYPT);

	/* combine with used_i */
	if (! canflip(a, ip, pos+1)) {
	    rin_output[0] = 0;
	}

	/* Combination: the bits are combined into a pseudorandom
	 *  one-time-pad
	 */
	aip->s6_addr[pos/8] |=  (rin_output[0] >> 7) << (7-(pos%8));
    }
    /* XOR the orginal address with the pseudorandom one-time-pad */
    for(i=0;i<16;i++) {
	aip->s6_addr[i] = aip->s6_addr[i] ^ ip.s6_addr[i];
    }
    return 0;
}
