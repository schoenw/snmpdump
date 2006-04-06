/*
 * anon-ip.c --
 *
 * Prefix-preserving and lexicographical-order-preserving IP address
 * anonymization library
 *
 * Prefix-preserving anonymization code taken from Crypto-PAn
 * http://www.cc.gatech.edu/computing/Telecomm/cryptopan/Crypto-PAn.1.0.tar.gz
 *
 * Copyright (c) 2005 Matus Harvan
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

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

struct _anon_ipv4 {
    struct node *tree;
    unsigned nodes;
    AES_KEY aes_key;	/* AES key */
    uint8_t m_key[16];	/* 128 bit secret key */
    uint8_t m_pad[16];	/* 128 bit secret pad */
};

#define IPv4LENGTH 32

static int canflip(anon_ipv4_t *a, const in_addr_t ip, const int prefixlen);
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

anon_ipv4_t*
anon_ipv4_new()
{
    anon_ipv4_t *a;

    a = (anon_ipv4_t *) malloc(sizeof(anon_ipv4_t));
    if (! a) {
	return NULL;
    }
    memset(a, 0, sizeof(anon_ipv4_t));
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

    /*
     * initialize the AES (Rijndael) cipher
     * (in case user forgets to call ..._set_key)
     */
    AES_set_encrypt_key(NULL, 0, &(a->aes_key));

    return a;
}

/*
 * Delete an IP anonymization object and free all its resources.
 */

void
anon_ipv4_delete(anon_ipv4_t *a)
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
 * Set the cryptographic key using a human memorizable passphrase
 * passphrase has to be null-terminated
 */

void
anon_ipv4_set_passphrase(anon_ipv4_t *a, const char *pass)
{
    /* we need a 32 byte key and SHA-1 produces 20 byte output */
    uint8_t key[2*SHA_DIGEST_LENGTH];
    
    /* do the SHA-1 hashing */
    SHA1((unsigned char *) pass, strlen(pass)/2, key);
    pass += strlen(pass)/2;
    SHA1((unsigned char *) pass, strlen(pass), key+SHA_DIGEST_LENGTH);

    anon_ipv4_set_key(a, key);
}

/*
 * Set the cryptographic key used for anonymization and initialize it.
 */

void
anon_ipv4_set_key(anon_ipv4_t *a, const uint8_t *key)
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
anon_ipv4_set_used(anon_ipv4_t *a, const in_addr_t ip, const int prefixlen) 
{
    struct node* nodep = a->tree; /* current node */
    struct node* childp = NULL; /* child node to be followed */
    int n = 0;
    int first_bit; /* first (most significant) bit of ip address
		    * - currently to be considered in traversing the tree
		    */
    uint8_t* c = (uint8_t*) &(ip); /* cut-down representation of ip */
    int pfl = prefixlen;
    
    assert(a);

    if (prefixlen > 32 || prefixlen < 1) pfl = 32;

    while (n < pfl) {
	// printf("n: %02d, ip: %d\n",n,ip >> n);
	if (nodep->complete) {
	    // printf("hit complete...\n");
	    return 0;
	}
	first_bit = c[n/8] & ( 0x80 >> (n % 8)); //( 1 << (7-(n%8)));
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
 * ip is expected in network byte order (the one from inet_pton)
 * 
 * can i-th (1-based indexing) bit in ip be flipped?
 * returns !( used_i(a_1 a_2 ... a_{i-1}0)
 *	&&  used_i(a_1 a_2 ... a_{i-1}1) )
 * where i = prefixlen and ip = a_1 a_2 ...
 */

static int
canflip(anon_ipv4_t *a, const in_addr_t ip, const int prefixlen)
{
    struct node* nodep = a->tree; /* current node */
    struct node* childp = NULL; /* child node to be followed */
    uint8_t* c = (uint8_t*) &(ip); /* cut-down representation of ip */
    int n = 0;
    int pfl = prefixlen-1; /* need a_1 a_2 ... a_{i-1} [0,1] */
    int first_bit; /* last bit of ip address - currently to be considered */
    while (n < pfl) {
	// printf("n: %02d, ip: %d\n",n,ip >> n);
	if (nodep->complete) {
	    // printf("hit complete... (n=%d)\n",n);
	    return 0;
	}
	first_bit = c[n/8] & ( 0x80 >> (n % 8)); //( 1 << (7-(n%8)));
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
anon_ipv4_nodes_count(anon_ipv4_t *a)
{
    return a->nodes;
}

int
canflipv4_count_ip(anon_ipv4_t *a)
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
	(*n) += 2 << (IPv4LENGTH-level-1);
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
 * ip and aip are expected in network byte order (as returned by inet_pton
 * slightly modified version of PAnonymizer::anonymize() from Crypto-PAn
 */
int
anon_ipv4_map_pref(anon_ipv4_t *a, const in_addr_t ip, in_addr_t *aip)
{
    uint8_t rin_output[16];
    uint8_t rin_input[16];
    int pos, i;
    uint8_t* c = (uint8_t*) &(ip); /* cut-down representation of ip */
    uint8_t* ac = (uint8_t*) aip ; /* cut-down representation of aip */

    assert(a);

    memset(aip, 0, sizeof(in_addr_t));
    memcpy(rin_input, a->m_pad, 16);

    /* For each prefix with length from 0 to 31, generate a bit
     * using the Rijndael cipher, which is used as a pseudorandom
     * function here. The bits generated in every round are combined
     * into a pseudorandom one-time-pad.
     */
    for (pos = 0; pos <= 31 ; pos++) { 
	/* Padding: The most significant pos bits are taken from
	 * ip. The other 128-pos bits are taken from m_pad.
	 */
	for(i=0;i<pos/8;i++) {
	    rin_input[i] = c[i];
	}
	rin_input[pos/8] = (c[pos/8] >> (8-pos%8)) << (8-pos%8);
	
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
	ac[pos/8] |=  (rin_output[0] >> 7) << (7-(pos%8));
	// fprintf(stderr, "bit %2d: flip bit: %d\n",
	// 	pos, (rin_output[0] >> 7));
    }
    /* XOR the orginal address with the pseudorandom one-time-pad */
    for(i=0;i<4;i++) {
	ac[i] = ac[i] ^ c[i];
    }
    return 0;
}

/*
 * prefix- and lexicographical-order-preserving anonymization on
 * ip
 */

int
anon_ipv4_map_pref_lex(anon_ipv4_t *a, const in_addr_t ip, in_addr_t *aip)
{
    uint8_t rin_output[16];
    uint8_t rin_input[16];
    int pos, i;
    uint8_t* c = (uint8_t*) &(ip); /* cut-down representation of ip */
    uint8_t* ac = (uint8_t*) aip ; /* cut-down representation of aip */
    

    assert(a);

    memset(aip, 0, sizeof(in_addr_t));
    memcpy(rin_input, a->m_pad, 16);

    /* For each prefix with length from 0 to 31, generate a bit
     * using the Rijndael cipher, which is used as a pseudorandom
     * function here. The bits generated in every round are combined
     * into a pseudorandom one-time-pad.
     */
    for (pos = 0; pos <= 31 ; pos++) { 
	/* Padding: The most significant pos bits are taken from
	 * ip. The other 128-pos bits are taken from m_pad.
	 */
	for(i=0;i<pos/8;i++) {
	    rin_input[i] = c[i];
	}
	rin_input[pos/8] = (c[pos/8] >> (8-pos%8)) << (8-pos%8);
	
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
	/*
	fprintf(stderr, "canflip pos %d: %d\n",
	pos+1, canflip(a, ip, pos+1));
	*/
	
	/* Combination: the bits are combined into a pseudorandom
	 *  one-time-pad
	 */
	ac[pos/8] |=  (rin_output[0] >> 7) << (7-(pos%8));
	// fprintf(stderr, "bit %2d: flip bit: %d\n",
	// 	pos, (rin_output[0] >> 7));
    }
    /* XOR the orginal address with the pseudorandom one-time-pad */
    for(i=0;i<4;i++) {
	ac[i] = ac[i] ^ c[i];
    }
    return 0;
}
