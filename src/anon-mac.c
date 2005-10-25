/*
 * anon-mac.c --
 *
 * IEEE MAC address anonymization functions.
 *
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/lhash.h>

#include "libanon.h"

/* node struct for a list */
struct node {
    uint8_t mac[8];
    struct node *next;
};

/* node struct for an lhash table */
struct hash_node {
    uint8_t mac[8];
    uint8_t hash[8];
};

/* For nonlexicographic order, we are generating hashes on the
 * fly. They are stored in anon_mac_t's list, to make sure we generate
 * unique addresses.
 *
 * For lexicographic order, we use anon_mac_t's list for storing the
 * real MAC addresses.
 */
struct _anon_mac {
    LHASH *hash_table;
    struct node *list;
    int state;
};

enum anon_mac_state_t {INIT=0, /* MAC anon object initialized,
				* set_used() may have been used
				* already, but no MAC address has yet
				* been anonymized using this object
				*/
		       NON_LEX, /* anon_mac_map() has already been used */
		       LEX}; /* anon_mac_map() has already been used */



/* functions for the lhash table */
static unsigned long
anon_mac_hash(const struct hash_node *tohash)
{
    long hash = 0;
    int i;
    for(i=0;i<8;i++) {
	hash += tohash->mac[i];
	hash << 8;
    }
    return hash;
}

static int
anon_mac_cmp(const struct hash_node *arg1, const struct hash_node *arg2) {
    int i;
    for(i=0;i<8;i++) {
	if (arg1->mac[i] != arg2->mac[i]) return 1;
    }
    return 0;
}

/* Create the type-safe wrapper functions for use in the LHASH internals */
static IMPLEMENT_LHASH_HASH_FN(anon_mac_hash, const struct hash_node *);
static IMPLEMENT_LHASH_COMP_FN(anon_mac_cmp, const struct hash_node *);

/* returns 0 if we're trying to insert a MAC address not yet in the list */
static int
list_insert(struct node **list, const uint8_t *mac)
{
    struct node *p, *q, *n;
    int c;
    
    assert(mac);
    
    for (p = *list, q = NULL; p; q = p, p = p->next) {
	c = memcmp(mac, p->mac, 8);
	if (c == 0) {
	    return 1;
	}
	if (c < 0) {
	    break;
	}
    }

    n = (struct node *) malloc(sizeof(struct node));
    if (! n) {
	return -1;
    }
    
    memset(n, 0, sizeof(struct node));
    memcpy(n->mac, mac, 8);
    if (! q) {
	n->next = *list;
	*list = n;
    } else {
	n->next = q->next;
	q->next = n;
    }

    return 0;
}

/*
 * Set/change the state of MAC anonymization object. Performs
 * neccessary checks if state change is ok.
 */
static int
anon_mac_set_state(anon_mac_t *a, int state)
{
    uint8_t mac[8];
    struct node *p, *q;
    int i, j;

    assert(a);
    
    switch (state) {
    case INIT:
	if (a->state == state) return 0;
	break;
    case NON_LEX:
	if (a->state == state) return 0;
	assert(a->state == INIT);
	a->state = state;
	return 0;
    case LEX:
	if (a->state == state) return 0;
	assert(a->state == INIT);
	a->state = state;

	/* populate hashlist with unique random MAC addresses */
	struct node* hashlist = NULL;
	for (p = a->list; p; p = p->next) {
	    do {
		memset(mac,0,8);
		RAND_bytes(mac,6);
		/* RAND_pseudo_bytes(mac,6); */
		/* preserve first bit */
		if (p->mac[0] & 0xFF) {
		    mac[0] |= 0x80;
		} else {
		    mac[0] &= 0x7F;
		}
	    } while (list_insert(&hashlist,mac)==1);
	}

	/* assign anon. macs to real macs in lhash table */
	struct hash_node *node;
	for (p = a->list, q = hashlist; p; q = q->next, p = p->next) {
	    node = (struct hash_node*) malloc(sizeof(struct hash_node));
	    assert(node);
	    memcpy(node->mac, p->mac, 8);
	    memcpy(node->hash, q->mac, 8);
	    lh_insert(a->hash_table, node);
	}

	/* we don't need the list of used MACs anymore */
	for (p = a->list; p; ) {
	    struct node *q = p;
	    p = p->next;
	    free(q);
	}
	a->list = NULL;
	/* we don't need the list of hashed MACs anymore */
	for (p = hashlist; p; ) {
	    struct node *q = p;
	    p = p->next;
	    free(q);
	}
	hashlist = NULL;

	return 0;
    default:
	fprintf(stderr,"trying to set ilegal state for an anon_mac_t\n");
	assert(0);
    }
    return 0;
}

/*
 * Create a new MAC anonymization object.
 */

anon_mac_t*
anon_mac_new()
{
    anon_mac_t *a;

    a = (anon_mac_t *) malloc(sizeof(anon_mac_t));
    if (! a) {
	return NULL;
    }
    memset(a, 0, sizeof(anon_mac_t));

    a->hash_table = lh_new(LHASH_HASH_FN(anon_mac_hash),
			   LHASH_COMP_FN(anon_mac_cmp));
    a->state = INIT; /* we're initializing, so we don't want to do
		      * checks on previous state values
		      */

    /* initialize randomness - this might not be the best way to do it */
    while (! RAND_status()) {
	fprintf(stderr, "initializing randomness...");
	char buf;
	buf = rand();
        RAND_seed(buf,1);
	fprintf(stderr, "done\n");
    }

    return a;
}

/*
 * recursively print list nodes
 */
void
print(struct node *p)
{
    if (p) {
	fprintf(stderr, "[%p]\n", p);
	fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		p->mac[0], p->mac[1], p->mac[2],
		p->mac[3], p->mac[4], p->mac[5]);
	print(p->next);
    }
}

/*
 * Delete an MAC anonymization object and free all its resources.
 */

void
anon_mac_delete(anon_mac_t *a)
{
    struct node *p;

    if (! a) {
	return;
    }

    lh_free(a->hash_table);

    for (p = a->list; p; ) {
	struct node *q = p;
	p = p->next;
	free(q);
    }

    free(a);
}

/*
 * Set the cryptographic key used for anonymization.
 */

void
anon_mac_set_key(anon_mac_t *a, const uint8_t *key)
{
    assert(a);
    /* we might want to use the key to seed the RAND_* stuff */
}

/*
 * Mark a MAC address as used. We simply put it into a linked list
 * sorted by lexicographic order. Note that this is not really
 * efficient - a heap like data structure might be more appropriate.
 */

int
anon_mac_set_used(anon_mac_t *a, const uint8_t *mac)
{
    struct node *p, *q, *n;
    int c;
    
    assert(a && mac);
    
    (void) anon_mac_set_state(a, INIT);

    if (list_insert(&(a->list), mac) >= 0) {
	return 0;
    } else{
	return -1;
    }
}

/*
 * anonymization on mac address
 * anonymized mac addresses are also kept in a linked list to make
 * sure they are unique
 */
int
anon_mac_map(anon_mac_t *a, const uint8_t *mac,
	     uint8_t *amac)
{
    struct hash_node node;
    struct hash_node *p;
    int j;
    int tmp;

    (void) anon_mac_set_state(a, NON_LEX);

    /* lookup anon. MAC in lhash table */
    memcpy(node.mac, mac, 8);
    p = (struct hash_node *) lh_retrieve(a->hash_table,(void*) &node);
    
    if (p) { /* MAC found in lhash table */
	memcpy(amac, p->hash, 8);
    } else { /* MAC not found in lhash table */
	/* generate a unique random MAC addresses */
	do {
	    memset(amac,0,8);
	    RAND_bytes(amac,6);
	    /* RAND_pseudo_bytes(amac,6); */
	    /* preserve first bit */
	    if (mac[0] & 0xFF) {
		amac[0] |= 0x80;
	    } else {
		amac[0] &= 0x7F;
	    }
	    tmp = list_insert(&(a->list),amac);
	    assert(tmp >= 0);
	} while (tmp==1);
	/* store anon. MAC in lhash table */
	p = (struct hash_node*) malloc(sizeof(struct hash_node));
	assert(p);
	memcpy(p->mac, mac, 8);
	memcpy(p->hash, amac, 8);
	lh_insert(a->hash_table, p);
    }
    return 0;
}

/*
 * lexicographical-order-preserving anonymization on mac address
 */
int
anon_mac_map_lex(anon_mac_t *a, const uint8_t *mac,
		 uint8_t *amac)
{
    struct hash_node node;
    struct hash_node *p;
    (void) anon_mac_set_state(a, LEX);
    
    /* lookup the anonymized mac address in the lhash table */
    memset(&node, 0, sizeof(struct hash_node));
    memcpy(node.mac, mac, 8);
    p = (struct hash_node *) lh_retrieve(a->hash_table,(void*) &node);
    assert(p);
    memcpy(amac, p->hash, 8);
    return 0;
}
