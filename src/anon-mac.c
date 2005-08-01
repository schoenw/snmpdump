/*
 * anon-mac.c --
 *
 * IEEE MAC address anonymization library.
 *
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/lhash.h>

#include "libanon.h"

struct node {
    uint8_t mac[8];
    uint8_t hash[8];
    struct node *next;
};


struct _anon_mac {
    LHASH *hash_table;
    struct node *list;
};


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
    return a;
}

void
print(struct node *p)
{
    if (p) {
	fprintf(stderr, "[%p]\n", p);
	fprintf(stderr, "%2x:%2x:%2x:%2x:%2x:%2x\n",
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

    /* lh_free(a->hash_table); */

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

    for (p = a->list, q = NULL; p; q = p, p = p->next) {
	c = memcmp(mac, p->mac, 8);
	if (c == 0) {
	    return 0;
	}
	if (c > 0) {
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
	a->list = n;
    } else {
	q->next = n;
	n->next = q->next;
    }

    return 0;
}

