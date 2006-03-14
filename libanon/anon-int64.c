/*
 * anon-int64.c --
 *
 * int64 anonymization functions.
 *
 * Numbers are mapped into range [lower, upper] (inclusive). Clearly,
 * number of distinct input numbers has to be <= (upper - lower + 1),
 * i.e. the total number of distinct numbers we can generate.
 *
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>

#include "libanon.h"

/* node struct for a list */
struct node {
    int64_t num;
    struct node *next;
};

/* node struct for an lhash table */
struct hash_node {
    int64_t num;
    int64_t hash;
};

/* For nonlexicographic order, we are generating hashes on the
 * fly. They are stored in anon_int64_t's list, to make sure we generate
 * unique addresses.
 *
 * For lexicographic order, we use anon_int64_t's list for storing the
 * unanonymized numbers .
 */
struct _anon_int64 {
    LHASH *hash_table;
    struct node *list;
    int state;
    int64_t lower, upper;
    uint64_t range; /* range = upper - lower + 1 */
};

enum anon_int64_state_t {INIT=0, /* anon object initialized,
				* set_used() may have been used
				* already, but nothing has yet
				* been anonymized using this object
				*/
			 NON_LEX, /* anon_int64_map() has already been used */
			 LEX}; /* anon_int64_map_lex() has already been used */


/* functions for the lhash table */
static unsigned long
anon_int64_hash(const struct hash_node *tohash)
{
    return tohash->num;
}

static int
anon_int64_cmp(const struct hash_node *arg1, const struct hash_node *arg2) {
    if (arg1->num == arg2->num) {
	return 0;
    } else {
	return 1;
    }
}

/* Create the type-safe wrapper functions for use in the LHASH internals */
static IMPLEMENT_LHASH_HASH_FN(anon_int64_hash, const struct hash_node *);
static IMPLEMENT_LHASH_COMP_FN(anon_int64_cmp, const struct hash_node *);

/* returns 0 if we're trying to insert a number not yet in the list */
static int
list_insert(struct node **list, const int64_t num)
{
    struct node *p, *q, *n;
    
    for (p = *list, q = NULL; p; q = p, p = p->next) {
	if (num == p->num) {
	    return 1;
	}
	if (num > p->num) {
	    break;
	}
    }

    n = (struct node *) malloc(sizeof(struct node));
    if (! n) {
	return -1;
    }
    
    memset(n, 0, sizeof(struct node));
    n->num = num;
    if (! q) {
	n->next = *list;
	*list = n;
    } else {
	n->next = q->next;
	q->next = n;
    }

    return 0;
}

/* generate a random number between a->lower and a->upper */
static void
generate_random_number(int64_t* anum, anon_int64_t* a)
{
    uint64_t u_anum = 0; /* unsigned version of anum */
    RAND_bytes((unsigned char *) &u_anum, sizeof(u_anum));
    u_anum %= a->range;
    
    if (u_anum > INT64_MAX) {
	*anum = (int64_t) (u_anum - ((uint64_t) INT64_MAX));
	*anum += a->lower; /* u_anum > INT64_MAX => range > INT64_MAX
			 * => lower < 0
			 */
	*anum += INT64_MAX;
    } else {
	*anum = (int64_t) u_anum;
	*anum += a->lower;
    }
}

/*
 * Set/change the state of int64 anonymization object. Performs
 * neccessary checks if state change is ok.
 */
static int
anon_int64_set_state(anon_int64_t *a, int state)
{
    int64_t anum;
    struct node *p, *q;

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

	/* populate hashlist with unique random numbers */
	struct node* hashlist = NULL;
	int count = 0;
	for (p = a->list; p; p = p->next) {
	    count++;
	    if (count > a->upper - a->lower + 1) {
		fprintf(stderr,"more numbers to anonymize than could be "
			"fitted in the range lower..upper\n");
		assert(0);
	    }
	    do {
		generate_random_number(&anum, a);
	    } while (list_insert(&hashlist,anum)==1);
	}

	/* assign anon. numbers to real numbers in lhash table */
	struct hash_node *node;
	for (p = a->list, q = hashlist; p; q = q->next, p = p->next) {
	    node = (struct hash_node*) malloc(sizeof(struct hash_node));
	    assert(node);
	    node->num = p->num;
	    node->hash = q->num;
	    lh_insert(a->hash_table, node);
	}

	/* we don't need the list of used numbers anymore */
	for (p = a->list; p; ) {
	    struct node *q = p;
	    p = p->next;
	    free(q);
	}
	a->list = NULL;
	/* we don't need the list of hashed numbers anymore */
	for (p = hashlist; p; ) {
	    struct node *q = p;
	    p = p->next;
	    free(q);
	}
	hashlist = NULL;

	return 0;
    default:
	fprintf(stderr,"trying to set ilegal state for an anon_int64_t\n");
	assert(0);
    }
    return 0;
}

/*
 * Create a new int64 anonymization object.
 */

anon_int64_t*
anon_int64_new(const int64_t lower, const int64_t upper)
{
    anon_int64_t *a;

    assert(lower <= upper);
    
    a = (anon_int64_t *) malloc(sizeof(anon_int64_t));
    if (! a) {
	return NULL;
    }
    memset(a, 0, sizeof(anon_int64_t));
    
    a->lower = lower;
    a->upper = upper;
    a->hash_table = lh_new(LHASH_HASH_FN(anon_int64_hash),
			   LHASH_COMP_FN(anon_int64_cmp));
    a->state = INIT; /* we're initializing, so we don't want to do
		      * checks on previous state values
		      */
    
    /* initialize randomness - this might not be the best way to do it */
    while (! RAND_status()) {
	fprintf(stderr, "initializing randomness...");
	char buf;
	buf = rand();
        RAND_seed(&buf,1);
	fprintf(stderr, "done\n");
    }

    /* calculate range = upper - lower + 1 */
    if (a->lower < 0) {
	a->range += (uint64_t) (0 - a->lower);
	if (upper < 0) {
	    /* lower:neg uppper:neg */
	    a->range = (uint64_t) (a->upper - a->lower);
	} else {
	    /* lower:neg uppper:nonneg */
	    a->range = (uint64_t) (a->upper);
	    a->range -= (uint64_t) (0 - a->lower);
	}
    } else {
	/* lower:noneg (=> uppper:nonneg) */
	a->range = (uint64_t) (a->upper - a->lower);
    }
    (a->range)++;

    return a;
}

/*
 * recursively print list nodes
 */
static void
print(struct node *p)
{
    if (p) {
	fprintf(stderr, "[%p]\n", p);
	fprintf(stderr, "%ld\n", p->num);
	print(p->next);
    }
}

/*
 * Delete an int64 anonymization object and free all its resources.
 */

void
anon_int64_delete(anon_int64_t *a)
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
anon_int64_set_key(anon_int64_t *a, const uint8_t *key)
{
    assert(a);
    /* we might want to use the key to seed the RAND_* stuff */
}

/*
 * Mark a number as used. We simply put it into a linked list
 * sorted by lexicographic order. Note that this is not really
 * efficient - a heap like data structure might be more appropriate.
 */

int
anon_int64_set_used(anon_int64_t *a, const int64_t num)
{
    assert(a);
    
    (void) anon_int64_set_state(a, INIT);

    if (list_insert(&(a->list), num) >= 0) {
	return 0;
    } else{
	return -1;
    }
}

/*
 * anonymization on int64 numbers
 * anonymized numbers are also kept in a linked list to make
 * sure they are unique
 */
int
anon_int64_map(anon_int64_t *a, const int64_t num, int64_t *anum)
{
    struct hash_node node;
    struct hash_node *p;
    int tmp;

    (void) anon_int64_set_state(a, NON_LEX);

    /* lookup anon. number in lhash table */
    node.num = num;
    p = (struct hash_node *) lh_retrieve(a->hash_table,(void*) &node);
    
    if (p) { /* num found in lhash table */
	*anum = p->hash;
    } else { /* num not found in lhash table */
	/* generate a unique random number */
	do {
	    generate_random_number(anum, a);
	    tmp = list_insert(&(a->list),*anum);
	    assert(tmp >= 0);
	} while (tmp==1);
	/* store anon. number in lhash table */
	p = (struct hash_node*) malloc(sizeof(struct hash_node));
	assert(p);
	p->num = num;
	p->hash = *anum;
	lh_insert(a->hash_table, p);
    }
    return 0;
}

/*
 * lexicographical-order-preserving anonymization on int64 number
 */
int
anon_int64_map_lex(anon_int64_t *a, const int64_t num, int64_t *anum)
{
    struct hash_node node;
    struct hash_node *p;
    (void) anon_int64_set_state(a, LEX);
    
    /* lookup the anonymized number address in the lhash table */
    memset(&node, 0, sizeof(struct hash_node));
    node.num = num;
    p = (struct hash_node *) lh_retrieve(a->hash_table,(void*) &node);
    assert(p);
    *anum = p->hash;
    return 0;
}
