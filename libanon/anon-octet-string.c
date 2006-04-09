/*
 * anon-octet-string.c --
 *
 * octet string anonymization functions.
 *
 * Copyright (c) 2005 Matus Harvan
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
    char* data;
    struct node *next;
};

/* node struct for an lhash table */
struct hash_node {
    char* data;
    char* hash;
    //    uint8_t hash[MAC_LENGTH];
};

/* For nonlexicographic order, we are generating hashes on the
 * fly. They are stored in anon_octet_string_t's list, to make sure we
 * generate unique strings.
 *
 * For lexicographic order, we use anon_octet_string_t's list for
 * storing the unanonymized strings.
 */
struct _anon_octet_string {
    LHASH *hash_table;
    struct node *list;
    int state;
};

enum anon_octet_string_state_t
    {INIT=0, /* MAC anon object initialized,
	      * set_used() may have been used
	      * already, but no MAC address has yet
	      * been anonymized using this object
	      */
     NON_LEX,/* anon_octet_string_map() has already been used */
     LEX};   /* anon_octet_string_map_lex() has already been used */


static char
generate_random_char()
{
    unsigned char c;
    do {
	(void) RAND_bytes(&c,1);
	/* disallow \0, \n, \r */
    } while(c=='\0' || c=='\n' || c=='\r');
    /* only allow alpha-numeric characters */
    /*} while( !(isalnum(c) || isspace(c)) );*/
    /*} while( !(isalnum(c)) );*/
    return c;
}

static char*
generate_random_string(char* buf, size_t len)
{
    int i;
    for (i=0; i<len; i++) {
	buf[i] = generate_random_char();
    }
    buf[len] = '\0';
    return buf;
}

/* functions for the lhash table */
/* implements SDBM hash function taken from
 * http://www.cs.yorku.ca/~oz/hash.html:
 *
 *	this algorithm was created for sdbm (a public-domain
 *	reimplementation of ndbm) database library. it was found to do
 *	well in scrambling bits, causing better distribution of the
 *	keys and fewer splits. it also happens to be a good general
 *	hashing function with good distribution. the actual function
 *	is hash(i) = hash(i - 1) * 65599 + str[i]; what is included
 *	below is the faster version used in gawk. [there is even a
 *	faster, duff-device version] the magic constant 65599 was
 *	picked out of thin air while experimenting with different
 *	constants, and turns out to be a prime. this is one of the
 *	algorithms used in berkeley db (see sleepycat) and elsewhere.
 */
static unsigned long
anon_octet_string_hash(const struct hash_node *tohash)
{
    unsigned long hash = 0;
    char *p;

    for (p = tohash->data; p; p++) {
	hash = *p + (hash << 6) + (hash << 16) - hash;
    }
    
    return hash;
}

static int
anon_octet_string_cmp(const struct hash_node *arg1,
		      const struct hash_node *arg2)
{
    return strcmp(arg1->data, arg2->data);
}

/* Create the type-safe wrapper functions for use in the LHASH internals */
static
IMPLEMENT_LHASH_HASH_FN(anon_octet_string_hash, const struct hash_node *);
static
IMPLEMENT_LHASH_COMP_FN(anon_octet_string_cmp, const struct hash_node *);

/*
 * lookup str in hash table and copy found hash into astr
 * copies at most strlen chars
 * return non-zero if found, 0 if str not found in hash table
 */
static int
hash_nlookup(LHASH *hash_table, char *str, char *astr, size_t strlen)
{
    struct hash_node node;
    struct hash_node *p;

    node.data = str;
    p = (struct hash_node *) lh_retrieve(hash_table,(void*) &node);
    if (p) { /* found in lhash table */
	strncpy(astr, p->hash, strlen);
	return 1;
    } else { /* not found in lhash table */
	return 0;
    }
}

/*
 * lookup str in hash table and copy found hash into astr
 * return non-zero if found, 0 if str not found in hash table
 */
static int
hash_lookup(LHASH *hash_table, char *str, char *astr)
{
    struct hash_node node;
    struct hash_node *p;

    memset(&node, 0, sizeof(struct hash_node));
    node.data = str;
    p = (struct hash_node *) lh_retrieve(hash_table,(void*) &node);
    if (p) { /* found in lhash table */
	strcpy(astr, p->hash);
	return 1;
    } else { /* not found in lhash table */
	return 0;
    }
}

/* returns 0 if we're trying to insert a string not yet in the list */
static int
list_insert(struct node **list, const char *str)
{
    struct node *p, *q, *n;
    int c;
    
    assert(str);
    
    for (p = *list, q = NULL; p; q = p, p = p->next) {
	c = strcmp(str, p->data);
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
    n->data = (char*) malloc(strlen(str)+1);
    strcpy(n->data, str);
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
 * remove str from list  
 * returns non-zero on success, 0 if str not found in list
 */
static int
list_remove(struct node **list, const char *str)
{
    struct node *p, *q;
    int c;
    
    assert(str);
    
    for (p = *list, q = NULL; p; q = p, p = p->next) {
	c = strcmp(str, p->data);
	if (c == 0) {
	    /* found, remove from list */
	    q->next = p->next;
	    free(p->data);
	    free(p);
	    return 1;
	}
	if (c < 0) {
	    /* not found */
	    return 0;
	}
    }
    return 0;
}

/*
 * remove all nodes from the list
 */
static void
list_remove_all(struct node **list)
{
    struct node *p;
    
    for (p = *list; p; ) {
	struct node *q = p;
	p = p->next;
	if (q->data) free(q->data);
	free(q);
    }
}

/*
 * recursively print list nodes
 */
static void
print(struct node *p)
{
    if (p) {
	fprintf(stderr, "[%p] - %s\n", p, p->data);
	print(p->next);
    }
}

/*
 * generate anonymized strings preserving lexicographic-order
 *
 * only strings between start and end (including start, excluding end)
 * will be processed
 * set end to null to process list to the end
 * prev_length - length of prefixes already processed. Hence all
 * strings in the range must be longer or of equal
 * length. Furthermore, all strings in the range are expected to have
 * identical prefixes of prev_length.
 * aprefix - anonymized prefix (first prev_length chars)
 */
static int
generate_lex_anonymizations(anon_octet_string_t *a, size_t prev_length,
			    const char* aprefix,
			    struct node *start, struct node *end)
{
    char* str;  /* prefix up to min_length */
    char* astr; /* astr - anonymized str */
    char* prefix; /* prefix of prev_length - same for all strings in group */
    //char* aprefix; /* anonymized (hash of) prefix */
    //char* middle; /* part of string between prev_length and min_length */
    char* amiddle; /* anonymized (hash of) middle */
    struct node *p, *q; /* nodes in list */
    struct node *start2; /* recursively process this part of the list */
    size_t min_length; /* minimum string length in our part of list */
    int count; /* number of unique prefixes (of min_length) */
    struct node* hashlist = NULL; /* stores generated amiddle's */
    struct node *hp; /* nodes in hash list */
    struct hash_node* node = NULL; /* lhash table node */
    int i;
    
    assert(a);
    if (!start)
	return 0;
    assert(aprefix || prev_length > 0);

    /* find min length */
    min_length = strlen(start->data);
    for (p = start; p && p!=end; p = p->next) {
	int tmp = strlen(p->data);
	if (tmp < min_length) {
	    min_length = tmp;
	}
    }
    assert(min_length > prev_length);
    
    /* count unique prefixes of min_length (after position prev_length) */
    count = 0;
    for (p = start, q = NULL; p && p!=end; q = p, p = p->next) {
	if (q) {
	    if (strncmp(p->data+prev_length, q->data+prev_length,
			min_length-prev_length)) {
		count++;
	    }
	} else { /* first element in list */
	    count++;
	}
    }

    /*  produce hashlist (amiddle) */
    for (i=0;i<count;i++) {
	do {
	    amiddle = (char*) malloc(min_length-prev_length+1);
	    amiddle = generate_random_string(amiddle, min_length-prev_length);
	} while (list_insert(&hashlist,amiddle)==1);
    }
    
    /* assign anon. strings to real strings and store them in lhash table */
    str = (char*) malloc(min_length+1);
    astr = (char*) malloc(min_length+1);
    assert(str);
    assert(astr);
    hp = hashlist;
    int group_size = 0; /* size of last group
			 * excluding min_lenght element (if it exists)
			 */
    int is_diff = 0; /* is current string (p) different from previous one (q)
		      * up to min_length?
		      */
    int was_minlength = 0; /* if last group contained (==started with)
			    * a string of min_length
			    * - determines if we need to allocate new str, astr
			    */
    start2 = start;
    for (p = start, q = NULL; p && p!=end; q = p, p = p->next) {
	/*
	fprintf(stderr, "assigning %s (hp: %s)...\n",
		p->data, (hp)?hp->data:"NULL");
	*/
	assert(strlen(p->data) >= min_length);
	/* check if p is different from q up to first min_length chars */
	is_diff = 0;
	if (q) {
	    if (strncmp(p->data+prev_length, q->data+prev_length,
			min_length-prev_length)) {
		is_diff = 1;
	    } else {
		group_size++;
	    }
	} else {
	    /* first item in list */
	    is_diff = 1;
	}
	if (is_diff) {
	    if (q) { /* don't call for first item in list */
		/* anonymize the previous group */
		if (group_size > 0) {
		    assert(strlen(start2->data) > min_length);
		    generate_lex_anonymizations(a, min_length, astr,
						start2, p);
		}
 		if (was_minlength) {
		    str = (char*) malloc(min_length+1);
		    astr = (char*) malloc(min_length+1);
		    assert(str);
		    assert(astr);
		}
	    }
	    start2 = p;
	    /* prepare str, astr */
	    strncpy(str, p->data, min_length);
	    str[min_length] = '\0';
	    /* aprefix generated earlier and passed as a function argument */
	    strncpy(astr, aprefix, prev_length);
	    assert(hp);
	    assert(hp->data);
	    strncpy(astr+prev_length, hp->data, min_length-prev_length);
	    astr[min_length] = '\0';

	    if (strlen(p->data) == min_length) {
		/* store (str, astr) in lhash */
		node = (struct hash_node*) malloc(sizeof(struct hash_node));
		assert(node);
		node->data = str;
		node->hash = astr;
		/*
		fprintf(stderr, "storing in hash table [%s --> %s]\n",
			str, astr);
		*/
		lh_insert(a->hash_table, node);
		/* omit this (min_length) element from recursion */
		start2 = p->next;
		was_minlength = 1;
		group_size = 0;
	    } else {
		/* don't need to store (str, astr) in lhash */
		was_minlength = 0;
		group_size = 1;
	    }
	    /* advance to next node in hashlist */
	    hp = hp->next;
	    
	} /* else do nothing */
    }
    if (start2 && group_size > 0) {
	assert(strlen(start2->data) > min_length);
	generate_lex_anonymizations(a, min_length, astr, start2, end);
    }
    if (was_minlength) {
	str = (char*) malloc(min_length+1);
	astr = (char*) malloc(min_length+1);
	assert(str);
	assert(astr);
    }

    /* we don't need the list of used strings anymore */
    //list_remove_all(&(a->list));
    list_remove_all(&hashlist);
    free(str);
    free(astr);
    return 0;
}

/*
 * Set/change the state of the anonymization object. Performs
 * neccessary checks to see if state change is ok.
 */
static int
anon_octet_string_set_state(anon_octet_string_t *a, int state)
{
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

	(void) generate_lex_anonymizations(a, 0, "", a->list, NULL);
	//list_remove_all(&(a->list));
	//list_remove_all(&hashlist);
	return 0;
    default:
	fprintf(stderr,"trying to set ilegal state for an anon_octet_string_t\n");
	assert(0);
    }
    return 0;
}

/*
 * Create a new anonymization object.
 */

anon_octet_string_t*
anon_octet_string_new()
{
    anon_octet_string_t *a;

    a = (anon_octet_string_t *) malloc(sizeof(anon_octet_string_t));
    if (! a) {
	return NULL;
    }
    memset(a, 0, sizeof(anon_octet_string_t));

    a->hash_table = lh_new(LHASH_HASH_FN(anon_octet_string_hash),
			   LHASH_COMP_FN(anon_octet_string_cmp));
    a->state = INIT; /* we're initializing, so we don't want to do
		      * checks on previous state values
		      */

    /* initialize randomness - this might not be the best way to do it */
    while (! RAND_status()) {
	fprintf(stderr, "initializing randomness...");
	char buf;
	buf = rand();
        RAND_seed(&buf, 1);
	fprintf(stderr, "done\n");
    }

    return a;
}

/*
 * Delete an anonymization object and free all its resources.
 */

void
anon_octet_string_delete(anon_octet_string_t *a)
{
    if (! a) {
	return;
    }

    lh_free(a->hash_table);

    list_remove_all(&(a->list));

    free(a);
}

/*
 * Set the cryptographic key used for anonymization.
 */

void
anon_octet_string_set_key(anon_octet_string_t *a, const uint8_t *key)
{
    assert(a);
    /* we might want to use the key to seed the RAND_* stuff */
}

/*
 * Mark a string as used. We simply put it into a linked list
 * sorted by lexicographic order. Note that this is not really
 * efficient - a heap like data structure might be more appropriate.
 */

int
anon_octet_string_set_used(anon_octet_string_t *a, const char *str)
{
    assert(a && str);
    
    (void) anon_octet_string_set_state(a, INIT);

    if (list_insert(&(a->list), str) >= 0) {
	return 0;
    } else{
	return -1;
    }
}

/*
 * anonymization of octet string
 * anonymized octet strings are also kept in a linked list to make
 * sure they are unique
 *
 * astr has to be a large enough buffer where the anonymized string
 * will be copied, the anonymized string will be as long as the
 * original string
 */
int
anon_octet_string_map(anon_octet_string_t *a, const char *str, char *astr)
{
    struct hash_node node;
    struct hash_node *p;
    int tmp;
    
    (void) anon_octet_string_set_state(a, NON_LEX);

    /* lookup anon. string in lhash table */
    node.data = (char*) str;
    p = (struct hash_node *) lh_retrieve(a->hash_table,(void*) &node);
    
    if (p) { /* found in lhash table */
	strcpy(astr, p->hash);
    } else { /* not found in lhash table */
	/* generate a unique random string */
	do {
	    generate_random_string(astr, strlen(str));
	    tmp = list_insert(&(a->list),astr);
	    assert(tmp >= 0);
	} while (tmp==1);
	/* store anon. string in lhash table */
	p = (struct hash_node*) malloc(sizeof(struct hash_node));
	assert(p);
	p->data = (char*) malloc(strlen(str)+1);
	assert(p->data);
	p->hash = (char*) malloc(strlen(astr)+1);
	assert(p->hash);
	strcpy(p->data, str);
	strcpy(p->hash, astr);
	lh_insert(a->hash_table, p);
    }
    return 0;
}

/*
 * lexicographical-order-preserving anonymization on strings
 *
 * astr has to be a large enough buffer where the anonymized string
 * will be copied, the anonymized string will be as long as the
 * original string
 */
int
anon_octet_string_map_lex(anon_octet_string_t *a, const char *str, char *astr)
{
    (void) anon_octet_string_set_state(a, LEX);
    
    /* lookup the anonymized string in the lhash table */
    int result = hash_lookup(a->hash_table, (char*) str, astr);
    if (result)
	return 0;
    else
	return 1;
}
