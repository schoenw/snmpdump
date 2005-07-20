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
#include <openssl/lhash.h>

#include "libanon.h"


struct _anon_mac {
    LHASH *hash_table;
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
    return a;
}

/*
 * Delete an MAC anonymization object and free all its resources.
 */

void
anon_mac_delete(anon_mac_t *a)
{
    if (! a) {
	return;
    }

    lh_free(a->hash_table);

    free(a);
}

