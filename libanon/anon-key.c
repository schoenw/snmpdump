/*
 * anon-key.c --
 *
 * Cryptographic anonymization key support funtions.
 *
 * Copyright (c) 2005 Matus Harvan
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>

#include "libanon.h"

anon_key_t*
anon_key_new()
{
    anon_key_t* key;
    key = (anon_key_t*) malloc(sizeof(anon_key_t));
    memset(key,0,sizeof(anon_key_t));
    return key;
}

/*
 * Set the cryptographic key directly
 */

void
anon_key_set_key(anon_key_t *key, const uint8_t *new_key, const size_t key_len)
{
    assert(key);
    if (key->key) {
	free(key->key);
    }
    key->key = malloc(key_len);
    memcpy(key->key, new_key, key_len);
    key->length = key_len;
}

/*
 * Generate a random cryptographic key
 */

void
anon_key_random_key(anon_key_t *key)
{
    assert(key);
    if (key->key) {
	free(key->key);
    }
    key->length = 32;
    key->key = malloc(key->length);

    /* initialize randomness - this might not be the best way to do it */
    while (! RAND_status()) {
	fprintf(stderr, "initializing randomness...");
	char buf;
	buf = rand();
        RAND_seed(&buf, 1);
	fprintf(stderr, "done\n");
    }

    RAND_bytes(key->key, key->length);

}

/*
 * Set the cryptographic key using a human memorizable passphrase
 * passphrase has to be null-terminated
 */

void
anon_key_set_passphase(anon_key_t *key, const char *passphrase)
{
    if (key->key) {
	free(key->key);
    }
    /* we need a 32 byte key and SHA-1 produces 20 byte output */
    key->key = malloc(2*SHA_DIGEST_LENGTH);
    if (! key->key) {
	fprintf(stderr, "Out of memory\n");
	return;
    }
    key->length = 2*SHA_DIGEST_LENGTH;
    
    /* do the SHA-1 hashing */
    SHA1((unsigned char *) passphrase, strlen(passphrase)/2, key->key);
    passphrase += strlen(passphrase)/2;
    SHA1((unsigned char *) passphrase, strlen(passphrase),
	 key->key+SHA_DIGEST_LENGTH);
}

void
anon_key_delete(anon_key_t *key) {
    if (key) {
	if (key->key) {
	    free(key->key);
	}
	free(key);
    }
}
