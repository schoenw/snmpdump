/*
 * anon_test_key.c --
 *

 * Small test program for anon_key_set_passphase(). Reads passphrases from
 * stdin and prints to stdout passphrase -> (hexify(key)\n.
 *
 * compile with: gcc -lssl anon_test_key.c anon_key.o -o anon_test_key
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/types.h>

#include "libanon.h"

#define STRLEN (64*1024)

static void
hexify(unsigned char *in, int n)
{
    int i;
    for (i=0; i<n; i++) {
	printf("%.2x", in[i]);
    }
    printf("\n");
}

/*
 * Implementation of the 'anon help' command.
 */

int main(int argc, char * argv[]) {

    FILE *in;
    anon_key_t *key = NULL;
    char str[STRLEN];

    key = anon_key_new();
    anon_key_set_random(key);
    /*
    printf("random key: ");
    hexify(key->key, key->length);
    */
    in = stdin;
    while (fgets(str, sizeof(str), in) != NULL) {
	size_t len = strlen(str);
	if (str[len-1] == '\n') str[len-1] = 0;
	anon_key_set_passphase(key, str);
	printf("%s ->", str);
	hexify(key->key, key->length);
    }

    //fclose(in);
    anon_key_delete(key);

    return EXIT_SUCCESS;
}
