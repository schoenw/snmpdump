/*
 * anon.c --
 *
 * Sample program to demonstrate usage of the anonymization library
 *
 * Applies prefix- and lexicographical-order-preserving anonymization
 * to addresses in input file and prints anonymized addresses to
 * standard output.
 *
 * Copyright (c) 2005 Matus Harvan
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "libanon.h"

static const char *progname = "anon";

static void cmd_help(int argc, char **argv);
static void cmd_ip(int argc, char **argv);
static void cmd_ip_lex(int argc, char **argv);

static struct handler {
    const char *name;
    void (*func)(int argc, char **argv);
} cmds[] = {
    { "help",	cmd_help },
    { "ip",	cmd_ip },
    { "ip-lex",	cmd_ip_lex },
    { NULL, NULL }
};

/* Provide your own 256-bit key here */
static unsigned char my_key[32] = 
  {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
   216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};


static FILE*
xfopen(const char *filename, const char *mode)
{
    FILE *f;

    f = fopen(filename, mode);
    if (! f) {
	fprintf(stderr, "%s: Cannot open file \"%s\": %s\n", 
		progname, filename, strerror(errno));
	exit(EXIT_FAILURE);
    }
    return f;
}



static void
ip_pref(anon_ip_t *a, FILE *f)
{
    unsigned int raw_addr, anonymized_addr;
    unsigned int packet_addr1, packet_addr2,
	packet_addr3, packet_addr4;

    /*
     * read ip addresses (one per input line) and print the anonymized
     * addresses
     */

    while (fscanf(f, "%u.%u.%u.%u", &packet_addr1, &packet_addr2,
		  &packet_addr3, &packet_addr4) == 4) {
	/* convert the raw IP from a.b.c.d format into uint32_t format */
	raw_addr = (packet_addr1 << 24) + (packet_addr2 << 16)
	    + (packet_addr3 << 8) + packet_addr4;
	
	/* Anonymize the raw IP */
	anonymized_addr = anon_ip_map_pref(a, raw_addr);
	
	/* convert the anonymized IP address from uint32_t 
	 * to a.b.c.d format
	 */
	packet_addr1 = anonymized_addr >> 24;
	packet_addr2 = (anonymized_addr << 8) >> 24;
	packet_addr3 = (anonymized_addr << 16) >> 24;
	packet_addr4 = (anonymized_addr << 24) >> 24;
	
	/* output the anonymized trace */
	printf("%u.%u.%u.%u\n",  packet_addr1, packet_addr2,
	       packet_addr3, packet_addr4 );
    }
}


static void
ip_lex(anon_ip_t *a, FILE *f)
{
    unsigned int raw_addr, anonymized_addr;
    unsigned int packet_addr1, packet_addr2,
	packet_addr3, packet_addr4;

    /*
     * first pass: read ip addresses (one per input line) and mark
     * them as used
     */

    while (fscanf(f, "%u.%u.%u.%u", &packet_addr1, &packet_addr2,
		  &packet_addr3, &packet_addr4) == 4) {
	/* convert the raw IP from a.b.c.d format into uint32_t format */
	raw_addr = (packet_addr1 << 24) + (packet_addr2 << 16)
	    + (packet_addr3 << 8) + packet_addr4;
	/* mark IP address and relevant nodes in the used_i tree */
	anon_ip_set_used(a, raw_addr, 32);
    }

    /*
     * second pass: read ip addresses and print the anonymized
     * addresses
     */

    fseek(f,0,SEEK_SET);
    while (fscanf(f, "%u.%u.%u.%u", &packet_addr1, &packet_addr2,
		  &packet_addr3, &packet_addr4) == 4) {
	/* convert the raw IP from a.b.c.d format into uint32_t format */
	raw_addr = (packet_addr1 << 24) + (packet_addr2 << 16)
	    + (packet_addr3 << 8) + packet_addr4;
	
	/* Anonymize the raw IP */
	anonymized_addr = anon_ip_map_pref_lex(a, raw_addr);

	/* convert the anonymized IP address from uint32_t 
	 * to a.b.c.d format */

	packet_addr1 = anonymized_addr >> 24;
	packet_addr2 = (anonymized_addr << 8) >> 24;
	packet_addr3 = (anonymized_addr << 16) >> 24;
	packet_addr4 = (anonymized_addr << 24) >> 24;
	
	/* output the anonymized trace */
	printf("%u.%u.%u.%u\n",  packet_addr1, packet_addr2,
	       packet_addr3, packet_addr4 );
    }
}

/*
 * Prefix-preserving IP address anonymization subcommand.
 */

static void
cmd_ip(int argc, char **argv)
{
    FILE *in;
    anon_ip_t *a;

    if (argc != 3) {
	fprintf(stderr, "%s: Too few arguments\n", progname);
	exit(EXIT_FAILURE);
    }

    in = xfopen(argv[2], "r");

    a = anon_ip_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IP mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_ip_set_key(a, my_key);
    ip_pref(a, in);
    anon_ip_delete(a);

    fclose(in);
}

/*
 * Prefix-preserving and lexicographic-order preserving IP address
 * anonymization subcommand.
 */

static void
cmd_ip_lex(int argc, char **argv)
{
    FILE *in;
    anon_ip_t *a;

    if (argc != 3) {
	fprintf(stderr, "%s: Too few arguments\n", progname);
	exit(EXIT_FAILURE);
    }

    in = xfopen(argv[2], "r");

    a = anon_ip_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IP mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_ip_set_key(a, my_key); 
    ip_lex(a, in);
    anon_ip_delete(a);

    fclose(in);
}

/*
 * Print some hopefully helpful usage information.
 */

static void
cmd_help(int argc, char **argv)
{
    int i;

    printf("usage: %s <subcommand> [options] [args]\n"
	   "\n"
	   "Most subcommands take a file as an argument.\n"
	   "\n"
	   "Available subcommands:\n",
	   progname);

    for (i = 0; cmds[i].name; i++) {
	printf("    %s\n", cmds[i].name);
    }
}

/*
 * Simply dispatch to the appropriate subcommand handler using
 * the cmds dispatch table.
 */

int main(int argc, char * argv[]) {

    int i;

    if (argc < 2) {
	fprintf(stderr, "Type '%s help' for usage information\n", progname);
	return EXIT_FAILURE;
    }

    for (i = 0; cmds[i].name; i++) {
	if (strcmp(cmds[i].name, argv[1]) == 0) {
	    break;
	}
    }

    if (! cmds[i].name) {
	fprintf(stderr, "Unkown subcomand: '%s'\n", argv[1]);
	fprintf(stderr, "Type '%s help' for usage information\n", progname);
	return EXIT_FAILURE;
    }

    (cmds[i].func) (argc, argv);

    return EXIT_SUCCESS;
}
