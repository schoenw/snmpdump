/*
 * anon.c --
 *
 * Sample program to demonstrate usage of the anonymization library.
 *
 * Applies prefix- and lexicographical-order-preserving anonymization
 * to addresses in input file and prints anonymized addresses to
 * standard output.
 *
 * Copyright (c) 2005 Matus Harvan
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "libanon.h"

static const char *progname = "anon";

struct cmd {
    const char *name;
    void (*func)(int argc, char **argv, struct cmd *cmd);
    const char *usage;
};

static void cmd_help(int argc, char **argv, struct cmd *cmd);
static void cmd_ip(int argc, char **argv, struct cmd *cmd);
static void cmd_mac(int argc, char **argv, struct cmd *cmd);

static struct cmd cmds[] = {
    { "help",		cmd_help,	"anon help" },
    { "ip",		cmd_ip,		"anon ip [-hl] file" },
    { "mac",		cmd_mac,	"anon mac [-hl] file" },
    { NULL, NULL }
};

/* Provide your own 256-bit key here */
static unsigned char my_key[32] = 
  {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
   216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};

/*
 * Open a file and handle all errors by producing an error message
 * before terminating the process.
 */

static FILE*
xfopen(const char *filename, const char *mode)
{
    FILE *f;

    f = fopen(filename, mode);
    if (! f) {
	fprintf(stderr, "%s: %s: %s\n", progname, filename, strerror(errno));
	exit(EXIT_FAILURE);
    }
    return f;
}

/*
 * Trim a string be removing leading or trailing white space
 * characters.
 */

static int
trim(char *buffer)
{
    char *s, *e;

    if (! buffer) return 0;

    for (s = buffer; *s && isspace(*s); s++) ;

    for (e = s + strlen(s)-1; e > s && isspace(*e); e--) *e = 0;
    
    memmove(buffer, s, e-s+2);
    return 1;
}

/*
 * Prefix preserving IP address anonymization.
 */

static void
ip_pref(anon_ip_t *a, FILE *f)
{
    in_addr_t raw_addr, anon_addr;
    char buf[10*INET_ADDRSTRLEN];

    /*
     * read ip addresses (one per input line), call the prefix
     * preserving anonymization function and print the anonymized
     * addresses
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET, buf, &raw_addr) > 0) {

	(void) anon_ip_map_pref(a, raw_addr, &anon_addr);
	
	printf("%s\n", inet_ntop(AF_INET, &anon_addr, buf, sizeof(buf)));
    }
}

/*
 * Prefix and lexicographic order preserving IP address anonymization.
 */

static void
ip_lex(anon_ip_t *a, FILE *f)
{
    in_addr_t raw_addr, anon_addr;
    char buf[10*INET_ADDRSTRLEN];

    /*
     * first pass: read ip addresses (one per input line) and mark
     * them as used
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET, buf, &raw_addr) > 0) {

	anon_ip_set_used(a, raw_addr, 32);
    }

    /*
     * second pass: read ip addresses (one per input line), call the
     * prefix and lexcographic oder preserving anonymization function
     * and print the anonymized addresses
     */

    rewind(f);
    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET, buf, &raw_addr) > 0) {
	
	(void) anon_ip_map_pref_lex(a, raw_addr, &anon_addr);

	printf("%s\n", inet_ntop(AF_INET, &anon_addr, buf, sizeof(buf)));
    }
}

/*
 * Prefix-preserving and lexicographic-order preserving IP address
 * anonymization subcommand.
 */

static void
cmd_ip(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_ip_t *a;
    int c, lflag = 0;

    optind = 2;
    while ((c = getopt(argc, argv, "lh")) != -1) {
	switch (c) {
	case 'l':
	    lflag = 1;
	    break;
	case 'h':
	case '?':
	default:
	    printf("usage: %s\n", cmd->usage);
	    exit(EXIT_SUCCESS);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
	fprintf(stderr, "usage: %s\n", cmd->usage);
	exit(EXIT_FAILURE);
    }

    in = xfopen(argv[0], "r");

    a = anon_ip_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IP mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_ip_set_key(a, my_key);
    if (lflag) {
	ip_lex(a, in);
    } else {
	ip_pref(a, in);
    }
    anon_ip_delete(a);

    fclose(in);
}

/*
 * Lexicographic order preserving IEEE 802 MAC address anonymization.
 */

static void
mac_lex(anon_mac_t *a, FILE *f)
{
    uint8_t mac[6];
    uint8_t amac[6];

    /*
     * first pass: read mac addresses (one per input line) and mark
     * them as used
     */
    while (fscanf(f, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
	anon_mac_set_used(a, mac);
    }

    /*
     * second pass: read mac addresses and print the anonymized
     * addresses
     */
    fseek(f,0,SEEK_SET);
    while (fscanf(f, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
	(void) anon_mac_map_lex(a,mac,amac);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       amac[0], amac[1], amac[2], amac[3], amac[4], amac[5]);
    }
}

/*
 * IEEE 802 MAC address anonymization (not preserving lexicographic order)
 */

static void
mac_nolex(anon_mac_t *a, FILE *f)
{
    uint8_t mac[6];
    uint8_t amac[6];

    /*
     *  read mac addresses and print the anonymized addresses
     */
    while (fscanf(f, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {

	(void) anon_mac_map(a,mac,amac);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       amac[0], amac[1], amac[2], amac[3], amac[4], amac[5]);
    }
}

/*
 * Lexicographic-order preserving IEEE 802 MAC address anonymization
 * subcommand.
 */

static void
cmd_mac(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_mac_t *a;
    int c, lflag = 0;

    optind = 2;
    while ((c = getopt(argc, argv, "lh")) != -1) {
	switch (c) {
	case 'l':
	    lflag = 1;
	    break;
	case 'h':
	case '?':
	default:
	    printf("usage: %s\n", cmd->usage);
	    exit(EXIT_SUCCESS);
	}
    }
     argc -= optind;
     argv += optind;

    if (argc != 1) {
	fprintf(stderr, "usage: %s\n", cmd->usage);
	exit(EXIT_FAILURE);
    }

    in = xfopen(argv[0], "r");

    a = anon_mac_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IEEE 802 MAC mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_mac_set_key(a, my_key);
    if (lflag) {
	mac_lex(a, in);
    } else {
	mac_nolex(a, in);
    }
    anon_mac_delete(a);

    fclose(in);
}

/*
 * Implementation of the 'anon help' command.
 */

static void
cmd_help(int argc, char **argv, struct cmd *cmd)
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

    (cmds[i].func) (argc, argv, cmds + i);

    return EXIT_SUCCESS;
}
