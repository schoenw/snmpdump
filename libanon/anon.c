/*
 * anon.c --
 *
 * Sample program to demonstrate usage of the anonymization library.
 *
 * Applies anonymization to addresses and other data types read from
 * input files and prints anonymized results to the standard output.
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
#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "libanon.h"

#define STRLEN 1024

static const char *progname = "anon";

struct cmd {
    const char *name;
    void (*func)(int argc, char **argv, struct cmd *cmd);
    const char *usage;
};

static void cmd_help(int argc, char **argv, struct cmd *cmd);
static void cmd_ipv4(int argc, char **argv, struct cmd *cmd);
static void cmd_ipv6(int argc, char **argv, struct cmd *cmd);
static void cmd_mac(int argc, char **argv, struct cmd *cmd);
static void cmd_int64(int argc, char **argv, struct cmd *cmd);
static void cmd_uint64(int argc, char **argv, struct cmd *cmd);
static void cmd_octs(int argc, char **argv, struct cmd *cmd);

static struct cmd cmds[] = {
    { "help",	cmd_help,   "anon help" },
    { "ipv4",	cmd_ipv4,   "anon ipv4 [-hlc] -p passphrase file" },
    { "ipv6",	cmd_ipv6,   "anon ipv6 [-hlc] -p passphrase file" },
    { "mac",	cmd_mac,    "anon mac [-hl] file" },
    { "int64",	cmd_int64,  "anon int64 lower upper [-hl] file" },
    { "uint64",	cmd_uint64, "anon uint64 lower upper [-hl] file" },
    { "octs",	cmd_octs,   "anon octs [-hl] file" },
    { NULL, NULL }
};

/* Provide your own 256-bit key here */
static unsigned char my_key[32] = 
  {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
   216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};
/*
static unsigned char my_key[32] = 
  {55,28,123,44,234,64,211,12,129,140,191,222,3,44,15,126,
   26,12,243,131,121,222,10,3,198,7,6,45,142,132,34,12};
*/
/*
static unsigned char my_key[32] = 
  {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
*/

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
 * Trim a string by removing leading or trailing white space
 * characters.
 */

static int
trim(char *buffer)
{
    char *s, *e;

    if (! buffer) return 0;

    for (s = buffer; *s && isspace(*s); s++) ;

    for (e = s + strlen(s)-1; e > s && isspace(*e); e--) *e = 0;
    
    if (s != buffer) memmove(buffer, s, e-s+2);
    return 1;
}

/*
 * Show information about the current resource usage on the given
 * stream.
 */

static void
show_resource_usage(FILE *stream)
{
    struct rusage r;
    
    if (0 == getrusage(RUSAGE_SELF, &r)) {
	fprintf(stream, "%s: user time in seconds:\t%u.%06u\n", progname,
		(unsigned) r.ru_utime.tv_sec, r.ru_utime.tv_usec);
    }
}

/*
 * Prefix preserving IP address anonymization.
 */

static unsigned
ipv4_pref(anon_ipv4_t *a, FILE *f)
{
    in_addr_t raw_addr, anon_addr;
    char buf[10*INET_ADDRSTRLEN];
    unsigned cnt = 0;

    /*
     * read ip addresses (one per input line), call the prefix
     * preserving anonymization function and print the anonymized
     * addresses
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET, buf, &raw_addr) > 0) {

	(void) anon_ipv4_map_pref(a, raw_addr, &anon_addr);
	cnt++;
	
	printf("%s\n", inet_ntop(AF_INET, &anon_addr, buf, sizeof(buf)));
    }

    return cnt;
}

/*
 * Prefix and lexicographic order preserving IP address anonymization.
 */

static unsigned
ipv4_lex(anon_ipv4_t *a, FILE *f)
{
    in_addr_t raw_addr, anon_addr;
    char buf[10*INET_ADDRSTRLEN];
    unsigned cnt = 0;

    /*
     * first pass: read ip addresses (one per input line) and mark
     * them as used
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET, buf, &raw_addr) > 0) {

	anon_ipv4_set_used(a, raw_addr, 32);
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
	
	(void) anon_ipv4_map_pref_lex(a, raw_addr, &anon_addr);
	cnt++;

	printf("%s\n", inet_ntop(AF_INET, &anon_addr, buf, sizeof(buf)));
    }

    return cnt;
}

/*
 * Prefix-preserving and lexicographic-order preserving IPv4 address
 * anonymization subcommand.
 */

static void
cmd_ipv4(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_ipv4_t *a;
    anon_key_t *key = NULL;
    int c, lflag = 0, cflag = 0, pflag = 0;
    unsigned cnt;

    key = anon_key_new();
    anon_key_set_key(key, my_key, sizeof(my_key));

    optind = 2;
    while ((c = getopt(argc, argv, "clhp:")) != -1) {
	switch (c) {
	case 'c':
	    cflag = 1;
	    break;
	case 'l':
	    lflag = 1;
	    break;
	case 'p':
	    anon_key_set_passphase(key, optarg);
	    pflag = 1;
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
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }

    /*
    if (!pflag) {
	anon_key_random_key(key);
    }
    */

    in = fopen(argv[0], "r");
    if (! in) {
	fprintf(stderr, "%s: %s: %s\n", progname, argv[0], strerror(errno));
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }

    a = anon_ipv4_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IP mapping\n", progname);
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }
    anon_ipv4_set_key(a, key);
    if (lflag) {
	cnt = ipv4_lex(a, in);
    } else {
	cnt = ipv4_pref(a, in);
    }
    if (cflag) {
	show_resource_usage(stderr);
	fprintf(stderr, "%s: number of addresses:\t%u\n", progname, cnt);
	fprintf(stderr, "%s: number of tree nodes:\t%u\n", progname,
		anon_ipv4_nodes_count(a));
    }

#if 0
    fprintf(stderr, "Measure memory consumption now\n");
    scanf("\n");
#endif
    
    anon_ipv4_delete(a);
    anon_key_delete(key);
    fclose(in);
}

/*
 * Prefix preserving IPv6 address anonymization.
 */

static unsigned
ipv6_pref(anon_ipv6_t *a, FILE *f)
{
    struct in6_addr raw_addr, anon_addr;
    char buf[10*INET6_ADDRSTRLEN];
    unsigned cnt = 0;

    /*
     * read ip addresses (one per input line), call the prefix
     * preserving anonymization function and print the anonymized
     * addresses
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET6, buf, &raw_addr) > 0) {

	(void) anon_ipv6_map_pref(a, raw_addr, &anon_addr);
	cnt++;
	
	printf("%s\n", inet_ntop(AF_INET6, &anon_addr, buf, sizeof(buf)));
    }

    return cnt;
}

/*
 * Prefix and lexicographic order preserving IPv6 address anonymization.
 */

static unsigned
ipv6_lex(anon_ipv6_t *a, FILE *f)
{
    struct in6_addr raw_addr, anon_addr;
    char buf[10*INET6_ADDRSTRLEN];
    unsigned cnt = 0;

    /*
     * first pass: read ip addresses (one per input line) and mark
     * them as used
     */

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET6, buf, &raw_addr) > 0) {

	anon_ipv6_set_used(a, raw_addr, 128);
    }

    /*
     * second pass: read ip addresses (one per input line), call the
     * prefix and lexcographic oder preserving anonymization function
     * and print the anonymized addresses
     */

    rewind(f);
    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET6, buf, &raw_addr) > 0) {
	
	(void) anon_ipv6_map_pref_lex(a, raw_addr, &anon_addr);
	cnt++;

	printf("%s\n", inet_ntop(AF_INET6, &anon_addr, buf, sizeof(buf)));
    }

    return cnt;
}

/*
 * Prefix-preserving and lexicographic-order preserving IPv6 address
 * anonymization subcommand.
 */

static void
cmd_ipv6(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_ipv6_t *a;
    anon_key_t *key = NULL;
    int c, lflag = 0, cflag = 0, pflag = 0;
    unsigned cnt = 0;

    key = anon_key_new();
    anon_key_set_key(key, my_key, sizeof(my_key));

    optind = 2;
    while ((c = getopt(argc, argv, "clhp:")) != -1) {
	switch (c) {
	case 'c':
	    cflag = 1;
	    break;
	case 'l':
	    lflag = 1;
	    break;
	case 'p':
	    anon_key_set_passphase(key, optarg);
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

    /*
    if (!pflag) {
	anon_key_random_key(key);
    }
    */

    in = fopen(argv[0], "r");
    if (! in) {
	fprintf(stderr, "%s: %s: %s\n", progname, argv[0], strerror(errno));
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }

    a = anon_ipv6_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IPv6 mapping\n", progname);
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }
    anon_ipv6_set_key(a, key);
    if (lflag) {
	cnt = ipv6_lex(a, in);
    } else {
	cnt = ipv6_pref(a, in);
    }
    if (cflag) {
	show_resource_usage(stderr);
	fprintf(stderr, "%s: number of addresses:\t%u\n", progname, cnt);
	fprintf(stderr, "%s: number of tree nodes:\t%u\n", progname,
		anon_ipv6_nodes_count(a));
    }

#if 0
    fprintf(stderr, "Measure memory consumption now\n");
    scanf("\n");
#endif

    anon_ipv6_delete(a);
    anon_key_delete(key);
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
 * Lexicographic order preserving int64 number anonymization.
 */

static void
int64_lex(anon_int64_t *a, FILE *f)
{
    int64_t num;
    int64_t anum;
    
    /*
     * first pass: read numbers (one per input line) and mark
     * them as used
     */
    while (fscanf(f, "%"SCNd64, &num) == 1) {
	anon_int64_set_used(a, num);
    }

    /*
     * second pass: read numbers and print the anonymized numbers
     */
    fseek(f,0,SEEK_SET);
    while (fscanf(f, "%"SCNd64, &num) == 1) {
	(void) anon_int64_map_lex(a,num,&anum);
	printf("%"PRId64"\n", anum);
    }
}

/*
 * int64 number anonymization (not preserving lexicographic order)
 */

static void
int64_nolex(anon_int64_t *a, FILE *f)
{
    int64_t num;
    int64_t anum;

    /*
     *  read numbers and print the anonymized numbers
     */
    while (fscanf(f, "%"SCNd64, &num) == 1) {
	(void) anon_int64_map(a,num,&anum);
	printf("%"PRId64"\n", anum);
    }
}

/*
 * Lexicographic-order preserving int64 numbers anonymization
 * subcommand.
 */

static void
cmd_int64(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_int64_t *a;
    int c, lflag = 0;
    int64_t lower, upper;

    if (argc < 4) {
	fprintf(stderr, "usage: %s\n", cmd->usage);
	exit(EXIT_FAILURE);
    }
    optind = 4;
    sscanf(argv[2], "%"SCNd64, &lower);
    sscanf(argv[3], "%"SCNd64, &upper);
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

    a = anon_int64_new(lower,upper);
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize int64 mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_int64_set_key(a, my_key);
    if (lflag) {
	int64_lex(a, in);
    } else {
	int64_nolex(a, in);
    }
    anon_int64_delete(a);

    fclose(in);
}

/*
 * Lexicographic order preserving uint64 number anonymization.
 */

static void
uint64_lex(anon_uint64_t *a, FILE *f)
{
    uint64_t num;
    uint64_t anum;
    
    /*
     * first pass: read numbers (one per input line) and mark
     * them as used
     */
    while (fscanf(f, "%"SCNu64, &num) == 1) {
	anon_uint64_set_used(a, num);
    }

    /*
     * second pass: read numbers and print the anonymized numbers
     */
    fseek(f,0,SEEK_SET);
    while (fscanf(f, "%"SCNu64, &num) == 1) {
	(void) anon_uint64_map_lex(a,num,&anum);
	printf("%"PRIu64"\n", anum);
    }
}

/*
 * uint64 number anonymization (not preserving lexicographic order)
 */

static void
uint64_nolex(anon_uint64_t *a, FILE *f)
{
    uint64_t num;
    uint64_t anum;

    /*
     *  read numbers and print the anonymized numbers
     */
    while (fscanf(f, "%"SCNu64, &num) == 1) {
	(void) anon_uint64_map(a,num,&anum);
	printf("%"PRIu64"\n", anum);
    }
}

/*
 * Lexicographic-order preserving uint64 numbers anonymization
 * subcommand.
 */

static void
cmd_uint64(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_uint64_t *a;
    int c, lflag = 0;
    uint64_t lower, upper;

    if (argc < 4) {
	fprintf(stderr, "usage: %s\n", cmd->usage);
	exit(EXIT_FAILURE);
    }
    optind = 4;
    lower = strtol(argv[2], NULL, 10);
    upper = strtol(argv[3], NULL, 10);
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

    a = anon_uint64_new(lower,upper);
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize uint64 mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_uint64_set_key(a, my_key);
    if (lflag) {
	uint64_lex(a, in);
    } else {
	uint64_nolex(a, in);
    }
    anon_uint64_delete(a);

    fclose(in);
}

/*
 * Lexicographic order preserving octet string anonymization.
 */

static void
octet_string_lex(anon_octs_t *a, FILE *f)
{
    char str[STRLEN];
    char astr[STRLEN];

    /*
     * first pass: read string (one per input line) and mark
     * them as used
     */
    while (fgets(str, sizeof(str), f) != NULL) {
	size_t len = strlen(str);
	if (str[len-1] == '\n') str[len-1] = 0;
	anon_octs_set_used(a, str);
    }

    /*
     * second pass: read strings and print the anonymized strings
     */
    rewind(f);
    while (fgets(str, sizeof(str), f) != NULL) {
	size_t len = strlen(str);
	if (str[len-1] == '\n') str[len-1] = 0;
	(void) anon_octs_map_lex(a, str, astr);
	printf("%s\n", astr);
    }
}

/*
 * octet string anonymization (not preserving lexicographic order)
 */

static void
octet_string_nolex(anon_octs_t *a, FILE *f)
{
    char str[STRLEN];
    char astr[STRLEN];

    /*
     *  read strings and print the anonymized strings
     */
    while (fgets(str, sizeof(str), f) != NULL) {
	size_t len = strlen(str);
	if (str[len-1] == '\n') str[len-1] = 0;
	(void) anon_octs_map(a, str, astr);
	printf("%s\n", astr);
    }
}

/*
 * Lexicographic-order preserving octet string anonymization
 * subcommand.
 */

static void
cmd_octs(int argc, char **argv, struct cmd *cmd)
{
    FILE *in;
    anon_octs_t *a;
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

    a = anon_octs_new();
    if (! a) {
	fprintf(stderr, "%s: Failed to initialize IEEE 802 MAC mapping\n", progname);
	exit(EXIT_FAILURE);
    }
    anon_octs_set_key(a, my_key);
    if (lflag) {
	octet_string_lex(a, in);
    } else {
	octet_string_nolex(a, in);
    }
    anon_octs_delete(a);

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
