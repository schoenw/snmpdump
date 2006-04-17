/*
 * THIS PROGRAM IS FAR FROM FINISHED !!!
 *
 * pcap_anon.c --
 *
 * Anonymization of pcap traces using the anonymization library.
 *
 * Applies anonymization to MAC addresses, IP addresses and port numbers.
 *
 * Copyright (c) 2005 Matus Harvan
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

/*
 * TODO:
 * o figure out how to get to the ethernet, ip tcp headers,
 *   worst case just copy what tcpdump is doing
 * o checksums
 * o ip-in-ip
 * o passphrase support via cmd line option
 * o remove default passphrase or make it random
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

#include <pcap.h>

#define STRLEN 1024

static const char *progname = "pcap_anon";

/* Provide your own 256-bit key here */
static unsigned char my_key[32] = 
  {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
   216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};

typedef struct _cb_data_t {
    anon_ipv4_t *a4;
    anon_ipv6_t *a6;
    anon_uint64_t *ap;
    pcap_dumper_t *pcap_dumper;
} cb_data_t;

/*
 * pcap callback function
 * called for each packet in trace - anonymizes it and writes into output file
 */

void callback(u_char *udata, const struct pcap_pkthdr *pkthdr,
	      const u_char *pktdata) {
    in_addr_t raw_addr, anon_addr;
    //struct in6_addr raw_addr, anon_addr;
    uint8_t mac[6];
    uint8_t amac[6];
    /* anonymize packet */
    /*
    (void) anon_ipv4_map_pref(a, raw_addr, &anon_addr);
    (void) anon_ipv6_map_pref(a, raw_addr, &anon_addr);
    (void) anon_mac_map(a,mac,amac);
    */
    /* redo checksums */

    /* write packet to output */
    /*
    pcap_dump();
    */
}

static void
usage()
{
    int i;

    printf("usage: %s <subcommand> [options] [args]\n"
	   "\n"
	   "Most subcommands take a file as an argument.\n"
	   "\n"
	   "Available subcommands:\n",
	   progname);
}

/*
 * Simply dispatch to the appropriate subcommand handler using
 * the cmds dispatch table.
 */

int main(int argc, char * argv[]) {

    FILE *in;
    cb_data_t cb_data;
    /*
    anon_ipv4_t *a4;
    anon_ipv6_t *a6;
    anon_uint64_t *ap;
    */
    
    int c, lflag = 0, cflag = 0;
    unsigned cnt;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *finname, *foutname;
    pcap_t *pcap;
    uint64_t lower, upper;
    anon_key_t *key = NULL;

    if (argc < 2) {
	fprintf(stderr, "Type '%s help' for usage information\n", progname);
	return EXIT_FAILURE;
    }

    key = anon_key_new();
    anon_key_set_key(key, my_key, sizeof(my_key));
    
    /*
    //optind = 2;
    while ((c = getopt(argc, argv, "h")) != -1) {
	switch (c) {
	case 'h':
	case '?':
	default:
	    printf("usage: %s\n", usage);
	    exit(EXIT_SUCCESS);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
	fprintf(stderr, "usage: %s\n", cmd->usage);
	exit(EXIT_FAILURE);
    }
    */

    if ((pcap = pcap_open_offline(finname, errbuf)) == NULL) {
	fprintf(stderr, "failded to open input file: %s\n", errbuf);
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }

    if ((cb_data.pcap_dumper = pcap_dump_open(pcap, foutname)) == NULL){
	fprintf(stderr, "failded to open output file\n");
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }

    cb_data.a4 = anon_ipv4_new();
    cb_data.a6 = anon_ipv6_new();
    cb_data.ap = anon_uint64_new(0,65535);
    if ( (!cb_data.a4) || (!cb_data.a6) || (!cb_data.ap)) {
	fprintf(stderr, "%s: Failed to initialize IP or port mappings\n",
		progname);
	anon_key_delete(key);
	exit(EXIT_FAILURE);
    }
    anon_ipv4_set_key(cb_data.a4, key);
    anon_ipv6_set_key(cb_data.a6, key);
    anon_uint64_set_key(cb_data.ap, key); /* not doing anything */

    pcap_loop(pcap, -1, &callback, (u_char*) &cb_data);
	

    pcap_close(pcap);
    pcap_dump_close(cb_data.pcap_dumper);
    
    anon_ipv4_delete(cb_data.a4);
    anon_ipv6_delete(cb_data.a6);
    anon_uint64_delete(cb_data.ap);
    anon_key_delete(key);

    return EXIT_SUCCESS;
}
