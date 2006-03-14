/*
 * snmpdump.c --
 *
 * A utility to convert pcap capture files containing SNMP messages
 * into snmp trace files. To create these pcap files, you can use:
 *
 *    tcpdump -i <interface> -s 0 -w <filename> udp and port 161 or port 162
 *
 * To convert the SNMP messages to XML, use this command:
 *
 *    snmpdump <filename>
 *
 * This implementation generates XML output directly rather than using
 * and XML writer API in order to be fast and memory efficient.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 */

#define _GNU_SOURCE

#include "config.h"
#include "snmp.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

static const char *progname = "snmpdump";

static regex_t _clr_regex, _del_regex;
static regex_t *clr_regex = NULL, *del_regex = NULL;

static int iflag = 0;


static void
print_xml(snmp_packet_t *pkt, void *user_data)
{
    FILE *stream = (FILE *) user_data;
    
    assert(pkt && user_data);
    
    snmp_xml_write_stream(stream, pkt);
}


static void
print_csv(snmp_packet_t *pkt, void *user_data)
{
    FILE *stream = (FILE *) user_data;

    assert(pkt && user_data);

    snmp_csv_write_stream(stream, pkt);
}



/*
 * The main function to parse arguments, initialize the libraries and
 * to fire off the libnids library using nids_run() for every input
 * file we process.
 */

int
main(int argc, char **argv)
{
    int i, c, errcode;
    char *expr = NULL;
    char buffer[256];

    while ((c = getopt(argc, argv, "Vc:d:f:ih")) != -1) {
	switch (c) {
	case 'c':
	    errcode = regcomp(&_clr_regex, optarg,
			      REG_EXTENDED | REG_ICASE | REG_NOSUB);
	    if (errcode) {
		regerror(errcode, &_clr_regex, buffer, sizeof(buffer));
		fprintf(stderr, "%s: ignoring clear regex: %s\n", progname, buffer);
		continue;
	    }
	    clr_regex = &_clr_regex;
	    break;
	case 'd':
	    errcode = regcomp(&_del_regex, optarg,
			      REG_EXTENDED | REG_ICASE | REG_NOSUB);
	    if (errcode) {
		regerror(errcode, &_clr_regex, buffer, sizeof(buffer));
		fprintf(stderr, "%s: ignoring delete regex: %s\n", progname, buffer);
		continue;
	    }
	    del_regex = &_del_regex;
	    break;
	case 'f':
	    expr = optarg;
	    break;
	case 'i':
	    iflag = 1;
	    break;
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-c regex] [-d regex] [-f filter] [-h] file ... \n", progname);
	    exit(0);
	}
    }

    snmp_xml_write_stream_begin(stdout);
    for (i = optind; i < argc; i++) {
	// snmp_pcap_read_file(argv[i], expr, print_xml, stdout);
	snmp_pcap_read_file(argv[i], expr, print_csv, stdout);
    }
    snmp_xml_write_stream_end(stdout);

    return 0;
}
