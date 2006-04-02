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
 *
 * $Id$
 */

#define _GNU_SOURCE

#include "config.h"
#include "snmp.h"
#include "anon.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <smi.h>

static const char *progname = "snmpdump";

typedef enum {
    INPUT_XML = 1,
    INPUT_PCAP = 2
} input_t;

typedef enum {
    OUTPUT_XML = 1,
    OUTPUT_CSV = 2
} output_t;


typedef struct {
    FILE *stream;
    snmp_filter_t *filter;
    void (*do_anon)(snmp_packet_t *pkt);
    void (*do_print)(FILE *stream, snmp_packet_t *pkt);
    void (*do_filter)(snmp_filter_t *filter, snmp_packet_t *pkt);
} callback_state_t;


/*
 * Not yet useful function to call the anonymization library.
 */

static void
anon(snmp_packet_t *pkt)
{
    snmp_varbind_t *vb;
    SmiNode *smiNode;
    SmiType *smiType;
    
    for (vb = pkt->snmp.scoped_pdu.pdu.varbindings.varbind;
	 vb; vb = vb->next) {
	smiNode = smiGetNodeByOID(vb->name.len, vb->name.value);
	if (smiNode) {
	    smiType = smiGetNodeType(smiNode);
	    if (smiType) {
		fprintf(stderr, "** %s\n", smiType->name);
	    }
	    anon_apply(vb, smiNode, smiType);
	}
    }
}


/*
 * The per message callback which does all the processing and
 * printing, controlled by the state argument.
 */

static void
print(snmp_packet_t *pkt, void *user_data)
{
    callback_state_t *state = (callback_state_t *) user_data;

    if (! state) {
	return;
    }

    if (state->filter && state->do_filter) {
	state->do_filter(state->filter, pkt);
    }

    if (state->do_anon) {
	state->do_anon(pkt);
    }

    if (state->stream && state->do_print) {
	state->do_print(state->stream, pkt);
    }
}


/*
 * The main function to parse arguments, initialize the libraries and
 * to fire off the libnids library using nids_run() for every input
 * file we process.
 */

int
main(int argc, char **argv)
{
    int i, c;
    char *expr = NULL;
    output_t output = OUTPUT_XML;
    input_t input = INPUT_PCAP;
    char *errmsg;
    snmp_filter_t *filter = NULL;
    callback_state_t _state, *state = &_state;

    smiInit(progname);

    memset(state, 0, sizeof(*state));

    while ((c = getopt(argc, argv, "Vz:f:i:o:c:m:ha")) != -1) {
	switch (c) {
	case 'a':
	    state->do_anon = anon;
	    break;
	case 'z':
	    filter = snmp_filter_new(optarg, &errmsg);
	    if (! filter) {
		fprintf(stderr, "%s: ignoring clear filter: %s\n",
			progname, errmsg);
		continue;
	    }
	    break;
	case 'i':
	    if (strcmp(optarg, "pcap") == 0) {
		input = INPUT_PCAP;
	    } else if (strcmp(optarg, "xml") == 0) {
		input = INPUT_XML;
	    } else {
		fprintf(stderr, "%s: ignoring input format: %s unknown\n",
			progname, optarg);
	    }
	    break;
	case 'o':
	    if (strcmp(optarg, "csv") == 0) {
		output = OUTPUT_CSV;
	    } else if (strcmp(optarg, "xml") == 0) {
		output = OUTPUT_XML;
	    } else {
		fprintf(stderr, "%s: ignoring output format: %s unknown\n",
			progname, optarg);
	    }
	    break;
	case 'f':
	    expr = optarg;
	    break;
	case 'c':
	    smiReadConfig(optarg, progname);
	    break;
	case 'm':
	    smiLoadModule(optarg);
	    break;
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-c config] [-m module] [-f filter] [-i format] [-o format] [-z regex] [-h] [-V] [-a] file ... \n", progname);
	    exit(0);
	}
    }

    state->stream = stdout;
    state->filter = filter;
    state->do_filter = snmp_filter_apply;
    state->do_print = NULL;

    if (state->do_anon) {
	anon_init();
    }

    switch (output) {
    case OUTPUT_XML:
	state->do_print = snmp_xml_write_stream;
	snmp_xml_write_stream_begin(stdout);
	for (i = optind; i < argc; i++) {
	    switch (input) {
	    case INPUT_XML:
		snmp_xml_read_file(argv[i], print, state);
		break;
	    case INPUT_PCAP:
		snmp_pcap_read_file(argv[i], expr, print, state);
		break;
	    }
	}
	snmp_xml_write_stream_end(stdout);
	break;
    case OUTPUT_CSV:
	state->do_print = snmp_csv_write_stream;
	snmp_csv_write_stream_begin(stdout);
	for (i = optind; i < argc; i++) {
	    switch (input) {
	    case INPUT_XML:
		snmp_xml_read_file(argv[i], print, state);
		break;
	    case INPUT_PCAP:
		snmp_pcap_read_file(argv[i], expr, print, state);
		break;
	    }
	}
	snmp_csv_write_stream_end(stdout);
	break;
    }

    if (filter) {
	snmp_filter_delete(filter);
    }

    return 0;
}
