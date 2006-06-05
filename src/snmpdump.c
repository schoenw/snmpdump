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
#include <errno.h>
#include <unistd.h>
#include <regex.h>
#include <smi.h>

const char *progname = "snmpdump";

typedef enum {
    INPUT_XML = 1,
    INPUT_PCAP = 2
} input_t;

typedef enum {
    OUTPUT_XML = 1,
    OUTPUT_CSV = 2
} output_t;

#define STATE_FLAG_V1V2	0x01

typedef struct {
    uint64_t cnt;
    snmp_filter_t *filter;
    void (*do_filter)(snmp_filter_t *filter, snmp_packet_t *pkt);
    void (*do_learn)(snmp_packet_t *pkt);
    void (*do_anon)(snmp_packet_t *pkt);
    void (*do_flow_init)(snmp_write_t *out);
    void (*do_flow_write)(snmp_write_t *out, snmp_packet_t *pkt);
    void (*do_flow_done)(snmp_write_t *out);
    snmp_write_t out;
    int flags;
} callback_state_t;


/*
 * The per message callback which does all the processing and
 * printing, controlled by the state argument. This function is called
 * with a NULL packet pointer once we are done processing all packets.
 */

static void
print(snmp_packet_t *pkt, void *user_data)
{
    callback_state_t *state = (callback_state_t *) user_data;

    if (! state) {
	return;
    }

    /* Cleanup by printing the proper closing text in case we have
     * dealt with all packets.
     */

    if (! pkt) {
	if (state->do_flow_done) {
	    state->do_flow_done(&state->out);
	    return;
	}
	if (state->cnt && state->out.write_end && state->out.stream) {
	    state->out.write_end(state->out.stream);
	}
	return;
    }

    /* First apply the filters. Then call the anonymization module. We
     * might have to call it twice for learning purposes.
     */
    
    if (state->filter && state->do_filter) {
	state->do_filter(state->filter, pkt);
    }

    /*
     * Check whether we have to first apply any conversion. If yes, we
     * filter a second time since we might now have to apply
     * additional filter rules.
     */

    if (state->flags & STATE_FLAG_V1V2) {
	snmp_pkt_v1tov2(pkt);
	if (state->filter && state->do_filter) {
	    state->do_filter(state->filter, pkt);
	}
    }

    if (state->do_learn) {
	state->do_learn(pkt);
    }

    if (state->do_anon) {
	state->do_anon(pkt);
    }

    /*
     * Call the flow handler if it is set and we are done.
     */

    if (state->do_flow_write) {
	state->do_flow_write(&state->out, pkt);
	if (state->flags & STATE_FLAG_V1V2) {
	    snmp_pkt_delete(pkt);
	}
	return;
    }

    /* Otherwise, check whether we have to generate a header and then
     * print the packet.
     */

    if (state->cnt == 0 && state->out.stream && state->out.write_new) {
	state->out.write_new(state->out.stream);
    }

    if (state->out.stream && state->out.write_pkt) {
	state->out.write_pkt(state->out.stream, pkt);
    }
    state->cnt++;

    if (state->flags & STATE_FLAG_V1V2) {
	snmp_pkt_delete(pkt);
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
    char *expr = NULL, *path = NULL;
    output_t output = OUTPUT_XML;
    input_t input = INPUT_PCAP;
    char *errmsg;
    anon_key_t *key = NULL;
    callback_state_t _state, *state = &_state;
    FILE *stream = stdout;

    smiInit(progname);

    memset(state, 0, sizeof(*state));

    key = anon_key_new();
    anon_key_set_random(key);

    while ((c = getopt(argc, argv, "FVz:f:w:i:o:c:m:hap:tC:")) != -1) {
	switch (c) {
	case 'a':
	    state->do_anon = snmp_anon_apply;
	    break;
	case 'z':
	    state->filter = snmp_filter_new(optarg, &errmsg);
	    if (! state->filter) {
		fprintf(stderr, "%s: ignoring clear filter: %s\n",
			progname, errmsg);
		continue;
	    }
	    state->do_filter = snmp_filter_apply;
	    break;
	case 'w':
	    stream = fopen(optarg, "w");
	    if (! stream) {
		fprintf(stderr, "%s: failed to open file %s: %s\n",
			progname, optarg, strerror(errno));
		exit(1);
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
	case 'C':
	    path = optarg;
	    break;
	case 't':
	    state->flags |= STATE_FLAG_V1V2;
	    break;
	case 'p':
	    anon_key_set_passphase(key, optarg);
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
	case 'F':
	    state->do_flow_write = snmp_flow_write;
	    state->do_flow_done = snmp_flow_done;
	    break;
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-c config] [-m module] [-f filter] [-i format] [-o format] [-z regex] [-p passphrase] [-w file] [-h] [-V] [-F] [-C path] [-a] file ... \n", progname);
	    exit(0);
	}
    }

    state->out.stream = stream;
    state->out.write_new = NULL;
    state->out.write_pkt = NULL;
    state->out.write_end = NULL;
    state->out.path = path;

    if (state->do_anon) {
	anon_init(key);
    }

    switch (output) {
    case OUTPUT_XML:
	state->out.write_new = snmp_xml_write_stream_new;
	state->out.write_pkt = snmp_xml_write_stream_pkt;
	state->out.write_end = snmp_xml_write_stream_end;
	state->out.ext = "xml";
	break;
    case OUTPUT_CSV:
	state->out.write_new = snmp_csv_write_stream_new;
	state->out.write_pkt = snmp_csv_write_stream_pkt;
	state->out.write_end = snmp_csv_write_stream_end;
	state->out.ext = "csv";
	break;
    default:
	fprintf(stderr, "%s: unknown output format - aborting...\n", progname);
	abort();
    }

    if (optind == argc) {
	switch (input) {
	case INPUT_XML:
	    snmp_xml_read_stream(stdin, print, state);
	    break;
	case INPUT_PCAP:
	    snmp_pcap_read_stream(stdin, expr, print, state);
	    break;
	}
    } else {
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
    }
    print(NULL, state);

    if (state->filter) {
	snmp_filter_delete(state->filter);
    }

    if (key) {
	anon_key_delete(key);
    }

    return 0;
}
