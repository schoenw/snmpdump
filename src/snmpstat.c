/*
 * snmpstat.c --
 *
 * A simple C program to analyze SNMP traffic traces using the libxml
 * xml reader interface. This is a fast memory conserving version of
 * the perl scripts.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 */

#include "config.h"
#include "snmp.h"

#include <stdlib.h>
#include <unistd.h>

static const char *progname = "snmpstat";
static unsigned long total=0;
static unsigned long version[3];

/*
 * This should generate a simple csv output format with just some key
 * information:
 *
 * timestamp, src, dst,
 * message-version,
 * message-length,
 * operation,
 * request-id,
 * error_status, error_index,
 * name, name, ...
 */

static void
callback(snmp_packet_t *pkt, void *user_data)
{
	printf("\n\n****************\n\n");
    if (pkt->message.version.value >= 0 && pkt->message.version.value < 3) {
	version[pkt->message.version.value]++;
	total++;
    }
}

int
main(int argc, char **argv)
{
    int i, c;

    while ((c = getopt(argc, argv, "Vh")) != -1) {
	switch (c) {
	case 'V':
	    printf("%s %s\n", progname, VERSION);
	    exit(0);
	case 'h':
	case '?':
	    printf("%s [-h] file ... \n", progname);
	    exit(0);
	}
    }

    for (i = optind; i < argc; i++) {
	snmp_read_pcap_file(argv[i], NULL, callback, NULL);
    }
    
    printf("SNMP version statistics:\n\n");
    for (i = 0; i < 3; i++) {
	printf("%18d: %5lu  %3lu%%\n", i, version[i],
	       total ? 100*version[i]/total : 0);
    }
    printf("    ---------------------------\n");
    printf("%18s: %5lu  %3d%%\n\n", "total", total, 100);

    return 0;
}
