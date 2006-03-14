/*
 * csv-write.c --
 *
 * Serialize the most important information about an SNMP packet into
 * as comma separated values (CSV). Every output line contains the
 * following fields:
 *
 *   a) time-stamp
 *   b) src address
 *   c) src port
 *   d) dst address
 *   e) dst port
 *   f) snmp message size
 *   g) snmp message version
 *   h) protocol operation (get/next/bulk/set/trap/inform/response/report)
 *   i) request ID
 *   j) error status
 *   k) error index
 *   *) list of object names in dotted notation
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#include "snmp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char sep = ',';

static void
csv_write_addr(FILE *stream, struct sockaddr *addr,
	       int show_addr, int show_port)
{
    struct sockaddr_in *sinv4;
    
    switch (addr->sa_family) {
    case AF_INET:
	sinv4 = (struct sockaddr_in *) addr;
	if (show_addr) {
	    fprintf(stream, "%c%s", sep, inet_ntoa(sinv4->sin_addr));
	} else {
	    fprintf(stream, "%c", sep);
	}
	if (show_port) {
	    fprintf(stream, "%c%d", sep, sinv4->sin_port);
	} else {
	    fprintf(stream, "%c", sep);
	}
	break;
    default:
	break;
    }
}

static void
csv_write_int32(FILE *stream, snmp_int32_t *val)
{
    if (val->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%d", sep, val->value);
    } else {
	fprintf(stream, "%c", sep);
    }
}

void
snmp_csv_write_stream(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;

    fprintf(stream, "\n%u.%06u", pkt->time.tv_sec, pkt->time.tv_usec);

    csv_write_addr(stream, (struct sockaddr *) &pkt->src,
		   pkt->attr.flags & SNMP_FLAG_SADDR,
		   pkt->attr.flags & SNMP_FLAG_SPORT);
    csv_write_addr(stream, (struct sockaddr *) &pkt->dst,
		   pkt->attr.flags & SNMP_FLAG_DADDR,
		   pkt->attr.flags & SNMP_FLAG_DPORT);
    
    if (pkt->msg.attr.flags & SNMP_FLAG_BLEN) {
	fprintf(stream, "%c%d", sep, pkt->msg.attr.blen);
    } else {
	fprintf(stream, "%c", sep);
    }

    csv_write_int32(stream, &pkt->msg.version);

    fprintf(stream, "\n");
}

void
snmp_csv_write_stream_begin(FILE *stream)
{
    /* this is at the moment an empty entry point */
}

void
snmp_csv_write_stream_end(FILE *stream)
{
    /* this is at the moment an empty entry point */
}
