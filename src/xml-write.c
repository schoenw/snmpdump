/*
 * xml-write.c --
 *
 * Serialize an SNMP packet into an XML representation conforming to
 * the snmptrace RNC schema that can be found in the documentation.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 */

#include "snmp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void
xml_write_addr(FILE *stream, char *name, struct sockaddr *addr)
{
    struct sockaddr_in *sinv4;
    
    switch (addr->sa_family) {
    case AF_INET:
	sinv4 = (struct sockaddr_in *) addr;
	fprintf(stream, "<%s ip=\"%s\" port=\"%d\"/>",
		name, inet_ntoa(sinv4->sin_addr), sinv4->sin_port);
	break;
    default:
	break;
    }
}

void
snmp_xml_write_stream(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;
    
    fprintf(stream, "<packet sec=\"%u\" usec=\"%u\">",
	    pkt->time.tv_sec, pkt->time.tv_usec);

    xml_write_addr(stream, "src", (struct sockaddr *) &pkt->src);
    xml_write_addr(stream, "dst", (struct sockaddr *) &pkt->dst);

    fprintf(stream, "<snmp>");
    fprintf(stream, "</snmp>");

    fprintf(stream, "</packet>\n");
}

void
snmp_xml_write_stream_begin(FILE *stream)
{
    fprintf(stream, "<?xml version=\"1.0\"?>\n<snmptrace>\n");
}

void
snmp_xml_write_stream_end(FILE *stream)
{
    fprintf(stream, "</snmptrace>\n");

}
