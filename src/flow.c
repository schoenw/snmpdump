/*
 * flow.c --
 *
 * Utility functions to make copies of packets and to convert trap
 * messages in the common RFC 3416 format.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#define _GNU_SOURCE

#include "config.h"
#include "snmp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNMP_FLOW_NONE		0x00
#define SNMP_FLOW_COMMAND	0x01
#define SNMP_FLOW_NOTIFY	0x02

typedef struct _snmp_flow {
    int			type;
    char		*name;
    snmp_ipaddr_t       src_addr;
    snmp_ip6addr_t      src_addr6;
    snmp_ipaddr_t       dst_addr;
    snmp_ip6addr_t      dst_addr6;
    uint64_t		cnt;
    struct _snmp_flow *next;
} snmp_flow_t;

static snmp_flow_t *flow_list = NULL;

static inline void*
xmalloc(size_t size)
{
    void *p;

    p = malloc(size);
    if (! p) {
	abort();
    }
    memset(p, 0, size);
    return p;
}

/*
 * Create a name for a flow file name. The name is dynamically
 * allocated and must be freed by the caller when he is done with it.
 */

static char*
snmp_flow_name(snmp_flow_t *flow)
{
    char *name;
    const char *src = NULL, *dst = NULL;
    char src_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
    char src_addr6[INET6_ADDRSTRLEN], dst_addr6[INET6_ADDRSTRLEN];
#define FLOW_NAME_SIZE 128

    name = xmalloc(FLOW_NAME_SIZE);

    if (flow->src_addr6.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET6,
			&flow->src_addr6.value, src_addr6, sizeof(src_addr6));
    }
    if (flow->dst_addr6.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET6,
			&flow->dst_addr6.value, dst_addr6, sizeof(dst_addr6));
    }
    
    if (flow->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET,
			&flow->src_addr.value, src_addr, sizeof(src_addr));
    }
    if (flow->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET,
			&flow->dst_addr.value, dst_addr, sizeof(dst_addr));
    }

    if (! src || ! dst) {
	free(name);
	return NULL;
    }
    
    snprintf(name, FLOW_NAME_SIZE, "%s-%s-%s-%s",
	     (flow->type == SNMP_FLOW_COMMAND) ? "cg" : "no",
	     src ? src : "xxx",
	     (flow->type == SNMP_FLOW_COMMAND) ? "cr" : "nr",
	     dst ? dst : "yyy");
    
    return name;	
}

/*
 * Find a flow, potentially creating new flows if the flow does not
 * yet exist.
 */

static snmp_flow_t*
snmp_flow_find(snmp_packet_t *pkt)
{
    snmp_flow_t *p;
    int type = SNMP_FLOW_NONE;

    switch (pkt->snmp.scoped_pdu.pdu.type) {
    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
    case SNMP_PDU_GETBULK:
    case SNMP_PDU_SET:
	type = SNMP_FLOW_COMMAND;
	break;
    case SNMP_PDU_RESPONSE:
	break;
    case SNMP_PDU_TRAP1:
    case SNMP_PDU_TRAP2:
    case SNMP_PDU_INFORM:
	type = SNMP_FLOW_NOTIFY;
	break;
    case SNMP_PDU_REPORT:
	break;
    }

    /* The simple case first - we know the type of the flow. Lookup a
     * flow entry or create a new one if there is no appropriate flow
     * entry.
     */

    if (type != SNMP_FLOW_NONE) {
	for (p = flow_list; p; p = p->next) {
	    if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE
		&& pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE
		&& memcmp(&p->dst_addr.value, &pkt->dst_addr.value, 4) == 0
		&& memcmp(&p->src_addr.value, &pkt->src_addr.value, 4) == 0
		&& p->type == type) {
		break;
	    }
	    if (pkt->src_addr6.attr.flags & SNMP_FLAG_VALUE
		&& pkt->dst_addr6.attr.flags & SNMP_FLAG_VALUE
		&& memcmp(&p->dst_addr6.value, &pkt->dst_addr6.value, 16) == 0
		&& memcmp(&p->src_addr6.value, &pkt->src_addr6.value, 16) == 0
		&& p->type == type) {
		break;
	    }
	}
	if (! p) {
	    p = xmalloc(sizeof(snmp_flow_t));
	    p->type = type;
	    if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE
		&& pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
		memcpy(&p->src_addr, &pkt->src_addr, sizeof(p->src_addr));
		memcpy(&p->dst_addr, &pkt->dst_addr, sizeof(p->dst_addr));
	    }
	    if (pkt->src_addr6.attr.flags & SNMP_FLAG_VALUE
		&& pkt->dst_addr6.attr.flags & SNMP_FLAG_VALUE) {
		memcpy(&p->src_addr6, &pkt->src_addr6, sizeof(p->src_addr6));
		memcpy(&p->dst_addr6, &pkt->dst_addr6, sizeof(p->dst_addr6));
	    }
	    p->name = snmp_flow_name(p);
	    p->next = flow_list;
	    flow_list = p;
	} /* perhaps we should put the hit always at the head of the list */
	return p;
    }

    return NULL;
}

void
snmp_flow_new(snmp_write_t *out)
{
    /* nothing to be done here yet */
}

static FILE*
snmp_flow_open_stream(snmp_flow_t *flow, snmp_write_t *out, const char *mode)
{
#define MAX_FILENAME_SIZE 4096
    char filename[MAX_FILENAME_SIZE];
    FILE *stream;

    snprintf(filename, MAX_FILENAME_SIZE, "%s.%s", flow->name, out->ext);
    stream = fopen(filename, mode);
    return stream;
}

void
snmp_flow_write(snmp_write_t *out, snmp_packet_t *pkt)
{
    snmp_flow_t *flow;
    
    flow = snmp_flow_find(pkt);
    if (flow && flow->name) {
	FILE *f;
	f = snmp_flow_open_stream(flow, out, (flow->cnt == 0) ? "w" : "a");
	if (f) {
	    if (flow->cnt == 0 && out->write_new) {
		out->write_new(f);
	    }
	    if (out->write_pkt) {
		out->write_pkt(f, pkt);
	    }
	    fclose(f);
	    flow->cnt++;
	    return;
	}
    }
    if (out->stream && out->write_pkt) {
	out->write_pkt(out->stream, pkt);
    }
}

void
snmp_flow_done(snmp_write_t *out)
{
    snmp_flow_t *p, *q;

    for (p = flow_list; p; ) {
	if (p->name) {
	    FILE *f;
	    f = snmp_flow_open_stream(p, out, "a");
	    if (f) {
		if (out->write_end) {
		    out->write_end(f);
		}
		fclose(f);
	    }
	    free(p->name);
	}
	q = p->next;
	free(p);
	p = q;
    }
}
