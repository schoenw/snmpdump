/*
 * snmp.c --
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
#include <unistd.h>

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

static inline void*
xmemdup(const void *src, size_t len)
{
    void *dst;
    
    dst = xmalloc(len);
    memcpy(dst, src, len);
    return dst;
}

static void
v1tov2(snmp_packet_t *pkt)
{
    if (pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP1) {
	return;
    }

    /* RFC 3584 */

    /* 1st varbind is sysUpTime.0 == time_stamp */
    /* 2nd varbind is snmpTrapOid.0 == ... */

    /* if not yet present, append snmpTrapAddress.0,
       snmpTrapCommunity.0, snmpTrapEnterprise.0 */

    /* How do we manage memory? Keep it around in static variables
       until the next call is made? */
}


snmp_packet_t*
snmp_pkt_new(void)
{
    snmp_packet_t *pkt;

    pkt = xmalloc(sizeof(snmp_packet_t));
    pkt->attr.flags |= SNMP_FLAG_DYNAMIC;
    return pkt;
}

snmp_packet_t*
snmp_pkt_copy(snmp_packet_t *pkt)
{
    snmp_packet_t *n;

    n = snmp_pkt_new();

    /* xxx more copying to be done here for SNMPv3 messages */

    memcpy(n, pkt, sizeof(snmp_packet_t));

    n->snmp.community.value
	= xmemdup(pkt->snmp.community.value, pkt->snmp.community.len);
    
    return n;
}

void
snmp_pkt_delete(snmp_packet_t *pkt)
{
    if (! pkt || ! (pkt->attr.flags & SNMP_FLAG_DYNAMIC)) {
	return;
    }

    if (pkt->snmp.community.value
	&& pkt->snmp.community.attr.flags & SNMP_FLAG_DYNAMIC) {
	free(pkt->snmp.community.value);
    }
    
    /* xxx more cleanup to be done here for SNMPv3 messages */
    
    free(pkt);
}
