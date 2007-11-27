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

void
snmp_pkt_v1tov2(snmp_packet_t *pkt)
{
    snmp_pdu_t *pdu;
    snmp_varbind_t *nvb, *vb;

    static uint32_t sysUpTime0[]   = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
    static uint32_t snmpTrapOid0[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
    static uint32_t snmpTrapAddress0[] = { 1, 3, 6, 1, 6, 3, 18, 1, 3, 0 };
    static uint32_t snmpTrapCommunity0[] = { 1, 3, 6, 1, 6, 3, 18, 1, 4, 0 };
    static uint32_t snmpTrapEnterprise0[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0 };

    static uint32_t coldStart[]    = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 1 };
    static uint32_t warmStart[]    = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 2 };
    static uint32_t linkDown[]     = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 3 };
    static uint32_t linkUp[]       = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 4 };
    static uint32_t authFailure[]  = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 5 };
    static uint32_t egpNeighLoss[] = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 6 };

    assert(pkt);

    pdu = &pkt->snmp.scoped_pdu.pdu;

    if (pdu->type != SNMP_PDU_TRAP1) {
	return;
    }

    /* set 2nd varbind to { snmpTrapOid.0 == ... } (RFC 3584) */

    nvb = (snmp_varbind_t *) xmalloc(sizeof(snmp_varbind_t));
    nvb->attr.flags |= SNMP_FLAG_DYNAMIC;
    nvb->attr.flags |= SNMP_FLAG_VALUE;
    nvb->type = SNMP_TYPE_OID;
    nvb->name.len = sizeof(snmpTrapOid0) / sizeof(snmpTrapOid0[0]);
    nvb->name.value = xmemdup(snmpTrapOid0, nvb->name.len * sizeof(uint32_t));
    nvb->name.attr.flags |= SNMP_FLAG_VALUE;
    if (! pdu->generic_trap.attr.flags & SNMP_FLAG_VALUE) {
	nvb->value.oid.len = 0;
	nvb->value.oid.value = NULL;
    } else {
	switch (pdu->generic_trap.value) {
	case 0: /* coldStart */
	    nvb->value.oid.len = sizeof(coldStart) / sizeof(coldStart[0]);
	    nvb->value.oid.value = xmemdup(coldStart,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 1: /* warmStart */
	    nvb->value.oid.len = sizeof(warmStart) / sizeof(warmStart[0]);
	    nvb->value.oid.value = xmemdup(warmStart,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 2: /* linkDown */
	    nvb->value.oid.len = sizeof(linkDown) / sizeof(linkDown[0]);
	    nvb->value.oid.value = xmemdup(linkDown,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 3: /* linkUp */
	    nvb->value.oid.len = sizeof(linkUp) / sizeof(linkUp[0]);
	    nvb->value.oid.value = xmemdup(linkUp,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 4: /* authenticationFailure */
	    nvb->value.oid.len = sizeof(authFailure) / sizeof(authFailure[0]);
	    nvb->value.oid.value = xmemdup(authFailure,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 5: /* egpNeighborLoss */
	    nvb->value.oid.len = sizeof(egpNeighLoss) / sizeof(egpNeighLoss[0]);
	    nvb->value.oid.value = xmemdup(egpNeighLoss,
				   nvb->value.oid.len * sizeof(uint32_t));
	    nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    break;
	case 6: /* enterprise specific */
	    if ((! pdu->specific_trap.attr.flags & SNMP_FLAG_VALUE)
		|| (! pdu->enterprise.attr.flags & SNMP_FLAG_VALUE)) {
		nvb->value.oid.len = 0;
		nvb->value.oid.value = NULL;
	    } else {
		int len = pdu->enterprise.len;
		nvb->value.oid.len = pdu->enterprise.len + 2;
		nvb->value.oid.value = xmalloc(nvb->value.oid.len
					       * sizeof(uint32_t));
		memcpy(nvb->value.oid.value, pdu->enterprise.value,
		       pdu->enterprise.len * sizeof(uint32_t));
		nvb->value.oid.value[len] = 0;
		nvb->value.oid.value[++len] = pdu->specific_trap.value;
		nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	    }
	    break;
	default:
	    abort();
	}
    }
    nvb->next = pdu->varbindings.varbind;
    pdu->varbindings.varbind = nvb;

    /* set 1st varbind to { sysUpTime.0, time_stamp } (RFC 3584) */

    nvb = (snmp_varbind_t *) xmalloc(sizeof(snmp_varbind_t));
    nvb->attr.flags |= SNMP_FLAG_DYNAMIC;
    nvb->attr.flags |= SNMP_FLAG_VALUE;
    nvb->type = SNMP_TYPE_UINT32;
    nvb->name.len = sizeof(sysUpTime0) / sizeof(sysUpTime0[0]);
    nvb->name.value = xmemdup(sysUpTime0, nvb->name.len * sizeof(uint32_t));
    nvb->name.attr.flags |= SNMP_FLAG_VALUE;
    if (! pdu->time_stamp.attr.flags & SNMP_FLAG_VALUE) {
	nvb->value.u32.value = 0;
    } else {
	nvb->value.u32.value = pdu->time_stamp.value;
	nvb->value.u32.attr.flags |= SNMP_FLAG_VALUE;
    }
    nvb->next = pdu->varbindings.varbind;
    pdu->varbindings.varbind = nvb;

    /* get a pointer to the last varbind */

    for (vb = pdu->varbindings.varbind; vb->next; vb = vb->next) ;

    /* set n-2nd varbind to { snmpTrapAddress.0, agent_addr } (RFC 3584) */

    nvb = (snmp_varbind_t *) xmalloc(sizeof(snmp_varbind_t));
    nvb->attr.flags |= SNMP_FLAG_DYNAMIC;
    nvb->attr.flags |= SNMP_FLAG_VALUE;
    nvb->type = SNMP_TYPE_IPADDR;
    nvb->name.len = sizeof(snmpTrapAddress0) / sizeof(snmpTrapAddress0[0]);
    nvb->name.value = xmemdup(snmpTrapAddress0, nvb->name.len * sizeof(uint32_t));
    nvb->name.attr.flags |= SNMP_FLAG_VALUE;
    if (! pdu->agent_addr.attr.flags & SNMP_FLAG_VALUE) {
	nvb->value.ip.value = 0;
    } else {
	nvb->value.ip.value = pdu->agent_addr.value;
	nvb->value.ip.attr.flags |= SNMP_FLAG_VALUE;
    }
    nvb->next = NULL;
    vb->next = nvb;
    vb = nvb;

    /* set n-1st varbind to { snmpTrapCommunity.0, community } (RFC 3584) */

    nvb = (snmp_varbind_t *) xmalloc(sizeof(snmp_varbind_t));
    nvb->attr.flags |= SNMP_FLAG_DYNAMIC;
    nvb->attr.flags |= SNMP_FLAG_VALUE;
    nvb->type = SNMP_TYPE_OCTS;
    nvb->name.len = sizeof(snmpTrapCommunity0) / sizeof(snmpTrapCommunity0[0]);
    nvb->name.value = xmemdup(snmpTrapCommunity0, nvb->name.len * sizeof(uint32_t));
    nvb->name.attr.flags |= SNMP_FLAG_VALUE;
    if (! pkt->snmp.community.attr.flags & SNMP_FLAG_VALUE) {
	nvb->value.octs.len = 0;
	nvb->value.octs.value = NULL;
    } else {
	nvb->value.octs.len = pkt->snmp.community.len;
	nvb->value.octs.value = xmemdup(pkt->snmp.community.value,
					pkt->snmp.community.len);
	nvb->value.octs.attr.flags |= SNMP_FLAG_VALUE;
	nvb->value.octs.attr.flags |= SNMP_FLAG_DYNAMIC;
    }
    nvb->next = NULL;
    vb->next = nvb;
    vb = nvb;

    /* set n-th varbind to { snmpTrapEnterprise.0, community } (RFC 3584) */

    nvb = (snmp_varbind_t *) xmalloc(sizeof(snmp_varbind_t));
    nvb->attr.flags |= SNMP_FLAG_DYNAMIC;
    nvb->attr.flags |= SNMP_FLAG_VALUE;
    nvb->type = SNMP_TYPE_OID;
    nvb->name.len = sizeof(snmpTrapEnterprise0) / sizeof(snmpTrapEnterprise0[0]);
    nvb->name.value = xmemdup(snmpTrapEnterprise0, nvb->name.len * sizeof(uint32_t));
    nvb->name.attr.flags |= SNMP_FLAG_VALUE;
    if (! pdu->enterprise.attr.flags & SNMP_FLAG_VALUE) {
	nvb->value.oid.len = 0;
	nvb->value.oid.value = NULL;
    } else {
	nvb->value.oid.len = pdu->enterprise.len;
	nvb->value.oid.value = xmemdup(pdu->enterprise.value,
					pdu->enterprise.len * sizeof(uint32_t));
	nvb->value.oid.attr.flags |= SNMP_FLAG_VALUE;
	nvb->value.oid.attr.flags |= SNMP_FLAG_DYNAMIC;
    }
    nvb->next = NULL;
    vb->next = nvb;
    vb = nvb;

    /* Finally, change the pdu type and mark all trap fields as unused
     * by clearing the value flags. */

    pdu->type = SNMP_PDU_TRAP2;

    pdu->enterprise.attr.flags &= ~SNMP_FLAG_VALUE;
    pdu->agent_addr.attr.flags &= ~SNMP_FLAG_VALUE;
    pdu->generic_trap.attr.flags &= ~SNMP_FLAG_VALUE;
    pdu->specific_trap.attr.flags &= ~SNMP_FLAG_VALUE;
    pdu->time_stamp.attr.flags &= ~SNMP_FLAG_VALUE;
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
    snmp_varbind_t *vb, **nvb = NULL;

    n = snmp_pkt_new();
    memcpy(n, pkt, sizeof(snmp_packet_t));
    n->attr.flags |= SNMP_FLAG_DYNAMIC;

    n->snmp.community.value
	= (unsigned char *) xmemdup(pkt->snmp.community.value, pkt->snmp.community.len);
    n->snmp.community.attr.flags |= SNMP_FLAG_DYNAMIC;
    
    /* xxx more copying to be done here for SNMPv3 messages */

    /*
     * Duplicate the varbind list.
     */

    for (vb = pkt->snmp.scoped_pdu.pdu.varbindings.varbind,
	     nvb = &n->snmp.scoped_pdu.pdu.varbindings.varbind;
	 vb; vb = vb->next) {
	*nvb = (snmp_varbind_t *) xmemdup(vb, sizeof(snmp_varbind_t));
	(*nvb)->attr.flags |= SNMP_FLAG_DYNAMIC;
	(*nvb)->name.attr.flags |= SNMP_FLAG_DYNAMIC;
	(*nvb)->name.value = xmemdup(vb->name.value,
				     vb->name.len * sizeof(uint32_t));
	switch (vb->type) {
	case SNMP_TYPE_OCTS:
	    (*nvb)->value.octs.value = xmemdup(vb->value.octs.value,
					       vb->value.octs.len);
	    (*nvb)->value.octs.attr.flags |= SNMP_FLAG_DYNAMIC;
	    break;
	case SNMP_TYPE_OID:
	    (*nvb)->value.oid.value = xmemdup(vb->value.oid.value,
					      vb->value.oid.len * sizeof(uint32_t));
	    (*nvb)->value.oid.attr.flags |= SNMP_FLAG_DYNAMIC;
	}
	nvb = &((*nvb)->next);
    }

    return n;
}

void
snmp_pkt_delete(snmp_packet_t *pkt)
{
    snmp_varbind_t *vb, *q;
    
    if (! pkt || ! (pkt->attr.flags & SNMP_FLAG_DYNAMIC)) {
	return;
    }

    if (pkt->snmp.community.value
	&& pkt->snmp.community.attr.flags & SNMP_FLAG_DYNAMIC) {
	free(pkt->snmp.community.value);
    }
    
    /* xxx more cleanup to be done here for SNMPv3 messages */

    /*
     * Delete the varbind list.
     */

    for (vb = pkt->snmp.scoped_pdu.pdu.varbindings.varbind; vb;) {
	if (vb->name.attr.flags & SNMP_FLAG_DYNAMIC) {
	    free(vb->name.value);
	}
	if (vb->type == SNMP_TYPE_OCTS
	    && vb->value.octs.attr.flags & SNMP_FLAG_DYNAMIC) {
	    free(vb->value.octs.value);
	}
	if (vb->type == SNMP_TYPE_OID
	    && vb->value.oid.attr.flags & SNMP_FLAG_DYNAMIC) {
	    free(vb->value.oid.value);
	}
	q = vb->next;
	if (vb->attr.flags & SNMP_FLAG_DYNAMIC) {
	    free(vb);
	}
	vb = q;
    }
    
    free(pkt);
}
