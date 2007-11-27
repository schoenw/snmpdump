/*
 * flow.c --
 *
 * The functions in this module identify SNMP flows.
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>

#define SNMP_FLOW_NONE		0x00
#define SNMP_FLOW_COMMAND	0x01
#define SNMP_FLOW_NOTIFY	0x02

static struct _flow_type_names {
    int type;
    const char *name;
} flow_type_names[] = {
    { .type = SNMP_FLOW_NONE,    .name = "none"   },
    { .type = SNMP_FLOW_COMMAND, .name = "cmd"    },
    { .type = SNMP_FLOW_NOTIFY,  .name = "notify" },
    { .type = 0,		 .name = 0        },
};

#define SNMP_SLICE_NONE		0x00
#define SNMP_SLICE_GET		0x01
#define SNMP_SLICE_SET		0x02
#define SNMP_SLICE_TRAP		0x03
#define SNMP_SLICE_INFORM	0x04
#define SNMP_SLICE_GETNEXT	0x05
#define SNMP_SLICE_GETBULK	0x06

static struct _slice_type_names {
    int type;
    const char *name;
} slice_type_names[] = {
    { .type = SNMP_SLICE_NONE,    .name = "none"    },
    { .type = SNMP_SLICE_GET,     .name = "get"     },
    { .type = SNMP_SLICE_SET,     .name = "set"     },
    { .type = SNMP_SLICE_TRAP,    .name = "trap"    },
    { .type = SNMP_SLICE_INFORM,  .name = "inform"  },
    { .type = SNMP_SLICE_GETNEXT, .name = "getnext" },
    { .type = SNMP_SLICE_GETBULK, .name = "getbulk" },
    { .type = 0,		  .name = 0         },
};

#if 0
typedef struct _snmp_flow_elem {
    snmp_packet_t	   *pkt;
    struct _snmp_flow_elem *next;
} snmp_flow_elem;
#endif

typedef struct _snmp_flow {
    unsigned		id;
    int			type;
    char		*name;
    snmp_ipaddr_t       src_addr;
    snmp_ip6addr_t      src_addr6;
    snmp_uint32_t	src_port;
    snmp_ipaddr_t       dst_addr;
    snmp_ip6addr_t      dst_addr6;
    snmp_uint32_t	dst_port;
    uint64_t		cnt;
    FILE		*stream;
    struct _snmp_flow	*next;
} snmp_flow_t;

static snmp_flow_t *flow_list = NULL;

typedef struct _snmp_slice {
    unsigned		id;
    int                 type;
    char                *name;
    snmp_ipaddr_t       src_addr;
    snmp_ip6addr_t      src_addr6;
    snmp_uint32_t	src_port;
    snmp_ipaddr_t       dst_addr;
    snmp_ip6addr_t      dst_addr6;
    snmp_uint32_t	dst_port;
    uint64_t		cnt;
    FILE		*stream;
    struct _snmp_slice	*next;
    snmp_packet_t	*pkt;
    snmp_packet_t	*last_response;
} snmp_slice_t;

static snmp_slice_t *slice_list = NULL;

typedef struct _snmp_cache_elem {
    snmp_packet_t *pkt;
    struct _snmp_cache_elem *next;
    struct _snmp_cache_elem *kids;
} snmp_cache_elem_t;

static snmp_cache_elem_t *snmp_cache_list = NULL;

static unsigned flow_id = 0;
static unsigned slice_id = 0;

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
 * Create a name for a slice file name. The name is dynamically
 * allocated and must be freed by the caller when he is done with it.
 */

static char*
snmp_slice_name(snmp_slice_t *slice)
{
    int i;
    char *name;
    const char *type = NULL;
    const char *src = NULL, *dst = NULL;
    char src_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
    char src_addr6[INET6_ADDRSTRLEN], dst_addr6[INET6_ADDRSTRLEN];
#define SLICE_NAME_SIZE 128

    name = xmalloc(SLICE_NAME_SIZE);

    if (slice->src_addr6.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET6,
			&slice->src_addr6.value, src_addr6, sizeof(src_addr6));
    }
    if (slice->dst_addr6.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET6,
			&slice->dst_addr6.value, dst_addr6, sizeof(dst_addr6));
    }
    
    if (slice->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	src = inet_ntop(AF_INET,
			&slice->src_addr.value, src_addr, sizeof(src_addr));
    }
    if (slice->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	dst = inet_ntop(AF_INET,
			&slice->dst_addr.value, dst_addr, sizeof(dst_addr));
    }

    if (! src || ! dst) {
	free(name);
	return NULL;
    }

    for (i = 0; slice_type_names[i].name; i++) {
	if (slice_type_names[i].type == slice->type) break;
    }

    type = slice_type_names[i].name ? slice_type_names[i].name : "UNKNOWN";

    snprintf(name, SLICE_NAME_SIZE, "%08u-%s-%s:%u-%s:%u",
	     slice->id,
	     type,
	     src ? src : "xxx",
	     slice->src_port.value,
	     dst ? dst : "yyy",
	     slice->dst_port.value);
    
    return name;	
}

/*
 * Helper function to test whether two IPv4 addresses are equal.
 */

static inline int
snmp_ipaddr_equal(snmp_ipaddr_t *a, snmp_ipaddr_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && memcmp(&a->value, &b->value, 4) == 0);
}

/*
 * Helper function to test whether two IPv6 addresses are equal.
 */

static inline int
snmp_ip6addr_equal(snmp_ip6addr_t *a, snmp_ip6addr_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && memcmp(&a->value, &b->value, 16) == 0);
}

/*
 * Helper function to test whether two int32 values are equal.
 */

static inline int
snmp_int32_equal(snmp_int32_t *a, snmp_int32_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && a->value == b->value);
}

/*
 * Helper function to test whether two uint32 values are equal.
 */

static inline int
snmp_uint32_equal(snmp_uint32_t *a, snmp_uint32_t *b)
{
    return (a->attr.flags & SNMP_FLAG_VALUE
	    && b->attr.flags & SNMP_FLAG_VALUE
	    && a->value == b->value);
}

/*
 * Helper function to test whether two oid values are equal.
 */

static inline int
snmp_oid_equal(snmp_oid_t *a, snmp_oid_t *b)
{
    int i;
    
    if (! a->attr.flags & SNMP_FLAG_VALUE
	|| ! b->attr.flags & SNMP_FLAG_VALUE) {
	return 0;
    }

    if (a->len != b->len) {
	return 0;
    }

    for (i = 0; i < a->len; i++) {
	if (a->value[i] != b->value[i]) {
	    return 0;
	}
    }

    return 1;
}

/*
 * Compare two varbind lists whether they contain the same varbind
 * names. Note that we allow the positions of the names to be
 * different!
 */

static int
snmp_vbl_cmp_names(snmp_packet_t *a, snmp_packet_t *b)
{
    snmp_varbind_t *vb1, *vb2;
    snmp_var_bindings_t *vbl1, *vbl2;

    if (!a || !b) {
	return 0;
    }

    vbl1 = &a->snmp.scoped_pdu.pdu.varbindings;
    vbl2 = &b->snmp.scoped_pdu.pdu.varbindings;

    for (vb1 = vbl1->varbind; vb1; vb1 = vb1->next) {
	for (vb2 = vbl2->varbind; vb2; vb2 = vb2->next) {
	    if (vb2->attr.flags & SNMP_FLAG_USER) {
		continue;
	    }
	    if (snmp_oid_equal(&vb1->name, &vb2->name)) {
		vb2->attr.flags |= SNMP_FLAG_USER;
		break;
	    }
	}
	if (! vb2) break;
    }

    /* clear the user flags in the name attr.flags */
    for (vb2 = vbl2->varbind; vb2; vb2 = vb2->next) {
	vb2->attr.flags &= ~SNMP_FLAG_USER;
    }

    if (vb1) {
	return 0;
    }

    return 1;
}


/*
 * Compare two varbind lists whether they contain at least one
 * identical names. Note that we allow the positions of the names to
 * be different!
 */

static int
snmp_vbl_lnk_names(snmp_packet_t *a, snmp_packet_t *b)
{
    snmp_varbind_t *vb1, *vb2;
    snmp_var_bindings_t *vbl1, *vbl2;

    if (!a && !b) {
	return 0;
    }

    vbl1 = &a->snmp.scoped_pdu.pdu.varbindings;
    vbl2 = &b->snmp.scoped_pdu.pdu.varbindings;

    for (vb1 = vbl1->varbind; vb1; vb1 = vb1->next) {
	for (vb2 = vbl2->varbind; vb2; vb2 = vb2->next) {
	    if (vb2->attr.flags & SNMP_FLAG_USER) {
		continue;
	    }
	    if (snmp_oid_equal(&vb1->name, &vb2->name)) {
		return 1;
	    }
	}
    }

    return 0;
}


/*
 * Compare two time stamps. This function returns a value less than 0
 * if a < b, the value 0 if a == b, and a value > 0 if a > b.
 */

static inline int
snmp_timestamp_compare(uint32_t a_sec, uint32_t a_usec,
		       uint32_t b_sec, uint32_t b_usec)
{
    if (a_sec < b_sec) {
	return -1;
    }

    if (a_sec > b_sec) {
	return 1;
    }
    
    if (a_sec == b_sec) {
	if (a_usec < b_usec) {
	    return -1;
	}
	if (a_usec < b_usec) {
	    return 1;
	}
    }

    return 0;
}

/*
 * Add a new packet to the cache of recently seen packets.
 */

static snmp_cache_elem_t*
snmp_cache_add(snmp_cache_elem_t *list, snmp_packet_t *pkt)
{
    snmp_cache_elem_t *p;

    p = xmalloc(sizeof(snmp_cache_elem_t));
    p->pkt = snmp_pkt_copy(pkt);
    p->next = list;
    return p;
}

/*
 * Remove all elements from the cache list that are older than the
 * given time stamp. Since we add new packets at the front of the
 * list, we basically have to traverse the list until we find old
 * packets and then we can discard the tail. Perhaps a smarter data
 * structure should be used to scale to very bursty SNMP traces...
 */

static snmp_cache_elem_t*
snmp_cache_expire(snmp_cache_elem_t *list,
		  uint32_t ts_sec, uint32_t ts_usec)
{
    snmp_cache_elem_t *p = list, *l = NULL, *x;
    
    while (p) {
	if (snmp_timestamp_compare(p->pkt->time_sec.value,
				   p->pkt->time_usec.value,
				   ts_sec, ts_usec) < 0) {
	    x = p;
	    if (l) {
		l->next = p->next;
	    } else {
		list = p->next;
	    }
	    p = p->next;
	    if (x->pkt) {
		snmp_pkt_delete(x->pkt);
		x->pkt = NULL;
	    }
	    free(x);
	} else {
	    l = p; p = p->next;
	}
    }

    return list;
}

/*
 * For a given packet pkt, find a suitable matching packet in the
 * cache.
 */

static snmp_cache_elem_t*
snmp_cache_find(snmp_cache_elem_t *list, snmp_packet_t *pkt)
{
    snmp_cache_elem_t *p;

    for (p = list; p; p = p->next) {
	if (snmp_int32_equal(&p->pkt->snmp.scoped_pdu.pdu.req_id,
			     &pkt->snmp.scoped_pdu.pdu.req_id)
	    
	    /* xxx what about ipv6 addresses ??? */
	    
	    /* xxx if I comment out the first ip address check, things
	     * behave very strange; we loose packets in unknown (kind
	     * of expected, but they do not show up elsewhere and in
	     * addition I saw an empty line in the unknown file and I
	     * have no clue where this is coming from; furthermore
	     * runtime seems to increase significantly xxx */
	    
	    && snmp_ipaddr_equal(&p->pkt->dst_addr, &pkt->src_addr)
	    && snmp_uint32_equal(&p->pkt->dst_port, &pkt->src_port)
	    && snmp_ipaddr_equal(&p->pkt->src_addr, &pkt->dst_addr)
  	    && snmp_uint32_equal(&p->pkt->src_port, &pkt->dst_port)) {
	    return p;
	}
    }

    return NULL;
}

static inline int
snmp_flow_type(snmp_packet_t *pkt)
{
    int type = SNMP_FLOW_NONE;
    
    if (! pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	return SNMP_FLOW_NONE;
    }

    switch (pkt->snmp.scoped_pdu.pdu.type) {
    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
    case SNMP_PDU_GETBULK:
    case SNMP_PDU_SET:
	type = SNMP_FLOW_COMMAND;
	break;
    case SNMP_PDU_RESPONSE:
	type = SNMP_FLOW_NONE;
	break;
    case SNMP_PDU_TRAP1:
    case SNMP_PDU_TRAP2:
    case SNMP_PDU_INFORM:
	type = SNMP_FLOW_NOTIFY;
	break;
    case SNMP_PDU_REPORT:
	type = SNMP_FLOW_NONE;
	break;
    }

    return type;
}

static inline int
snmp_slice_type(snmp_packet_t *pkt)
{
    int type = SNMP_SLICE_NONE;
    
    if (! pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	return SNMP_SLICE_NONE;
    }

    switch (pkt->snmp.scoped_pdu.pdu.type) {
    case SNMP_PDU_GET:
	type = SNMP_SLICE_GET;
	break;
    case SNMP_PDU_GETNEXT:
	type = SNMP_SLICE_GETNEXT;
	break;
    case SNMP_PDU_GETBULK:
	type = SNMP_SLICE_GETBULK;
	break;
    case SNMP_PDU_SET:
	type = SNMP_SLICE_SET;
	break;
    case SNMP_PDU_RESPONSE:
	type = SNMP_FLOW_NONE;
	break;
    case SNMP_PDU_TRAP1:
    case SNMP_PDU_TRAP2:
	type = SNMP_SLICE_TRAP;
	break;
    case SNMP_PDU_INFORM:
	type = SNMP_SLICE_INFORM;
	break;
    case SNMP_PDU_REPORT:
	type = SNMP_FLOW_NONE;
	break;
    }

    return type;
}

/*
 * Find a flow, potentially creating new flows if a flow does not yet
 * exist.
 */

static snmp_flow_t*
snmp_flow_find(snmp_packet_t *pkt)
{
    snmp_flow_t *p;
    snmp_cache_elem_t *e;
    int flow_type;
    int reverse = 0;

    flow_type = snmp_flow_type(pkt);

    /*
     * If we have a report or a response, we try to find the
     * corresponding request in the list of recently seen requests. If
     * we find the request, we can set the flow type. If we are
     * unsuccessful, we return that we were unable to identify the
     * flow to which this packet belongs.
     */

    if (flow_type == SNMP_FLOW_NONE) {
	e = snmp_cache_find(snmp_cache_list, pkt);
	if (e && e->pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	    flow_type = snmp_flow_type(e->pkt);
	    reverse = 1;
	}
    }

    if (flow_type == SNMP_FLOW_NONE) {
	return NULL;
    }

    /*
     * Now we know the flow type. Lookup a flow entry or create a new
     * one if there is no appropriate flow entry yet.
     */

    for (p = flow_list; p; p = p->next) {
	if (p->type == flow_type
	    && snmp_ipaddr_equal(&p->src_addr,
				 reverse ? &pkt->dst_addr : &pkt->src_addr)
	    && snmp_ipaddr_equal(&p->dst_addr,
				 reverse ? &pkt->src_addr : &pkt->dst_addr)) {
	    break;
	}
	if (p->type == flow_type
	    && snmp_ip6addr_equal(&p->src_addr6,
				  reverse ? &pkt->dst_addr6 : &pkt->src_addr6)
	    && snmp_ip6addr_equal(&p->dst_addr6,
				  reverse ? &pkt->src_addr6 : &pkt->dst_addr6)) {
	    break;
	}
    }

    if (! p) {
	p = xmalloc(sizeof(snmp_flow_t));
	p->id = flow_id++;
	p->type = flow_type;
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
	memcpy(&p->src_port, &pkt->src_port, sizeof(p->src_port));
	memcpy(&p->dst_port, &pkt->dst_port, sizeof(p->dst_port));
	p->name = snmp_flow_name(p);
	p->next = flow_list;
	flow_list = p;
    }
    
    return p;
}

/*
 * Find a slice, potentially creating new slices if a slice does not
 * yet exist.
 */

static snmp_slice_t*
snmp_slice_find(snmp_packet_t *pkt)
{
    snmp_slice_t *p;
    snmp_cache_elem_t *e = NULL;
    int slice_type;
    int reverse = 0;

    slice_type = snmp_slice_type(pkt);

    /*
     * If we have a report or a response, we try to find the
     * corresponding request in the list of recently seen requests. If
     * we find the request, we can set the flow type. If we are
     * unsuccessful, we return that we were unable to identify the
     * flow to which this packet belongs.
     */

    if (slice_type == SNMP_FLOW_NONE) {
	e = snmp_cache_find(snmp_cache_list, pkt);
	if (e && e->pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	    slice_type = snmp_slice_type(e->pkt);
	    reverse = 1;
	}
    }

    if (slice_type == SNMP_FLOW_NONE) {
	return NULL;
    }

    /*
     * Now we know the slice type. Lookup a slice entry or create a new
     * one if there is no appropriate slice entry yet.
     */

    for (p = slice_list; p; p = p->next) {

	if (p->type != slice_type) continue;

	if (p->src_addr.attr.flags & SNMP_FLAG_VALUE
	    && p->src_port.attr.flags & SNMP_FLAG_VALUE
	    && p->dst_addr.attr.flags & SNMP_FLAG_VALUE
	    && p->dst_port.attr.flags & SNMP_FLAG_VALUE) {
	    if (! snmp_ipaddr_equal(&p->src_addr,
				    reverse ? &pkt->dst_addr : &pkt->src_addr) ||
		! snmp_uint32_equal(&p->src_port,
				    reverse ? &pkt->dst_port : &pkt->src_port) ||
		! snmp_ipaddr_equal(&p->dst_addr,
				    reverse ? &pkt->src_addr : &pkt->dst_addr) ||
		! snmp_uint32_equal(&p->dst_port,
				    reverse ? &pkt->src_port : &pkt->dst_port)) {
		continue;
	    }
	} else if (p->src_addr6.attr.flags & SNMP_FLAG_VALUE
		   && p->src_port.attr.flags & SNMP_FLAG_VALUE
		   && p->dst_addr6.attr.flags & SNMP_FLAG_VALUE
		   && p->dst_port.attr.flags & SNMP_FLAG_VALUE) {
	    if (! snmp_ip6addr_equal(&p->src_addr6,
				     reverse ? &pkt->dst_addr6 : &pkt->src_addr6) ||
		! snmp_uint32_equal(&p->src_port,
				    reverse ? &pkt->dst_port : &pkt->src_port) ||
		! snmp_ip6addr_equal(&p->dst_addr6,
				     reverse ? &pkt->src_addr6 : &pkt->dst_addr6) ||
		! snmp_uint32_equal(&p->dst_port,
				    reverse ? &pkt->src_port : &pkt->dst_port)) {
		continue;
	    }
	} else {
	    continue;
	}

#if 0
	fprintf(stderr, "\n(current, first, last_response):\n");
	snmp_csv_write_stream_pkt(stderr, pkt);
	snmp_csv_write_stream_pkt(stderr, p->pkt);
	snmp_csv_write_stream_pkt(stderr, p->last_response);
#endif
	    
	if (slice_type == SNMP_SLICE_GET ||
	    slice_type == SNMP_SLICE_SET ||
	    slice_type == SNMP_SLICE_TRAP ||
	    slice_type == SNMP_SLICE_INFORM) {
	    if (! e && ! snmp_vbl_cmp_names(pkt, p->pkt)) {
		continue;
	    }
	}

	if (slice_type == SNMP_SLICE_GETNEXT ||
	    slice_type == SNMP_SLICE_GETBULK) {
	    if (! e
		&& p->last_response
		&& ! snmp_vbl_lnk_names(pkt, p->last_response)) {
		continue;
	    }
	}

	break;
    }

    if (! p) {
	p = xmalloc(sizeof(snmp_slice_t));
	p->id = slice_id++;
	p->type = slice_type;
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
	memcpy(&p->src_port, &pkt->src_port, sizeof(p->src_port));
	memcpy(&p->dst_port, &pkt->dst_port, sizeof(p->dst_port));
	p->name = snmp_slice_name(p);
	p->pkt = snmp_pkt_copy(pkt);
	p->last_response = NULL;
	p->next = slice_list;
	slice_list = p;
    }

    if (e) {
	if (p->last_response) {
	    snmp_pkt_delete(p->last_response);
	}
	p->last_response = snmp_pkt_copy(pkt);
    }
    
    return p;
}

/*
 * Helper function to open a flow file with a nice extension.
 */

static FILE*
snmp_flow_open_stream(snmp_flow_t *flow, snmp_write_t *out, const char *mode)
{
#define MAX_FILENAME_SIZE 4096
    char filename[MAX_FILENAME_SIZE];
    FILE *stream;

    snprintf(filename, MAX_FILENAME_SIZE, "%s%s%s%s%s.%s",
	     out->path ? out->path : "",
	     out->path ? "/" : "",
	     out->prefix ? out->prefix : "",
	     out->prefix ? "-" : "",
	     flow->name,
	     out->ext ? out->ext : "");
    stream = fopen(filename, mode);
    if (! stream) {
	fprintf(stderr, "%s: failed to open flow file %s: %s\n",
		progname, filename, strerror(errno));
    }
    return stream;
}

/*
 * Helper function to close a flow file stream. Any stream errors that
 * might have occured are reported to stderr.
 */

static void
snmp_flow_close_stream(snmp_flow_t *flow)
{
    if (flow && flow->stream) {
	if (fflush(flow->stream) || ferror(flow->stream)) {
	    fprintf(stderr, "%s: error on flow stream %s: %s\n",
		    progname, flow->name, strerror(errno));
	}
	fclose(flow->stream);
	flow->stream = NULL;
    }
}

/*
 * Helper function to open a slice file with a nice extension.
 */

static FILE*
snmp_slice_open_stream(snmp_slice_t *slice, snmp_write_t *out, const char *mode)
{
#define MAX_FILENAME_SIZE 4096
    char filename[MAX_FILENAME_SIZE];
    FILE *stream;

    snprintf(filename, MAX_FILENAME_SIZE, "%s%s%s%s%s.%s",
	     out->path ? out->path : "",
	     out->path ? "/" : "",
	     out->prefix ? out->prefix : "",
	     out->prefix ? "-" : "",
	     slice->name,
	     out->ext ? out->ext : "");
    stream = fopen(filename, mode);
    if (! stream) {
	fprintf(stderr, "%s: failed to open slice file %s: %s\n",
		progname, filename, strerror(errno));
    }
    return stream;
}

/*
 * Helper function to close a slice file stream. Any stream errors that
 * might have occured are reported to stderr.
 */

static void
snmp_slice_close_stream(snmp_slice_t *slice)
{
    if (slice && slice->stream) {
	if (fflush(slice->stream) || ferror(slice->stream)) {
	    fprintf(stderr, "%s: error on slice stream %s: %s\n",
		    progname, slice->name, strerror(errno));
	}
	fclose(slice->stream);
	slice->stream = NULL;
    }
}

/*
 * We keep an LRU cache of open flows to reduce the number of open()
 * close() system calls.
 */

static snmp_flow_t **open_flow_cache = NULL;
static int open_flow_cache_size = 0;
static int cnt = 0;

static void
open_flow_cache_init()
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
	fprintf(stderr,
		"%s: getrlimit() failed: unable to allocate open flow cache\n",
		progname);
	exit(1);
    }
    
    if (rl.rlim_max == RLIM_INFINITY) {
	open_flow_cache_size = 1024;		/* pretend to be like Linux */
    } else if (rl.rlim_max > 8) {		/* arbitrary safety margin */
	open_flow_cache_size = rl.rlim_max - 8;
    } else {
	fprintf(stderr, "%s: not enough open file descriptors left\n",
		progname);
	exit(1);
    }

    open_flow_cache = xmalloc(sizeof(snmp_flow_t*) * open_flow_cache_size);
}

static void
open_flow_cache_update(snmp_packet_t *pkt)
{
    if (cnt == 0) {
	open_flow_cache_init();
    }

    cnt++;

    if (! (cnt % 1024)) {
	snmp_cache_list = snmp_cache_expire(snmp_cache_list,
					    pkt->time_sec.value - 300,
					    pkt->time_usec.value);
    }
}

#if 0
static void
open_flow_cache_print()
{
    int i;

    for (i = 0; i < open_flow_cache_size; i++) {
	fprintf(stderr, "%3d: %s\n", i,
		open_flow_cache[i] ? open_flow_cache[i]->name : "");
    }
}
#endif

static void
open_flow_cache_add(snmp_flow_t *flow)
{
    int i, j;
    snmp_flow_t *tmp;

    for (i = 0; i < open_flow_cache_size; i++) {
	if (open_flow_cache[i] == flow) {
	    break;
	}
	if (!open_flow_cache[i]) {
	    i = open_flow_cache_size;
	    break;
	}
    }

    /* The current flow is on the top - don't bother any further... */

    if (i == 0) {
	if (! open_flow_cache[0]) {
	    open_flow_cache[0] = flow;
	}
	return;
    }

    /* Flow not found in the cache, so close the last flow and assign
       the new flow to it... */
    
    if (i == open_flow_cache_size) {
	i--;
	if (open_flow_cache[i]) {
	    snmp_flow_close_stream(open_flow_cache[i]);
	}
	open_flow_cache[i] = flow;
    }

    /* Move the flow to the top... */

    tmp = open_flow_cache[i];
    for (j = i; j > 0; j--) {
	open_flow_cache[j] = open_flow_cache[j-1];
    }
    open_flow_cache[0] = tmp;
}

static void
open_flow_cache_reset()
{
    if (open_flow_cache) {
	free(open_flow_cache);
	open_flow_cache = NULL;
	open_flow_cache_size = 0;
	cnt = 0;
    }
}

/*
 * Below are the flow interface functions as defined in snmp.h, namely
 * the initializing function, the per packet write functions, and the
 * finalizing function.
 */

void
snmp_flow_init(snmp_write_t *out)
{
    flow_id = 0;
}

void
snmp_flow_write(snmp_write_t *out, snmp_packet_t *pkt)
{
    snmp_flow_t *flow;

    open_flow_cache_update(pkt);
    
    flow = snmp_flow_find(pkt);
    if (flow && flow->name) {
	if (! flow->stream) {
	    flow->stream = snmp_flow_open_stream(flow, out,
						 (flow->cnt == 0) ? "w" : "a");
	}
	if (flow->stream) {
	    if (flow->cnt == 0 && out->write_new) {
		out->write_new(flow->stream);
	    }
	    if (out->write_pkt) {
		out->write_pkt(flow->stream, pkt);
	    }
	    flow->cnt++;
	    if (pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP1
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP2
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE) {
		snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
	    }
	    open_flow_cache_add(flow);
	    return;
	}
    }

    /*
     * xxx shall we cache these packets since the request might still
     * be coming? xxx
     */

    if (out->stream && out->write_pkt) {
	out->write_pkt(out->stream, pkt);
    }
    snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
}

void
snmp_flow_done(snmp_write_t *out)
{
    snmp_flow_t *p, *q;

    for (p = flow_list; p; ) {
	if (p->name) {
	    if (! p->stream) {
		p->stream = snmp_flow_open_stream(p, out, "a");
	    }
	    if (p->stream) {
		if (out->write_end) {
		    out->write_end(p->stream);
		}
		snmp_flow_close_stream(p);
	    }
	    free(p->name);
	}
	q = p->next;
	free(p);
	p = q;
    }

    open_flow_cache_reset();
}

/*
 * Below are the slice interface functions as defined in snmp.h, namely
 * the initializing function, the per packet write functions, and the
 * finalizing function.
 */

void
snmp_slice_init(snmp_write_t *out)
{
    slice_id = 0;
}

void
snmp_slice_write(snmp_write_t *out, snmp_packet_t *pkt)
{
    snmp_slice_t *slice;

    open_flow_cache_update(pkt);

    slice = snmp_slice_find(pkt);
    if (slice && slice->name) {
	if (! slice->stream) {
	    slice->stream = snmp_slice_open_stream(slice, out,
						   (slice->cnt == 0) ? "w" : "a");
	}
	if (slice->stream) {
	    if (slice->cnt == 0 && out->write_new) {
		out->write_new(slice->stream);
	    }
	    if (out->write_pkt) {
		out->write_pkt(slice->stream, pkt);
	    }
	    slice->cnt++;
	    if (pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP1
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_TRAP2
		&& pkt->snmp.scoped_pdu.pdu.type != SNMP_PDU_RESPONSE) {
		snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
	    }
#if 0
	    open_flow_cache_add(flow);
#endif
	    return;
	}
    }

    /*
     * xxx shall we cache these packets since the request might still
     * be coming? xxx
     */

    if (out->stream && out->write_pkt) {
	out->write_pkt(out->stream, pkt);
    }
    snmp_cache_list = snmp_cache_add(snmp_cache_list, pkt);
}

void
snmp_slice_done(snmp_write_t *out)
{
    snmp_slice_t *p, *q;

    for (p = slice_list; p; ) {
	if (p->name) {
	    if (! p->stream) {
		p->stream = snmp_slice_open_stream(p, out, "a");
	    }
	    if (p->stream) {
		if (out->write_end) {
		    out->write_end(p->stream);
		}
		snmp_slice_close_stream(p);
	    }
	    free(p->name);
	    snmp_pkt_delete(p->pkt);
	}
	q = p->next;
	free(p);
	p = q;
    }

    open_flow_cache_reset();
}
