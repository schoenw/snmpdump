/*
 * csv-write.c --
 *
 * Serialize the most important information about an SNMP packet into
 * as comma separated values (CSV). The format is specified in the
 * measure.txt documentation.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#include "snmp.h"

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char sep = ',';

static void
csv_write_null(FILE *stream, snmp_null_t *v, const char *tag)
{
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%s", sep, tag ? tag : "");
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_int32(FILE *stream, snmp_int32_t *v)
{
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%"PRId32, sep, v->value);
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_uint32(FILE *stream, snmp_uint32_t *v)
{
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%"PRIu32, sep, v->value);
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_uint64(FILE *stream, snmp_uint64_t *v)
{
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c%"PRIu64, sep, v->value);
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_ipaddr(FILE *stream, snmp_ipaddr_t *v)
{
    char buffer[INET_ADDRSTRLEN];

    if (v->attr.flags & SNMP_FLAG_VALUE
	&& inet_ntop(AF_INET, &v->value, buffer, sizeof(buffer))) {
	fprintf(stream, "%c%s", sep, buffer);
    } else {
	fprintf(stream, "%c", sep);
    }
}


static void
csv_write_ip6addr(FILE *stream, snmp_ip6addr_t *v)
{
    char buffer[INET6_ADDRSTRLEN];

    if (v->attr.flags & SNMP_FLAG_VALUE
	&& inet_ntop(AF_INET6, &v->value, buffer, sizeof(buffer))) {
	fprintf(stream, "%c%s", sep, buffer);
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_octs(FILE *stream, snmp_octs_t *v)
{
    int i;
    
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%c", sep);
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%.2x", v->value[i]);
	}
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_oid(FILE *stream, snmp_oid_t *v)
{
    int i;
    
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%c%"PRIu32, (i == 0) ? sep : '.', v->value[i]);
	}
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_type(FILE *stream, int type, snmp_attr_t  *attr)
{
    const char *name = NULL;
    
    if (attr->flags & SNMP_FLAG_VALUE) {
	switch (type) {
	case SNMP_PDU_GET:
	    name = "get-request";
	    break;
	case SNMP_PDU_GETNEXT:
	    name = "get-next-request";
	    break;
	case SNMP_PDU_GETBULK:
	    name = "get-bulk-request";
	    break;
	case SNMP_PDU_SET:
	    name = "set-request";
	    break;
	case SNMP_PDU_RESPONSE:
	    name = "response";
	    break;
	case SNMP_PDU_TRAP1:
	    name = "trap";
	    break;
	case SNMP_PDU_TRAP2:
	    name = "trap2";
	    break;
	case SNMP_PDU_INFORM:
	    name = "inform";
	    break;
	case SNMP_PDU_REPORT:
	    name = "report";
	    break;
	}
	fprintf(stream, "%c%s", sep, name ? name : "");
    } else {
	fprintf(stream, "%c", sep);
    }
}

static void
csv_write_varbind(FILE *stream, snmp_varbind_t *varbind)
{
    if (varbind->attr.flags & SNMP_FLAG_VALUE) {
	csv_write_oid(stream, &varbind->name);
	switch(varbind->type) {
	case SNMP_TYPE_NULL:
	    csv_write_null(stream, &varbind->value.null, NULL);
	    break;
	case SNMP_TYPE_INT32:
	    csv_write_int32(stream, &varbind->value.i32);
	    break;
	case SNMP_TYPE_UINT32:
	    csv_write_uint32(stream, &varbind->value.u32);
	    break;
	case SNMP_TYPE_UINT64:
	    csv_write_uint64(stream, &varbind->value.u64);
	    break;
	case SNMP_TYPE_IPADDR:
	    csv_write_ipaddr(stream, &varbind->value.ip);
	    break;
	case SNMP_TYPE_OCTS:
	    csv_write_octs(stream, &varbind->value.octs);
	    break;
	case SNMP_TYPE_OID:
	    csv_write_oid(stream, &varbind->value.oid);
	    break;
	case SNMP_TYPE_NO_SUCH_OBJ:	/* xxx */
	    csv_write_null(stream, &varbind->value.null, "no-such-object");
	    break;
	case SNMP_TYPE_NO_SUCH_INST:	/* xxx */
	    csv_write_null(stream, &varbind->value.null, "no-such-instance");
	    break;
	case SNMP_TYPE_END_MIB_VIEW:	/* xxx */
	    csv_write_null(stream, &varbind->value.null, "end-of-mib-view");
	    break;
	default:
	    /* xxx */
	    break;
	}
    } else {
	fprintf(stream, "%c%c", sep, sep);
    }
}

static void
csv_write_varbind_list(FILE *stream, snmp_var_bindings_t *varbindlist)
{
    snmp_varbind_t *vb;

    if (varbindlist->attr.flags & SNMP_FLAG_VALUE) {
	for (vb = varbindlist->varbind; vb; vb = vb->next) {
	    csv_write_varbind(stream, vb);
	}
    }
}

static void
csv_write_varbind_list_count(FILE *stream, snmp_var_bindings_t *varbindlist)
{
    snmp_varbind_t *vb;
    int c = 0;

    if (varbindlist->attr.flags & SNMP_FLAG_VALUE) {
	for (vb = varbindlist->varbind; vb; vb = vb->next, c++) ;
	fprintf(stream, "%c%d", sep, c);
    } else {
	fprintf(stream, "%c", sep);
    }
}

void
snmp_csv_write_stream(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;

    fprintf(stream, "%u.%06u", pkt->time_sec.value, pkt->time_usec.value);

    if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_write_ipaddr(stream, &pkt->src_addr);
    } else {
	csv_write_ip6addr(stream, &pkt->src_addr6);
    }
    csv_write_uint32(stream, &pkt->src_port);
    if (pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_write_ipaddr(stream, &pkt->dst_addr);
    } else {
	csv_write_ip6addr(stream, &pkt->dst_addr6);
    }
    csv_write_uint32(stream, &pkt->dst_port);

    if (pkt->snmp.attr.flags & SNMP_FLAG_BLEN) {
	fprintf(stream, "%c%d", sep, pkt->snmp.attr.blen);
    } else {
	fprintf(stream, "%c", sep);
    }

    if (pkt->snmp.attr.flags & SNMP_FLAG_VALUE) {
	csv_write_int32(stream, &pkt->snmp.version);
	
	csv_write_type(stream, pkt->snmp.scoped_pdu.pdu.type,
		       &pkt->snmp.scoped_pdu.pdu.attr);
	
	csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.req_id);
	
	csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.err_status);
	
	csv_write_int32(stream, &pkt->snmp.scoped_pdu.pdu.err_index);
	
	csv_write_varbind_list_count(stream,
				     &pkt->snmp.scoped_pdu.pdu.varbindings);
	
	csv_write_varbind_list(stream, &pkt->snmp.scoped_pdu.pdu.varbindings);
    }

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
