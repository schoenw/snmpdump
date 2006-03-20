/*
 * xml-write.c --
 *
 * Serialize an SNMP packet into an XML representation conforming to
 * the snmptrace RNC schema that can be found in the documentation.
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


static void
xml_write_addr(FILE *stream, char *name, struct sockaddr *addr,
	       int show_addr, int show_port)
{
    struct sockaddr_in *sinv4;
    
    switch (addr->sa_family) {
    case AF_INET:
	sinv4 = (struct sockaddr_in *) addr;
	fprintf(stream, "<%s", name);
	if (show_addr) {
	    fprintf(stream, " ip=\"%s\"", inet_ntoa(sinv4->sin_addr));
	}
	if (show_port) {
	    fprintf(stream, " port=\"%d\"", sinv4->sin_port);
	}
	fprintf(stream, "/>");
	break;
    default:
	break;
    }
}


static void
xml_write_attr(FILE *stream, snmp_attr_t *attr)
{
    if (attr->flags & SNMP_FLAG_BLEN) {
	fprintf(stream, " blen=\"%d\"", attr->blen);
    }
    if (attr->flags & SNMP_FLAG_VLEN) {
	fprintf(stream, " vlen=\"%d\"", attr->vlen);
    }
}


static void
xml_write_open(FILE *stream, char *name, snmp_attr_t *attr)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, attr);
    fprintf(stream, ">");
}


static void
xml_write_close(FILE *stream, char *name)
{
    fprintf(stream, "</%s>", name);
}


static void
xml_write_null(FILE *stream, char *name, snmp_null_t *v)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, "/>");
}


static void
xml_write_int32(FILE *stream, char *name, snmp_int32_t *v)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRId32, v->value);
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_uint32(FILE *stream, char *name, snmp_uint32_t *v)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRIu32, v->value);
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_uint64(FILE *stream, char *name, snmp_uint64_t *v)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRIu64, v->value);
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_ipaddr(FILE *stream, char *name, snmp_ipaddr_t *v)
{
    char buffer[20];

    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	if (inet_ntop(AF_INET, &v->value, buffer, sizeof(buffer))) {
	    fprintf(stream, "%s", buffer);
	}
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_octs(FILE *stream, char *name, snmp_octs_t *v)
{
    int i;

    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%.2x", v->value[i]);
	}
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_oid(FILE *stream, char *name, snmp_oid_t *v)
{
    int i;

    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &v->attr);
    fprintf(stream, ">");
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%s%"PRIu32, (i == 0) ? "" : ".", v->value[i]);
	}
    }
    fprintf(stream, "</%s>", name);
}


static void
xml_write_varbind(FILE *stream, snmp_varbind_t *varbind)
{
    char *name = "varbind";
    
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, &varbind->attr);
    fprintf(stream, ">");
    xml_write_oid(stream, "name", &varbind->name);
    switch (varbind->type) {
    case SNMP_TYPE_NULL:
	xml_write_null(stream, "null", &varbind->value.null);
	break;
    case SNMP_TYPE_INT32:
	xml_write_int32(stream, "integer32", &varbind->value.i32);
	break;
    case SNMP_TYPE_UINT32:
	xml_write_uint32(stream, "unsigned32", &varbind->value.u32);
	break;
    case SNMP_TYPE_UINT64:
	xml_write_uint64(stream, "unsigned64", &varbind->value.u64);
	break;
    case SNMP_TYPE_IPADDR:
	xml_write_ipaddr(stream, "ipaddress", &varbind->value.ip);
	break;
    case SNMP_TYPE_OCTS:
	xml_write_octs(stream, "octet-string", &varbind->value.octs);
	break;
    case SNMP_TYPE_OID:
	xml_write_oid(stream, "object-identifier", &varbind->value.oid);
	break;
    case SNMP_TYPE_NO_SUCH_OBJ:
	xml_write_null(stream, "no-such-object", &varbind->value.null);
	break;
    case SNMP_TYPE_NO_SUCH_INST:
	xml_write_null(stream, "no-such-instance", &varbind->value.null);
	break;
    case SNMP_TYPE_END_MIB_VIEW:
	xml_write_null(stream, "end-of-mib-view", &varbind->value.null);
	break;
    default:
	/* xxx */
	break;
    }
    
    fprintf(stream, "</%s>", name);
}


static void
xml_write_varbindlist(FILE *stream, snmp_var_bindings_t *varbindlist)
{
    snmp_varbind_t *vb;
    
    fprintf(stream, "<variable-bindings");
    xml_write_attr(stream, &varbindlist->attr);
    fprintf(stream, ">");

    for (vb = varbindlist->varbind; vb; vb = vb->next) {
	xml_write_varbind(stream, vb);
    }
    
    fprintf(stream, "</variable-bindings>");
}


static void
xml_write_pdu(FILE *stream, snmp_pdu_t *pdu)
{
    char *name = NULL;
    
    if (pdu->attr.flags & SNMP_FLAG_VALUE) {
	switch (pdu->type) {
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
    }
    
    xml_write_open(stream, name, &pdu->attr);

    xml_write_int32(stream, "request-id", &pdu->req_id);
    xml_write_int32(stream, "error-status", &pdu->err_status);
    xml_write_int32(stream, "error-index", &pdu->err_index);
    xml_write_varbindlist(stream, &pdu->varbindings);

    xml_write_close(stream, name);
}


static void
xml_write_msg(FILE *stream, snmp_msg_t *msg)
{
    xml_write_open(stream, "snmp", &msg->attr);
    
    xml_write_int32(stream, "version", &msg->version);
    
    switch (msg->version.value) {
    case 0:
    case 1:
	xml_write_octs(stream, "community", &msg->community);
	xml_write_pdu(stream, &msg->scoped_pdu.pdu);
	break;
    case 3:
	break;
    default:
	break;
    }

    xml_write_close(stream, "snmp");
}


void
snmp_xml_write_stream(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;
    
    fprintf(stream, "<packet sec=\"%lu\" usec=\"%lu\">",
	    pkt->time.tv_sec, pkt->time.tv_usec);

    xml_write_addr(stream, "src", (struct sockaddr *) &pkt->src,
		   pkt->attr.flags & SNMP_FLAG_SADDR,
		   pkt->attr.flags & SNMP_FLAG_SPORT);
    xml_write_addr(stream, "dst", (struct sockaddr *) &pkt->dst,
		   pkt->attr.flags & SNMP_FLAG_DADDR,
		   pkt->attr.flags & SNMP_FLAG_DPORT);

    xml_write_msg(stream, &pkt->msg);

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
