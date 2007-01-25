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


static inline void
xml_write_attr(FILE *stream, snmp_attr_t *attr)
{
    if (attr->flags & SNMP_FLAG_BLEN) {
	fprintf(stream, " blen=\"%d\"", attr->blen);
    }
    if (attr->flags & SNMP_FLAG_VLEN) {
	fprintf(stream, " vlen=\"%d\"", attr->vlen);
    }
}


static inline void
xml_write_open(FILE *stream, const char *name, snmp_attr_t *attr)
{
    fprintf(stream, "<%s", name);
    xml_write_attr(stream, attr);
    fprintf(stream, ">");
}


static inline void
xml_write_close(FILE *stream, const char *name)
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
xml_write_int32(FILE *stream, const char *name, snmp_int32_t *v)
{
    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRId32, v->value);
    }
    xml_write_close(stream, name);
}


static void
xml_write_uint32(FILE *stream, const char *name, snmp_uint32_t *v)
{
    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRIu32, v->value);
    }
    xml_write_close(stream, name);
}


static void
xml_write_uint64(FILE *stream, const char *name, snmp_uint64_t *v)
{
    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	fprintf(stream, "%"PRIu64, v->value);
    }
    xml_write_close(stream, name);
}


static void
xml_write_ipaddr(FILE *stream, const char *name, snmp_ipaddr_t *v)
{
    char buffer[INET_ADDRSTRLEN];

    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	if (inet_ntop(AF_INET, &v->value, buffer, sizeof(buffer))) {
	    fprintf(stream, "%s", buffer);
	}
    }
    xml_write_close(stream, name);
}


static void
xml_write_ip6addr(FILE *stream, const char *name, snmp_ip6addr_t *v)
{
    char buffer[INET6_ADDRSTRLEN];

    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	if (inet_ntop(AF_INET6, &v->value, buffer, sizeof(buffer))) {
	    fprintf(stream, "%s", buffer);
	}
    }
    xml_write_close(stream, name);
}


static void
xml_write_octs(FILE *stream, const char *name, snmp_octs_t *v)
{
    int i;

    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%.2x", v->value[i]);
	}
    }
    xml_write_close(stream, name);
}


static void
xml_write_oid(FILE *stream, const char *name, snmp_oid_t *v)
{
    int i;

    xml_write_open(stream, name, &v->attr);
    if (v->attr.flags & SNMP_FLAG_VALUE) {
	for (i = 0; i < v->len; i++) {
	    fprintf(stream, "%s%"PRIu32, (i == 0) ? "" : ".", v->value[i]);
	}
    }
    xml_write_close(stream, name);
}


static void
xml_write_varbind(FILE *stream, snmp_varbind_t *varbind)
{
    char *name = "varbind";
    
    xml_write_open(stream, name, &varbind->attr);
    
    if (varbind->name.attr.flags) { /* don't write an empty name tag */
	xml_write_oid(stream, "name", &varbind->name);
    }

    if (varbind->attr.flags & SNMP_FLAG_VALUE) {
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
    }
    
    xml_write_close(stream, name);
}


static void
xml_write_varbindlist(FILE *stream, snmp_var_bindings_t *varbindlist)
{
    const char *name = "variable-bindings";
    snmp_varbind_t *vb;

    xml_write_open(stream, name, &varbindlist->attr);
    if (varbindlist->attr.flags & SNMP_FLAG_VALUE) {
	for (vb = varbindlist->varbind; vb; vb = vb->next) {
	    xml_write_varbind(stream, vb);
	}
    }
    xml_write_close(stream, name);
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
xml_write_trap(FILE *stream, snmp_pdu_t *pdu)
{
    const char *name = "trap";
    
    xml_write_open(stream, name, &pdu->attr);
    xml_write_oid(stream, "enterprise", &pdu->enterprise);
    xml_write_ipaddr(stream, "agent-addr", &pdu->agent_addr);
    xml_write_int32(stream, "generic-trap", &pdu->generic_trap);
    xml_write_int32(stream, "specific-trap", &pdu->specific_trap);
    xml_write_int32(stream, "time-stamp", &pdu->time_stamp);
    xml_write_varbindlist(stream, &pdu->varbindings);
    xml_write_close(stream, name);
}


static void
xml_write_scoped_pdu(FILE *stream, snmp_scoped_pdu_t *scoped_pdu)
{
    const char *name = "scoped-pdu";
    
    xml_write_open(stream, name, &scoped_pdu->attr);
    if (scoped_pdu->attr.flags & SNMP_FLAG_VALUE) {
	xml_write_octs(stream, "context-engine-id",
		       &scoped_pdu->context_engine_id);
	xml_write_octs(stream, "context-name",
		       &scoped_pdu->context_name);
	xml_write_pdu(stream, &scoped_pdu->pdu);
    }
    xml_write_close(stream, name);
}


static void
xml_write_usm(FILE *stream, snmp_usm_t *usm)
{
    const char *name = "usm";

    xml_write_open(stream, name, &usm->attr);
    if (usm->attr.flags & SNMP_FLAG_VALUE) {
	xml_write_octs(stream, "auth-engine-id", &usm->auth_engine_id);
	xml_write_uint32(stream, "auth-engine-boots", &usm->auth_engine_boots);
	xml_write_uint32(stream, "auth-engine-time", &usm->auth_engine_time);
	xml_write_octs(stream, "user", &usm->user);
	xml_write_octs(stream, "auth-params", &usm->auth_params);
	xml_write_octs(stream, "priv-params", &usm->priv_params);
    }
    xml_write_close(stream, name);
}


static void
xml_write_message(FILE *stream, snmp_msg_t *msg)
{
    const char *name = "message";

    xml_write_open(stream, name, &msg->attr);
    if (msg->attr.flags & SNMP_FLAG_VALUE) {
	xml_write_uint32(stream, "msg-id", &msg->msg_id);
	xml_write_uint32(stream, "max-size", &msg->msg_max_size);
	xml_write_octs(stream, "flags", &msg->msg_flags);
	xml_write_uint32(stream, "security-model", &msg->msg_sec_model);
    }
    xml_write_close(stream, name);
}


static void
xml_write_snmp(FILE *stream, snmp_snmp_t *snmp)
{
    const char *name = "snmp";
    
    xml_write_open(stream, name, &snmp->attr);
    if (snmp->attr.flags & SNMP_FLAG_VALUE) {
	xml_write_int32(stream, "version", &snmp->version);
	switch (snmp->version.value) {
	case 0:
	case 1:
	    xml_write_octs(stream, "community", &snmp->community);
	    if (snmp->scoped_pdu.pdu.type == SNMP_PDU_TRAP1) {
		xml_write_trap(stream, &snmp->scoped_pdu.pdu);
	    } else {
		xml_write_pdu(stream, &snmp->scoped_pdu.pdu);
	    }
	    break;
	case 3:
	    xml_write_message(stream, &snmp->message);
	    xml_write_usm(stream, &snmp->usm);
	    xml_write_scoped_pdu(stream, &snmp->scoped_pdu);
	    break;
	default:
	    break;
	}
    }
    xml_write_close(stream, name);
}


void
snmp_xml_write_stream_pkt(FILE *stream, snmp_packet_t *pkt)
{
    if (! pkt) return;
    
    fprintf(stream, "<packet>");

    xml_write_uint32(stream, "time-sec", &pkt->time_sec);
    xml_write_uint32(stream, "time-usec", &pkt->time_usec);

    if (pkt->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	xml_write_ipaddr(stream, "src-ip", &pkt->src_addr);
    } else {
	xml_write_ip6addr(stream, "src-ip", &pkt->src_addr6);
    }
    xml_write_uint32(stream, "src-port", &pkt->src_port);
    if (pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	xml_write_ipaddr(stream, "dst-ip", &pkt->dst_addr);
    } else {
	xml_write_ip6addr(stream, "dst-ip", &pkt->dst_addr6);
    }
    xml_write_uint32(stream, "dst-port", &pkt->dst_port);

    if (pkt->attr.flags & SNMP_FLAG_VALUE) {
	xml_write_snmp(stream, &pkt->snmp);
    }

    fprintf(stream, "</packet>\n");
}


void
snmp_xml_write_stream_new(FILE *stream)
{
    fprintf(stream,
	    "<?xml version=\"1.0\"?>\n<snmptrace xmlns='%s'>\n",
	    "http://www.irtf.org/nmrg/snmptrace");
}


void
snmp_xml_write_stream_end(FILE *stream)
{
    fprintf(stream, "</snmptrace>\n");
}
