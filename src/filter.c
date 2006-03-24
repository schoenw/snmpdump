/*
 * filter.c --
 *
 * Filter SNMP traffic traces using a filter-out approach.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 *
 * $Id$
 */

#include "config.h"

#include "snmp.h"

#include <string.h>
#include <stdlib.h>
#include <regex.h>

#define FLT_NONE		0
#define FLT_BLEN		1
#define FLT_VLEN		2
#define FLT_TIME_SEC		3
#define FLT_TIME_USEC		4
#define FLT_SRC_IP		5
#define FLT_SRC_PORT		6
#define FLT_DST_IP		7
#define FLT_DST_PORT		8
#define FLT_SNMP		9
#define FLT_VERSION		10
#define FLT_COMMUNITY		11
#define FLT_MESSAGE		12
#define FLT_MSG_ID		13
#define FLT_MAX_SIZE		14
#define FLT_FLAGS		15
#define FLT_SECURITY_MODEL	16
#define FLT_USM			17
#define FLT_AUTH_ENGINE_ID	18
#define FLT_AUTH_ENGINE_BOOTS	19
#define FLT_AUTH_ENGINE_TIME	20
#define FLT_USER	        21
#define FLT_AUTH_PARAMS		22
#define FLT_PRIV_PARAMS		23
#define FLT_SCOPED_PDU		24
#define FLT_CONTEXT_ENGINE_ID	25
#define FLT_CONTEXT_NAME	26
#define FLT_GET_REQUEST		27
#define FLT_GET_NEXT_REQUEST	28
#define FLT_GET_BULK_REQUEST	29
#define FLT_SET_REQUEST		30
#define FLT_INFORM		31
#define FLT_TRAP		32
#define FLT_TRAP2		33
#define FLT_RESPONSE		34
#define FLT_REPORT		35
#define FLT_REQUEST_ID		36
#define FLT_ERROR_STATUS	37
#define FLT_ERROR_INDEX		38
#define FLT_ENTERPRISE		39
#define FLT_AGENT_ADDR		40
#define FLT_GENERIC_TRAP	41
#define FLT_SPECIFIC_TRAP	42
#define FLT_TIME_STAMP		43
#define FLT_MAX			43

struct _snmp_filter {
    char hide[FLT_MAX];
};

static struct {
    const char *elem;
    int flag;
} filter_table[] = {
    { "blen",			FLT_BLEN },
    { "vlen",			FLT_VLEN },
    { "time-sec",		FLT_TIME_SEC },
    { "time-usec",		FLT_TIME_USEC },
    { "src-ip",			FLT_SRC_IP },
    { "src-port",		FLT_SRC_PORT },
    { "dst-ip",			FLT_DST_IP },
    { "src-port",		FLT_DST_PORT },
    { "snmp",			FLT_SNMP },
    { "version",		FLT_VERSION },
    { "community",		FLT_COMMUNITY },
    { "message",		FLT_MESSAGE },
    { "msg-id",			FLT_MSG_ID },
    { "max-size",		FLT_MAX_SIZE },
    { "flags",			FLT_FLAGS },
    { "security-model",		FLT_SECURITY_MODEL },
    { "usm",			FLT_USM },
    { "auth-engine-id",		FLT_AUTH_ENGINE_ID },
    { "auth-engine-boots",	FLT_AUTH_ENGINE_BOOTS },
    { "auth-engine-time",	FLT_AUTH_ENGINE_TIME },
    { "user",			FLT_USER },
    { "auth-params",		FLT_AUTH_PARAMS },
    { "priv-params",		FLT_PRIV_PARAMS },
    { "scoped-pdu",		FLT_SCOPED_PDU },
    { "context-engine-id",	FLT_CONTEXT_ENGINE_ID },
    { "context-name",		FLT_CONTEXT_NAME },
    { "get-request",		FLT_GET_REQUEST },
    { "get-next-request",	FLT_GET_NEXT_REQUEST },
    { "get-bulk-request",	FLT_GET_BULK_REQUEST },
    { "set-request",		FLT_SET_REQUEST },
    { "inform",			FLT_INFORM },
    { "trap",			FLT_TRAP },
    { "trap2",			FLT_TRAP2 },
    { "response",		FLT_RESPONSE },
    { "report",			FLT_REPORT },
    { "request-id",		FLT_REQUEST_ID },
    { "error-status",		FLT_ERROR_STATUS },
    { "error-index",		FLT_ERROR_INDEX },
    { "enterprise",		FLT_ENTERPRISE },
    { "agent-addr",		FLT_AGENT_ADDR },
    { "generic-trap",		FLT_GENERIC_TRAP },
    { "specific-trap",		FLT_SPECIFIC_TRAP },
    { "time-stamp",		FLT_TIME_STAMP },
    { NULL,			0 }
};

snmp_filter_t*
snmp_filter_new(const char *pattern, char **error)
{
    snmp_filter_t *filter;
    int i, errcode;
    regex_t regex;
    static char buffer[256];

    filter = (snmp_filter_t *) malloc(sizeof(snmp_filter_t));
    if (! filter) {
	abort();
    }
    
    errcode = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    if (errcode) {
	regerror(errcode, &regex, buffer, sizeof(buffer));
	free(filter);
	if (error) {
	    *error = buffer;
	}
	return NULL;
    }

    for (i = 0; filter_table[i].elem; i++) {
	int flag = filter_table[i].flag;
	filter->hide[flag] =
	    (0 == regexec(&regex, filter_table[i].elem, 0, NULL, 0));
    }

    regfree(&regex);

    return filter;
}

static inline void
filter_attr(snmp_filter_t *filter, int flt, snmp_attr_t *a)
{
    if (filter->hide[flt]) {
	a->flags &= ~SNMP_FLAG_VALUE;
    }
    if (filter->hide[FLT_BLEN]) {
	a->blen = 0;
	a->flags &= ~SNMP_FLAG_BLEN;
    }
    if (filter->hide[FLT_VLEN]) {
	a->vlen = 0;
	a->flags &= ~SNMP_FLAG_VLEN;
    }
}

static inline void
filter_int32(snmp_filter_t *filter, int flt, snmp_int32_t *v)
{
    if (filter->hide[flt]) {
	v->value = 0;
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_uint32(snmp_filter_t *filter, int flt, snmp_uint32_t *v)
{
    if (filter->hide[flt]) {
	v->value = 0;
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_octs(snmp_filter_t *filter, int flt, snmp_octs_t *v)
{
    int i;
    
    if (filter->hide[flt] && v->value) {
	for (i = 0; i < v->len; i++) {
	    v->value[i] = 0;
	}
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_oid(snmp_filter_t *filter, int flt, snmp_oid_t *v)
{
    int i;
    
    if (filter->hide[flt] && v->value) {
	for (i = 0; i < v->len; i++) {
	    v->value[i] = 0;
	}
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_ipaddr(snmp_filter_t *filter, int flt, snmp_ipaddr_t *v)
{
    if (filter->hide[flt]) {
	memset(&v->value, 0, sizeof(v->value));
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_ip6addr(snmp_filter_t *filter, int flt, snmp_ip6addr_t *v)
{
    if (filter->hide[flt]) {
	memset(&v->value, 0, sizeof(v->value));
    }
    filter_attr(filter, flt, &v->attr);
}

static inline void
filter_pdu(snmp_filter_t *filter, snmp_pdu_t *pdu)
{
    switch (pdu->type) {
    case SNMP_PDU_GET:
	filter_attr(filter, FLT_GET_REQUEST, &pdu->attr);
	break;
    case SNMP_PDU_GETNEXT:
	filter_attr(filter, FLT_GET_NEXT_REQUEST, &pdu->attr);
	break;
    case SNMP_PDU_GETBULK:
	filter_attr(filter, FLT_GET_BULK_REQUEST, &pdu->attr);
	break;
    case SNMP_PDU_SET:
	filter_attr(filter, FLT_SET_REQUEST, &pdu->attr);
	break;
    case SNMP_PDU_RESPONSE:
	filter_attr(filter, FLT_RESPONSE, &pdu->attr);
	break;
    case SNMP_PDU_TRAP1:
	filter_attr(filter, FLT_TRAP, &pdu->attr);
	break;
    case SNMP_PDU_TRAP2:
	filter_attr(filter, FLT_TRAP2, &pdu->attr);
	break;
    case SNMP_PDU_INFORM:
	filter_attr(filter, FLT_INFORM, &pdu->attr);
	break;
    case SNMP_PDU_REPORT:
	filter_attr(filter, FLT_REPORT, &pdu->attr);
	break;
    default:
	break;
    }
    
    filter_int32(filter, FLT_REQUEST_ID, &pdu->req_id);
    filter_int32(filter, FLT_ERROR_STATUS, &pdu->err_status);
    filter_int32(filter, FLT_ERROR_INDEX, &pdu->err_index);
    filter_oid(filter, FLT_ENTERPRISE, &pdu->enterprise);
    filter_ipaddr(filter, FLT_AGENT_ADDR, &pdu->agent_addr);
    filter_int32(filter, FLT_GENERIC_TRAP, &pdu->generic_trap);
    filter_int32(filter, FLT_SPECIFIC_TRAP, &pdu->specific_trap);
    filter_int32(filter, FLT_TIME_STAMP, &pdu->time_stamp);

    /* VARBINDLIST, VARBIND */
}

static inline void
filter_scoped_pdu(snmp_filter_t *filter, snmp_scoped_pdu_t *spdu)
{
    filter_attr(filter, FLT_SCOPED_PDU, &spdu->attr);
    filter_octs(filter, FLT_CONTEXT_ENGINE_ID, &spdu->context_engine_id);
    filter_octs(filter, FLT_CONTEXT_NAME, &spdu->context_name);
}

static inline void
filter_usm(snmp_filter_t *filter, snmp_usm_t *usm)
{
    filter_attr(filter, FLT_USM, &usm->attr);
    filter_octs(filter, FLT_AUTH_ENGINE_ID, &usm->auth_engine_id);
    filter_uint32(filter, FLT_AUTH_ENGINE_BOOTS, &usm->auth_engine_boots);
    filter_uint32(filter, FLT_AUTH_ENGINE_TIME, &usm->auth_engine_time);
    filter_octs(filter, FLT_USER, &usm->user);
    filter_octs(filter, FLT_AUTH_PARAMS, &usm->auth_params);
    filter_octs(filter, FLT_PRIV_PARAMS, &usm->priv_params);
}

static inline void
filter_message(snmp_filter_t *filter, snmp_msg_t *msg)
{
    filter_uint32(filter, FLT_MSG_ID, &msg->msg_id);
    filter_uint32(filter, FLT_MAX_SIZE, &msg->msg_max_size);
    filter_octs(filter, FLT_FLAGS, &msg->msg_flags);
    filter_uint32(filter, FLT_SECURITY_MODEL, &msg->msg_sec_model);
}

static inline void
filter_snmp(snmp_filter_t *filter, snmp_snmp_t *snmp)
{
    filter_attr(filter, FLT_SNMP, &snmp->attr);
    filter_int32(filter, FLT_VERSION, &snmp->version);
    filter_octs(filter, FLT_COMMUNITY, &snmp->community);
}

void
snmp_filter_apply(snmp_filter_t *filter, snmp_packet_t *pkt)
{
    if (! pkt || ! filter) {
	return;
    }

    filter_uint32(filter, FLT_TIME_SEC, &pkt->time_sec);
    filter_uint32(filter, FLT_TIME_USEC, &pkt->time_usec);
    filter_ipaddr(filter, FLT_SRC_IP, &pkt->src_addr);
    filter_ip6addr(filter, FLT_SRC_IP, &pkt->src_addr6);
    filter_uint32(filter, FLT_SRC_PORT, &pkt->src_port);
    filter_ipaddr(filter, FLT_DST_IP, &pkt->dst_addr);
    filter_ip6addr(filter, FLT_DST_IP, &pkt->dst_addr6);
    filter_uint32(filter, FLT_DST_PORT, &pkt->dst_port);

    filter_snmp(filter, &pkt->snmp);
    filter_message(filter, &pkt->snmp.message);
    filter_usm(filter, &pkt->snmp.usm);
    filter_scoped_pdu(filter, &pkt->snmp.scoped_pdu);
    filter_pdu(filter, &pkt->snmp.scoped_pdu.pdu);
}

void
snmp_filter_delete(snmp_filter_t *filter)
{
    if (filter) {
	free(filter);
    }
}
