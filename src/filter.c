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

#include <stdlib.h>
#include <regex.h>

#define FLT_NONE		0
#define FLT_BLEN		1
#define FLT_VLEN		2
#define FLT_SRC			3
#define FLT_DST			4
#define FLT_SNMP		5
#define FLT_VERSION		6
#define FLT_COMMUNITY		7
#define FLT_MESSAGE		8
#define FLT_MSG_ID		9
#define FLT_MAX_SIZE		10
#define FLT_FLAGS		11
#define FLT_SECURITY_MODEL	12
#define FLT_USM			13
#define FLT_AUTH_ENGINE_ID	14
#define FLT_AUTH_ENGINE_BOOTS	15
#define FLT_AUTH_ENGINE_TIME	16
#define FLT_USER		17
#define FLT_AUTH_PARAMS		18
#define FLT_PRIV_PARAMS		19
#define FLT_SCOPED_PDU		20
#define FLT_CONTEXT_ENGINE_ID	21
#define FLT_CONTEXT_NAME	22
#define FLT_MAX			22

struct _snmp_filter {
    char hide[FLT_MAX];
};

static struct {
    const char *elem;
    int flag;
} filter_table[] = {
    { "blen",			FLT_BLEN },
    { "vlen",			FLT_VLEN },
    { "src",			FLT_SRC },
    { "dst",			FLT_DST },
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

void
snmp_filter_apply(snmp_filter_t *filter, snmp_packet_t *pkt)
{
    if (! pkt || ! filter) {
	return;
    }

    filter_attr(filter, FLT_SNMP, &pkt->snmp.attr);
    filter_int32(filter, FLT_VERSION, &pkt->snmp.version);
    filter_octs(filter, FLT_COMMUNITY, &pkt->snmp.community);

    filter_attr(filter, FLT_MESSAGE, &pkt->snmp.message.attr);
    filter_uint32(filter, FLT_MSG_ID, &pkt->snmp.message.msg_id);
    filter_uint32(filter, FLT_MAX_SIZE, &pkt->snmp.message.msg_max_size);
    filter_octs(filter, FLT_FLAGS, &pkt->snmp.message.msg_flags);
    filter_uint32(filter, FLT_SECURITY_MODEL, &pkt->snmp.message.msg_sec_model);

    filter_attr(filter, FLT_USM, &pkt->snmp.usm.attr);
    filter_octs(filter, FLT_AUTH_ENGINE_ID, &pkt->snmp.usm.auth_engine_id);
    filter_uint32(filter, FLT_AUTH_ENGINE_BOOTS, &pkt->snmp.usm.auth_engine_boots);
    filter_uint32(filter, FLT_AUTH_ENGINE_TIME, &pkt->snmp.usm.auth_engine_time);
    filter_octs(filter, FLT_USER, &pkt->snmp.usm.user);
    filter_octs(filter, FLT_AUTH_PARAMS, &pkt->snmp.usm.auth_params);
    filter_octs(filter, FLT_PRIV_PARAMS, &pkt->snmp.usm.priv_params);

    filter_attr(filter, FLT_SCOPED_PDU, &pkt->snmp.scoped_pdu.attr);
    filter_octs(filter, FLT_CONTEXT_ENGINE_ID, &pkt->snmp.scoped_pdu.context_engine_id);
    filter_octs(filter, FLT_CONTEXT_NAME, &pkt->snmp.scoped_pdu.context_name);

    /* PDU */
    /* VARBIND */
    /* TRAP */
}

void
snmp_filter_delete(snmp_filter_t *filter)
{
    if (filter) {
	free(filter);
    }
}
