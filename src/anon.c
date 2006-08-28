/*
 * anon.c --
 *
 * Anonymization filtering utility functions for snmpdump.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

#include "config.h"

#include "anon.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

static anon_tf_t *tf_list = NULL;
static anon_rule_t *rule_list = NULL;

struct _anon_tf {
    char *name;
    int   type;
    union {
	anon_ipv4_t	*an_ipv4;
	anon_ipv6_t	*an_ipv6;
	anon_mac_t	*an_mac;
	anon_int64_t	*an_int64;
	anon_uint64_t	*an_uint64;
	anon_octs_t	*an_octs;
    } u;
    struct _anon_tf *next;
};

struct _anon_rule {
    char              *name;
    anon_tf_t	      *tfp;
    regex_t	      reg;
    struct _anon_rule *next;
};

static struct {
    const char *name;
    int type;
} type_table [] = {
    { "ipv4",	ANON_TYPE_IPV4 },
    { "ipv6",	ANON_TYPE_IPV6 },
    { "mac",	ANON_TYPE_MAC },
    { "int32",	ANON_TYPE_INT32 },
    { "uint32", ANON_TYPE_UINT32 },
    { "int64",	ANON_TYPE_INT64 },
    { "uint64", ANON_TYPE_UINT64 },
    { "octs",	ANON_TYPE_OCTS },
    { NULL,	ANON_TYPE_NONE }
};


anon_tf_t*
anon_tf_new(anon_key_t *key, const char *name, const char *type,
	    const char *range, const char *option)
{
    anon_tf_t *tfp = NULL;
    int i;

    assert(name && type);

    for (i = 0; type_table[i].name; i++) {
	if (strcmp(type_table[i].name, type) == 0) {
	    break;
	}
    }
    if (! type_table[i].name) {
	return NULL;
    }

    /* create a new transformation object */

    tfp = (anon_tf_t *) malloc(sizeof(anon_tf_t));
    memset(tfp, 0, sizeof(anon_tf_t));
    if (! tfp) {
	return NULL;
    }

    tfp->type = type_table[i].type;
    tfp->name = strdup(name);
    if (! tfp->name) {
	free(tfp);
	return NULL;
    }

    switch (tfp->type) {
    case ANON_TYPE_IPV4:
	tfp->u.an_ipv4 = anon_ipv4_new();
	if (tfp->u.an_ipv4) {
	    anon_ipv4_set_key(tfp->u.an_ipv4, key);
	}
	break;
    case ANON_TYPE_MAC:
	/* xxx */
	break;
    case ANON_TYPE_INT32:
	tfp->u.an_int64 = anon_int64_new(0, INT32_MAX);
	if (tfp->u.an_int64) {
	    anon_int64_set_key(tfp->u.an_int64, key);
	}
	break;
    case ANON_TYPE_UINT32:
	tfp->u.an_uint64 = anon_uint64_new(0, UINT32_MAX);
	if (tfp->u.an_uint64) {
	    anon_uint64_set_key(tfp->u.an_uint64, key);
	}
	break;
    case ANON_TYPE_INT64:
	tfp->u.an_int64 = anon_int64_new(0, INT64_MAX);
	if (tfp->u.an_int64) {
	    anon_int64_set_key(tfp->u.an_int64, key);
	}
	break;
    case ANON_TYPE_UINT64:
	tfp->u.an_uint64 = anon_uint64_new(0, UINT64_MAX);
	if (tfp->u.an_uint64) {
	    anon_uint64_set_key(tfp->u.an_uint64, key);
	}
	break;
    case ANON_TYPE_OCTS:
	tfp->u.an_octs = anon_octs_new();
	if (tfp->u.an_octs) {
	    anon_octs_set_key(tfp->u.an_octs, key);
	}
	break;
    }

    /* append to list */

    if (! tf_list) {
	tf_list = tfp;
    } else {
	anon_tf_t *p;
	for (p = tf_list; p->next; p = p->next) ;
	p->next = tfp;
    }

    return tfp;
}

anon_tf_t*
anon_tf_find_by_name(const char *name)
{
    anon_tf_t *tfp;

    assert(name);

    for (tfp = tf_list; tfp; tfp = tfp->next) {
	if (strcmp(tfp->name, name) == 0) {
	    break;
	}
    }
    return tfp;
}

void
anon_tf_delete(anon_tf_t *tfp)
{
    assert (tfp);
    
    /* xxx make sure no rule points to this transform */

    /* cleanup and release */
}


anon_rule_t*
anon_rule_new(const char *name, const char *transform, const char *targets)
{
    anon_tf_t *tfp;
    anon_rule_t *rp;

    assert(name && transform && targets);

    tfp = anon_tf_find_by_name(transform);
    if (! tfp) {
	return NULL;
    }

    /* create a new rule object */

    rp = (anon_rule_t *) malloc(sizeof(anon_rule_t));
    memset(rp, 0, sizeof(anon_rule_t));
    if (! rp) {
	return NULL;
    }

    rp->tfp = tfp;
    rp->name = strdup(name);
    if (! rp->name) {
	free(rp);
	return NULL;
    }

    if (0 != regcomp(&rp->reg, targets,
		     REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
	free(rp->name);
	free(rp);
	return NULL;
    }

    /* append to list */

    if (! rule_list) {
	rule_list = rp;
    } else {
	anon_rule_t *p;
	for (p = rule_list; p->next; p = p->next) ;
	p->next = rp;
    }

    return rp;
}

anon_rule_t*
anon_rule_find_by_name(const char *name)
{
    anon_rule_t *rp;

    assert(name);

    for (rp = rule_list; rp; rp = rp->next) {
	if (strcmp(rp->name, name) == 0) {
	    break;
	}
    }
    return rp;
}

void
anon_rule_delete(anon_rule_t *rp)
{
    assert(rp);

    regfree(&rp->reg);

    if (rp->name) {
	free(rp->name);
    }
    free(rp);
}


void
anon_init(anon_key_t *key)
{
    int i;

    const char *tftab[] = {
	"tr-inet-address-ipv4", "ipv4",
	"tr-ieee-mac",		"mac",
	"tr-inet-port-number",	"uint32",
	NULL, NULL
    };

    const char *rtab[] = {
	"ipv4-by-type", "tr-inet-address-ipv4", "IpAddress|InetAddressIPv4",
	"port-by-type", "tr-inet-port-number", "InetPortNumber",
	NULL, NULL, NULL
    };

    for (i = 0; tftab[2*i]; i++) {
	if (0 == anon_tf_new(key, tftab[2*i], tftab[2*i+1], NULL, NULL)) {
	    fprintf(stderr, "*** adding transform %s failed\n", tftab[2*i]);
	} else {
	    fprintf(stderr, "transform: %s\n", tftab[2*i]);
	}
    }

    for (i = 0; rtab[3*i]; i++) {
	if (0 == anon_rule_new(rtab[3*i], rtab[3*i+1], rtab[3*i+2])) {
	    fprintf(stderr, "*** adding rule %s failed\n", rtab[3*i]);
	} else {
	    fprintf(stderr, "rule: %s\n", tftab[2*i]);
	}
    }
}


static anon_tf_t*
anon_find_transform(SmiNode *smiNode, SmiType *smiType)
{
    anon_rule_t *rp;

    /*
     * We apply the first rule that matches and ignore any other rules
     * that might match as well. This allows to have an object
     * specific rule overwrite a more general type specific rule.
     */

    for (rp = rule_list; rp; rp = rp->next) {
#if 0
	fprintf(stderr, "%s: %s (%s)\n", rp->name,
		smiNode ? smiNode->name : "?",
		smiType ? smiType->name : "?");
#endif
	if (smiType && smiType->name) {
	    if (0 == regexec(&rp->reg, smiType->name, 0, NULL, 0)) {
		break;
	    }
	}
	if (smiNode && smiNode->name) {
	    if (0 == regexec(&rp->reg, smiNode->name, 0, NULL, 0)) {
		break;
	    }
	}
    }

    return (rp ? rp->tfp : NULL);
}



static inline void
anon_int32(anon_tf_t *tfp, snmp_int32_t *v)
{
    int64_t new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_INT32
	|| 0 != anon_int64_map(tfp->u.an_int64, v->value, &new_value)) {
	v->value = 0;
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;	
    }

    v->value = (uint32_t) new_value;
}

static inline void
anon_uint32(anon_tf_t *tfp, snmp_uint32_t *v)
{
    uint64_t new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_UINT32
	|| 0 != anon_uint64_map(tfp->u.an_uint64, v->value, &new_value)) {
	v->value = 0;
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;	
    }

    v->value = (uint32_t) new_value;
}

static inline void
anon_int64(anon_tf_t *tfp, snmp_uint32_t *v)
{
    int64_t new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_INT32
	|| 0 != anon_int64_map(tfp->u.an_int64, v->value, &new_value)) {
	v->value = 0;
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;	
    }

    v->value = new_value;
}

static inline void
anon_uint64(anon_tf_t *tfp, snmp_uint64_t *v)
{
    uint64_t new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_UINT32
	|| 0 != anon_uint64_map(tfp->u.an_uint64, v->value, &new_value)) {
	v->value = 0;
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;	
    }

    v->value = new_value;
}

static inline void
anon_octs(anon_tf_t *tfp, snmp_octs_t *v)
{
    char *new_value = NULL;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (tfp && tfp->type == ANON_TYPE_OCTS && v->len) {
	new_value = malloc(v->len);
    }

    if (! tfp || tfp->type != ANON_TYPE_OCTS
	|| ! new_value
	|| 0 != anon_octs_map(tfp->u.an_octs,
				      (char *) v->value, new_value)) {
	memset(v->value, 0, v->len);
	v->len = 0;
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	if (new_value) free(new_value);
	return;	
    }

    memcpy(v->value, new_value, v->len);
    free(new_value);
}

static inline void
anon_ipaddr(anon_tf_t *tfp, snmp_ipaddr_t *v)
{
    in_addr_t new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_IPV4
	|| 0 != anon_ipv4_map_pref(tfp->u.an_ipv4, v->value, &new_value)) {
	memset(&v->value, 0, sizeof(v->value));
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;
    }

    memcpy(&v->value, &new_value, sizeof(v->value));
}

static inline void
anon_ip6addr(anon_tf_t *tfp, snmp_ip6addr_t *v)
{
    struct in6_addr new_value;

    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

    if (! tfp || tfp->type != ANON_TYPE_IPV6
	|| 0 != anon_ipv6_map_pref(tfp->u.an_ipv6, v->value, &new_value)) {
	memset(&v->value, 0, sizeof(v->value));
	v->attr.flags &= ~SNMP_FLAG_VALUE;
	return;
    }

    memcpy(&v->value, &new_value, sizeof(v->value));
}

static inline void
anon_oid(anon_tf_t *tfp, snmp_oid_t *v)
{
    SmiNode *smiNode;
    SmiValue *vals;
    int i, valslen;
    
    if (! v->attr.flags & SNMP_FLAG_VALUE) {
	return;
    }

#if 0
    smiNode = smiGetNodeByOID(v->len, v->value);
    if (! smiNode) {
	goto nukeOid;
    }

    smiUnpack(smiNode, v->value, v->len, &vals, &valslen);
    for (i = 0; i < valslen; i++) {
	printf("x");
    }
    printf("\n");
#endif

 nukeOid:
    memset(v->value, 0, v->len * sizeof(uint32_t));
    v->len = 0;
    v->attr.flags &= ~SNMP_FLAG_VALUE;
}

static void
anon_pdu(snmp_pdu_t *pdu)
{
    snmp_varbind_t *vb;
    anon_tf_t *tfp = NULL;
    
    for (vb = pdu->varbindings.varbind; vb; vb = vb->next) {
	SmiNode *smiNode = NULL;
	SmiType *smiType = NULL;
	smiNode = smiGetNodeByOID(vb->name.len, vb->name.value);
	if (smiNode) {
	    smiType = smiGetNodeType(smiNode);
	}
	tfp = anon_find_transform(smiNode, smiType);

	anon_oid(NULL, &vb->name);

	switch (vb->type) {
	case SNMP_TYPE_NULL:
	    break;
	case SNMP_TYPE_INT32:
	    anon_int32(tfp, &vb->value.i32);
	    break;
	case SNMP_TYPE_UINT32:
 	    anon_uint32(tfp, &vb->value.u32);
	    break;
	case SNMP_TYPE_UINT64:
 	    anon_uint64(tfp, &vb->value.u64);
	    break;
	case SNMP_TYPE_IPADDR:
	    anon_ipaddr(tfp, &vb->value.ip);
	    break;
	case SNMP_TYPE_OCTS:
	    anon_octs(tfp, &vb->value.octs);
	    break;
	case SNMP_TYPE_OID:
	    anon_oid(tfp, &vb->value.oid);
	    break;
	}
    }
}

/*
 * Not yet useful function to call the anonymization library.
 */

void
snmp_anon_apply(snmp_packet_t *pkt)
{
    anon_tf_t *tfp = NULL;
    SmiType *smiType;

    if (! pkt) {
	return;
    }
    
    smiType = smiGetType(NULL, "IpAddress");
    if (! smiType) {
	fprintf(stderr,
		"%s: libsmi failed to locate the type 'IpAddress'\n",
		progname);
    }
    tfp = smiType ? anon_find_transform(NULL, smiType) : NULL;
    anon_ipaddr(tfp, &pkt->src_addr);
    anon_ipaddr(tfp, &pkt->dst_addr);

    smiType = smiGetType(NULL, "InetPortNumber");
    if (! smiType) {
	fprintf(stderr,
		"%s: libsmi failed to locate the type 'InetPortNumber'\n",
		progname);
    }
    tfp = smiType ? anon_find_transform(NULL, smiType) : NULL;
    anon_uint32(tfp, &pkt->src_port);
    anon_uint32(tfp, &pkt->dst_port);

    /* time_sec, time_usec */

    anon_pdu(&pkt->snmp.scoped_pdu.pdu);
}
