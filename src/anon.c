/*
 * anon.c --
 *
 * Anonymization filtering utility functions for snmpdump.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
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
	anon_octet_string_t *an_octs;
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
    { NULL,	ANON_TYPE_NONE }
};


anon_tf_t*
anon_tf_new(const char *name, const char *type,
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
	break;
    case ANON_TYPE_MAC:
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
anon_init()
{
    int i;

    const char *tftab[] = {
	"tr-inet-address-ipv4", "ipv4",
	"tr-ieee-mac",		"mac",
	NULL, NULL
    };

    const char *rtab[] = {
	"ipv4-by-type", "tr-inet-address-ipv4", "IpAddress|InetAddressIPv4",
	NULL, NULL, NULL
    };

    for (i = 0; tftab[2*i]; i++) {
	if (0 == anon_tf_new(tftab[2*i], tftab[2*i+1], NULL, NULL)) {
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

void
anon_apply(snmp_varbind_t *vb, SmiNode *smiNode, SmiType *smiType)
{
    anon_rule_t *rp;

    for (rp = rule_list; rp; rp = rp->next) {
	fprintf(stderr, "%s: %s (%s)\n", rp->name,
		smiNode->name, smiType ? smiType->name : "?");
	if (smiType && smiType->name) {
	    if (0 == regexec(&rp->reg, smiType->name, 0, NULL, 0)) {
		/* got a transform to apply */
		fprintf(stderr, "%s: match: %s\n", rp->name, smiType->name);
		break;
	    }
	}
	if (smiNode && smiNode->name) {
	    if (0 == regexec(&rp->reg, smiNode->name, 0, NULL, 0)) {
		/* got a transform to apply */
		fprintf(stderr, "%s: match: %s\n", rp->name, smiNode->name);
		break;
	    }
	}
    }

    if (rp) {
	/* xxx getc(stdin); */
    }
}
