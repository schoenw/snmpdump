/*
 * anon.h --
 *
 * Define anonymization filter abstract data types which can be
 * used to filter in anonymized object values.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 *
 * $Id$
 */

/*
transform {
    name	tr-inet-address-ipv4;
    type	ipv4; 
    option	lex;
};

transform {
    name	tr-ieee-mac;
    type	mac;
};

transform {
    name	tr-inet-port-number;
    type	int64;
    range	0..65535;
    option	lex;
};

rule {
    name	rule-ipv4-by-type;
    apply	tr-inet-address-ipv4;
    targets	"IpAddress|InetAddressIPv4";
};

rule {
    name	rule-ieee-mac-by-type;
    apply	tr-ieee-mac;
    targets	"MacAddress"	// what about PhysAddress?
};
*/


#ifndef _ANON_H
#define _ANON_H

#include "libanon.h"

typedef struct _anon_transform anon_transform_t;

extern anon_transform_t* anon_tform_new(char *name, char *type,
					char *range, char *option);
extern anon_transform_delete(anon_transform_t *transform);

typedef struct _anon_rule anon_rule_t;

extern anon_rule_t* anon_rule_new(char *name, char *transform, char *targets);
extern void anon_rule_delete(anon_rule_t *rule);

#endif _ANON_H
