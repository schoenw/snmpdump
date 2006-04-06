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
    targets	"MacAddress";	// what about PhysAddress?
};
*/


#ifndef _ANON_H
#define _ANON_H

#include "smi.h"
#include "snmp.h"
#include "libanon.h"

/*
 * Anonymization transformations...
 */

#define ANON_TYPE_NONE		0x00
#define ANON_TYPE_IPV4		0x01
#define ANON_TYPE_IPV6		0x02
#define ANON_TYPE_MAC		0x03
#define ANON_TYPE_INT32		0x04
#define ANON_TYPE_UINT32	0x05
#define ANON_TYPE_INT64		0x06
#define ANON_TYPE_UINT64	0x07
#define ANON_TYPE_OCTS		0x08

typedef struct _anon_tf anon_tf_t;

extern anon_tf_t* anon_tf_new(const char *name,
			      const char *type,
			      const char *range,
			      const char *option);
extern anon_tf_t* anon_tf_find_by_name(const char *name);
extern void anon_tf_delete(anon_tf_t *tfp);

/*
 * Anonymization rules...
 */

typedef struct _anon_rule anon_rule_t;

extern anon_rule_t* anon_rule_new(const char *name,
				  const char *transform,
				  const char *targets);
extern anon_rule_t* anon_rule_find_by_name(const char *name);
extern void anon_rule_delete(anon_rule_t *rule);

/*
 * Main entrance function...
 */

extern void anon_apply(snmp_varbind_t *vb,
		       SmiNode *smiNode,
		       SmiType *smiType);
/*
 * Utility functions...
 */

extern void anon_init(void);

#endif /* _ANON_H */
