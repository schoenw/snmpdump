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

struct _snmp_filter {
    regex_t regex;
};

static struct {
    const char *element;
    int flag;
} filter_table[] = {
    { "version",	0 },
    { "community",	0 },
};

snmp_filter_t*
snmp_filter_new(const char *regex, char **error)
{
    snmp_filter_t *filter;
    int errcode;
    static char buffer[256];

    filter = (snmp_filter_t *) malloc(sizeof(snmp_filter_t));
    if (! filter) {
	abort();
    }
    
    errcode = regcomp(&filter->regex, regex,
		      REG_EXTENDED | REG_ICASE | REG_NOSUB);
    if (errcode) {
	regerror(errcode, &filter->regex, buffer, sizeof(buffer));
	free(filter);
	if (error) {
	    *error = buffer;
	}
	return NULL;
    }
    
    return filter;
}

void
snmp_filter_apply(snmp_filter_t *filter, snmp_packet_t *pkt)
{
    /* xxx */
}

void
snmp_filter_delete(snmp_filter_t *filter)
{
    if (filter) {
	free(filter);
    }
}
