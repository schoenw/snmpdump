/*
 * xpath-filter.h --
 *
 * Implements a filter object which can be used to delete or clear
 * elements in an XML document identified by an xpath expression.
 *
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#ifndef _XPATH_FILTER_H
#define _XPATH_FILTER_H

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

typedef enum {
    XPATH_FILTER_TYPE_DELETE,
    XPATH_FILTER_TYPE_CLEAR
} xpath_filter_type_t;

typedef struct _xpath_filter xpath_filter_t;

extern xpath_filter_t* xpath_filter_new();

extern void xpath_filter_delete(xpath_filter_t *xpf);

extern int  xpath_filter_add(xpath_filter_t *xpf,
			     xmlChar *expr, xpath_filter_type_t type);

extern void xpath_filter_apply(xpath_filter_t *xpf, xmlDocPtr doc);

#endif /* _XPATH_FILTER_H */
