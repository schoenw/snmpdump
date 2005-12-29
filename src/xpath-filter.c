/*
 * xpath-filter.c --
 *
 * Implements a filter object which can be used to delete or clear
 * elements in an XML document identified by an xpath expression.
 *
 * Copyright (c) 2005 Juergen Schoenwaelder
 */

#include "xpath-filter.h"

struct _xpath_filter {
    xmlChar		 *expr;
    xpath_filter_type_t  type;
    struct _xpath_filter *next;
};


static void
xpath_filter_apply_one(xmlDocPtr doc, xmlChar *xpath, xpath_filter_type_t type)
{
    xmlXPathContextPtr ctxt;
    xmlXPathObjectPtr obj;
    xmlNodePtr node;
    int i, size;
    
    ctxt = xmlXPathNewContext(doc);
    ctxt->node = xmlDocGetRootElement(doc);
    obj = xmlXPathEval(xpath, ctxt);
    if (obj && obj->type == XPATH_NODESET && obj->nodesetval) {
	size = xmlXPathNodeSetGetLength(obj->nodesetval);
	for (i = size -1; i >= 0; i--) {
	    node = obj->nodesetval->nodeTab[i];
	    switch (type) {
	    case XPATH_FILTER_TYPE_DELETE:
		xmlUnlinkNode(node);
		xmlFreeNode(node);
		break;
	    case XPATH_FILTER_TYPE_CLEAR:
		xmlNodeSetContent(node, NULL);
		break;
	    }
	    if (node->type != XML_NAMESPACE_DECL) {
		node = NULL;
	    }
	}
    }

    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
}

xpath_filter_t*
xpath_filter_new()
{
    xpath_filter_t *xpf;
    
    xpf = (xpath_filter_t *) malloc(sizeof(xpath_filter_t));
    if (xpf) {
	xpf->expr = NULL;
	xpf->type = XPATH_FILTER_TYPE_DELETE;
	xpf->next = NULL;
    }
    return xpf;
}

void
xpath_filter_delete(xpath_filter_t *xpf)
{
    if (xpf) {
	xpath_filter_delete(xpf->next);
	if (xpf->expr) free(xpf->expr);
	free(xpf);
    }
}

int
xpath_filter_add(xpath_filter_t *xpf,
		 xmlChar *expression,
		 xpath_filter_type_t type)
{
    xpath_filter_t *new_xpf, *p;
    
    new_xpf = (xpath_filter_t *) malloc(sizeof(xpath_filter_t));
    if (! new_xpf) {
	return -1;
    }
    new_xpf->expr = xmlStrdup(expression);
    new_xpf->type = type;
    new_xpf->next = NULL;

    for (p = xpf; p->next; p = p->next) ;
    p->next = new_xpf;
    return 0;
}

void
xpath_filter_apply(xpath_filter_t *xpf, xmlDocPtr doc)
{
    if (xpf->expr) {
	xpath_filter_apply_one(doc, xpf->expr, xpf->type);
    }

    if (xpf->next) {
	xpath_filter_apply(xpf->next, doc);
    }
}
