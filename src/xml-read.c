/*
 * xml-read.c --
 *
 * A simple C program to deserialize XML representation of SNMP
 * traffic traces.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 * (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
 *
 * $Id$
 */

#include "config.h"

#include "snmp.h"

#include <libxml/xmlreader.h>
#include <assert.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define debug 1
#ifdef debug
#define DEBUG(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else
#define DEBUG(format, ...)
#endif

#define ERROR(format, ...) fprintf (stderr, format, ## __VA_ARGS__)

static enum {
	IN_NONE,
	IN_SNMPTRACE,
	IN_PACKET,
	IN_TIME_SEC,
	IN_TIME_USEC,
	IN_SRC_IP,
	IN_SRC_PORT,
	IN_DST_IP,
	IN_DST_PORT,
	IN_SNMP,
	IN_VERSION,
	IN_COMMUNITY,
	/* add SNMPv3 stuff here */
	IN_MESSAGE,
	IN_MSG_ID,
	IN_MAX_SIZE,
	IN_FLAGS,
	IN_SEC_MODEL,
	IN_USM,
	IN_AUTH_ENGINE_ID,
	IN_AUTH_ENGINE_BOOTS,
	IN_AUTH_ENGINE_TIME,
	IN_USER,
	IN_AUTH_PARAMS,
	IN_PRIV_PARAMS,
	IN_SCOPED_PDU,
	IN_CONTEXT_ENGINE_ID,
	IN_CONTEXT_NAME,
	
	IN_TRAP,
	IN_ENTERPRISE,
	IN_AGENT_ADDR,
	IN_GENERIC_TRAP,
	IN_SPECIFIC_TRAP,
	IN_TIME_STAMP,
	IN_VARIABLE_BINDINGS,
	IN_GET_REQUEST,
	IN_GET_NEXT_REQUEST,
	IN_GET_BULK_REQUEST,
	IN_SET_REQUEST,
	IN_INFORM,
	IN_TRAP2,
	IN_RESPONSE,
	IN_REPORT,
	IN_REQUEST_ID,
	IN_ERROR_STATUS,
	IN_ERROR_INDEX,
	IN_VARBIND,
	IN_NAME,
	IN_NULL,
	IN_INTEGER32,
	IN_UNSIGNED32,
	IN_COUNTER32,
	IN_TIMETICKS,
	IN_COUNTER64,
	IN_IPADDRESS,
	IN_OCTET_STRING,
	IN_OBJECT_IDENTIFIER,
	IN_OPAQUE,
	IN_NO_SUCH_OBJECT,
	IN_NO_SUCH_INSTANCE,
	IN_END_OF_MIB_VIEW,
	IN_VALUE
} state = IN_NONE;


/*
static int
UTF8atoi(const xmlChar* xmlstr) {
    int i=0;
    int out = 0;
    for(i=0;xmlstr[i] >= '0' && xmlstr[i] <= '9';i++) {
	out *= 10;
	out += xmlstr[i] - '0';
    }
    return out;
}
*/

/*
 * deallocate memory for a filled-in snmp_packet_t
 */
void
snmp_packet_free(snmp_packet_t* packet) {
    snmp_varbind_t *varbind, *next;
    assert(packet);
    /* free varbinds */
    next = packet->snmp.scoped_pdu.pdu.varbindings.varbind;
    while (next) {
	varbind = next;
	//DEBUG("freeing... varbind: %x\n", varbind);
	if (varbind->name.value) {
	    free(varbind->name.value);
	}
	switch (varbind->type) {
	case SNMP_TYPE_OCTS:
	    if (varbind->value.octs.value) {
		free(varbind->value.octs.value);
	    }
	    break;
	case SNMP_TYPE_OID:
	    if (varbind->value.oid.value) {
		free(varbind->value.oid.value);
	    }
	    break;
	case SNMP_TYPE_OPAQUE:
	    if (varbind->value.octs.value) {
		free(varbind->value.octs.value);
	    }
	    break;
	default:
	    break;
	}
	next = next->next;
	free(varbind);
    }
    /* free community string */
    if ((packet->snmp.community.attr.flags & SNMP_FLAG_VALUE)
	&& packet->snmp.community.value) {
	xmlFree(packet->snmp.community.value);
    }
}

/*
 * just set the state
 * could evolve into some error-checking and state-keeping fct
 * using a linked list to keep track of parent-states
 */
static void
set_state(int newState) {
    state = newState;
}

/*
 * parse node currently in reader for snmp_int32_t
 */
static void
process_snmp_int32(xmlTextReaderPtr reader, snmp_int32_t* snmpint) {
    char *end;
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpint->value = (int32_t) strtol((char *) value, &end, 10);
	if (*end == '\0' && *value != '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_uint32_t
 */
static void
process_snmp_uint32(xmlTextReaderPtr reader, snmp_uint32_t* snmpint) {
    char *end;
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpint->value = (uint32_t) strtoul((char *) value, &end, 10);
	if (*end == '\0' && *value != '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_uint64_t
 */
static void
process_snmp_uint64(xmlTextReaderPtr reader, snmp_uint64_t* snmpint) {
    char *end;
    assert(snmpint);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpint->value = (uint64_t) strtoull((char *) value, &end, 10);
	if (*end == '\0' && *value != '\0') {
	    snmpint->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
 * parse node currently in reader for snmp_ipaddr_t
 */
static void
process_snmp_ipaddr(xmlTextReaderPtr reader, snmp_ipaddr_t* snmpaddr) {
    assert(snmpaddr);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	if (inet_pton(AF_INET, (const char*) value, &(snmpaddr->value)) > 0) {
	    snmpaddr->attr.flags |= SNMP_FLAG_VALUE;
	}
	/*
	// IPv6 not allowed here
	else if (inet_pton(AF_INET6, value,  &(snmpaddr->value)) > 0) {
	    snmpaddr->attr.flags |= SNMP_FLAG_VALUE;
	}
	*/
    }
}

/* helper function for dehexify */
static int
char_to_i(char c){
    int n = c;
    if (n >= '0' && n <= '9') {
	n -= '0';
    } else if (n >= 'a' && n <= 'f') {
	n -= 'a' - 10;
    } else if (n >= 'A' && n <= 'F') {
	n -= 'A' - 10;
    } else {
	n = -1;
    }
    return n;
}

/*
 * convert octet string into string (i.e. xml -> pcap)
 * fills in length
 * returned buffer is NOT null-terminated and may contain \0 at any position
 * user has to deallocate returned buffer
 */
static unsigned char*
dehexify(const char *str, unsigned *length) {
    static size_t size = 0; /* buffer size, i.e. length of output 
			     * which is strlen(str)/2
			     */
    static unsigned char *buffer = NULL;
    int i;
    int tmp, tmp2;
    
    if (strlen(str)%2 != 0) {
	/* octet string implies pairs of hex numbers */
	return NULL;
    }
    size = strlen(str)/2;
    assert(size);
    buffer = malloc(size);
    assert(buffer);
    memset(buffer, 0, size);
    for (i = 0; i < size; i++) {
	tmp = char_to_i(str[2*i]);
	tmp2 = char_to_i(str[2*i+1]);
	if (tmp < 0 || tmp2 < 0) {
	    /* encountered invalid character */
	    free(buffer);
	    return NULL;
	}
	buffer[i] = tmp*16 + tmp2;
    }
    *length = size;
    DEBUG("dehexify(%s): %s\n", str, buffer);
    return buffer;
}

/*
 * parse node currently in reader for snmp_octs_t
 */
static void
process_snmp_octs(xmlTextReaderPtr reader, snmp_octs_t* snmpstr) {
    assert(snmpstr);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpstr->value = dehexify((const char *) value, &snmpstr->len);
	if (snmpstr->value)
	    snmpstr->attr.flags |= SNMP_FLAG_VALUE;
    }
}

/*
 * return number of numbers in oid (number of dots + 1)
 * WARNING: not xmlChar-safe
 */
static int
count_snmp_oid(const char* value) {
    const char *p;
    int count = 0;

    if (value) {
	count++;
	for (p = value; *p; p++) {
	    count += (*p == '.');
	}
    }
    return count;
}

/*
 * parse node currently in reader for snmp_oid_t
 */
static void
process_snmp_oid(xmlTextReaderPtr reader, snmp_oid_t* snmpoid) {
    int i;
    char *end;
    int count = 0;
    assert(snmpoid);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    count = count_snmp_oid((const char*) value);
    if (value && count > 0) {
	snmpoid->value = malloc(sizeof(uint32_t)*count);
	assert(snmpoid->value);
	memset(snmpoid->value, 0, sizeof(uint32_t)*count);
	snmpoid->len = count;

	snmpoid->value[0] = (uint32_t) strtoul((const char *) value, &end, 10);
	if (*end == '\0' || *end == '.') {
	    if (!(snmpoid->value[0] >= 0 && snmpoid->value[0] <= 2)) {
		ERROR("warning: oid first value %d should be in  0..2\n",
		      snmpoid->value[0]);
	    }
	}
	for(i=1;i<count && *end == '.';i++) {
	    value = (xmlChar*) end+1;
	    //end = NULL;
	    snmpoid->value[i] = (uint32_t) strtoul((const char *) value, &end, 10);
	}
	
	if (*end == '\0' && *value != '\0') {
	    snmpoid->attr.flags |= SNMP_FLAG_VALUE;
	}
    }
}

/*
  parse node currently in reader for snmp_attr_t blen and vlen  
 */
static void
process_snmp_attr(xmlTextReaderPtr reader, snmp_attr_t* attr) {
    xmlChar* strattr;
    /* attributes */
    /* blen */
    assert(attr);
    strattr = xmlTextReaderGetAttribute(reader, BAD_CAST("blen"));
    if (strattr) {
	attr->blen = atoi((char*)strattr);
	attr->flags |= SNMP_FLAG_BLEN;
	//DEBUG("snmp-blen: %d\n", attr->blen);
	xmlFree(strattr);
    }
    /* vlen */
    strattr = xmlTextReaderGetAttribute(reader, BAD_CAST("vlen"));
    if (strattr) {
	attr->vlen = atoi((char*)strattr);
	attr->flags |= SNMP_FLAG_VLEN;
	//DEBUG("snmp-vlen: %d\n", attr->vlen);
	xmlFree(strattr);
    }
}

/*
 * process node currently in reader by filling in snmp_packet_t structure
 * allocates a new snmp_packet_t when new "packet" xml node is reached
 * when end of "packet" xml node is reached, callback function is called
 */
static void
process_node(xmlTextReaderPtr reader, snmp_packet_t* packet,
	     snmp_varbind_t** varbind, snmp_callback func, void *user_data) {
    const xmlChar *name, *value;

    assert(packet);
    /* 1, 3, 8, 14, 15 */
    switch (xmlTextReaderNodeType(reader)) {
    case XML_READER_TYPE_ELEMENT:
	/*
	 * check what node we have:
	 * first has to come snmptrace
	 * node packet - allocate new snmp_msg_t
	 * other nodes - allocate respective storage part within
	 *		 current snmp_msg_t and fill in data
	 */
	name = xmlTextReaderConstName(reader);
	if (name == NULL)
	    name = BAD_CAST "--";
	/* packet */
	if (name && xmlStrcmp(name, BAD_CAST("packet")) == 0) {
	    DEBUG("in PACKET\n");
	    set_state(IN_PACKET);
	    memset(packet, 0, sizeof(snmp_packet_t));
	    *varbind = NULL;
	    /* no attributes */
	    packet->attr.flags |= SNMP_FLAG_VALUE;
	/* time-sec */
	} else if (name && xmlStrcmp(name, BAD_CAST("time-sec")) == 0) {
	    DEBUG("in TIME-SEC\n");
	    set_state(IN_TIME_SEC);
	    /* no attributes */
	/* time-usec */
	} else if (name && xmlStrcmp(name, BAD_CAST("time-usec")) == 0) {
	    DEBUG("in TIME-USEC\n");
	    set_state(IN_TIME_USEC);
	    /* no attributes */
	/* src-ip */
	} else if (name && xmlStrcmp(name, BAD_CAST("src-ip")) == 0) {
	    DEBUG("in SRC-IP\n");
	    set_state(IN_SRC_IP);
	    /* no attributes */
	/* src-port */
	} else if (name && xmlStrcmp(name, BAD_CAST("src-port")) == 0) {
	    DEBUG("in SRC-PORT\n");
	    set_state(IN_SRC_PORT);
	    /* no attributes */
	/* dst-ip */
	} else if (name && xmlStrcmp(name, BAD_CAST("dst-ip")) == 0) {
	    DEBUG("in DST-IP\n");
	    set_state(IN_DST_IP);
	    /* no attributes */
	/* dst-port */
	} else if (name && xmlStrcmp(name, BAD_CAST("dst-port")) == 0) {
	    DEBUG("in DST-PORT\n");
	    set_state(IN_DST_PORT);
	    /* no attributes */
	/* snmp */
	} else if (name && xmlStrcmp(name, BAD_CAST("snmp")) == 0) {
	    DEBUG("in SNMP\n");
	    //assert(state == IN_PACKET);
	    set_state(IN_SNMP);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.attr));
	    packet->snmp.attr.flags |= SNMP_FLAG_VALUE;
	/* version */
	} else if (name && xmlStrcmp(name, BAD_CAST("version")) == 0) {
	    assert(state == IN_SNMP);
	    set_state(IN_VERSION);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.version.attr));
	/* community */
	} else if (name && xmlStrcmp(name, BAD_CAST("community")) == 0) {
	    set_state(IN_COMMUNITY);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.community.attr));
	/* trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("trap")) == 0) {
	    set_state(IN_TRAP);
	    packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_TRAP1;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.pdu.attr));
	    packet->snmp.scoped_pdu.pdu.attr.flags |= SNMP_FLAG_VALUE;
	/* enterprise */
	} else if (name && xmlStrcmp(name, BAD_CAST("enterprise")) == 0) {
	    set_state(IN_ENTERPRISE);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.pdu.enterprise.attr));
	/* agent-addr */
	} else if (name && xmlStrcmp(name, BAD_CAST("agent-addr")) == 0) {
	    set_state(IN_AGENT_ADDR);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.pdu.agent_addr.attr));
	/* generic-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("generic-trap")) == 0) {
	    set_state(IN_GENERIC_TRAP);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.generic_trap.attr));
	/* specific-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("specific-trap")) == 0) {
	    set_state(IN_SPECIFIC_TRAP);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.specific_trap.attr));
	/* time-stamp */
	} else if (name && xmlStrcmp(name, BAD_CAST("time-stamp")) == 0) {
	    set_state(IN_TIME_STAMP);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.time_stamp.attr));
	/*
	 * get-request | get-next-request | get-bulk-request |
         * set-request | inform-request | snmpV2-trap | response | report
	 */
	} else if (name &&
		   (xmlStrcmp(name, BAD_CAST("get-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-next-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("set-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("inform")) == 0
		    || xmlStrcmp(name, BAD_CAST("inform-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("trap2")) == 0
		    || xmlStrcmp(name, BAD_CAST("snmpV2-trap")) == 0
		    || xmlStrcmp(name, BAD_CAST("response")) == 0
		    || xmlStrcmp(name, BAD_CAST("report")) == 0
		    )) {
	    /* state */
	    if (xmlStrcmp(name, BAD_CAST("get-request")) == 0) {
		set_state(IN_GET_REQUEST);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_GET;
	    } else if (xmlStrcmp(name, BAD_CAST("get-next-request")) == 0) {
		set_state(IN_GET_NEXT_REQUEST);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_GETNEXT;
	    } else if (xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0) {
		set_state(IN_GET_BULK_REQUEST);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_GETBULK;
	    } else if (xmlStrcmp(name, BAD_CAST("set-request")) == 0) {
		set_state(IN_SET_REQUEST);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_SET;
	    } else if (xmlStrcmp(name, BAD_CAST("inform")) == 0
		|| xmlStrcmp(name, BAD_CAST("inform-request")) == 0) {
		set_state(IN_INFORM);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_INFORM;
	    } else if (xmlStrcmp(name, BAD_CAST("trap2")) == 0
		|| xmlStrcmp(name, BAD_CAST("snmpV2-trap")) == 0) {
		set_state(IN_TRAP2);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_TRAP2;
	    } else if (xmlStrcmp(name, BAD_CAST("response")) == 0) {
		set_state(IN_RESPONSE);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_RESPONSE;
	    } else if (xmlStrcmp(name, BAD_CAST("report")) == 0) {
		set_state(IN_REPORT);
		packet->snmp.scoped_pdu.pdu.type = SNMP_PDU_REPORT;
	    }
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.attr));
	    packet->snmp.scoped_pdu.pdu.attr.flags |= SNMP_FLAG_VALUE;
	/* request-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("request-id")) == 0) {
	    set_state(IN_REQUEST_ID);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.req_id.attr));
	/* error-status */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-status")) == 0) {
	    set_state(IN_ERROR_STATUS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.err_status.attr));
	/* error-index */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-index")) == 0) {
	    set_state(IN_ERROR_INDEX);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.err_index.attr));
	/* variable-bindings */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("variable-bindings")) == 0) {
	    set_state(IN_VARIABLE_BINDINGS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &(packet->snmp.scoped_pdu.pdu.varbindings.attr));
	    packet->snmp.scoped_pdu.pdu.varbindings.attr.flags
		|= SNMP_FLAG_VALUE;
	/* varbind */
	} else if (name && xmlStrcmp(name, BAD_CAST("varbind")) == 0) {
	    set_state(IN_VARBIND);
	    if (*varbind != NULL) {
		(*varbind)->next =
		    (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		*varbind = (*varbind)->next;
	    } else {
		*varbind = (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		packet->snmp.scoped_pdu.pdu.varbindings.varbind = *varbind;
	    }
	    assert(*varbind);
	    memset(*varbind,0,sizeof(snmp_varbind_t));
	    //DEBUG("malloc... *varbind: %x\n", *varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(*varbind)->attr);
	/* varbind - name */
	} else if (name && xmlStrcmp(name, BAD_CAST("name")) == 0) {
	    assert(state == IN_VARBIND);
	    set_state(IN_NAME);
	    assert(*varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->name.attr));
	/* varbind (- value) - null */
	} else if (name && xmlStrcmp(name, BAD_CAST("null")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NULL); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NULL;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.null.attr));
	/* varbind (- value) - integer32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("integer32")) == 0) {
	    DEBUG("in INTEGER32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_INTEGER32); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_INT32;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.i32.attr));
	/* varbind (- value) - unsigned32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("unsigned32")) == 0) {
	    DEBUG("in UNSIGNED32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_UNSIGNED32); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_UINT32;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u32.attr));
	/* varbind (- value) - counter32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("counter32")) == 0) {
	    DEBUG("in COUNTER32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_COUNTER32); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_COUNTER32;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u32.attr));
	/* varbind (- value) - timeticks */
	} else if (name && xmlStrcmp(name, BAD_CAST("timeticks")) == 0) {
	    DEBUG("in TIMETICKS\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_TIMETICKS); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_TIMETICKS;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u32.attr));
	/* varbind (- value) - counter64 */
	} else if (name && (xmlStrcmp(name, BAD_CAST("counter64")) == 0
		       || xmlStrcmp(name, BAD_CAST("unsigned64")) == 0)) {
	    DEBUG("in COUNTER64\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_COUNTER64); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_COUNTER64;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u64.attr));
	/* varbind (- value) - ipaddress */
	} else if (name && xmlStrcmp(name, BAD_CAST("ipaddress")) == 0) {
	    DEBUG("in IPADDRESS\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_IPADDRESS); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_IPADDR;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.ip.attr));
	/* varbind (- value) - octet-string */
	} else if (name && xmlStrcmp(name, BAD_CAST("octet-string")) == 0) {
	    DEBUG("in OCTET-STRING\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OCTET_STRING); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OCTS;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.octs.attr));
	/* varbind (- value) - object-identifier */
	} else if (name &&
		   xmlStrcmp(name, BAD_CAST("object-identifier")) == 0) {
	    DEBUG("in OBJECT-IDENTIFIER\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OBJECT_IDENTIFIER); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OID;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.oid.attr));
	} else if (name && xmlStrcmp(name, BAD_CAST("opaque")) == 0) {
	    DEBUG("in OPAQUE\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OPAQUE); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OPAQUE;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.octs.attr));
	/* varbind (- value) - no-such-object */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-object")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_OBJECT); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_OBJ;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.null.attr));
	/* varbind (- value) - no-such-instance */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-instance")) == 0){
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_INSTANCE); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_INST;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.null.attr));
	/* varbind (- value) - end-of-mib-view */
	} else if (name && xmlStrcmp(name, BAD_CAST("end-of-mib-view")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_END_OF_MIB_VIEW); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_END_MIB_VIEW;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.null.attr));
	/* varbind (- value) - value */
	} else if (name && xmlStrcmp(name, BAD_CAST("value")) == 0) {
	    if (state != IN_NAME) {
		ERROR("varbind value before name\n");
	    }
	    /* we should also check if parrent is a varbind */
	    set_state(IN_VALUE); 
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_VALUE;
	    (*varbind)->attr.flags |= SNMP_FLAG_VALUE;
	    /* should be empty */
	/* SNMPv3 msg */
	} else if (name && xmlStrcmp(name, BAD_CAST("message")) == 0) {
	    DEBUG("in MESSAGE\n");
	    set_state(IN_MESSAGE);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &packet->snmp.message.attr);
	    packet->snmp.message.attr.flags |= SNMP_FLAG_VALUE;
	/* msg-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("msg-id")) == 0) {
	    set_state(IN_MSG_ID);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.message.msg_id.attr));
	/* max-size */
	} else if (name && xmlStrcmp(name, BAD_CAST("max-size")) == 0) {
	    set_state(IN_MAX_SIZE);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			      &(packet->snmp.message.msg_max_size.attr));
	/* flags */
	} else if (name && xmlStrcmp(name, BAD_CAST("flags")) == 0) {
	    set_state(IN_FLAGS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.message.msg_flags.attr));
	/* security-model */
	} else if (name && xmlStrcmp(name, BAD_CAST("security-model")) == 0) {
	    set_state(IN_SEC_MODEL);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			      &(packet->snmp.message.msg_sec_model.attr));
	/* usm */
	} else if (name && xmlStrcmp(name, BAD_CAST("usm")) == 0) {
	    set_state(IN_USM);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.attr));
	    packet->snmp.usm.attr.flags |= SNMP_FLAG_VALUE;
	/* scoped-pdu */
	} else if (name && xmlStrcmp(name, BAD_CAST("scoped-pdu")) == 0) {
	    set_state(IN_SCOPED_PDU);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.attr));
	    packet->snmp.scoped_pdu.attr.flags |= SNMP_FLAG_VALUE;
	/* context-engine-id */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("context-engine-id")) == 0) {
	    set_state(IN_CONTEXT_ENGINE_ID);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.
					context_engine_id.attr));
	/* context-name */
	} else if (name && xmlStrcmp(name, BAD_CAST("context-name")) == 0) {
	    set_state(IN_CONTEXT_NAME);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.scoped_pdu.
					context_name.attr));
	/* auth-engine-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("auth-engine-id")) == 0) {
	    set_state(IN_AUTH_ENGINE_ID);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					auth_engine_id.attr));
	/* auth-engine-boots */
	} else if (name 
		   && xmlStrcmp(name, BAD_CAST("auth-engine-boots")) == 0) {
	    set_state(IN_AUTH_ENGINE_BOOTS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					auth_engine_boots.attr));
	/* auth-engine-time */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("auth-engine-time")) == 0) {
	    set_state(IN_AUTH_ENGINE_TIME);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					auth_engine_time.attr));
	/* user */
	} else if (name && xmlStrcmp(name, BAD_CAST("user")) == 0) {
	    set_state(IN_USER);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					user.attr));
	/* auth-params */
	} else if (name && xmlStrcmp(name, BAD_CAST("auth-params")) == 0) {
	    set_state(IN_AUTH_PARAMS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					auth_params.attr));
	/* priv-params */
	} else if (name && xmlStrcmp(name, BAD_CAST("priv-params")) == 0) {
	    set_state(IN_PRIV_PARAMS);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &(packet->snmp.usm.
					priv_params.attr));
	} else {
	    state = IN_NONE;
	}
	break;
    case XML_READER_TYPE_TEXT:
	value = xmlTextReaderConstValue(reader);
	//xmlStrlen(value)
	//printf(" %s\n", value);
	switch (state) {
	case IN_TIME_SEC:
	    process_snmp_uint32(reader, &(packet->time_sec));
	    break;
	case IN_TIME_USEC:
	    process_snmp_uint32(reader, &(packet->time_usec));
	    break;
	case IN_SRC_IP:
	    process_snmp_ipaddr(reader, &(packet->src_addr));
	    break;
	case IN_SRC_PORT:
	    process_snmp_uint32(reader, &(packet->src_port));
	    break;
	case IN_DST_IP:
	    process_snmp_ipaddr(reader, &(packet->dst_addr));
	    break;
	case IN_DST_PORT:
	    process_snmp_uint32(reader,  &(packet->dst_port));
	    break;
	case IN_VERSION:
	    process_snmp_int32(reader,  &packet->snmp.version);
	    if (packet->snmp.version.attr.flags & SNMP_FLAG_VALUE) {
		if (packet->snmp.version.value <0
		    || packet->snmp.version.value >3) {
		    ERROR("warning: invalid SNMP version %d\n",
			  packet->snmp.version.value);
		    //packet->snmp.version.attr.flags &= !SNMP_FLAG_VALUE;
		}
	    }
	    break;
	case IN_COMMUNITY:
	    process_snmp_octs(reader, &(packet->snmp.community));
	    break;
	case IN_ENTERPRISE:
	    process_snmp_oid(reader, &(packet->snmp.scoped_pdu.pdu.enterprise));
	    break;
	case IN_AGENT_ADDR:
	    process_snmp_ipaddr(reader,
				&packet->snmp.scoped_pdu.pdu.agent_addr);
	    	    break;
	case IN_GENERIC_TRAP:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.generic_trap));
	    break;
	case IN_SPECIFIC_TRAP:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.specific_trap));
	    break;
	case IN_TIME_STAMP:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.time_stamp));
	    break;
	case IN_REQUEST_ID:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.req_id));
	    break;
	case IN_ERROR_STATUS:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.err_status));
	    break;
	case IN_ERROR_INDEX:
	    process_snmp_int32(reader, &(packet->snmp.scoped_pdu.pdu.err_index));
	    break;
	/* varbind */
	case IN_NAME:
	    assert(*varbind);
	    process_snmp_oid(reader, &((*varbind)->name));
	    break;
	case IN_INTEGER32:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_INT32);
	    process_snmp_int32(reader, &((*varbind)->value.i32));
	    break;
	case IN_UNSIGNED32:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_UINT32);
	    process_snmp_uint32(reader, &((*varbind)->value.u32));
	    break;
	case IN_COUNTER32:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_COUNTER32);
	    process_snmp_uint32(reader, &((*varbind)->value.u32));
	    break;
	case IN_TIMETICKS:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_TIMETICKS);
	    process_snmp_uint32(reader, &((*varbind)->value.u32));
	    break;
	case IN_COUNTER64:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_COUNTER64);
	    process_snmp_uint64(reader, &((*varbind)->value.u64));
	    break;
	case IN_IPADDRESS:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_IPADDR);
	    process_snmp_ipaddr(reader, &((*varbind)->value.ip));
	    break;
	case IN_OCTET_STRING:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_OCTS);
	    process_snmp_octs(reader, &((*varbind)->value.octs));
	    break;
	case IN_OBJECT_IDENTIFIER:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_OID);
	    process_snmp_oid(reader, &((*varbind)->value.oid));
	    break;
	case IN_OPAQUE:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_OPAQUE);
	    process_snmp_octs(reader, &((*varbind)->value.octs));
	    break;
	/* snmpv3 */
	case IN_MSG_ID:
	    process_snmp_uint32(reader, &(packet->snmp.message.msg_id));
	    break;
	case IN_MAX_SIZE:
	    process_snmp_uint32(reader, &(packet->snmp.message.msg_max_size));
	    break;
	case IN_FLAGS:
	    process_snmp_octs(reader, &(packet->snmp.message.msg_flags));
	    break;
	case IN_SEC_MODEL:
	    process_snmp_uint32(reader, &(packet->snmp.message.msg_sec_model));
	    break;
	case IN_AUTH_ENGINE_ID:
	    process_snmp_octs(reader, &(packet->snmp.usm.
					auth_engine_id));
	    break;
	case IN_AUTH_ENGINE_BOOTS:
	    process_snmp_uint32(reader, &(packet->snmp.usm.
					  auth_engine_boots));
	    break;
	case IN_AUTH_ENGINE_TIME:
	    process_snmp_uint32(reader, &(packet->snmp.usm.
				    auth_engine_time));
	    break;
	case IN_USER:
	    process_snmp_octs(reader, &(packet->snmp.usm.user));
	    break;
	case IN_AUTH_PARAMS:
	    process_snmp_octs(reader, &(packet->snmp.usm.
					auth_params));
	    break;
	case IN_PRIV_PARAMS:
	    process_snmp_octs(reader, &(packet->snmp.usm.
					priv_params));
	    break;
	case IN_CONTEXT_ENGINE_ID:
	    process_snmp_octs(reader, &(packet->snmp.scoped_pdu.
				    context_engine_id));
	    break;
	case IN_CONTEXT_NAME:
	    process_snmp_octs(reader, &(packet->snmp.scoped_pdu.
				    context_name));
	    break;
	}
	break;
    case XML_READER_TYPE_COMMENT:
	return;
    case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
	return;
    case XML_READER_TYPE_END_ELEMENT:
	name = xmlTextReaderConstName(reader);
	if (name == NULL)
	    name = BAD_CAST "--";
	/* packet */
	if (name && xmlStrcmp(name, BAD_CAST("packet")) == 0) {
	    // call calback function and give it filled-in snmp_packet_t object
	    DEBUG("out PACKET\n");
	    func(packet, user_data);
	    snmp_packet_free(packet);
	}
	break;
    default:
	fprintf(stderr, "unknown xml node type: %d\n",
		xmlTextReaderNodeType(reader));
	break;
    }

    /* dump name, values */
    #ifdef debug
    name = xmlTextReaderConstName(reader);
    if (name == NULL)
        name = BAD_CAST "--";
    
    value = xmlTextReaderConstValue(reader);
    
    printf("%d %d %s %d %d", 
            xmlTextReaderDepth(reader),
	   xmlTextReaderNodeType(reader),
	   name,
	   xmlTextReaderIsEmptyElement(reader),
	   xmlTextReaderHasValue(reader));
    if (value == NULL)
        printf("\n");
    else {
        if (xmlStrlen(value) > 40)
            printf(" %.40s...\n", value);
        else
            printf(" %s\n", value);
    }
    #endif
}


static void
process_reader(xmlTextReaderPtr reader, snmp_callback func, void *user_data)
{
    snmp_packet_t packet;
    snmp_varbind_t *varbind = NULL;
    int ret;
	
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	process_node(reader, &packet, &varbind, func, user_data);
	ret = xmlTextReaderRead(reader);
    }
    xmlFreeTextReader(reader);
    if (ret != 0) {
	fprintf(stderr, "xmlTextReaderRead: failed to parse\n");
	//return -2;
    }

}

void
snmp_xml_read_file(const char *file, snmp_callback func, void *user_data)
{
    xmlTextReaderPtr reader;

    assert(file);
    
    reader = xmlNewTextReaderFilename(file);
    if (! reader) {
	fprintf(stderr, "%s: failed to open XML file '%s'\n",
		progname, file);
	return;
    }

    process_reader(reader, func, user_data);
}

void
snmp_xml_read_stream(FILE *stream, snmp_callback func, void *user_data)
{
    xmlTextReaderPtr reader;
    xmlParserInputBufferPtr input;

    assert(stream);
	
    input = xmlParserInputBufferCreateFile(stream, XML_CHAR_ENCODING_NONE);
    if (! input) {
	fprintf(stderr, "%s: failed to open XML stream\n", progname);
	return;
    }
    reader = xmlNewTextReader(input, NULL);
    if (! reader) {
	xmlFreeParserInputBuffer(input);
	fprintf(stderr, "%s: failed to create XML reader\n", progname);
	return;
    }
    
    process_reader(reader, func, user_data);
}

