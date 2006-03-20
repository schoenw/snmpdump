/*
 * deserializer.c --
 *
 * A simple C program to deserialize XML representation of SNMP
 * traffic traces.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 * (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
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

#define debug 1
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
	IN_UNSIGNED64,
	IN_IPADDRESS,
	IN_OCTET_STRING,
	IN_OBJECT_IDENTIFIER,
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
 * deallocate snmp_packet_t and all its data members
 * TODO: (xml)string deallocation (also in other parts of packet)
 */
void
snmp_packet_free(snmp_packet_t* packet) {
    snmp_varbind_t* varbind;
    snmp_varbind_t* next;
    assert(packet);
    /* free varbinds */
    next = packet->msg.scoped_pdu.pdu.varbindings.varbind;
    while (next) {
	varbind = next;
	//DEBUG("freeing... varbind: %x\n", varbind);
	if (varbind->type == SNMP_TYPE_OCTS) {
	    if (varbind->value.octs.value) {
		free(varbind->value.octs.value);
		//xmlFree(varbind->value.octs.value);
	    }
	}  else if (varbind->type == SNMP_TYPE_OCTS) {
	    if (varbind->value.oid.value) {
		free(varbind->value.oid.value);
	    }
	}
	next = next->next;
	free(varbind);
    }
    /* free community string */
    if (packet->msg.community.attr.flags & SNMP_FLAG_VALUE) {
	assert(packet->msg.community.value);
	xmlFree(packet->msg.community.value);
    }
    free(packet);
}

/*
 * just set the state
 * could evolve into some error-checking and state-keeping fct
 * using a linked listto keep track of parent-states
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
	if (*end == '\0') {
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
	if (*end == '\0') {
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
	if (*end == '\0') {
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
	if (inet_pton(AF_INET, value, &(snmpaddr->value)) > 0) {
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
	n -= 'F' - 10;
    } else {
	n = -1;
    }
    return n;
}

/*
 * convert octet string into string (i.e. xml -> pcap)
 * user has to deallocate returned buffer
 */
static char*
dehexify(const char *str) {
    static size_t size = 0; /* buffer size, i.e. length of output 
			     * which is strlen(str)/2
			     */
    static char *buffer = NULL;
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
    DEBUG("dehexify(%s): %s\n", str, buffer);
    return buffer;
}

/*
 * parse node currently in reader for snmp_octs_t
 * we're using the xmlString, maybe we should rather copy it !!!
 * user has to call xmlFree in this string !!!
 */
static void
process_snmp_octs(xmlTextReaderPtr reader, snmp_octs_t* snmpstr) {
    assert(snmpstr);
    //xmlChar* value = xmlTextReaderValue(reader);
    const xmlChar* value = xmlTextReaderConstValue(reader);
    if (value) {
	snmpstr->value = (unsigned char*) dehexify((const char *) value);
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
	
	snmpoid->value[0] = (uint32_t) strtoul((const char *) value, &end, 10);
	if (*end == '\0' || *end == '.') {
	    if (!(snmpoid->value[0] >= 0 && snmpoid->value[0] <= 2)) {
		ERROR("warning: oid first value %d should be in  0..2\n",
		      snmpoid->value[0]);
	    }
	}
	for(i=1;i<128 && i<count && *end == '.';i++) {
	    value = (xmlChar*) end+1;
	    //end = NULL;
	    snmpoid->value[i] = (uint32_t) strtoul((const char *) value, &end, 10);
	}
	
	if (*end == '\0') {
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
process_node(xmlTextReaderPtr reader, snmp_packet_t** packet,
	     snmp_varbind_t** varbind) {
    const xmlChar *name, *value;
    xmlChar* attr;
    char *end;

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
	    *packet = (snmp_packet_t*) malloc(sizeof(snmp_packet_t));
	    assert(*packet);
	    memset(*packet, 0, sizeof(snmp_packet_t));
	    *varbind = NULL;
	    /* attributes */
	    /* date */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("date"));
	    if (attr) {
		strptime(attr, "%FT%H:%M:%S", &((*packet)->time));
		(*packet)->msg.attr.flags |= SNMP_FLAG_DATE;
		xmlFree(attr);
	    }
	    /* delta */
	    /*
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("delta"));
	    if (attr) {
		(*packet)->delta =
		    (unsigned long) strtoll((char*) attr, &end, 10);
		assert(strtoll((char*) attr, &end, 10) >= 0);
		if (*end == '\0') {
		    (*packet)->msg.attr.flags |= SNMP_FLAG_DELTA;
		}
		xmlFree(attr);
	    }
	    */
	    //value = xmlTextReaderGetAttribute(reader, BAD_CAST("delta"));
	/* src */
	} else if (name && xmlStrcmp(name, BAD_CAST("src")) == 0) {
	    DEBUG( "in SRC\n");
	    /* no state */
	    assert(state == IN_PACKET);
	    assert(*packet);
	    /* attributes */
	    /* ip */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("ip"));
	    if (attr) {
		if (inet_pton(AF_INET, attr, &((*packet)->src)) > 0) {
		    (*packet)->msg.attr.flags |= SNMP_FLAG_SADDR;
		} else if (inet_pton(AF_INET6, attr, &((*packet)->src)) > 0) {
			(*packet)->msg.attr.flags |= SNMP_FLAG_SADDR;
		}
		//DEBUG("ip: %s\n", inet_ntoa((*packet)->src));
		xmlFree(attr);
	    }
	    /* port */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("port"));
	    if (attr) {
		/*
		((struct sockaddr_in*)(&((*packet)->src)))->sin_port =
		    htons(atoi((char*) attr));
		(*packet)->msg.attr.flags |= SNMP_FLAG_SPORT;
		*/
		switch((*packet)->src.ss_family) {
		case AF_INET6:
		    ((struct sockaddr_in6*)(&((*packet)->src)))->sin6_port =
			htons(atoi((char*) attr));
		    (*packet)->msg.attr.flags |= SNMP_FLAG_SPORT;
		    break;
		default:
		    ((struct sockaddr_in*)(&((*packet)->src)))->sin_port =
			htons(atoi((char*) attr));
		    (*packet)->msg.attr.flags |= SNMP_FLAG_SPORT;
		    break;
		}
		xmlFree(attr);
	    }
	/* dst */
	} else if (name && xmlStrcmp(name, BAD_CAST("dst")) == 0) {
	    DEBUG("in DST\n");
	    /* no state */
	    assert(state == IN_PACKET);
	    assert((*packet));
	    /* attributes */
	    /* ip */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("ip"));
	    if (attr) {
		if (inet_pton(AF_INET, attr, &((*packet)->dst)) > 0) {
		    (*packet)->msg.attr.flags |= SNMP_FLAG_DADDR;
		} else if (inet_pton(AF_INET6, attr, &((*packet)->dst)) > 0) {
		    (*packet)->msg.attr.flags |= SNMP_FLAG_DADDR;
		}
		//DEBUG("ip: %s\n", inet_ntoa((*packet)->dst));
		xmlFree(attr);
	    }
	    /* port */
	    attr = xmlTextReaderGetAttribute(reader, BAD_CAST("port"));
	    if (attr) {
		/*
		((struct sockaddr_in*)(&((*packet)->dst)))->sin_port =
		    htons(atoi((char*) attr));
		(*packet)->msg.attr.flags |= SNMP_FLAG_DPORT;
		*/
		switch((*packet)->dst.ss_family) {
		case AF_INET6:
		    ((struct sockaddr_in6*)(&((*packet)->dst)))->sin6_port =
			htons(atoi((char*) attr));
		    (*packet)->msg.attr.flags |= SNMP_FLAG_DPORT;
		    break;
		default:
		    ((struct sockaddr_in*)(&((*packet)->dst)))->sin_port =
			htons(atoi((char*) attr));
		    (*packet)->msg.attr.flags |= SNMP_FLAG_DPORT;
		    break;
		}
		xmlFree(attr);
	    }
	/* snmp */
	} else if (name && xmlStrcmp(name, BAD_CAST("snmp")) == 0) {
	    DEBUG("in SNMP\n");
	    assert(state == IN_PACKET);
	    set_state(IN_SNMP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.attr));
	/* version */
	} else if (name && xmlStrcmp(name, BAD_CAST("version")) == 0) {
	    assert(state == IN_SNMP);
	    set_state(IN_VERSION);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.version.attr));
	/* community */
	} else if (name && xmlStrcmp(name, BAD_CAST("community")) == 0) {
	    set_state(IN_COMMUNITY);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.community.attr));
	/* trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("trap")) == 0) {
	    set_state(IN_TRAP);
	    assert((*packet));
	    (*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_TRAP1;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.scoped_pdu.pdu.attr));
	/* enterprise */
	} else if (name && xmlStrcmp(name, BAD_CAST("enterprise")) == 0) {
	    set_state(IN_ENTERPRISE);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.scoped_pdu.pdu.enterprise.attr));
	/* agent-addr */
	} else if (name && xmlStrcmp(name, BAD_CAST("agent-addr")) == 0) {
	    set_state(IN_AGENT_ADDR);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.scoped_pdu.pdu.agent_addr.attr));
	/* generic-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("generic-trap")) == 0) {
	    set_state(IN_GENERIC_TRAP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.generic_trap.attr));
	/* specific-trap */
	} else if (name && xmlStrcmp(name, BAD_CAST("specific-trap")) == 0) {
	    set_state(IN_SPECIFIC_TRAP);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.specific_trap.attr));
	/* time-stamp */
	} else if (name && xmlStrcmp(name, BAD_CAST("time-stamp")) == 0) {
	    set_state(IN_TIME_STAMP);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.time_stamp.attr));
	/*
	 * get-request | get-next-request | get-bulk-request |
         * set-request | inform | trap2 | response | report
	 */
	} else if (name &&
		   (xmlStrcmp(name, BAD_CAST("get-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-next-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("set-request")) == 0
		    || xmlStrcmp(name, BAD_CAST("inform")) == 0
		    || xmlStrcmp(name, BAD_CAST("trap2")) == 0
		    || xmlStrcmp(name, BAD_CAST("response")) == 0
		    || xmlStrcmp(name, BAD_CAST("report")) == 0
		    )) {
	    /* state */
	    assert((*packet));
	    if (xmlStrcmp(name, BAD_CAST("get-request")) == 0) {
		set_state(IN_GET_REQUEST);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_GET;
	    } else if (xmlStrcmp(name, BAD_CAST("get-next-request")) == 0) {
		set_state(IN_GET_NEXT_REQUEST);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_GETNEXT;
	    } else if (xmlStrcmp(name, BAD_CAST("get-bulk-request")) == 0) {
		set_state(IN_GET_BULK_REQUEST);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_GETBULK;
	    } else if (xmlStrcmp(name, BAD_CAST("set-request")) == 0) {
		set_state(IN_SET_REQUEST);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_SET;
	    } else if (xmlStrcmp(name, BAD_CAST("inform")) == 0) {
		set_state(IN_INFORM);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_INFORM;
	    } else if (xmlStrcmp(name, BAD_CAST("trap2")) == 0) {
		set_state(IN_TRAP2);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_TRAP2;
	    } else if (xmlStrcmp(name, BAD_CAST("response")) == 0) {
		set_state(IN_RESPONSE);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_RESPONSE;
	    } else if (xmlStrcmp(name, BAD_CAST("report")) == 0) {
		set_state(IN_REPORT);
		(*packet)->msg.scoped_pdu.pdu.type = SNMP_PDU_REPORT;
	    }
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.attr));
	/* request-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("request-id")) == 0) {
	    set_state(IN_REQUEST_ID);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.req_id.attr));
	/* error-status */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-status")) == 0) {
	    set_state(IN_ERROR_STATUS);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.err_status.attr));
	/* error-index */
	} else if (name && xmlStrcmp(name, BAD_CAST("error-index")) == 0) {
	    set_state(IN_ERROR_INDEX);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.err_index.attr));
	/* variable-bindings */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("variable-bindings")) == 0) {
	    set_state(IN_VARIABLE_BINDINGS);
	    assert(*packet);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			    &((*packet)->msg.scoped_pdu.pdu.varbindings.attr));
	/* varbind */
	} else if (name && xmlStrcmp(name, BAD_CAST("varbind")) == 0) {
	    set_state(IN_VARBIND);
	    assert(*packet);
	    if (*varbind != NULL) {
		(*varbind)->next =
		    (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		*varbind = (*varbind)->next;
	    } else {
		*varbind = (snmp_varbind_t*) malloc(sizeof(snmp_varbind_t));
		(*packet)->msg.scoped_pdu.pdu.varbindings.varbind = *varbind;
	    }
	    assert(*varbind);
	    memset(*varbind,0,sizeof(snmp_varbind_t));
	    //DEBUG("malloc... *varbind: %x\n", *varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->attr));
	/* varbind - name */
	} else if (name && xmlStrcmp(name, BAD_CAST("name")) == 0) {
	    assert(state == IN_VARBIND);
	    set_state(IN_NAME);
	    assert(*packet);
	    assert(*varbind);
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->name.attr));
	/* varbind (- value) - null */
	} else if (name && xmlStrcmp(name, BAD_CAST("null")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NULL); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NULL;
	    //assert((*varbind)->value == NULL);
	    /* should be empty */
	/* varbind (- value) - integer32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("integer32")) == 0) {
	    DEBUG("in INTEGER32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_INTEGER32); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_INT32;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.i32.attr));
	/* varbind (- value) - unsigned32 */
	} else if (name && xmlStrcmp(name, BAD_CAST("unsigned32")) == 0) {
	    DEBUG("in UNSIGNED32\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_UNSIGNED32); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_UINT32;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u32.attr));
	/* varbind (- value) - unsigned64 */
	} else if (name && xmlStrcmp(name, BAD_CAST("unsigned64")) == 0) {
	    DEBUG("in UNSIGNED64\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_UNSIGNED64); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_UINT64;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.u64.attr));
	/* varbind (- value) - ipaddress */
	} else if (name && xmlStrcmp(name, BAD_CAST("ipaddress")) == 0) {
	    DEBUG("in IPADDRESS\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_IPADDRESS); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_IPADDR;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.ip.attr));
	/* varbind (- value) - octet-string */
	} else if (name && xmlStrcmp(name, BAD_CAST("octet-string")) == 0) {
	    DEBUG("in OCTET-STRING\n");
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_OCTET_STRING); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OCTS;
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
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_OID;
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*varbind)->value.oid.attr));
	/* varbind (- value) - no-such-object */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-object")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_OBJECT); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_OBJ;
	    /* should be empty */
	/* varbind (- value) - no-such-instance */
	} else if (name && xmlStrcmp(name, BAD_CAST("no-such-instance")) == 0){
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_NO_SUCH_INSTANCE); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_NO_SUCH_INST;
	    /* should be empty */
	/* varbind (- value) - end-of-mib-view */
	} else if (name && xmlStrcmp(name, BAD_CAST("end-of-mib-view")) == 0) {
	    assert(state == IN_NAME); /* maybe not needed/wanted */
	    /* we should also check if parrent is varbind */
	    set_state(IN_END_OF_MIB_VIEW); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_END_MIB_VIEW;
	    /* should be empty */
	/* varbind (- value) - value */
	} else if (name && xmlStrcmp(name, BAD_CAST("value")) == 0) {
	    if (state != IN_NAME) {
		ERROR("varbind value before name\n");
	    }
	    /* we should also check if parrent is a varbind */
	    set_state(IN_VALUE); 
	    assert(*packet);
	    assert(*varbind);
	    (*varbind)->type = SNMP_TYPE_VALUE;
	    /* should be empty */

	/* SNMPv3 msg */
	} else if (name && xmlStrcmp(name, BAD_CAST("msg")) == 0) {
	    set_state(IN_MESSAGE);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.attr));
	/* msg-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("msg-id")) == 0) {
	    set_state(IN_MSG_ID);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.header.msg_id.attr));
	/* max-size */
	} else if (name && xmlStrcmp(name, BAD_CAST("max-size")) == 0) {
	    set_state(IN_MAX_SIZE);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			      &((*packet)->msg.header.msg_max_size.attr));
	/* flags */
	} else if (name && xmlStrcmp(name, BAD_CAST("flags")) == 0) {
	    set_state(IN_FLAGS);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.header.msg_flags.attr));
	/* security-model */
	} else if (name && xmlStrcmp(name, BAD_CAST("security-model")) == 0) {
	    set_state(IN_SEC_MODEL);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			      &((*packet)->msg.header.msg_sec_model.attr));
	/* usm */
	} else if (name && xmlStrcmp(name, BAD_CAST("usm")) == 0) {
	    set_state(IN_USM);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    /* !!! these attr are missing in the relax ng schema !!! */
	    process_snmp_attr(reader, &((*packet)->msg.usm.attr));
	/* scoped-pdu */
	} else if (name && xmlStrcmp(name, BAD_CAST("scoped-pdu")) == 0) {
	    set_state(IN_SCOPED_PDU);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader,
			      &((*packet)->msg.scoped_pdu.attr));
	/* context-engine-id */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("context-engine-id")) == 0) {
	    set_state(IN_CONTEXT_ENGINE_ID);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.scoped_pdu.
					context_engine_id.attr));
	/* context-name */
	} else if (name && xmlStrcmp(name, BAD_CAST("context-name")) == 0) {
	    set_state(IN_CONTEXT_NAME);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.scoped_pdu.
					context_name.attr));
	/* auth-engine-id */
	} else if (name && xmlStrcmp(name, BAD_CAST("auth-engine-id")) == 0) {
	    set_state(IN_AUTH_ENGINE_ID);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
					auth_engine_id.attr));
	/* auth-engine-boots */
	} else if (name 
		   && xmlStrcmp(name, BAD_CAST("auth-engine-boots")) == 0) {
	    set_state(IN_AUTH_ENGINE_BOOTS);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
					auth_engine_boots.attr));
	/* auth-engine-time */
	} else if (name
		   && xmlStrcmp(name, BAD_CAST("auth-engine-time")) == 0) {
	    set_state(IN_AUTH_ENGINE_TIME);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
					auth_engine_time.attr));
	/* user */
	} else if (name && xmlStrcmp(name, BAD_CAST("user")) == 0) {
	    set_state(IN_USER);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
					user.attr));
	/* auth-params */
	} else if (name && xmlStrcmp(name, BAD_CAST("auth-params")) == 0) {
	    set_state(IN_AUTH_PARAMS);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
					auth_params.attr));
	/* priv-params */
	} else if (name && xmlStrcmp(name, BAD_CAST("priv-params")) == 0) {
	    set_state(IN_PRIV_PARAMS);
	    assert((*packet));
	    /* attributes */
	    /* blen, vlen */
	    process_snmp_attr(reader, &((*packet)->msg.usm.
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
	case IN_VERSION:
	    assert(*packet);
	    if (value) {
		(*packet)->msg.version.value = (int32_t)
		    strtol((char *) value, &end, 10);
		if (*end == '\0'&& (*packet)->msg.version.value >=0
		    && (*packet)->msg.version.value <3) {
		    (*packet)->msg.version.attr.flags |= SNMP_FLAG_VALUE;
		}
	    }
	    break;
	case IN_COMMUNITY:
	    assert(*packet);
	    /*
	    value = xmlTextReaderValue(reader);
	    if (value) {
		(*packet)->msg.community.value = (unsigned char*)value;
		(*packet)->msg.community.len = xmlStrlen(value);
		(*packet)->msg.community.attr.flags |= SNMP_FLAG_VALUE;
	    }
	    */
	    process_snmp_octs(reader, &((*packet)->msg.community));
	    break;
	case IN_ENTERPRISE:
	    assert(*packet);
	    process_snmp_oid(reader, &((*packet)->msg.scoped_pdu.pdu.enterprise));
	    break;
	case IN_AGENT_ADDR:
	    assert(*packet);
	    if (value) {
		if (inet_pton(AF_INET, attr,
			      &((*packet)->msg.scoped_pdu.pdu.agent_addr.value)) > 0){
		    (*packet)->msg.scoped_pdu.pdu.agent_addr.attr.flags
			|= SNMP_FLAG_VALUE;
		} else {
		    if (inet_pton(AF_INET6, attr,
			      &((*packet)->msg.scoped_pdu.pdu.agent_addr.value)) > 0){
			(*packet)->msg.scoped_pdu.pdu.agent_addr.attr.flags
			    |= SNMP_FLAG_VALUE;
		    }
		}
	    }
	    break;
	case IN_GENERIC_TRAP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.generic_trap));
	    break;
	case IN_SPECIFIC_TRAP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.specific_trap));
	    break;
	case IN_TIME_STAMP:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.time_stamp));
	    break;
	case IN_REQUEST_ID:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.req_id));
	    break;
	case IN_ERROR_STATUS:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.err_status));
	    break;
	case IN_ERROR_INDEX:
	    assert(*packet);
	    process_snmp_int32(reader, &((*packet)->msg.scoped_pdu.pdu.err_index));
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
	case IN_UNSIGNED64:
	    assert(*varbind);
	    assert((*varbind)->type == SNMP_TYPE_UINT64);
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
	/* snmpv3 */
	case IN_MSG_ID:
	    assert(*packet);
	    process_snmp_uint32(reader, &((*packet)->msg.header.msg_id));
	    break;
	case IN_MAX_SIZE:
	    assert(*packet);
	    process_snmp_uint32(reader, &((*packet)->msg.header.msg_max_size));
	    break;
	case IN_FLAGS:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.header.msg_flags));
	    break;
	case IN_SEC_MODEL:
	    assert(*packet);
	    process_snmp_uint32(reader, &((*packet)->msg.header.msg_sec_model));
	    break;
	case IN_AUTH_ENGINE_ID:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.usm.
					auth_engine_id));
	    break;
	case IN_AUTH_ENGINE_BOOTS:
	    assert(*packet);
	    process_snmp_uint32(reader, &((*packet)->msg.usm.
					  auth_engine_boots));
	    break;
	case IN_AUTH_ENGINE_TIME:
	    assert(*packet);
	    process_snmp_uint32(reader, &((*packet)->msg.usm.
				    auth_engine_time));
	    break;
	case IN_USER:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.usm.user));
	    break;
	case IN_AUTH_PARAMS:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.usm.
					auth_params));
	    break;
	case IN_PRIV_PARAMS:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.usm.
					priv_params));
	    break;
	case IN_CONTEXT_ENGINE_ID:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.scoped_pdu.
				    context_engine_id));
	    break;
	case IN_CONTEXT_NAME:
	    assert(*packet);
	    process_snmp_octs(reader, &((*packet)->msg.scoped_pdu.
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
	    snmp_packet_free(*packet);
	}
	break;
    default:
	fprintf(stderr, "unkown xml node type: %d\n",
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

#if 0
static int
stream_file(char *filename)
{
    snmp_packet_t *packet = NULL;
    snmp_varbind_t *varbind = NULL;
    xmlTextReaderPtr reader;
    int i, ret;
    
    if (filename) {
	reader = xmlNewTextReaderFilename(filename);
	if (! reader) {
	    return -1;
	}
    } else {
	xmlParserInputBufferPtr input;
	
	input = xmlParserInputBufferCreateFile(stdin,
		       XML_CHAR_ENCODING_NONE);
	if (! input) {
	    return -1;
	}
	reader = xmlNewTextReader(input, NULL);
	if (! reader) {
	    xmlFreeParserInputBuffer(input);
	    return -1;
	}
    }
    
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	process_node(reader, &packet, &varbind);
	ret = xmlTextReaderRead(reader);
    }
    xmlFreeTextReader(reader);
    if (ret != 0) {
	fprintf(stderr, "%s: xmlTextReaderRead: failed to parse '%s'\n",
		progname, filename);
	return -2;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int i;

    if (argc == 1) {
	stream_file(NULL);
    } else {
	for (i = 1; i < argc; i++) {
	    stream_file(argv[i]);
	}
    }
    
    return 0;
}
#endif
