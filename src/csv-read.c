/*
 * csv-read.c --
 *
 * A simple C program to deserialize CSV representation of SNMP
 * traffic traces.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 * (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
 *
 * $Id: csv-read.c 1960 2006-06-14 16:15:34Z schoenw $
 */

#include "config.h"

#include "snmp.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static inline void*
xmalloc(size_t size)
{
    void *p;

    p = malloc(size);
    if (! p) {
	abort();
    }
    memset(p, 0, size);
    return p;
}

/*
 * tokenizes s using delim, modifies s
 * return also empty strings for successive token, as opposed to strtok
 */
static  char*
mytok(char **s, char* delim)
{
    char *c;
    char* str;
    str = *s;

    if (! *s) return NULL; /* end of string s */

    for(c=*s;**s && !strchr(delim, **s);(*s)++);
    if (**s) {
	**s = '\0';
	(*s)++;
    }
    return c;
}

/*
 * Deallocate memory for a parsed SNMP packet.
 */

static void
snmp_free(snmp_packet_t *pkt)
{
    snmp_varbind_t *varbind, *last_varbind;

    varbind = pkt->snmp.scoped_pdu.pdu.varbindings.varbind;

    while (varbind) {
	if (varbind->name.value) {
	    free(varbind->name.value);
	}
	switch (varbind->type) {
	case SNMP_TYPE_OID:
	    if (varbind->value.oid.value) {
		free(varbind->value.oid.value);
	    }
	    break;
	case SNMP_TYPE_OCTS:
	    if (varbind->value.octs.value) {
		free(varbind->value.octs.value);
	    }
	    break;
	default:
	    break;
	}
	last_varbind = varbind;
	varbind = varbind->next;
	free(last_varbind);
    }
}

static void
csv_read_int32(char *s, snmp_int32_t *v)
{
    char *end;

    v->value = (int32_t) strtol(s, &end, 10);
    if (*end == '\0' && *s != '\0') {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_uint32(char *s, snmp_uint32_t *v)
{
    char *end;

    v->value = (uint32_t) strtoul(s, &end, 10);
    if (*end == '\0' && *s != '\0') {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_uint64(char *s, snmp_uint64_t *v)
{
    char *end;

    v->value = (uint64_t) strtoull(s, &end, 10);
    if (*end == '\0' && *s != '\0') {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_ipaddr(char *s, snmp_ipaddr_t *v)
{
    if (inet_pton(AF_INET, s, &(v->value)) > 0) {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_ip6addr(char *s, snmp_ip6addr_t *v)
{
    if (inet_pton(AF_INET6, s, &(v->value)) > 0) {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_type(char *s, snmp_pdu_t *v)
{
    if (strcmp(s, "get-request") == 0) {
	v->type = SNMP_PDU_GET;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "get-next-request") == 0) {
	v->type = SNMP_PDU_GETNEXT;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "get-bulk-request") == 0) {
	v->type = SNMP_PDU_GETBULK;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "set-request") == 0) {
	v->type = SNMP_PDU_SET;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "response") == 0) {
	v->type = SNMP_PDU_RESPONSE;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "trap") == 0) {
	v->type = SNMP_PDU_TRAP1;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "trap2") == 0) {
	v->type = SNMP_PDU_TRAP2;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "inform") == 0) {
	v->type = SNMP_PDU_INFORM;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(s, "report") == 0) {
	v->type = SNMP_PDU_REPORT;
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

/*
 * return number of numbers in oid (number of dots + 1)
 */
static int
csv_read_oid_count(const char* s) {
    const char *p;
    int count = 0;

    if (s) {
	count++;
	for (p = s; *p; p++) {
	    count += (*p == '.');
	}
    }
    return count;
}

static void
csv_read_oid(char *s, snmp_oid_t *v) {
    int i;
    char *end;
    int count = 0;

    count = csv_read_oid_count(s);
    if (s && count > 0) {
	v->value = xmalloc(sizeof(uint32_t)*count);
	v->len = count;

	v->value[0] = (uint32_t) strtoul((const char *) s, &end, 10);
	if (*end == '\0' || *end == '.') {
	    if (!(v->value[0] >= 0 && v->value[0] <= 2)) {
		fprintf(stderr, "%s: warning: oid first value %d should be"
			"in  0..2\n", progname, v->value[0]);
	    }
	}
	for(i=1;i<count && *end == '.';i++) {
	    s = end+1;
	    v->value[i] = (uint32_t) strtoul((const char *) s, &end, 10);
	}
	
	if (*end == '\0' && *s != '\0') {
	    v->attr.flags |= SNMP_FLAG_VALUE;
	}
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
 * convert octet string into string (i.e. csv -> pcap)
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
    
    if (strlen(str)%2 != 0 || strlen(str) == 0) {
	/* octet string implies pairs of hex numbers */
	return NULL;
    }
    size = strlen(str)/2;
    assert(size);
    buffer = xmalloc(size);
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
    return buffer;
}

static void
csv_read_octs(char* s, snmp_octs_t* v)
{
    v->value = dehexify(s, &v->len);
    if (v->value) v->attr.flags |= SNMP_FLAG_VALUE;
}

static void
csv_read_varbind(char **s, snmp_varbind_t *v)
{
    char *oid;
    char *type;
    char *value;
    
    //fprintf(stdout, "s: %s\n", *s);
    oid = mytok(s, ",");
    if (! oid) return;
    csv_read_oid(oid, &v->name);

    type = mytok(s, ",");
    if (! type) return;
    value = mytok(s, ",");
    if (! value) return;
    //fprintf(stdout, "varbind: %s,%s,%s\n", oid, type, value);
    if (strcmp(type, "null") == 0) {
	v->type = SNMP_TYPE_NULL;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(type, "integer32") == 0) {
	v->type = SNMP_TYPE_INT32;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_int32(value, &v->value.i32);
    } else if (strcmp(type, "unsigned32") == 0) {
	v->type = SNMP_TYPE_UINT32;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_uint32(value, &v->value.u32);
    } else if (strcmp(type, "unsigned64") == 0) {
	v->type = SNMP_TYPE_UINT64;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_uint64(value, &v->value.u64);
    } else if (strcmp(type, "ipaddress") == 0) {
	v->type = SNMP_TYPE_IPADDR;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_ipaddr(value, &v->value.ip);
    } else if (strcmp(type, "octet-string") == 0) {
	v->type = SNMP_TYPE_OCTS;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_octs(value, &v->value.octs);
    } else if (strcmp(type, "object-identifier") == 0) {
	v->type = SNMP_TYPE_OID;
	v->attr.flags |= SNMP_FLAG_VALUE;
	csv_read_oid(value, &v->value.oid);
    } else if (strcmp(type, "no-such-object") == 0) {
	v->type = SNMP_TYPE_NO_SUCH_OBJ;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(type, "no-such-instance") == 0) {
	v->type = SNMP_TYPE_NO_SUCH_INST;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else if (strcmp(type, "end-of-mib-view") == 0) {
	v->type = SNMP_TYPE_END_MIB_VIEW;
	v->attr.flags |= SNMP_FLAG_VALUE;
    } else {
	fprintf(stderr, "%s: unkown varbind type: %s\n", progname, type);
    }
}

static void
parse(char *line, snmp_callback func, void *user_data)
{
    snmp_packet_t _pkt, *pkt = &_pkt;
    char *token;
    snmp_int32_t i32;
    int len;
    char *end;
    int varbind_count;
    int i;
    char *c;

    memset(pkt, 0, sizeof(snmp_packet_t));

    /* cut string at first newline (marks the end of a CSV record */
    for (c=line; *c; c++) {
	if (*c == '\n') {
	    *c = '\0';
	    break;
	}
    }

    
    /* xxx won't work if there is no time stamp in the input */

    if (2 != sscanf(line, "%u.%u,%n",
		    &pkt->time_sec.value, &pkt->time_usec.value, &len)) {
	fprintf(stderr, "%s: parsing time stamp failed - ignoring line\n",
		progname);
	return;
    }
    pkt->time_sec.attr.flags |= SNMP_FLAG_VALUE;
    pkt->time_usec.attr.flags |= SNMP_FLAG_VALUE;
    line += len;

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_ipaddr(token, &pkt->src_addr);
    if (! pkt->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_read_ip6addr(token, &pkt->src_addr6);
    }
    
    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_uint32(token, &pkt->src_port);
    
    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_ipaddr(token, &pkt->dst_addr);
    if (! pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_read_ip6addr(token, &pkt->dst_addr6);
    }
    
    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_uint32(token, &pkt->dst_port);

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    pkt->snmp.attr.blen = strtol(token, &end, 10);
    if (*end == '\0' && *token != '\0') {
	pkt->snmp.attr.flags |= SNMP_FLAG_BLEN;
    }

    pkt->attr.flags |= SNMP_FLAG_VALUE;

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.version);
    if (pkt->snmp.version.attr.flags & SNMP_FLAG_VALUE) {
	pkt->snmp.attr.flags |= SNMP_FLAG_VALUE;
    }

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_type(token, &pkt->snmp.scoped_pdu.pdu);
    if (pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	pkt->snmp.attr.flags |= SNMP_FLAG_VALUE;
    }

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.req_id);

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.err_status);

    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.err_index);
    
    token = mytok(&line, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &i32);
    varbind_count = i32.value;
    if (!(i32.attr.flags & SNMP_FLAG_VALUE)) {
	varbind_count = 0;
    }

    snmp_var_bindings_t *varbindlist;
    snmp_varbind_t *p, *q = NULL;
    varbindlist = &pkt->snmp.scoped_pdu.pdu.varbindings;
    
    varbindlist->attr.flags |= SNMP_FLAG_VALUE; /* even if zero varbinds */
    
    for (i=0; i<varbind_count; i++) {
	p = xmalloc(sizeof(snmp_varbind_t));
	if (! varbindlist->varbind) {
	    varbindlist->varbind = p;
	} else {
	    q->next = p;
	}
	q = p;
	csv_read_varbind(&line, p);
    }

    if (func) {
	func(pkt, user_data);
    }

    cleanup:
    snmp_free(pkt);
}

void
snmp_csv_read_file(const char *file, snmp_callback func, void *user_data)
{
    FILE *stream;

    assert(file);

    stream = fopen(file, "r");
    if (! stream) {
	fprintf(stderr, "%s: failed to open CSV file '%s': %s\n",
		progname, file, strerror(errno));
	return;
    }

    snmp_csv_read_stream(stream, func, user_data);

    fclose(stream);
}

void
snmp_csv_read_stream(FILE *stream, snmp_callback func, void *user_data)
{
    char buffer[123456];

    assert(stream);

    while (fgets(buffer, sizeof(buffer), stream)) {
	parse(buffer, func, user_data);
    }
}

