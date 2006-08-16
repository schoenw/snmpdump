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
    if (*end == '\0') {
	v->attr.flags |= SNMP_FLAG_VALUE;
    }
}

static void
csv_read_uint32(char *s, snmp_uint32_t *v)
{
    char *end;

    v->value = (uint32_t) strtoul(s, &end, 10);
    if (*end == '\0') {
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

static void
parse(char *line, snmp_callback func, void *user_data)
{
    snmp_packet_t _pkt, *pkt = &_pkt;
    char *token;
    snmp_int32_t i32;
    int len;
    char *end;

    memset(pkt, 0, sizeof(snmp_packet_t));

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

    token = strtok(line, ",");
    if (! token) goto cleanup;
    csv_read_ipaddr(token, &pkt->src_addr);
    if (! pkt->src_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_read_ip6addr(token, &pkt->src_addr6);
    }
    
    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_uint32(token, &pkt->src_port);
    
    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_ipaddr(token, &pkt->dst_addr);
    if (! pkt->dst_addr.attr.flags & SNMP_FLAG_VALUE) {
	csv_read_ip6addr(token, &pkt->dst_addr6);
    }
    
    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_uint32(token, &pkt->dst_port);

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    pkt->snmp.attr.blen = strtol(token, &end, 10);
    if (*end == '\0') {
	pkt->snmp.attr.flags |= SNMP_FLAG_BLEN;
    }

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.version);
    if (pkt->snmp.version.attr.flags & SNMP_FLAG_VALUE) {
	pkt->snmp.attr.flags |= SNMP_FLAG_VALUE;
    }

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_type(token, &pkt->snmp.scoped_pdu.pdu);
    if (pkt->snmp.scoped_pdu.pdu.attr.flags & SNMP_FLAG_VALUE) {
	pkt->snmp.attr.flags |= SNMP_FLAG_VALUE;
    }

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.req_id);

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.err_status);

    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &pkt->snmp.scoped_pdu.pdu.err_index);
    
    token = strtok(NULL, ",");
    if (! token) goto cleanup;
    csv_read_int32(token, &i32);
    
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

