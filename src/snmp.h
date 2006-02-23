/*
 * snmp.h --
 *
 * Internal representation of an SNMP message read from either a raw
 * pcap file or an XML serialization. The data structure described
 * here must be semantically equivalent to the snmptrace.rnc
 * definition.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 * Copyright (c) 2006 Matus Harvan
 */

#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SNMP_FLAG_VALUE	0x01
#define SNMP_FLAG_BLEN	0x02
#define SNMP_FLAG_VLEN	0x04
#define SNMP_FLAG_SPORT	0x08
#define SNMP_FLAG_SADDR	0x10
#define SNMP_FLAG_DPORT	0x20
#define SNMP_FLAG_DADDR	0x40
#define SNMP_FLAG_CLEAR	0x80

typedef struct {
    int      blen;	/* length of the BER encided TLV triple */
    int      vlen;	/* length of the BER encoded value */
    int      flags;	/* flags controlling visibility and things */
} snmp_attr_t;


typedef struct {
    int32_t     value;		/* signed 32bit values (Integer32,
				   Enumerations) */
    snmp_attr_t attr;		/* attributes */
} snmp_int32_t;

typedef struct {
    uint32_t    value;		/* unsigned 32bit values (TimeTicks,
				   Counter32, Gauge32, Unsigned32) */
    snmp_attr_t attr;		/* attributes */
} snmp_uint32_t;

typedef struct {
    uint64_t    value;		/* unsigned 64bit values (Counter64) */
    snmp_attr_t attr;		/* attributes */
} snmp_uint64_t;

typedef struct {
    unsigned char *value;	/* octet string value */
    unsigned       len;		/* length of the octet string */
    snmp_attr_t    attr;	/* attributes */
} snmp_octs_t;

typedef struct {
    uint32_t value[128];	/* oid value (sequence of unsigned ints) */
    unsigned len;		/* number of oids present */
    snmp_attr_t attr;		/* attributes */
} snmp_oid_t;

#define SNMP_PDU_GET		0x01
#define SNMP_PDU_GETNEXT	0x02
#define SNMP_PDU_GETBULK	0x03
#define SNMP_PDU_SET		0x04
#define SNMP_PDU_RESPONSE	0x05
#define SNMP_PDU_TRAP1		0x06
#define SNMP_PDU_TRAP2		0x07
#define SNMP_PDU_INFORM		0x08
#define SNMP_PDU_REPORT		0x09

typedef struct {
    int		 type;		/* pdu type */
    snmp_int32_t req_id;	/* request ID */
    snmp_int32_t err_status;	/* error status */
    snmp_int32_t err_index;	/* error index */
    /* more stuff here */
    snmp_attr_t  attr;		/* attributes */
} snmp_pdu_t;

typedef struct {
    snmp_int32_t version;
    snmp_octs_t  community;
    snmp_pdu_t	 pdu;
    snmp_attr_t  attr;
} snmp_msg_t;

typedef struct {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    struct timeval time;
    snmp_msg_t message;
} packet_t;

