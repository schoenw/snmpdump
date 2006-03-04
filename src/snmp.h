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
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SNMP_FLAG_VALUE	0x01
#define SNMP_FLAG_BLEN	0x02
#define SNMP_FLAG_VLEN	0x04
#define SNMP_FLAG_SPORT	0x08
#define SNMP_FLAG_SADDR	0x10
#define SNMP_FLAG_DPORT	0x20
#define SNMP_FLAG_DADDR	0x40
#define SNMP_FLAG_CLEAR	0x80 /* ??? */
#define SNMP_FLAG_DATE	0x100
#define SNMP_FLAG_DELTA	0x200

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
    uint32_t    *value;		/* oid value (sequence of unsigned ints) */
    unsigned    len;		/* number of oids present */
    snmp_attr_t attr;		/* attributes */
} snmp_oid_t;

typedef struct {
    in_addr_t	    value;	/* ip address value */
    snmp_attr_t     attr;	/* attributes */
} snmp_ipaddr_t;

#define SNMP_TYPE_NULL		0x01
#define SNMP_TYPE_INT32		0x02
#define SNMP_TYPE_UINT32	0x04
#define SNMP_TYPE_UINT64	0x08
#define SNMP_TYPE_IPADDR	0x10
#define SNMP_TYPE_OCTS		0x20
#define SNMP_TYPE_OID		0x40
#define SNMP_TYPE_NO_SUCH_OBJ	0x80
#define SNMP_TYPE_NO_SUCH_INST	0x100
#define SNMP_TYPE_END_MIB_VIEW	0x200
#define SNMP_TYPE_VALUE		0x400

typedef struct _snmp_varbind {
    uint32_t	    type;	/* type of value */
    snmp_oid_t	    name;	/* name */
    union u {
	snmp_int32_t  i32;
	snmp_uint32_t u32;
	snmp_uint64_t u64;
	snmp_octs_t   octs;
	snmp_oid_t    oid;
	snmp_ipaddr_t ip;
    } value;
    //void	   *value;	/* value (one of above defined types) */
    struct
     _snmp_varbind *next;	/* next varbind (linked list) */
    snmp_attr_t     attr;	/* attributes */
} snmp_varbind_t;

typedef struct {
    snmp_varbind_t *varbind;	/* linked list of varbinds */
    snmp_attr_t     attr;	/* attributes */
} snmp_var_bindings_t;

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
    int		 type;		 /* pdu type */
    snmp_int32_t req_id;	 /* request ID */
    snmp_int32_t err_status;	 /* error status */
    snmp_int32_t err_index;	 /* error index */
    /* more stuff here */
    snmp_oid_t   enterprise;
    snmp_ipaddr_t agent_addr;
    snmp_int32_t generic_trap;
    snmp_int32_t specific_trap;
    snmp_int32_t time_stamp;
    snmp_var_bindings_t
		varbindings;     /* variable-bindings */
    snmp_attr_t  attr;		 /* attributes */
} snmp_pdu_t;

typedef struct {
    snmp_int32_t version;
    snmp_octs_t  community;	/* only SNMPv1/SNMPv2c */
    
    snmp_pdu_t	 pdu;
    snmp_attr_t  attr;
} snmp_msg_t;

typedef struct {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    struct timeval time;
    snmp_msg_t message;
} snmp_packet_t;

/*
 *
 */

typedef void (*snmp_callback)(snmp_packet_t *pkt, void *user_data);

void snmp_read_xml_file(const char *file,
			snmp_callback func, void *user_data);
void snmp_read_xml_stream(const FILE *stream,
			  snmp_callback func, void *user_data);

void snmp_write_xml_stream_begin(FILE *stream);
void snmp_write_xml_stream(FILE *stream, snmp_packet_t *pkt);
void snmp_write_xml_stream_end(FILE *stream);

void snmp_read_pcap_file(const char *file, const char *filter,
		    snmp_callback func, void *user_data);
#if 0
void snmp_read_pcap_life(const char *file, snmp_callback func, void *user_data);
#endif

