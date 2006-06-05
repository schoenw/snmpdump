/*
 * snmp.h --
 *
 * Internal representation of an SNMP message read from either a raw
 * pcap file or an XML serialization. The data structure described
 * here must be semantically equivalent to the snmptrace.rnc relaxng
 * definition.
 *
 * Copyright (c) 2006 Juergen Schoenwaelder
 * Copyright (c) 2006 Matus Harvan
 *
 * $Id$
 */

#ifndef _SNMP_H
#define _SNMP_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SNMP_FLAG_VALUE		0x0001
#define SNMP_FLAG_BLEN		0x0002
#define SNMP_FLAG_VLEN		0x0004
#define SNMP_FLAG_SPORT		0x0008
#define SNMP_FLAG_SADDR		0x0010
#define SNMP_FLAG_DPORT		0x0020
#define SNMP_FLAG_DADDR		0x0040
#define SNMP_FLAG_DYNAMIC	0x8000

typedef struct {
    int      blen;	/* length of the BER encided TLV triple */
    int      vlen;	/* length of the BER encoded value */
    int      flags;	/* flags controlling visibility and things */
} snmp_attr_t;


typedef struct {
    snmp_attr_t attr;		/* attributes */
} snmp_null_t;

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
    unsigned       len;		/* length of the octet string  - IGNORED !!! */
    snmp_attr_t    attr;	/* attributes */
} snmp_octs_t;

typedef struct {
    uint32_t    *value;		/* oid value (sequence of unsigned ints) */
    unsigned     len;		/* number of oids present */
    snmp_attr_t  attr;		/* attributes */
} snmp_oid_t;

typedef struct {
    in_addr_t	    value;	/* ip address value */
    snmp_attr_t     attr;	/* attributes */
} snmp_ipaddr_t;

typedef struct {
    struct in6_addr value;	/* ip address value */
    snmp_attr_t     attr;	/* attributes */
} snmp_ip6addr_t;

#define SNMP_TYPE_NULL		0x0001
#define SNMP_TYPE_INT32		0x0002
#define SNMP_TYPE_UINT32	0x0004
#define SNMP_TYPE_UINT64	0x0008
#define SNMP_TYPE_IPADDR	0x0010
#define SNMP_TYPE_OCTS		0x0020
#define SNMP_TYPE_OID		0x0040
#define SNMP_TYPE_NO_SUCH_OBJ	0x0080
#define SNMP_TYPE_NO_SUCH_INST	0x0100
#define SNMP_TYPE_END_MIB_VIEW	0x0200
#define SNMP_TYPE_VALUE		0x0400		/* what is this good for? */

typedef struct _snmp_varbind {
    uint32_t	          type;	/* type of value */
    snmp_oid_t	          name;	/* name */
    union u {
	snmp_null_t   null;
	snmp_int32_t  i32;
	snmp_uint32_t u32;
	snmp_uint64_t u64;
	snmp_octs_t   octs;
	snmp_oid_t    oid;
	snmp_ipaddr_t ip;
    } value;
    struct _snmp_varbind *next;	/* next varbind (linked list) */
    snmp_attr_t		  attr;	/* attributes */
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
    int		 type;		/* pdu type */
    snmp_int32_t req_id;	/* request ID */
    snmp_int32_t err_status;	/* error status */
    snmp_int32_t err_index;	/* error index */
    /* more stuff here */
    snmp_oid_t   enterprise;	/* SNMPv1 traps only */
    snmp_ipaddr_t agent_addr;	/* SNMPv1 traps only */
    snmp_int32_t generic_trap;	/* SNMPv1 traps only */
    snmp_int32_t specific_trap;	/* SNMPv1 traps only */
    snmp_int32_t time_stamp;	/* SNMPv1 traps only */
    snmp_var_bindings_t
		 varbindings;   /* variable-bindings */
    snmp_attr_t  attr;		/* attributes */
} snmp_pdu_t;

typedef struct {
    snmp_octs_t   auth_engine_id;
    snmp_uint32_t auth_engine_boots;
    snmp_uint32_t auth_engine_time;
    snmp_octs_t   user;  /* should be type text according to schema */
    snmp_octs_t   auth_params;
    snmp_octs_t   priv_params;
    snmp_attr_t   attr; /* missing in the xml, used to determine if present */
} snmp_usm_t;

typedef struct {
    snmp_octs_t   context_engine_id;
    snmp_octs_t   context_name;  /* should be type text according to schema */
    snmp_pdu_t	  pdu;           /* present in snmp_msg_t, not duplicating */
    snmp_attr_t   attr;
} snmp_scoped_pdu_t;

typedef struct {
    snmp_uint32_t     msg_id;
    snmp_uint32_t     msg_max_size;
    snmp_octs_t       msg_flags; /* should be type text according to schema */
    snmp_uint32_t     msg_sec_model;
    snmp_attr_t       attr;
} snmp_msg_t;

typedef struct {
    snmp_int32_t      version;
    snmp_octs_t       community;	/* only SNMPv1/SNMPv2c */
    snmp_msg_t        message;		/* only SNMPv3 */
    snmp_usm_t	      usm;		/* only SNMPv3/USM */
    snmp_scoped_pdu_t scoped_pdu;
    snmp_attr_t	      attr;
} snmp_snmp_t;

typedef struct {
    snmp_uint32_t	time_sec;
    snmp_uint32_t	time_usec;
    snmp_ipaddr_t	src_addr;
    snmp_ip6addr_t	src_addr6;
    snmp_uint32_t	src_port;
    snmp_ipaddr_t	dst_addr;
    snmp_ip6addr_t	dst_addr6;
    snmp_uint32_t	dst_port;
    snmp_snmp_t		snmp;
    snmp_attr_t		attr;
} snmp_packet_t;

/*
 * Functions to deal with dynamically allocated packets. Note that
 * packets allocated by the XML/pcap parsers are managed by the
 * parsers and thus not something applications have to take care of.
 * Packets which are dynamically allocated have the SNMP_FLAG_DYNAMIC
 * set to distinguish them from packets allocated by the parsers.
 */

snmp_packet_t* snmp_pkt_new(void);
snmp_packet_t* snmp_pkt_copy(snmp_packet_t *pkt);
void           snmp_pkt_delete(snmp_packet_t *pkt);
void	       snmp_pkt_v1tov2(snmp_packet_t *pkt);

/*
 * Prototype of the callback function which is called for each
 * SNMP message in the input stream.
 */

typedef void (*snmp_callback)(snmp_packet_t *pkt, void *user_data);

/*
 * XML input and output functions.
 */

void snmp_xml_read_file(const char *file,
			snmp_callback func, void *user_data);
void snmp_xml_read_stream(const FILE *stream,
			  snmp_callback func, void *user_data);

void snmp_xml_write_stream_new(FILE *stream);
void snmp_xml_write_stream_pkt(FILE *stream, snmp_packet_t *pkt);
void snmp_xml_write_stream_end(FILE *stream);

/*
 * PCAP input functions (we do not write pcap files)
 */

void snmp_pcap_read_file(const char *file, const char *filter,
			 snmp_callback func, void *user_data);
void snmp_pcap_read_stream(const FILE *stream, const char *filter,
			   snmp_callback func, void *user_data);
void snmp_pcap_read_life(const char *file,
			 snmp_callback func, void *user_data);

/*
 * CSV output functions (we do not read CVS files)
 */

void snmp_csv_write_stream_new(FILE *stream);
void snmp_csv_write_stream_pkt(FILE *stream, snmp_packet_t *pkt);
void snmp_csv_write_stream_end(FILE *stream);

/*
 * Interface for SNMP flows. We encapsulate the write functions into a
 * common interface so that we can pass the set of related output
 * functions around easily.
 */

typedef struct _snmp_write {
    FILE *stream;
    void (*write_new) (FILE *stream);
    void (*write_pkt) (FILE *stream, snmp_packet_t *pkt);
    void (*write_end) (FILE *stream);
    const char *path;
    const char *ext;
} snmp_write_t;

void snmp_flow_init(snmp_write_t *out);
void snmp_flow_write(snmp_write_t *out, snmp_packet_t *pkt);
void snmp_flow_done(snmp_write_t *out);

/*
 * Interface for the filter-out filter which can be used to suppress
 * sensitive information. Note that filter-out should be applied as
 * early as possible in a processing chain and that filter-out will
 * change values so that subsequent modules won't get sensitive
 * information by ignoring the attribute flags.
 */

typedef struct _snmp_filter snmp_filter_t;

snmp_filter_t* snmp_filter_new(const char *regex, char **error);
void snmp_filter_apply(snmp_filter_t *filter, snmp_packet_t *pkt);
void snmp_filter_delete(snmp_filter_t *filter);

/*
 * Interface for anonymization. This is likely to change since we
 * still code this part of the tool.
 */

void snmp_anon_learn(snmp_packet_t *pkt);
void snmp_anon_apply(snmp_packet_t *pkt);

/*
 * Other useful global symbols...
 */

extern const char *progname;

#endif /* _SNMP_H */
