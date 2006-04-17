/*
 * libanon.h --
 *
 * Anonymization library which supports among other things
 * prefix-preserving and lexicographical-order-preserving IP address
 * anonymization.
 *
 * note on byte order: in_addr_t and in6_addr_t are expected in
 * network byte order
 *
 * Copyright (c) 2005 Matus Harvan
 */

#ifndef _LIBANON_H_
#define _LIBANON_H_

#include <stdint.h>
#include <netinet/in.h>

/*
 * anonymization key API.
 */

typedef struct	_anon_key {
    uint8_t*  key;
    size_t length;
} anon_key_t;

anon_key_t*	anon_key_new();
void		anon_key_set_key(anon_key_t *key, const uint8_t *new_key,
				 const size_t key_len);
void		anon_key_set_random(anon_key_t *key);
void		anon_key_set_passphase(anon_key_t *key,
				       const char *passphrase);
void		anon_key_delete(anon_key_t *key);

/*
 * IPv4 address anonymization API.
 */

typedef struct _anon_ipv4 anon_ipv4_t;

anon_ipv4_t*	anon_ipv4_new();
void		anon_ipv4_set_key(anon_ipv4_t *a, const anon_key_t *key);
int		anon_ipv4_set_used(anon_ipv4_t *a, const in_addr_t ip,
				   const int prefixlen);
int		anon_ipv4_map_pref(anon_ipv4_t *a, const in_addr_t ip,
				   in_addr_t *aip);
int		anon_ipv4_map_pref_lex(anon_ipv4_t *a, const in_addr_t ip,
				       in_addr_t *aip);
void		anon_ipv4_delete(anon_ipv4_t *a);
unsigned	anon_ipv4_nodes_count(anon_ipv4_t *a);

/*
 * IPv6 address anonymization API.
 */

typedef struct _anon_ipv6 anon_ipv6_t;
typedef struct in6_addr in6_addr_t;

anon_ipv6_t*	anon_ipv6_new();
void		anon_ipv6_set_key(anon_ipv6_t *a, const anon_key_t *key);
int		anon_ipv6_set_used(anon_ipv6_t *a, const in6_addr_t ip,
				   const int prefixlen);
int		anon_ipv6_map_pref(anon_ipv6_t *a, const in6_addr_t ip,
				   in6_addr_t *aip);
int		anon_ipv6_map_pref_lex(anon_ipv6_t *a, const in6_addr_t ip,
				       in6_addr_t *aip);
void		anon_ipv6_delete(anon_ipv6_t *a);
unsigned	anon_ipv6_nodes_count(anon_ipv6_t *a);

/*
 * IEEE MAC address anonymization API.
 */

typedef struct _anon_mac anon_mac_t;

anon_mac_t*	anon_mac_new();
void		anon_mac_set_key(anon_mac_t *a, const anon_key_t *key);
int		anon_mac_set_used(anon_mac_t *a, const uint8_t *mac);
int		anon_mac_map(anon_mac_t *a, const uint8_t *mac,
			     uint8_t *amac);
int		anon_mac_map_lex(anon_mac_t *a, const uint8_t *mac,
				 uint8_t *amac);
void		anon_mac_delete(anon_mac_t *a);

/*
 * Signed integer anonymization API.
 */

typedef struct _anon_int64 anon_int64_t;

anon_int64_t*	anon_int64_new(const int64_t lower, const int64_t upper);
void		anon_int64_set_key(anon_int64_t *a, const anon_key_t *key);
int		anon_int64_set_used(anon_int64_t *a, const int64_t num);
int		anon_int64_map(anon_int64_t *a, const int64_t num,
			       int64_t *anum);
int		anon_int64_map_lex(anon_int64_t *a, const int64_t num,
				   int64_t *anum);
void		anon_int64_delete(anon_int64_t *a);

/*
 * Unsigned integer anonymization API.
 */

typedef struct _anon_uint64 anon_uint64_t;

anon_uint64_t*	anon_uint64_new(const uint64_t lower, const uint64_t upper);
void		anon_uint64_set_key(anon_uint64_t *a, const anon_key_t *key);
int		anon_uint64_set_used(anon_uint64_t *a, const uint64_t num);
int		anon_uint64_map(anon_uint64_t *a, const uint64_t num,
			       uint64_t *anum);
int		anon_uint64_map_lex(anon_uint64_t *a, const uint64_t num,
				   uint64_t *anum);
void		anon_uint64_delete(anon_uint64_t *a);

/*
 * octet string anonymization API.
 */

typedef struct _anon_octs anon_octs_t;

anon_octs_t*	anon_octs_new();
void		anon_octs_set_key(anon_octs_t *a,
					  const anon_key_t *key);
int		anon_octs_set_used(anon_octs_t *a,
					   const char *str);
int		anon_octs_map(anon_octs_t *a,
				      const char *str, char *astr);
int		anon_octs_map_lex(anon_octs_t *a,
					  const char *str, char *astr);
void		anon_octs_delete(anon_octs_t *a);

/*
 * Other stuff goes here...
 */

#endif /* _LIBANON_H_ */
