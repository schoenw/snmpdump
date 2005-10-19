/*
 * libanon.h --
 *
 * Anonymization library which supports among other things
 * prefix-preserving and lexicographical-order-preserving IP address
 * anonymization.
 *
 * Copyright (c) 2005 Matus Harvan
 */

#ifndef _LIBANON_H_
#define _LIBANON_H_

#include <stdint.h>
#include <netinet/in.h>

/*
 * IPv4 address anonymization API.
 */

typedef struct _anon_ip anon_ip_t;

anon_ip_t*	anon_ip_new();
void		anon_ip_set_key(anon_ip_t *a, const uint8_t *key);
int		anon_ip_set_used(anon_ip_t *a, in_addr_t ip, int prefixlen);
int		anon_ip_map_pref(anon_ip_t *a, const in_addr_t ip,
				 in_addr_t *aip);
int		anon_ip_map_pref_lex(anon_ip_t *a, const in_addr_t ip,
				     in_addr_t *aip);
void		anon_ip_delete(anon_ip_t *a);

/*
 * IEEE MAC address anonymization API.
 */

typedef struct _anon_mac anon_mac_t;

anon_mac_t*	anon_mac_new();
void		anon_mac_set_key(anon_mac_t *a, const uint8_t *key);
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
void		anon_int64_set_key(anon_int64_t *a, const uint8_t *key);
int		anon_int64_set_used(anon_int64_t *a, const int64_t n);
void		anon_int64_map(anon_int64_t *a, const int64_t *n);
void		anon_int64_map_lex(anon_int64_t *a, const int64_t *n);
void		anon_int64_delete(anon_int64_t *a);

/*
 * Unsigned integer anonymization API.
 */

typedef struct _anon_uint64 anon_uint64_t;

anon_uint64_t*	anon_uint64_new(const uint64_t lower, const uint64_t upper);
void		anon_uint64_set_key(anon_uint64_t *a, const uint8_t *key);
int		anon_uint64_set_used(anon_uint64_t *a, const uint64_t n);
void		anon_uint64_map(anon_uint64_t *a, const uint64_t *n);
void		anon_uint64_map_lex(anon_uint64_t *a, const uint64_t *n);
void		anon_uint64_delete(anon_uint64_t *a);

/*
 * Other stuff goes here...
 */

#endif /* _LIBANON_H_ */
