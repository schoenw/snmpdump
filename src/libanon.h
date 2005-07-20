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
void		anon_ip_set_used(anon_ip_t *a, in_addr_t ip, int prefixlen);
in_addr_t	anon_ip_map_pref(anon_ip_t *a, const in_addr_t ip);
in_addr_t	anon_ip_map_pref_lex(anon_ip_t *a, const in_addr_t ip);
void		anon_ip_delete(anon_ip_t *a);

/*
 * IEEE MAC address anonymization API.
 */

typedef struct _anon_mac anon_mac_t;

anon_mac_t*	anon_mac_new();
void		anon_mac_set_key(anon_mac_t *a, const uint8_t *key);
void		anon_mac_set_used(anon_mac_t *a, const uint8_t *mac);
void		anon_mac_map(anon_mac_t *a, const uint8_t *mac);
void		anon_mac_map_lex(anon_mac_t *a, const uint8_t *mac);
void		anon_mac_delete(anon_mac_t *a);

/*
 * Other stuff goes here...
 */

#endif /* _LIBANON_H_ */
