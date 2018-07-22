/*
 * checksum.h
 *
 *  Created on: 18.12.2015
 *      Author: fxb
 */

#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <string.h>

#endif /* CHECKSUM_H_ */

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
void compute_ip_checksum(struct ip*);
u_int16_t compute_udp_checksum(struct ip *pIph, unsigned short *ipPayload);
