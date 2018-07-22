/*
 * dns_spoofing_tuple.h
 *
 *  Created on: Dec 23, 2015
 *      Author: fxb
 */

#ifndef DNS_SPOOFING_TUPLE_H_
#define DNS_SPOOFING_TUPLE_H_



#endif /* DNS_SPOOFING_TUPLE_H_ */

typedef struct {
	u_char name[253]; // per Definition
	u_char ip[15];
} spoof_tuple;
