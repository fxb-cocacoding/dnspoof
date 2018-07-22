/*
 * dns_spoofing.h
 *
 *  Created on: Dec 23, 2015
 *      Author: fxb
 */

#ifndef DNS_SPOOFING_H_
#define DNS_SPOOFING_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#endif /* DNS_SPOOFING_H_ */

int calculate_payload(int (*calc)(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip), const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip);
int spoof_dns_payload(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip);
