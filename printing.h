/*
 * printing.h
 *
 *  Created on: 17.12.2015
 *      Author: fxb
 */

#ifndef PRINTING_H_
#define PRINTING_H_

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

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#endif /* PRINTING_H_ */

void print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len);
