/*
 * networking.h
 *
 *  Created on: Dec 23, 2015
 *      Author: fxb
 */

#ifndef NETWORKING_H_
#define NETWORKING_H_

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

#include "printing.h"
#include "checksum.h"
#include "dns_spoofing.h"

#endif /* NETWORKING_H_ */

// Copied value from tcpdump project, see sniffer.c
#define SNAP_LEN 1518
//#define SIZE_ETHERNET 14			// see sizeof(struct ethhdr)
#define SIZE_ETHERNET ETH_HLEN		// from if_ether.h

//define INTERFACE "wlan0"


int craft_packet(	u_char *args,
					const struct pcap_pkthdr *header,
					const u_char *packet,
					u_char *new_packet_raw,
					int (*calculate_payload)(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip),
					u_char *ip);

void send_spoofed_frame(char *INTERFACE, u_char *packet, int frame_length);
