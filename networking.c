/*

  Author:  Felix Bilstein
  Date:	   23-Dec-2015
  Comment: This is a proof-of-concept and a short example how to use libpcap in C.
           Interesting is for example the source for the calculation of the checksums as well
           as parsing different structures using buffers and struct castings (interesting for newbies in C),
           since this is a basic way in C to work with data.
           It is not designed to be used by anyone, more kind of a project to learn raw sockets and libpcap.

  File:    networking.c
*/

#include "networking.h"

int craft_packet(	u_char *args,
					const struct pcap_pkthdr *header,
					const u_char *packet,
					u_char *new_packet_raw,
					int (*calculate_payload)(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip),
					u_char *ip) {

	//MEMO: void *memcpy(void *dest, const void *src, size_t n);

	/*
	 * Some constant values. Header size is here always the same
	 */

	unsigned int size_eth = 14;
	unsigned int size_ip = 20;
	unsigned int size_udp = 8;

	/*
	 * Pointer environment for packet crafting (output) and reading (input)
	 */

	const struct ethhdr *eth_packet_input;
	const struct ip *ip_packet_input;
	const struct udphdr *udp_packet_input;
	const u_char *payload_input;
	unsigned int size_payload_in;

	struct ethhdr *eth_packet_output;
	struct ip *ip_packet_output;
	struct udphdr *udp_packet_output;
	u_char *payload_output;
	int size_payload_out = SNAP_LEN-SIZE_ETHERNET-size_ip-size_udp;
	unsigned int new_packet_raw_size;

	/*
	 * setup pointer environment from packet we receive
	 */

	eth_packet_input = (struct ethhdr*)(packet);
	ip_packet_input = (struct ip*)(packet + SIZE_ETHERNET);
	udp_packet_input = (struct udphdr*)(packet + SIZE_ETHERNET+ size_ip);
	payload_input = (u_char*)(packet + SIZE_ETHERNET+ size_ip + size_udp);

	eth_packet_output = (struct ethhdr*)(new_packet_raw);
	ip_packet_output = (struct ip*)(new_packet_raw + SIZE_ETHERNET);
	udp_packet_output = (struct udphdr*)(new_packet_raw + SIZE_ETHERNET+ size_ip);
	payload_output = (u_char*)(new_packet_raw + SIZE_ETHERNET+ size_ip + size_udp);

	size_payload_in = ntohs(ip_packet_input->ip_len) - (size_ip + size_udp);

	/*
	 * we will now compute a packet -> this means writing from scratch!
	 */

	// spoof ethernet header
	memcpy(eth_packet_output->h_dest, eth_packet_input->h_source, ETH_ALEN);
	memcpy(eth_packet_output->h_source, eth_packet_input->h_dest, ETH_ALEN);
	memcpy(&eth_packet_output->h_proto, &eth_packet_input->h_proto, sizeof(eth_packet_input->h_proto));

	// spoof ip header
	ip_packet_output->ip_dst = ip_packet_input->ip_src;
	ip_packet_output->ip_src = ip_packet_input->ip_dst;
	ip_packet_output->ip_v = ip_packet_input->ip_v;
	ip_packet_output->ip_hl = ip_packet_input->ip_hl;
	ip_packet_output->ip_tos = ip_packet_input->ip_tos;
	ip_packet_output->ip_len = 0x0000;
	ip_packet_output->ip_id = 0x0000;//htons(54321);
	ip_packet_output->ip_ttl = ip_packet_input->ip_ttl-1;
	ip_packet_output->ip_p = ip_packet_input->ip_p;
	ip_packet_output->ip_sum = 0x0000;


	udp_packet_output->uh_dport = udp_packet_input->uh_sport;
	udp_packet_output->uh_sport = udp_packet_input->uh_dport;
	udp_packet_output->uh_ulen = 0x0000;
	udp_packet_output->uh_sum = 0x0000;

	new_packet_raw_size = size_eth + size_ip + size_udp;

	size_payload_out = calculate_payload(payload_input, size_payload_in, payload_output, size_payload_out, ip);
	printf("size_payload_out=%u\n", size_payload_out);
	new_packet_raw_size = new_packet_raw_size + size_payload_out;

	udp_packet_output->uh_ulen = htons(size_udp+size_payload_out);
	ip_packet_output->ip_len = htons(size_ip+size_udp+size_payload_out);
	compute_ip_checksum(ip_packet_output);

	/*
	 * You can try to compute udp_checksum, but if you keep the entry zero'ed,
	 * this is also no problem as unchecked is standard conform.
	 */

	//compute_udp_checksum(ip_packet_output, (u_int16_t*)udp_packet_output);

	return new_packet_raw_size;
}

void send_spoofed_frame(char *INTERFACE, u_char *packet, int frame_length) {
	int sd;
	struct sockaddr_ll device;
	const struct ethhdr *eth_header = (struct ethhdr*)(packet);
	memset (&device, 0, sizeof (device));

	if ((device.sll_ifindex = if_nametoindex (INTERFACE)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
	    exit (EXIT_FAILURE);
	}

	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, eth_header->h_source, sizeof(eth_header->h_source));
	device.sll_halen = 6;

	/*
	 * Keep in mind: we are crafting our packets from scratch, even the Ethernet header.
	 * This buffer will be sent.
	 */

	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	    perror ("socket() failed ");
	    exit (EXIT_FAILURE);
	}
	if( sendto(sd, packet, frame_length, 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
		perror("sendto() error");
		exit(-1);
	} else {
		printf("sendto() is OK.\n");
	}
	close(sd);
	printf("socket closed\n");
}
