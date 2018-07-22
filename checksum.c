/*
These functions are unmodified copies from this implementation:
http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-2-implementation/
from Liu Feipeng
*/

#include "checksum.h"


static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
	register unsigned long sum = 0;
	while (count > 1) {
		sum += * addr++;
		count -= 2;
	}
	//if any bytes left, pad the bytes and add
	if(count > 0) {
		sum += ((*addr)&htons(0xFF00));
	}
	//Fold sum to 16 bits: add carrier to result

	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	//one's complement
	sum = ~sum;
	return ((unsigned short)sum);
}


void compute_ip_checksum(struct ip* iphdrp){
	iphdrp->ip_sum = 0x0000;
	iphdrp->ip_sum = compute_checksum((unsigned short*)iphdrp, iphdrp->ip_hl<<2);
}



// Build IPv4 UDP pseudo-header and call checksum function.
u_int16_t compute_udp_checksum(struct ip *pIph, unsigned short *ipPayload) {

    register unsigned long sum = 0;

    struct udphdr* udphdrp = (struct udphdr*)(ipPayload);

    unsigned short udpLen = htons(udphdrp->uh_sum);

    //printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%d\n", udpLen);

    //add the pseudo header

    //printf("add pseudo header\n");

    //the source ip

    sum += (pIph->ip_src.s_addr>>16)&0xFFFF;

    sum += (pIph->ip_src.s_addr)&0xFFFF;

    //the dest ip

    sum += (pIph->ip_dst.s_addr>>16)&0xFFFF;

    sum += (pIph->ip_dst.s_addr)&0xFFFF;

    //protocol and reserved: 17

    sum += htons(IPPROTO_UDP);

    //the length

    sum += udphdrp->uh_ulen;



    //add the IP payload

    //printf("add ip payload\n");

    //initialize checksum to 0

    udphdrp->uh_sum = 0;

    while (udpLen > 1) {

        sum += * ipPayload++;

        udpLen -= 2;

    }

    //if any bytes left, pad the bytes and add

    if(udpLen > 0) {

        //printf("+++++++++++++++padding: %d\n", udpLen);

        sum += ((*ipPayload)&htons(0xFF00));

    }

      //Fold sum to 16 bits: add carrier to result

    //printf("add carrier\n");

      while (sum>>16) {

          sum = (sum & 0xffff) + (sum >> 16);

      }

    //printf("one's complement\n");

      sum = ~sum;

    //set computation result

      return ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}
