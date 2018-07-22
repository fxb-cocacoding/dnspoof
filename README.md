# dnspoof - another practical approach using libpcap

This is a short project to start developing with raw sockets and 
libpcap. Its nature is proof-of-concept only. Use dnsspoof instead.

The nature of the hosts file for this project looks like this:

example:
 google.de|1.2.3.4

This will ensure that a *response* from the real dns will be copied and 
spoofed with these entries (not classic dns spoofing, since *here* the 
spoofed response will always be slower). This means you need in your 
setup a valid MITM position to attack the target as well as a iptables rule to drop 
the correct packets.

## Compile:

`cd Debug && make all`

## Usage:
run dnspoof with privileges to use raw sockets. Usually this will be 
root privileges. There are some unchecked boundaries, for example in spoof_dns_payload in dns_spoof.c
are memcpy with pointer arithmetic without explicit bounds checking. Handle with care, execute only if
you are sure nobody exploits you.
