/*

  Author:  Felix Bilstein
  Date:	   23-Dec-2015
  Comment: This is a proof-of-concept and a short example how to use libpcap in C.
           Interesting is for example the source for the calculation of the checksums as well
           as parsing different structures using buffers and struct castings (interesting for newbies in C),
           since this is a basic way in C to work with data.
           It is not designed to be used by anyone, more kind of a project to learn raw sockets and libpcap.

  File:    file_io.c
*/

#include "file_io.h"


size_t fsize(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0)
        return st.st_size;
    else {
    	exit(-1);
    }
    return 0;
}

size_t getFileContent(const char *filename, char *target, size_t target_size) {
	FILE *fd = fopen(filename, "r");
	size_t new = fread(target, sizeof(char), target_size, fd);
	if(new == 0) {
		printf("File not found\n");
		exit(-1);
	}
	return new;
}
