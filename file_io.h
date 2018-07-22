/*
 * file_io.h
 *
 *  Created on: Dec 23, 2015
 *      Author: fxb
 */

#ifndef FILE_IO_H_
#define FILE_IO_H_

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#endif /* FILE_IO_H_ */

size_t fsize(const char *filename);
size_t getFileContent(const char *filename, char *target, size_t target_size);
