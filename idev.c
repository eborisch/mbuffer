/*
 *  Copyright (C) 2017, Thomas Maier-Komor
 *
 *  This is the source code of mbuffer.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

ssize_t (*d_open)(const char *path, int oflag, int mode) = 0;
ssize_t (*d_read)(int filedes, void *buf, size_t nbyte) = 0;
int (*d_fstat)(int ver, int fd, struct stat *st) = 0;

ssize_t Fd = -1;
size_t BSize = 0;



int open(const char *path, int oflag, int mode)
{
	if (d_open == 0) {
		d_open = (ssize_t (*)(const char *,int,int)) dlsym(RTLD_NEXT, "open");
		fprintf(stderr,"idev.so: d_open = %p\n",d_open);
		fflush(stderr);
	}
	assert(d_open);
	int fd = d_open(path, oflag, mode);
	fprintf(stderr,"idev.so: open %s (%s)\n",path,getenv("IDEV"));
	if (strcmp(path, getenv("IDEV")) == 0) {
		fprintf(stderr,"idev.so: FD = %d\n",fd);
		fflush(stderr);
		Fd = fd;
	}
	return fd;
}



ssize_t read(int fd,void *buf, size_t s)
{
	if (d_read == 0) {
		d_read = (ssize_t (*)(int,void*,size_t)) dlsym(RTLD_NEXT, "read");
		fprintf(stderr,"idev.so: d_read = %p\n",d_read);
	}
	assert(d_read);
	if (fd != Fd) 
		return d_read(fd,buf,s);
	if (BSize == 0)
		BSize = strtol(getenv("BSIZE"),0,0);
	if (s < BSize) {
		fprintf(stderr,"idev.so: read(%d,%p,%lu<%lu) = ENOMEM\n",fd,buf,s,BSize);
		fflush(stderr);
		errno = ENOMEM;
		return -1;
	}
	return d_read(fd,buf,s);
}


int __fxstat(int ver, int fd, struct stat *st)
{
	fprintf(stderr,"idev.so: fstat(%d,%d,%p)\n",ver,fd,st);
	if (d_fstat == 0) {
		d_fstat = (int (*)(int,int,struct stat *)) dlsym(RTLD_NEXT, "__fxstat");
		fprintf(stderr,"idev.so: d_fstat = %p\n",d_fstat);
	}
	assert(d_fstat);
	int r = d_fstat(ver,fd,st);
	if (fd == Fd) {
		if (BSize == 0)
			BSize = strtol(getenv("BSIZE"),0,0);
		fprintf(stderr,"idev.so: blksize set to %lu\n",BSize);
		fflush(stderr);
		st->st_blksize = BSize;
		st->st_mode &= ~S_IFMT;
		st->st_mode |= S_IFCHR;
	}
	return r;
}
