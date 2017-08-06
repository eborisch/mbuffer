/*
 *  Copyright (C) 2017 Adam Nielsen <a.nielsen@shikadi.net>
 *
 *  Test code for mbuffer's tape-end detection option.
 *
 *  Use:
 *    LD_PRELOAD=$PWD/tapetest.so ./mbuffer -b5 -v5 --tapeaware -o output-test < in
 *
 *  Only specify one filename beginning with the string "output" as this is the
 *  file that will be intercepted, and there can only be one.  write() calls
 *  are passed through unchanged until the number of calls given by
 *  EARLY_END_BLOCK has been reached.  Then every second write() will fail with
 *  ENOSPC until FINAL_END_BLOCK calls have succeeded in total.  Then write()
 *  will return ENOSPC continually until the next call to open(), when the
 *  call count is reset to zero and the process starts again.
 *
 *  This emulates the behaviour of an LTO tape, with the alternating write()
 *  failures used by the Linux kernel to signal the imminent end of the tape.
 *  mbuffer closes and reopens the device after a tape change, which this code
 *  picks up in the open() call, resetting the counts to simulate the insertion
 *  of a fresh tape.  This allows mbuffer's tape-end-detection code to be
 *  tested without needing an actual tape drive.
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
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Block number where we start signalling imminent end of tape */
#define EARLY_END_BLOCK 5

/* Block number where we indicate we have reached the end of the tape */
#define FINAL_END_BLOCK 10

typedef ssize_t (*orig_open_f_type)(const char *path, int oflag, int mode);
typedef ssize_t (*orig_write_f_type)(int filedes, const void *buf, size_t nbyte);

int block = 0;     /* Current block */
int toggle = 0;    /* Used to return ENOSPC for every other write() */
int file = -1;     /* File handle we are intercepting */
int opencount = 0; /* Number of calls made to open() */

int open(const char *path, int oflag, int mode)
{
	int fd;
	char newpath[256];
	orig_open_f_type orig_open;
	orig_open = (orig_open_f_type)dlsym(RTLD_NEXT, "open");
	printf("[INTERCEPT] open: %s", path);
	if (strncmp(path, "output", 6) == 0) {
		/* Opening a file that starts with "output", this is the one we will
		   intercept. */

		/* Add .000, .001, etc. onto the end */
		sprintf(newpath, "%s.%03d", path, ++opencount);
		printf(", intercepted and writing as %s", newpath);

		fd = orig_open(newpath, oflag, mode);

		/* Remember this descriptor */
		file = fd;

		/* Reset the block count to zero every time the file is opened, so that we
		   get another full "tape". */
		block = 0;
		toggle = 0;
	} else {
		fd = orig_open(path, oflag, mode);
	}
	printf("\n");
	return fd;
}

ssize_t write(int filedes, const void *buf, size_t nbyte)
{
	orig_write_f_type orig_write;
	orig_write = (orig_write_f_type)dlsym(RTLD_NEXT, "write");
	if (filedes == file) {
		printf("[INTERCEPT] write(block %d): ", block);
		if (block >= FINAL_END_BLOCK) {
			printf("ENOSPC (final)\n");
			errno = ENOSPC;
			return -1;
		} else if (block >= EARLY_END_BLOCK) {
			toggle++;
			toggle &= 1;
			if (toggle) {
				printf("ENOSPC (early)\n");
				errno = ENOSPC;
				return -1;
			}
		}
		printf("OK\n");
		block++;
	}
	return orig_write(filedes, buf, nbyte);
}
