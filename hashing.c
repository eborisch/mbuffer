/*
 *  Copyright (C) 2000-2017, Thomas Maier-Komor
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

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#if defined HAVE_GCRYPT_H && defined HAVE_LIBGCRYPT
#include <gcrypt.h>
#define USE_GCRYPT 1
#elif defined HAVE_MHASH_H && defined HAVE_LIBMHASH
#include <mhash.h>
#define USE_MHASH 1
#elif defined HAVE_LIBMD5 && defined HAVE_MD5_H
#include <md5.h>
static MD5_CTX MD5ctxt;
#define MD5_INIT(ctxt)		MD5Init(&ctxt);
#define MD5_UPDATE(ctxt,at,num) MD5Update(&ctxt,(unsigned char *)(at),(unsigned int)(num))
#define MD5_END(hash,ctxt)	MD5Final(hash,&(ctxt))
#elif defined HAVE_LIBCRYPTO
#include <openssl/md5.h>
static MD5_CTX MD5ctxt;
#define MD5_INIT(ctxt)		MD5_Init(&ctxt);
#define MD5_UPDATE(ctxt,at,num)	MD5_Update(&ctxt,at,num)
#define MD5_END(hash,ctxt)	MD5_Final(hash,&(ctxt))
#endif

#include "dest.h"
#include "hashing.h"
#include "log.h"


extern volatile int
	SendSize,
	Terminate;	/* abort execution, because of error or signal */
extern dest_t *Dest;
extern char *volatile SendAt;

int syncSenders(char *b, int s);


void listHashAlgos()
{
#if defined USE_GCRYPT
	(void) fprintf(stderr,"valid hash functions of libgcrypt are:\n");
	int algo = 1;
	const char *name;
	for (algo = 1; algo < 512; ++algo ) {
		name = gcry_md_algo_name(algo);
		assert(name);
		if (name[0] != '?') {
			assert(algo == gcry_md_map_name(name));
			printf("\t%s\n",name);
		}
	}
#elif defined USE_MHASH
	(void) fprintf(stderr,"valid hash functions of libmhash are:\n");
	int algo = mhash_count();
	while (algo >= 0) {
		char *algoname = mhash_get_hash_name(algo);
		if (algoname) {
			(void) fprintf(stderr,"\t%s\n",algoname);
			free(algoname);
		}
		--algo;
	}
#elif defined HAVE_MD5
	(void) fprintf(stderr,"valid hash functions are:\n"
		"\tMD5\n");
#else
	fatal("hash calculation support has not been compiled in!\n");
#endif
}


static void addDigestDestination(int algo, const char *algoname)
{
	dest_t *dest = malloc(sizeof(dest_t));
	bzero(dest,sizeof(dest_t));
	dest->name = algoname;
	dest->fd = -2;
	dest->mode = algo;
	if (Dest) {
		dest->next = Dest->next;
		Dest->next = dest;
	} else {
		Dest = dest;
		dest->next = 0;
	}
}


int addHashAlgorithm(const char *name)
{
#if defined USE_GCRYPT
	int algo = gcry_md_map_name(name);
	if (algo == 0) {
		errormsg("libgcrypt is unable to find digest '%s'\n",name);
		return 0;
	}
	addDigestDestination(algo,name);
	debugmsg("enabled hash algorithm %s\n",name);
	return 1;
#else
#if defined USE_MHASH
	int algo = 0;
	char *algoname = "";
	int numalgo = mhash_count();

	while (algo <= numalgo) {
		algoname = mhash_get_hash_name(algo);
		if (algoname && (strcasecmp(algoname,name) == 0))
			break;
		free(algoname);
		algoname = 0;
		++algo;
	}
#elif defined HAVE_MD5
	int algo = 0;
	char *algoname = strdup("MD5");
#endif
	if (strcasecmp(algoname,name) != 0) {
		errormsg("invalid or unsupported hash function %s\n",name);
		return 0;
	}
	addDigestDestination(algo,algoname);
	debugmsg("enabled hash algorithm %s\n",name);
	return 1;
#endif
}


void *hashThread(void *arg)
{
#if defined USE_GCRYPT
	dest_t *dest = (dest_t *) arg;
	gcry_md_hd_t hd;
	gcry_md_open(&hd, dest->mode, 0);
#elif defined HAVE_MD5	/*************** md5 ***************/
	dest_t *dest = (dest_t *) arg;
#ifdef USE_MHASH
	int algo = dest->mode;

	assert(dest->fd == -2);
	MHASH ctxt = mhash_init(algo);
	assert(ctxt != MHASH_FAILED);
#else
	MD5_INIT(MD5ctxt);
#endif
#endif
	debugmsg("hashThread(): starting...\n");
	for (;;) {
		int size;

		(void) syncSenders(0,0);
		size = SendSize;
		if (0 == size) {
			size_t ds;
			unsigned char hashvalue[128];
			char *msg, *m;
			const char *an;
			int i;
			
			debugmsg("hashThread(): done.\n");
#if defined USE_GCRYPT
			ds = gcry_md_get_algo_dlen(dest->mode);
			an = gcry_md_algo_name(dest->mode);
			memcpy(hashvalue,gcry_md_read(hd,dest->mode),ds);
#elif defined USE_MHASH
			mhash_deinit(ctxt,hashvalue);
			an = (const char *) mhash_get_hash_name_static(algo);
			ds = mhash_get_block_size(algo);
#else
			MD5_END(hashvalue,MD5ctxt);
			an = "md5";
			ds = 16;
#endif
			assert(sizeof(hashvalue) >= ds);
			m = msg = malloc(300);
			m += snprintf(m,300,"%s hash: ",an);
			for (i = 0; i < ds; ++i)
				m += snprintf(m,300-(m-msg),"%02x",(unsigned int)hashvalue[i]);
			if (m-msg < 300-2) {
				*m++ = '\n';
				*m = 0;
			} else 
				msg[299] = 0;
			dest->result = msg;
			pthread_exit((void *) msg);
			return 0;	/* for lint */
		}
		if (Terminate) {
			(void) syncSenders(0,-1);
			infomsg("hashThread(): terminating early upon request...\n");
			pthread_exit((void *) 0);
		}
		debugiomsg("hashThread(): hashing %d@0x%p\n",size,(void*)SendAt);
#if defined USE_GCRYPT
		gcry_md_write(hd,SendAt,size);
#elif defined USE_MHASH
		mhash(ctxt,SendAt,size);
#else
		MD5_UPDATE(MD5ctxt,SendAt,size);
#endif
	}
	return 0;
}


