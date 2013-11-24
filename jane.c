/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2013 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void scrypt_hash(const void* input, size_t inputlen, uint32_t *res, unsigned char Nfactor)
{
    return scrypt((const unsigned char*)input, inputlen,
                  (const unsigned char*)input, inputlen,
                  9, 5, 0, (unsigned char*)res, 32);
}

int scanhash_scrypt(int thr_id, uint32_t *pdata,
	unsigned char *scratchbuf, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t data[80], hash[32];
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	int i;
	do {
		data[19] = bswap_32(++n);

		scrypt_hash(data, 80, hash, 12);
		
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			*hashes_done = n - pdata[19] + 1;
			pdata[19] = bswap_32(data[19]);
			return 1;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}
