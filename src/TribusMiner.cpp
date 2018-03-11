#include "TribusMiner.h"
#include "types.h"
#include "util.h"
#include <stdlib.h>

#include "cuda_sph_keccak.h"
#include "cuda_sph_echo.h"
#include "cuda_sph_jh.h"

uint_32 TribusMiner::mine(Job job) {
	uint_32 nonce = 0xFFFFFFFF;

	try {
		std::cout << "TribusMiner called" << std::endl;

		std::string prevHash = reverseHexStr(job.blockHeader.previousHash);
		std::string jobId = job.jobId;

		uchar_8 hash[64] = {0};

		do {
			setNonceInHeader(job.data, nonce);

			jh512_80(job.data, hash);

			keccak512_80(hash, hash);

//			sph_echo512_context ctx_echo;
//			sph_echo512_init(&ctx_echo);
//			sph_echo512(&ctx_echo, hash, 64);
//			sph_echo512_close(&ctx_echo, (void*) hash);
			echo512_80(hash, hash);

			if( !(nonce % 0x10000) ) {
				printf("Nonce: %s {%s} [%s]\n", reverseHexStr(print((uchar_8*)&nonce, 4)).c_str(), jobId.c_str(), prevHash.c_str());
			}
			nonce--;

		} while (memcmp(hash, job.target, 32) > 0);

		printf("Nonce found: %x \n", nonce);
		printf("previousHash: %s\n", job.blockHeader.previousHash.c_str());
		printf("merkleRoot: %s\n", job.blockHeader.merkleRoot.c_str());
		printf("nBits: %x\n", job.blockHeader.nBits);
		printf("blockVersion: %x\n", job.blockHeader.blockVersion);
		printf("nTime: %x\n", job.blockHeader.nTime);

	} catch (boost::thread_interrupted&) {
		std::cout << "TribusMiner::mine() interrupted." << std::endl;
	}

	return nonce;
}

