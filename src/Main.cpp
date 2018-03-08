#include "TribusStratumManager.h"
#include "TribusMiner.h"
#include "StratumUtil.h"
#include <stdlib.h>

#include "jh_bitslice_ref64.h"

#include "cuda_sph_jh.h"
#include "sph_keccak.h"
#include "sph_echo.h"


#include "util.h"
#include "openssl/sha.h"

// yiimp 86.200.212.88 8533
// hashbag 185.181.8.92 8688
// yiimp 86.200.212.88 3333 (Titcoin (sha256))

#define YIIMP "86.200.212.88"
#define HASHBAG "185.181.8.92"
#define miningpoolhub_zclassic "139.162.73.35"

#define YIIMP_DNR_PORT "8533"
#define YIIMP_TIT_PORT "3333"
#define MININGPOOL_ZCL_PORT "20575" //

#define HASHBAG_DNR_PORT "8688" // Denarius (tribus)

#define TIT_PUBLIC_ADDRESS "136K4arcN9GgsrGTqKYaoqvXyZ2BAdTLZ3" // Denarius (tribus)
#define DNR_PUBLIC_ADDRESS "DFhRKmTDmiz3v3QkRm9NUcTuYnBjsj3r9d" // Titcoin (sha256)
#define BTC_PUBLIC_ADDRESS "1F6yaWLQiFv3NyL3AA7yejDWN7DaPKnJaQ" // Bitcoin (sha256)


//Hash: 7FFE93565D2946
//Hash: CE5383A3F9188
//Hash: 8B55F33AE22F58
//Hash: AF23279A58E9C7

using namespace std;

int main1() {
	// Test Stratum Client
	StratumUtil stratumUtil;
	StratumManager stratum(&stratumUtil, HASHBAG, HASHBAG_DNR_PORT, DNR_PUBLIC_ADDRESS, "c=DNR,stats");
//	StratumManager stratum(YIIMP, YIIMP_DNR_PORT, DNR_PUBLIC_ADDRESS, "c=DNR,stats");
	TribusMiner miner(&stratum);

	stratum.subscribe("Test/1.0.0.0");
	stratum.authorize();
	stratum.start(&miner);

	return 0;
}

int main2() {
	Job job;
	job.blockHeader.blockVersion = hexToInt("00000006");
	job.blockHeader.previousHash = "936db7e36aeb57943a1c5e7eac6972f72d4f26a40dd31f49c1b9c5f0e77e8d99";
	job.blockHeader.merkleRoot = "";
	job.blockHeader.nTime = hexToInt("5a9eaa2e");
	job.blockHeader.nBits = hexToInt("1b027803");
//	job.coinbase1 = "02000000942e905a010000000000000000000000000000000000000000000000000000000000000000ffffffff180382080904952e905a08";
//	job.coinbase1 = "7969696d7000000000000100a3e11100000000232103637df881c595e8b440c019adca5ab2d89a865633e67fc129288ad65861b15d91ac00000000";

	MiningSessionSettings settings;
	settings.extranonce1 = "81001869";
	settings.extranonce2 = "01000000";
	settings.extranonce2Size = 4;

	try {
		StratumUtil stratumUtil;
		stratumUtil.buildHeader(job);
		std::cout << "StratumUtil Data: " << print(job.data, 80) << std::endl;
		std::cout << "StratumUtil Target: " << stratumUtil.getHexTarget() << std::endl;
	}
	catch(std::string &e) {
		std::cout << e;
		throw e;
	}

	return 0;
}

int main3() {
//	uint_32 ver = 2;
//	string prev_block = "00000000000001b843c3c20f8c9f2265889909eeb66b9e9d32f11db79ff7666f";
//	string mrkl_root = "788eae06ed4754ec79e078da059cec45446803023ee6a1f5606a281fe75187d6";
//	uint_32 time_ = 1520113103; // 2014-02-20 04:57:25
//	uint_32 bits = 0x1a01ecbe;

	uint_32 ver = 6;
	string prev_block = "00000000185ee000a8041f1f4edcf74f29ccedbb12db80b0231f1b2620589474";
	string mrkl_root = "d45c2f7f3231e44001f379c610d96a1ced5d3d813e4b079d6e9f0f691a41a621";
	uint_32 time_ = 1392871388; // 2014-02-20 04:57:25
	uint_32 bits = 0x1b10bc60;
	uint_32 nonce = 4242274009;

	uchar_8 data[80] = {0};

	buildHeader(ver, prev_block, mrkl_root, time_, bits, data);

	// # https://en.bitcoin.it/wiki/Difficulty
	uchar_8 target[32] = {0};

	calculateTargetByBits(bits, target, 32);
//	printf("Target by bits: %s\n", print(target, 32).c_str());

//	double diff1 = 3129573174.52;
//	double diff2 = 3007383866429.73;
	double diff3 = 8716326.4460687;
	clculateTargetByDifficulty(diff3, target, 32);
//	printf("Target by diff: %s\n", print(target, 32).c_str());

//	unsigned long nonce = 856192328;
//	unsigned long nonce = 2468105677;

    for (int j=0; j<1; j++, nonce++ ) {
    		setNonceInHeader(data, nonce);

    		uchar_8 hash[SHA256_DIGEST_LENGTH];
		sha256(data, 80, hash);
		sha256(hash, SHA256_DIGEST_LENGTH, hash);

	    cout << "Data: " << print(data, 80) << endl;
	    cout << "Hash: " << print(hash, 32) << endl;

	    for (int q=SHA256_DIGEST_LENGTH-1; q>=0; q--) {
	    		printf("%02x", hash[q]);
	    }
    }

    return 0;
}

void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

int main(int argc, char* argv[]) {
	Job job;
	job.blockHeader.blockVersion = 6;
	job.blockHeader.previousHash = "00000000000edd8adb8a7f53b2f7319963da1542260125912fb83757edc697ff";
	job.blockHeader.merkleRoot = "eb6d23c6cfd584522c91c9c296c83cdfcf4527b9d8a7ac1f5983693c15636365";
	job.blockHeader.nTime = 1520493559;
	job.blockHeader.nBits = 0x1b1f2b11;
	uint_32 nonce = 2479828255;

	MiningSessionSettings settings;
	settings.extranonce1 = "81001869";
	settings.extranonce2 = "01000000";
	settings.extranonce2Size = 4;

	StratumUtil stratumUtil;
	stratumUtil.buildHeader(job);
	stratumUtil.setNonceInHeader(job, nonce);

	std::cout << "StratumUtil Data: " << print(job.data, 80) << std::endl;
	std::cout << "StratumUtil Target: " << stratumUtil.getHexTarget() << std::endl;

	uchar_8 *data = job.data;
	uchar_8 hash[64];

	jh512_80(data, hash);
	cout << "Hash 1: " << print(hash, 64) << endl;

	sph_keccak512_context ctx_keccak;
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, (const void*) hash, 64);
	sph_keccak512_close(&ctx_keccak, (void*) hash);
	cout << "Hash 2: " << print(hash, 64) << endl;

	sph_echo512_context ctx_echo;
	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, (void*) hash);
	cout << "Hash 3: " << print(hash, 64) << endl;

	cout << "hash  : " << reverseHexStr( print(hash, 32) ) << endl;
	string correct("000000000009b6d70c3ebcb3a7f35663202b008531197894e4238ae845d434ec");
	cout << "VALID : " << (!correct.compare(reverseHexStr(print(hash, 32))) ? "TRUE" : "FALSE") << endl;
	cout << "target: " << print(stratumUtil.getTarget(), 32)  << endl;
	cout << "memcmp 1: " << memcmp(hash, stratumUtil.getTarget(), 32) << endl;
	cout << "memcmp 2: " << memcmp(stratumUtil.getTarget(), hash, 32) << endl;

	return 0;
}

