#include "TribusStratumManager.h"
#include "TribusMiner.h"
#include "StratumUtil.h"
#include <stdlib.h>

#include "jh_bitslice_ref64.h"

#include "cuda_sph_jh.h"
#include "cuda_sph_keccak.h"
#include "cuda_sph_echo.h"


#include "util.h"
#include "openssl/sha.h"

#define YIIMP "86.200.61.239"
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
//	StratumManager stratum(&stratumUtil, HASHBAG, HASHBAG_DNR_PORT, DNR_PUBLIC_ADDRESS, "c=DNR,stats");
	StratumManager stratum(&stratumUtil, YIIMP, YIIMP_DNR_PORT, DNR_PUBLIC_ADDRESS, "c=DNR,stats");
	TribusMiner miner(&stratum);

	stratum.subscribe("Test/0.0.0.1");
	stratum.authorize();
	stratum.start(&miner);

	return 0;
}

int main2() {
	Job job;
	job.blockHeader.blockVersion = hexToInt("00000006");
	job.blockHeader.previousHash = "00000000000bb28d430811fe9a45129f9a63e189814cac0393b66d0426cff08f";
	job.blockHeader.merkleRoot = "96364453a5c7fd918ef052e0c2908f1d3b4ec3ddd0731cdf7f4b30df59077566";
	job.blockHeader.nTime = 1520721853;
	job.blockHeader.nBits = hexToInt("1b07e716");
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

//	Job job;
//	job.blockHeader.blockVersion = hexToInt("00000006");
//	job.blockHeader.previousHash = "00000000000bb28d430811fe9a45129f9a63e189814cac0393b66d0426cff08f";
//	job.blockHeader.merkleRoot = "96364453a5c7fd918ef052e0c2908f1d3b4ec3ddd0731cdf7f4b30df59077566";
//	job.blockHeader.nTime = 1520721853;
//	job.blockHeader.nBits = hexToInt("1b07e716");
//	uint_32 nonce = 2759401150;

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
//	Job job;
//	job.blockHeader.blockVersion = 6;
//	job.blockHeader.previousHash = "6ff82140864bf7ba0f42d9c3d91ad26395e24ddb6a31282e3fa37e1af8c2bf76";
//	job.blockHeader.merkleRoot = "4a78a89b2d46ec585e5e0595dd3b44b5c0062b2d5e41bf5df46bc2a47b7f5ea2";
//	job.blockHeader.nTime = 1519135271;
//	job.blockHeader.nBits = 0x1b09f630;
//	uint_32 nonce = 320665675;
//	string correct = "000000000008a40ddd02700ea978a8091c0be6f296be848027ca9fa234aded12";

	Job job;
	job.blockHeader.blockVersion = hexToInt("00000006");
	job.blockHeader.previousHash = "00000000000bb28d430811fe9a45129f9a63e189814cac0393b66d0426cff08f";
	job.blockHeader.merkleRoot = "96364453a5c7fd918ef052e0c2908f1d3b4ec3ddd0731cdf7f4b30df59077566";
	job.blockHeader.nTime = 1520721853;
	job.blockHeader.nBits = hexToInt("1b07e716");
	uint_32 nonce = 2759401154;
	string correct = "0000000000003bde22643cd7932705a3f84ac4c474a8a812ffdfcf969ded7d4c";

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

	keccak512_80(data, hash);
	cout << "Hash 2: " << print(hash, 64) << endl;

	echo512_80(data, hash);
	cout << "Hash 3: " << print(hash, 64) << endl;

	cout << "hash  : " << reverseHexStr( print(hash, 32) ) << endl;
	cout << "VALID : " << (!correct.compare(reverseHexStr(print(hash, 32))) ? "TRUE" : "FALSE") << endl;
	cout << "target: " << print(stratumUtil.getTarget(), 32)  << endl;
	cout << "memcmp 1: " << memcmp(hash, stratumUtil.getTarget(), 32) << endl;
	cout << "memcmp 2: " << memcmp(stratumUtil.getTarget(), hash, 32) << endl;

	return 0;
}


