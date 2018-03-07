#pragma once

#include <iostream>
#include "types.h"

struct MiningSessionSettings {
	std::string extranonce1; // Extranonce1 - Hex-encoded, per-connection unique string which will be used for coinbase serialization later. Keep it safe!
	std::string extranonce2; // "00000004"; // can be anything, however, its size must be equal to extranonce2Size
	int extranonce2Size; // Represents expected length of extranonce2 which will be generated by the miner.
};

struct BlockHeader {
	uint_32 blockVersion;
	std::string previousHash;
	std::string merkleRoot;
	uint_32 nTime;
	uint_32 nBits;
};

struct Job {
	std::string username;

	BlockHeader blockHeader;

	std::string jobId;
	std::string coinbase1;
	std::string coinbase2;
	std::string cleanJob;

	uchar_8 *data;
	uchar_8 *target;

};

struct Submission {
	std::string jobId;
	std::string extranonce1;
	unsigned int rollingTime;
	unsigned long nonce;
};
