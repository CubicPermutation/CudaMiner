#pragma once

#include "types.h"

#include <iostream>


typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;
typedef short int16_t;

#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))

static inline uint32_t swab32(uint32_t v) {
	return bswap_32(v);
}

//static bool hashbelowtarget(const uint32_t *const __restrict__ hash, const uint32_t *const __restrict__ target);

double calc_network_diff(uint32_t nbits_input);

uint32_t le32dec(const void *pp);

bool hex2bin(void *output, const char *hexstr, int len);

unsigned char getMerkleTree(int merkle_count, unsigned char **merkle);

std::string reverseHexStr(std::string);

void hexToBin(std::string, uchar_8*, int binaryLength);

uint_32 hexToInt(std::string hexStr);

std::string print(uchar_8* hash, int length);

void sha256(const uchar_8 *d, int len, uchar_8 *hash);

void calculateTargetByBits(uint_32 bits, uchar_8 *target, int targetLength);

void clculateTargetByDifficulty(double diff, uchar_8 *target, int targetLength);

void setNonceInHeader(uchar_8 *data, uint_32 nonce);

void buildHeader(uint_32 ver, std::string prev_block, std::string mrkl_root, uint_32 time_, uint_32 bits, uchar_8 *data);

uint_64 randomNonce();

