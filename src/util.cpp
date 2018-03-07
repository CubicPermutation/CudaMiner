#include "util.h"
#include <stdint.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <random>

#include <openssl/sha.h>

//static bool hashbelowtarget(const uint32_t *const __restrict__ hash, const uint32_t *const __restrict__ target)
//{
//	if (hash[7] > target[7])
//		return false;
//	if (hash[7] < target[7])
//		return true;
//	if (hash[6] > target[6])
//		return false;
//	if (hash[6] < target[6])
//		return true;
//
//	if (hash[5] > target[5])
//		return false;
//	if (hash[5] < target[5])
//		return true;
//	if (hash[4] > target[4])
//		return false;
//	if (hash[4] < target[4])
//		return true;
//
//	if (hash[3] > target[3])
//		return false;
//	if (hash[3] < target[3])
//		return true;
//	if (hash[2] > target[2])
//		return false;
//	if (hash[2] < target[2])
//		return true;
//
//	if (hash[1] > target[1])
//		return false;
//	if (hash[1] < target[1])
//		return true;
//	if (hash[0] > target[0])
//		return false;
//
//	return true;
//}

/* compute nbits to get the network diff */
double calc_network_diff(uint32_t nbits_input) {
	// sample for diff 43.281 : 1c05ea29
	uint32_t nbits = swab32(nbits_input);
	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

//	uint64_t diffone = 0x0000FFFF00000000ull;
	double d = (double)0x0000ffff / (double)bits;

	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;

	return d;
}

uint32_t le32dec(const void *pp) {
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

bool hex2bin(void *output, const char *hexstr, int len) {
	unsigned char *p = (unsigned char *) output;
	char hex_byte[4];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			std::cout << "hex2bin str truncated" << std::endl;
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			std::cout << "hex2bin failed on " << hex_byte << std::endl;
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return (len == 0 && *hexstr == 0) ? true : false;
}

unsigned char getMerkleTree(int merkle_count, unsigned char **merkle) {
//	if (merkle_count)
//		merkle = (unsigned char **) malloc(merkle_count * sizeof(char *));
//	for (int i = 0; i < merkle_count; i++) {
//		const char *s = 0; // = json_string_value(json_array_get(merkle_arr, i));
//		if (!s || strlen(s) != 64) {
//			while (i--)
//				free(merkle[i]);
//			free(merkle);
//			std::cout << "Stratum notify: invalid Merkle branch" << std::endl;
//			// ERROR OUT
//		}
//		merkle[i] = (unsigned char*) malloc(32);
//		hex2bin(merkle[i], s, 32);
//	}
	return 0;
}

std::string reverseHexStr(std::string str) {
	int n = str.length();
	for (int i=0; i<n/2; i+=2) {
		std::swap(str[i], str[n-1-i-1]);
		std::swap(str[i+1], str[n-1-i]);
	}

	return str;
}

void hexToBin(std::string hexStr, uchar_8* binary, int binaryLength) {
	if( 0 == hexStr.length() ) {
		memset(binary, 0, 32);
		return;
	}

	if (binaryLength != hexStr.length()/2) {
		std::cout << std::endl << hexStr << std::endl;
		std::cout << "ERROR! binaryLength(" << binaryLength << ") does not match hexStr length(" << hexStr.length()/2 << ")";
		std::cout << std::endl;

		std::ostringstream stringStream;
		stringStream << "ERROR! binaryLength(" << binaryLength << ") does not match hexStr length(" << hexStr.length()/2 << ")";
		throw stringStream.str();
	}

	for (int l=0, cursor=0; l<hexStr.length(); l+=sizeof(uint_32)*2) {
		uint_32 tmp = hexToInt(hexStr.substr(l, sizeof(uint_32)*2));
		for (int shiftSize=(sizeof(uint_32)-1)*8; shiftSize>=0; shiftSize-=8, cursor++) {
			binary[cursor] = (uchar_8) (tmp >> shiftSize);
		}
	}
}

uint_32 hexToInt(std::string hexStr) {
	uint_32 tmp;
	std::stringstream ss;
	ss << std::hex << hexStr;
	ss >> tmp;

	return tmp;
}

std::string print(uchar_8 *hash, int length) {
	std::stringstream ss;
	char hex[2];
	for (int i=0; i<length; i++) {
		sprintf(hex, "%02x", hash[i]);
		ss << hex;
	}

	return ss.str();
}

void sha256(const uchar_8 *d, int len, uchar_8 *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, d, len);
    SHA256_Final(hash, &sha256);
}

void calculateTargetByBits(uint_32 bits, uchar_8 *target, int targetLength) {
	unsigned long exp = bits >> 24;
	unsigned long mant = bits & 0xffffff;

	int location = exp - 3;
	target[targetLength - ++location] = ( mant >>  0 ) & 0xFF;
	target[targetLength - ++location] = ( mant >>  8 ) & 0xFF;
	target[targetLength - ++location] = ( mant >> 16 ) & 0xFF;
	target[targetLength - ++location] = ( mant >> 24 ) & 0xFF;
}

void clculateTargetByDifficulty(double diff, uchar_8 *target, int targetLength) {
	double denominator32Bit = 0x100000000;
	uint_64 tmpVar;
	int loc;
	for (loc = 0; loc < targetLength && diff > 1.0; loc+=4) {
		diff /= denominator32Bit;
	}

	tmpVar = (uint_64)(0xFFFF0000 / diff);
	if (tmpVar == 0 && loc == targetLength) {
		memset(target, 0xff, targetLength);
	} else {
		memset(target, 0, 32);
		for (int i=56; i>=0; i-=8) {
			target[loc++] = (tmpVar >> i);
		}
	}
}

void setNonceInHeader(uchar_8 *data, uint_32 nonce) {
	data[76] = (nonce >> 0) & 0xFF;
	data[77] = (nonce >> 8) & 0xFF;
	data[78] = (nonce >> 16) & 0xFF;
	data[79] = (nonce >> 24) & 0xFF;
}

void buildHeader(uint_32 ver, std::string prev_block, std::string mrkl_root, uint_32 time_, uint_32 bits, uchar_8 *data) {
	memset(data, 0, 80);
	int i = 0;

	data[i++] = (ver >> 0) & 0xFF;
	data[i++] = (ver >> 8) & 0xFF;
	data[i++] = (ver >> 16) & 0xFF;
	data[i++] = (ver >> 24) & 0xFF;
	hexToBin( reverseHexStr(prev_block), data+i, 32);
	i += 32;
	hexToBin( reverseHexStr(mrkl_root), data+i, 32);
	i += 32;
	data[i++] = (time_ >> 0) & 0xFF;
	data[i++] = (time_ >> 8) & 0xFF;
	data[i++] = (time_ >> 16) & 0xFF;
	data[i++] = (time_ >> 24) & 0xFF;
	data[i++] = (bits >> 0) & 0xFF;
	data[i++] = (bits >> 8) & 0xFF;
	data[i++] = (bits >> 16) & 0xFF;
	data[i++] = (bits >> 24) & 0xFF;
}


uint_64 randomNonce() {
	/* Seed */
	std::random_device rd;
	/* Random number generator */
	std::default_random_engine generator(rd());
	/* Distribution on which to apply the generator */
	std::uniform_int_distribution<long unsigned> distribution(0,0xFFFFFFFF);

	return distribution(generator);
}


