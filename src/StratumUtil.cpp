#include "StratumUtil.h"
#include "util.h"

#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>
#include <stdlib.h>


StratumUtil::StratumUtil() {
	target = (uchar_8*)malloc( sizeof(uchar_8) * getTargetSize() );
}

StratumUtil::~StratumUtil() {
	printf("StratumUtil: Freeing Memory...\n");
	free(target);
}

void StratumUtil::setSettings(MiningSessionSettings &settings) {
	this->settings = settings;
}

uchar_8* StratumUtil::getTarget() {
	return target;
}

uint_32 StratumUtil::getDataSize() {
	return DEFAULT_DATA_SIZE;
}

std::string StratumUtil::getHexTarget() {
	return print(target, getTargetSize());
}

uint_32 StratumUtil::getTargetSize() {
	return DEFAULT_TARGET_SIZE;
}

void StratumUtil::setDifficulty(double difficulty) {
	clculateTargetByDifficulty(difficulty);
}

void StratumUtil::buildHeader(Job &job) {
	job.data = (uchar_8*)malloc( sizeof(uchar_8) * getDataSize() );
	job.target = (uchar_8*)malloc( sizeof(uchar_8) * getTargetSize() );
	memset(job.data, 0, 80);
	int i = 0;

	job.data[i++] = (job.blockHeader.blockVersion >> 0) & 0xFF;
	job.data[i++] = (job.blockHeader.blockVersion >> 8) & 0xFF;
	job.data[i++] = (job.blockHeader.blockVersion >> 16) & 0xFF;
	job.data[i++] = (job.blockHeader.blockVersion >> 24) & 0xFF;
	hexToBin( reverseHexStr(job.blockHeader.previousHash), job.data+i, 32);
	i += 32;
	hexToBin( reverseHexStr(job.blockHeader.merkleRoot), job.data+i, 32);
	i += 32;
	job.data[i++] = (job.blockHeader.nTime >> 0) & 0xFF;
	job.data[i++] = (job.blockHeader.nTime >> 8) & 0xFF;
	job.data[i++] = (job.blockHeader.nTime >> 16) & 0xFF;
	job.data[i++] = (job.blockHeader.nTime >> 24) & 0xFF;
	job.data[i++] = (job.blockHeader.nBits >> 0) & 0xFF;
	job.data[i++] = (job.blockHeader.nBits >> 8) & 0xFF;
	job.data[i++] = (job.blockHeader.nBits >> 16) & 0xFF;
	job.data[i++] = (job.blockHeader.nBits >> 24) & 0xFF;


	calculateTargetByBits(job.blockHeader.nBits);
	memcpy(job.target, target, getTargetSize());
}

void StratumUtil::calculateTargetByBits(uint_32 nBits) {
	unsigned long exp = nBits >> 24;
	unsigned long mant = nBits & 0xFFFFFF;

	int location = exp - 3;
	target[getTargetSize() - ++location] = ( mant >>  0 ) & 0xFF;
	target[getTargetSize() - ++location] = ( mant >>  8 ) & 0xFF;
	target[getTargetSize() - ++location] = ( mant >> 16 ) & 0xFF;
	target[getTargetSize() - ++location] = ( mant >> 24 ) & 0xFF;
}

void StratumUtil::clculateTargetByDifficulty(double difficulty) {
	double denominator32Bit = 0x100000000;
	uint_64 tmpVar;
	int loc;
	for (loc = 0; loc < getTargetSize() && difficulty > 1.0; loc+=4) {
		difficulty /= denominator32Bit;
	}

	tmpVar = (uint_64)(0xFFFF0000 / difficulty);
	if (tmpVar == 0 && loc == getTargetSize()) {
		memset(target, 0xff, getTargetSize());
	} else {
		memset(target, 0, 32);
		for (int i=56; i>=0; i-=8) {
			target[loc++] = (tmpVar >> i);
		}
	}
}

void StratumUtil::setNonceInHeader(Job &job, uint_32 nonce) {
	job.data[76] = (nonce >> 0) & 0xFF;
	job.data[77] = (nonce >> 8) & 0xFF;
	job.data[78] = (nonce >> 16) & 0xFF;
	job.data[79] = (nonce >> 24) & 0xFF;
}


//std::string StratumUtil::merkle(std::string merkles[]) {
//	std::string merkle;
//	int size = sizeof(*merkles)/sizeof(std::string*);
//	std::cout << " size : " << size << std::endl;
//	for (int i=0; i<size; i++) {
////		std::cout << " mmm : " << merkles[i] << std::endl;
//		merkle.append(merkles[i]);
//	}
//	return merkle;
//}
//
//std::string StratumUtil::getCoinbase() {
//	std::string coinbase;
////	coinbase.append(coinbase1);
//	coinbase.append(settings.extranonce1);
//	coinbase.append(settings.extranonce2);
////	coinbase.append(job.coinbase2);
//
//	return coinbase;
//}


