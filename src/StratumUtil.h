#pragma once

#include "Structs.h"
#include "types.h"

#include <iostream>

#define DEFAULT_DATA_SIZE 80
#define DEFAULT_TARGET_SIZE 32

class StratumUtil {
private:
//	Job job;
	MiningSessionSettings settings;

//	uchar_8 *data;

//	uchar_8 *version;
//	uchar_8 *previousHash;
//	uchar_8 *merkleRoot;
//	uchar_8 *nTime;
//	uchar_8 *nBits;
//	uchar_8 *constant1;
//	uchar_8 *constant2;

//	double difficulty;
	uchar_8* target;

protected:
	uint_32 getDataSize();
	uint_32 getTargetSize();

	void calculateTargetByBits(uint_32 nBits);
	void clculateTargetByDifficulty(double difficulty);

public:
	StratumUtil();
	~StratumUtil();

	void buildHeader(Job &job);
	void setSettings(MiningSessionSettings &settings);
	void setNonceInHeader(Job &job, uint_32 nonce);
	void setDifficulty(double difficulty);

//	uchar_8* getData();
//	std::string getHexData();
	uchar_8* getTarget();
	std::string getHexTarget();


//	uint_32 getMaxnonce();

//	std::string getCoinbase();

//	std::string merkle(std::string[]);
};
