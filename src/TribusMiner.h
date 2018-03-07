#pragma once

#include "Miner.h"

class TribusMiner : public Miner {
protected:
	uint_32 mine(Job job);
	StratumUtil getStratumUtil();

public:
	TribusMiner(StratumManager *stratumManager) : Miner(stratumManager) {};
};
