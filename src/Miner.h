#pragma once

#include "Structs.h"
#include "types.h"
#include "StratumUtil.h"

#include <boost/thread.hpp>
//#include <boost/lockfree/spsc_queue.hpp>

class StratumManager;

class Miner {
private:
	boost::thread *minerThread;
	StratumManager *stratum;

	Job currentJob;
	float difficulty = 0.0f;
//	boost::lockfree::spsc_queue<std::string, boost::lockfree::capacity<20>> queue;

	void miner();

protected:
	virtual uint_32 mine(Job job) = 0;

public:
	Miner(StratumManager*);
    virtual ~Miner();

	void enqueue(Job&);
	void setDifficulty(double difficulty);
};
