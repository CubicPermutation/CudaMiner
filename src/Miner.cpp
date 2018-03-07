#include "Miner.h"
#include "StratumManager.h"
#include <chrono>

using namespace std::chrono;

Miner::Miner(StratumManager *stratum) {
	this->stratum = stratum;
	this->minerThread = 0;
}

Miner::~Miner() {
	printf("Miner: Destructing Miner ...\n");
//	delete queue;
	delete minerThread;
}

void Miner::enqueue(Job &job) {
	this->currentJob = job;
	std::cout << "A new job has arrived with the id: " << currentJob.jobId << " Thread: " << minerThread << std::endl;
	if (minerThread != 0) {
//		std::cout << "Trying to kill thread: " << minerThread << std::endl;
//		minerThread->interrupt();
//		std::cout << "Interruption sent to thread: " << minerThread << std::endl;
//		boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
//		std::cout << "Waited for 100 milliseconds" << std::endl;
//		delete minerThread;
//		std::cout << "Old thread deleted" << std::endl;
	} else if ( 0 == minerThread ) {
		minerThread = new boost::thread(boost::bind(&Miner::miner, this));
	}
}

void Miner::setDifficulty(double difficulty) {
	this->difficulty = difficulty;
	std::cout << "Miner difficulty: " << difficulty <<  std::endl;
}

void Miner::miner() {
	try {
		unsigned int s = system_clock::now().time_since_epoch().count() / 1000000;
		std::cout << "Miner::mine() started at " << s <<  std::endl;

		uint_64 nonce = mine(currentJob);

		uint_32 rollingTime = system_clock::now().time_since_epoch().count() / 1000000;
		Submission submission;
		submission.jobId = currentJob.jobId;
		submission.extranonce1 = "e3002e28";
		submission.rollingTime = rollingTime;
		submission.nonce = nonce;
		stratum->submit(submission);

		std::cout << "Miner::mine() ended at " << rollingTime << " [took: " << rollingTime-s << "]" <<  std::endl;
	} catch (boost::thread_interrupted&) {
		std::cout << "Miner::mine() Interrupted." << std::endl;
	}

	free(currentJob.data);
	free(currentJob.target);
}
