
#pragma once

#include "Structs.h"
#include "StratumUtil.h"

#include <iostream>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
//#include <boost/lockfree/queue.hpp>

class Miner;

namespace ip = boost::asio::ip;
namespace pt = boost::property_tree;

class StratumManager {
private:
	std::string host;
	std::string port;
	std::string username;
	std::string password;
	ip::tcp::socket *socket_;
	boost::mutex *mutex_;
	boost::thread *managerThread_;
	Miner *miner;
//	boost::lockfree::queue<std::string> queue(10);


	void readLine(std::string&);
	void receive();
	ip::tcp::socket createSocket();
	void send(std::string);
	void process(std::string);
	double readDifficulty(pt::ptree);
	Job readJob(pt::ptree);
	MiningSessionSettings readMiningSessionSettings(pt::ptree);

protected:
	StratumUtil *stratumUtil;

public:
	StratumManager(StratumUtil *stratumUtil, std::string host, std::string port, std::string username, std::string password);
	~StratumManager();

	void start(Miner*);
	void subscribe(const char*);
	void authorize();
	void submit(Submission);

	double difficulty(std::string difficulty);
};
