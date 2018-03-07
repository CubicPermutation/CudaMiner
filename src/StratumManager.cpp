#include "StratumManager.h"
#include "Miner.h"
#include "util.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <stdio.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

namespace pt = boost::property_tree;
namespace ip = boost::asio::ip;

StratumManager::StratumManager(StratumUtil *stratumUtil, std::string host, std::string port, std::string username, std::string password) {
	printf("StratumManager: Constructing StratumManager ...\n");
	this->host = host;
	this->port = port;
	this->username = username;
	this->password = password;
	this->miner = 0;
	this->managerThread_ = 0;
	this->mutex_ = new boost::mutex();
	this->stratumUtil = stratumUtil;

	boost::asio::io_service io_service;
	socket_ = new ip::tcp::socket(io_service);
	ip::tcp::resolver resolver(io_service);
	boost::asio::connect(*socket_, resolver.resolve( { host, port }));
	printf("StratumManager: Done Constructing StratumManager ...\n");
}

StratumManager::~StratumManager() {
	printf("StratumManager: Destructing ...\n");
	delete mutex_;
	delete managerThread_;
	delete socket_;
	printf("StratumManager: Done Destructing ...\n");
}

ip::tcp::socket StratumManager::createSocket() {
	boost::asio::io_service io_service;
    ip::tcp::socket socket(io_service);
	ip::tcp::resolver resolver(io_service);
	boost::asio::connect(socket, resolver.resolve( { this->host, this->port }));

	return socket;
}

void StratumManager::start(Miner *miner) {
	this->miner = miner;
	managerThread_ = new boost::thread(boost::bind(&StratumManager::receive, this));
	managerThread_->join();
}

void StratumManager::readLine(std::string &line) {
//	mutex_->lock();
	char bufferChar[2] = {0};
	while (true) {
		boost::asio::read(*socket_, boost::asio::buffer(bufferChar, 1));
		if (bufferChar[0] == '\n' || bufferChar[0] == '\r' ) {
			break;
		}
		line.append(bufferChar);
	}
	std::cout << "+++ Received (" << line.length() << ") " << line << std::endl;
//	mutex_->unlock();
}

void StratumManager::receive() {
	try {
		while (true) {
			std::string line;
			readLine( line );
			process( line );
		}
	} catch (boost::thread_interrupted&) {
		std::cout << "StratumManager::receive() interrupted." << std::endl;
	}
}

void StratumManager::process(std::string json) {
//	(*mutex_).lock();

	std::stringstream ss;
	ss << json;

	pt::ptree root;
	pt::read_json(ss, root);

	std::string id = root.get<std::string>("id");

	if (id == "1") {
		// Subscription response
		std::string error = root.get<std::string>("error");
		if (error != "null") {
			std::cout << "ERROR! Subscription failed: " << error << std::endl;
		} else {
			std::cout << "OK! Subscription succeeded." << std::endl;
			readMiningSessionSettings(root);
		}
	} else if (id == "2") {
		// Authorization response
		std::string error = root.get<std::string>("error");
		if (error != "null") {
			std::cout << "ERROR! Authorization failed: " << error << std::endl;
		} else {
			std::cout << "OK! Authorization succeeded." << std::endl;
		}
	} else if (id == "3") {
		// Extranonce subscription response
		std::string error = root.get<std::string>("error");
		if (error != "null") {
			std::cout << "ERROR! Extranonce-subscription failed: " << error << std::endl;
		} else {
			std::cout << "OK! Extranonce-subscription succeeded." << std::endl;
		}
	} else if (id == "4") {
		// Submission response
		std::string error = root.get<std::string>("error");
		if (error != "null") {
			std::cout << "ERROR! Submission failed: ";
			std::vector<std::string> errors;
			for (pt::ptree::value_type &err : root.get_child("error")) {
				errors.push_back(err.second.data());
			}
			std::cout << errors.at(1) << std::endl;
		} else {
			std::cout << "OK! Submission succeeded." << std::endl;
		}
	} else if (id == "null") {
		std::string method = root.get<std::string>("method");
		std::cout << "method: " << method << std::endl;

		if (method.find("mining.set_difficulty") != std::string::npos) {
			stratumUtil->setDifficulty( readDifficulty(root) );
		} else if (method.find("mining.notify") != std::string::npos) {
			Job job = readJob(root);
			miner->enqueue(job);
		}
	}

//	(*mutex_).unlock();
}

void StratumManager::subscribe(const char *agent) {
	char command[100];
	sprintf(command, "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"%s\"]}", agent);
	send(command);

	std::string line;
	readLine(line);
	process( line );
}

void StratumManager::authorize() {
	char command[100];
	sprintf(command, "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}", username.c_str(), password.c_str());
	send(command);

	std::string line;
	readLine(line);
	process( line );
}

void StratumManager::submit(Submission submission) {
	char rollingTimeHex[9] = {0};
	sprintf(rollingTimeHex, "%x", submission.rollingTime);

	char nonceHex[9] = {0};
	sprintf(nonceHex, "%lx", submission.nonce);

	char command[300];
	sprintf(command, "{\"id\":4, \"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]}",
			username.c_str(), submission.jobId.c_str(), submission.extranonce1.c_str(), rollingTimeHex, nonceHex);
	send(command);
}

void StratumManager::send(std::string msg) {
//	mutex_->lock();
//	queue.push("1");
	std::cout << ">>> Sending: " << msg << std::endl;
	boost::asio::write(*socket_, boost::asio::buffer(msg, msg.length()));
//	mutex_->unlock();
}

double StratumManager::readDifficulty(pt::ptree root) {
	std::vector<std::string> params;
	for (pt::ptree::value_type &p : root.get_child("params")) {
		params.push_back(p.second.data());
	}
	return atof(params.at(0).c_str());
}

Job StratumManager::readJob(pt::ptree root) {
	std::vector<std::string> params;
	for (pt::ptree::value_type &p : root.get_child("params")) {
		params.push_back(p.second.data());
	}
	Job job;
	job.username = username;
	job.jobId = params.at(0);

	job.blockHeader.blockVersion = hexToInt(params.at(5));
	job.blockHeader.previousHash = params.at(1);
	job.blockHeader.merkleRoot = "";
	job.blockHeader.nTime = hexToInt( params.at(7) );
	job.blockHeader.nBits = hexToInt( params.at(6) );

	job.coinbase1 = params.at(2);
	job.coinbase2 = params.at(3);
	job.cleanJob = params.at(8);

	stratumUtil->buildHeader(job);

	return job;
}

MiningSessionSettings StratumManager::readMiningSessionSettings(pt::ptree root) {
	std::vector<std::string> params;
	for (pt::ptree::value_type &p : root.get_child("result")) {
		params.push_back(p.second.data());
	}
	MiningSessionSettings settings;
	settings.extranonce1 = params.at(1);
	settings.extranonce2Size = std::stoi(params.at(2));

	std::cout << "Settings {extranonce1: '" << "'" << settings.extranonce1 << "', extranonce2Size: '" << settings.extranonce2Size << "'}" << "  '" << std::endl;

	return settings;
}


double StratumManager::difficulty(std::string difficulty) {
	return 0;
}


