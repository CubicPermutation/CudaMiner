#pragma once

#include "StratumManager.h"

class TribusStratumManager : public StratumManager {
public:
	TribusStratumManager(StratumUtil *stratumUtil, std::string host, std::string port, std::string username, std::string password);
	~TribusStratumManager();
};
