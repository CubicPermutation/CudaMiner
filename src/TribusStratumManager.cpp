#include "TribusStratumManager.h"

TribusStratumManager::TribusStratumManager(StratumUtil *stratumUtil, std::string host, std::string port, std::string username, std::string password)
: StratumManager(stratumUtil, host, port, username, password) {
};

TribusStratumManager::~TribusStratumManager() {
}
