#ifndef COMMANDS_HPP
#define COMMANDS_HPP

#include "aux.hpp"
#include <netdb.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <filesystem>

using namespace std;

bool login(istringstream& iss, User* user, int fd, struct addrinfo *res);
bool unregisterUser(istringstream& iss, User* user, int fd, struct addrinfo *res);
bool logout(istringstream& iss, User* user, int fd, struct addrinfo *res);
bool exitUser(istringstream& iss, User* user, int fd, struct addrinfo *res, struct addrinfo *res_tcp);
bool publishFile(istringstream& iss, User* user, int fd, struct addrinfo *res);
bool removeFile(istringstream& iss, User* user, int fd, struct addrinfo *res);
bool list(istringstream& iss, int fd, struct addrinfo *res);
bool versions(istringstream& iss, struct addrinfo *res);
void help();

#endif
