#ifndef AUX_HPP
#define AUX_HPP

#include <cstring>
#include <iostream>

using namespace std;

#define STANDARD_DSIP "193.136.138.142" // Fora do Técnico
// #define STANDARD_DSIP "192.168.1.1" // No LT5
#define STANDARD_DSPORT "59000" //Change port number
#define UPD_TIMEOUT 5
#define TCP_TIMEOUT 5

struct User {
    string UID;
    string password;
    string peerport;
    int login_state = 0;
};

bool only_digits(const char str[]);
bool only_alnum(const char str[]);
void argument_handler(int argc, char* argv[], string *peerport, string *DSIP, string *DSport);

#endif
